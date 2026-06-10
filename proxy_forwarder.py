#!/usr/bin/env python3
"""
proxy_forwarder.py — локальный SOCKS5-сервер, который форвардит трафик через
лучший upstream-прокси из списка, собранного proxy_harvester.py.

Использование:
    python proxy_forwarder.py --country FR --port 1080 [options]

Примеры:
    python proxy_forwarder.py --country FR --port 1080 --bind 127.0.0.1
    python proxy_forwarder.py --country NL --port 1081 --ping 300 --check 15

Как работает:
    1. Читает proxies/state.json (только чтение, не мешает harvester'у).
    2. Выбирает лучший живой прокси для указанной страны (минимальный пинг).
    3. Поднимает SOCKS5-сервер на bind:port.
    4. Каждые --check секунд проверяет upstream, переключается на следующий
       если текущий упал.
    5. state.json перечитывается при каждой проверке — список всегда актуален.
"""

import argparse
import asyncio
import json
import logging
import signal
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy_forwarder")

# ---------------------------------------------------------------------------
# Upstream proxy dataclass (read from state.json)
# ---------------------------------------------------------------------------

@dataclass
class UpstreamProxy:
    host: str
    port: int
    type: str       # SOCKS5 / SOCKS4 / HTTPS / HTTP
    country: str
    ping_ms: int    # TCP ping, наш замер

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


def load_proxies(state_path: Path, country: str, ping_limit: int) -> list[UpstreamProxy]:
    """Read state.json, return alive proxies for country sorted by ping."""
    if not state_path.exists():
        return []
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            data: dict = json.load(f)
    except Exception as exc:
        log.warning("Cannot read %s: %s", state_path, exc)
        return []

    result: list[UpstreamProxy] = []
    for entry in data.values():
        if not entry.get("alive"):
            continue
        if entry.get("country", "").upper() != country.upper():
            continue
        eff_ping = entry.get("check_ping_ms") or entry.get("ping_ms", 9999)
        if eff_ping > ping_limit:
            continue
        result.append(UpstreamProxy(
            host=entry["host"],
            port=entry["port"],
            type=entry.get("type", "SOCKS5"),
            country=entry["country"],
            ping_ms=eff_ping,
        ))

    result.sort(key=lambda p: p.ping_ms)
    return result


async def tcp_check(host: str, port: int, timeout: float = 5.0) -> Optional[int]:
    """TCP connect check; returns latency ms or None on failure."""
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        ms = int((time.monotonic() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ms
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SOCKS5 server implementation
# ---------------------------------------------------------------------------
# RFC 1928 subset: no auth, CONNECT command only.
# Upstream connections are made via SOCKS5 tunnel to upstream proxy.

SOCKS5_VER = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_FAILURE = 0x01
SOCKS5_REP_CONN_REFUSED = 0x05
SOCKS5_REP_HOST_UNREACHABLE = 0x04


async def socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[tuple[str, int]]:
    """
    Perform SOCKS5 handshake with the client.
    Returns (dst_host, dst_port) or None on error.
    """
    # Auth negotiation
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=10)
    except Exception:
        return None
    ver, nmethods = header
    if ver != SOCKS5_VER:
        return None
    methods = await reader.readexactly(nmethods)
    if SOCKS5_NO_AUTH not in methods:
        writer.write(bytes([SOCKS5_VER, 0xFF]))  # no acceptable methods
        await writer.drain()
        return None
    writer.write(bytes([SOCKS5_VER, SOCKS5_NO_AUTH]))
    await writer.drain()

    # Request
    try:
        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
    except Exception:
        return None
    ver, cmd, _, atyp = req
    if ver != SOCKS5_VER or cmd != SOCKS5_CMD_CONNECT:
        _socks5_reply(writer, SOCKS5_REP_FAILURE)
        await writer.drain()
        return None

    if atyp == SOCKS5_ATYP_IPV4:
        addr_bytes = await reader.readexactly(4)
        dst_host = socket.inet_ntoa(addr_bytes)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        dst_host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
    elif atyp == SOCKS5_ATYP_IPV6:
        addr_bytes = await reader.readexactly(16)
        dst_host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        _socks5_reply(writer, SOCKS5_REP_FAILURE)
        await writer.drain()
        return None

    port_bytes = await reader.readexactly(2)
    dst_port = struct.unpack("!H", port_bytes)[0]
    return dst_host, dst_port


def _socks5_reply(writer: asyncio.StreamWriter, rep: int) -> None:
    writer.write(bytes([
        SOCKS5_VER, rep, 0x00,
        SOCKS5_ATYP_IPV4, 0, 0, 0, 0,  # BND.ADDR = 0.0.0.0
        0, 0,                            # BND.PORT = 0
    ]))


async def connect_via_socks5(upstream: UpstreamProxy, dst_host: str, dst_port: int, timeout: float = 15.0):
    """
    Open a tunnel to dst_host:dst_port through a SOCKS5 upstream proxy.
    Returns (reader, writer) of the upstream tunnel.
    """
    r, w = await asyncio.wait_for(
        asyncio.open_connection(upstream.host, upstream.port),
        timeout=timeout,
    )
    # Auth negotiation with upstream
    w.write(bytes([SOCKS5_VER, 1, SOCKS5_NO_AUTH]))
    await w.drain()
    resp = await asyncio.wait_for(r.readexactly(2), timeout=timeout)
    if resp[1] != SOCKS5_NO_AUTH:
        w.close()
        raise ConnectionError("Upstream SOCKS5 requires auth")

    # CONNECT request to upstream
    host_bytes = dst_host.encode()
    w.write(bytes([
        SOCKS5_VER, SOCKS5_CMD_CONNECT, 0x00,
        SOCKS5_ATYP_DOMAIN, len(host_bytes),
    ]) + host_bytes + struct.pack("!H", dst_port))
    await w.drain()

    resp2 = await asyncio.wait_for(r.readexactly(4), timeout=timeout)
    if resp2[1] != SOCKS5_REP_SUCCESS:
        w.close()
        raise ConnectionError(f"Upstream SOCKS5 CONNECT failed: rep={resp2[1]}")

    # skip BND.ADDR / BND.PORT
    atyp = resp2[3]
    if atyp == SOCKS5_ATYP_IPV4:
        await r.readexactly(4 + 2)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        n = (await r.readexactly(1))[0]
        await r.readexactly(n + 2)
    elif atyp == SOCKS5_ATYP_IPV6:
        await r.readexactly(16 + 2)

    return r, w


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class ProxyForwarder:
    def __init__(self, bind: str, port: int, state_path: Path,
                 country: str, ping_limit: int, check_interval: int):
        self.bind = bind
        self.port = port
        self.state_path = state_path
        self.country = country.upper()
        self.ping_limit = ping_limit
        self.check_interval = check_interval

        self.upstream: Optional[UpstreamProxy] = None
        self.server: Optional[asyncio.AbstractServer] = None
        self._blacklist: set[str] = set()  # temporarily failed upstreams

    def _pick_upstream(self) -> Optional[UpstreamProxy]:
        """Read state.json and pick best available upstream."""
        candidates = load_proxies(self.state_path, self.country, self.ping_limit)
        for p in candidates:
            if p.address not in self._blacklist:
                return p
        # all blacklisted — reset and try again
        if candidates:
            log.warning("All upstream candidates were blacklisted, resetting blacklist")
            self._blacklist.clear()
            return candidates[0]
        return None

    async def _check_and_rotate(self) -> None:
        """Verify current upstream; rotate if dead."""
        if self.upstream is None:
            self.upstream = self._pick_upstream()
            if self.upstream:
                log.info("Selected upstream: %s (%d ms)", self.upstream.address, self.upstream.ping_ms)
            else:
                log.warning("No upstream available for country=%s", self.country)
            return

        ms = await tcp_check(self.upstream.host, self.upstream.port)
        if ms is not None:
            log.debug("Upstream %s alive (%d ms)", self.upstream.address, ms)
        else:
            log.warning("Upstream %s is dead, rotating…", self.upstream.address)
            self._blacklist.add(self.upstream.address)
            self.upstream = self._pick_upstream()
            if self.upstream:
                log.info("Switched to: %s (%d ms)", self.upstream.address, self.upstream.ping_ms)
            else:
                log.warning("No alive upstream for country=%s", self.country)

    async def handle_client(
        self,
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
    ) -> None:
        peer = client_w.get_extra_info("peername", ("?", 0))
        log.debug("Client connected from %s:%s", *peer)
        try:
            await self._handle_client_inner(client_r, client_w)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass  # client dropped connection mid-handshake — normal browser behaviour
        except asyncio.TimeoutError:
            pass  # upstream slow, client already left
        except Exception as exc:
            log.debug("handle_client unexpected: %s", exc)
        finally:
            try:
                client_w.close()
            except Exception:
                pass

    async def _handle_client_inner(
        self,
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
    ) -> None:
        result = await socks5_handshake(client_r, client_w)
        if result is None:
            return
        dst_host, dst_port = result

        upstream = self.upstream
        if upstream is None:
            _socks5_reply(client_w, SOCKS5_REP_FAILURE)
            await client_w.drain()
            return

        try:
            up_r, up_w = await connect_via_socks5(upstream, dst_host, dst_port)
        except Exception as exc:
            log.debug("Upstream connect failed (%s → %s:%d): %s",
                      upstream.address, dst_host, dst_port, exc)
            try:
                _socks5_reply(client_w, SOCKS5_REP_HOST_UNREACHABLE)
                await client_w.drain()
            except Exception:
                pass
            return

        # Success — tell client we're connected
        _socks5_reply(client_w, SOCKS5_REP_SUCCESS)
        await client_w.drain()

        log.debug("Tunnel: client → %s → %s:%d", upstream.address, dst_host, dst_port)
        await asyncio.gather(
            pipe(client_r, up_w),
            pipe(up_r, client_w),
            return_exceptions=True,
        )

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(self.check_interval)
            await self._check_and_rotate()

    async def start(self) -> None:
        # Initial upstream selection
        await self._check_and_rotate()

        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.bind,
            port=self.port,
        )
        addrs = [s.getsockname() for s in self.server.sockets]
        log.info("SOCKS5 forwarder listening on %s", addrs)
        log.info("Country: %s  |  upstream: %s",
                 self.country,
                 self.upstream.address if self.upstream else "NONE")

        asyncio.create_task(self._health_loop())
        async with self.server:
            await self.server.serve_forever()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Local SOCKS5 forwarder via upstream proxies from state.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--country", required=True, metavar="CC",
                   help="ISO country code for upstream proxy (e.g. FR, NL, DE)")
    p.add_argument("--port", type=int, required=True,
                   help="Local port to listen on (e.g. 1080)")
    p.add_argument("--bind", default="127.0.0.1",
                   help="Local address to bind. Default: 127.0.0.1")
    p.add_argument("--state", default="proxies/state.json", metavar="PATH",
                   help="Path to state.json from proxy_harvester. Default: proxies/state.json")
    p.add_argument("--ping", type=int, default=500, metavar="MS",
                   help="Max upstream ping to consider (ms). Default: 500")
    p.add_argument("--check", type=int, default=20, metavar="SEC",
                   help="Upstream health-check interval (s). Default: 20")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="DEBUG level logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    forwarder = ProxyForwarder(
        bind=args.bind,
        port=args.port,
        state_path=Path(args.state),
        country=args.country,
        ping_limit=args.ping,
        check_interval=args.check,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _shutdown(sig, frame):
        log.info("Signal %s, shutting down…", sig)
        loop.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        loop.run_until_complete(forwarder.start())
    except (asyncio.CancelledError, RuntimeError):
        pass
    finally:
        loop.close()
        log.info("Bye.")
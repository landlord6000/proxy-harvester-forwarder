#!/usr/bin/env python3
"""
proxy_harvester.py — периодически парсит proxymania.su, проверяет доступность
прокси и сохраняет актуальный список в нескольких форматах.

Использование:
    python proxy_harvester.py [options]

Примеры:
    # NL + DE, SOCKS5, порог пинга 500 мс, обновление каждые 30 с
    python proxy_harvester.py --countries NL DE --type SOCKS5 --ping 500 --update 30

    # Все страны, все типы, порог 1000 мс
    python proxy_harvester.py --countries ALL --type ALL --ping 1000 --update 60
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy_harvester")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Proxy:
    host: str
    port: int
    type: str          # SOCKS5 / SOCKS4 / HTTPS / HTTP
    country: str       # ISO alpha-2, e.g. "NL"
    country_name: str  # "Netherlands"
    anonymity: str     # Высокая / Средняя / Низкая
    ping_ms: int       # пинг с сайта (ms)
    alive: bool = False
    check_ping_ms: Optional[int] = None   # наш собственный замер (TCP)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def key(self) -> str:
        return self.address

# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

BASE_URL = "https://proxymania.su/free-proxy"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    "Referer": "https://proxymania.su/",
}

COUNTRY_ALL_SENTINEL = "ALL"
TYPE_ALL_SENTINEL = "ALL"


def build_url(proxy_type: str, country: str) -> str:
    params = []
    if proxy_type != TYPE_ALL_SENTINEL:
        params.append(f"type={proxy_type}")
    if country != COUNTRY_ALL_SENTINEL:
        params.append(f"country={country}")
    params.append("speed=")
    return BASE_URL + "?" + "&".join(params)


async def fetch_page(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Direct fetch (no proxy)."""
    try:
        async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                log.warning("HTTP %d for %s", resp.status, url)
                return None
            return await resp.text()
    except Exception as exc:
        log.warning("Fetch error (%s): %s", url, exc)
        return None


async def fetch_page_via_proxy(
    session: aiohttp.ClientSession,
    url: str,
    proxy: "Proxy",
) -> Optional[str]:
    """Fetch through an upstream SOCKS5/HTTP proxy."""
    ptype = proxy.type.upper()
    if "SOCKS" in ptype:
        version = "5" if "5" in ptype else "4"
        proxy_url = f"socks5h://{proxy.host}:{proxy.port}" if version == "5" \
                    else f"socks4://{proxy.host}:{proxy.port}"
    else:
        proxy_url = f"http://{proxy.host}:{proxy.port}"
    try:
        async with session.get(
            url, headers=HEADERS,
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status != 200:
                return None
            return await resp.text()
    except Exception as exc:
        log.debug("Proxy %s failed for %s: %s", proxy.address, url, exc)
        return None


async def fetch_with_rotation(
    session: aiohttp.ClientSession,
    url: str,
    pool: list["Proxy"],
) -> Optional[str]:
    """
    Try fetching url through each alive proxy in pool (sorted by ping),
    fall back to direct if all fail.
    """
    candidates = sorted(
        [p for p in pool if p.alive],
        key=lambda p: p.check_ping_ms if p.check_ping_ms is not None else p.ping_ms,
    )
    for proxy in candidates:
        html = await fetch_page_via_proxy(session, url, proxy)
        if html:
            log.debug("Fetched via %s", proxy.address)
            return html
    log.debug("All proxies failed, falling back to direct connection")
    return await fetch_page(session, url)


def parse_proxies(html: str, expected_country: str) -> list[Proxy]:
    soup = BeautifulSoup(html, "html.parser")
    tbody = soup.find("tbody", id="resultTable")
    if not tbody:
        log.warning("resultTable not found in HTML")
        return []

    results: list[Proxy] = []
    for row in tbody.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 6:
            continue

        # proxy cell: "1.2.3.4:1080"
        proxy_text = cells[0].get_text(strip=True)
        if ":" not in proxy_text:
            continue
        host, port_str = proxy_text.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            continue

        # country
        country_cell = cells[1]
        img = country_cell.find("img")
        if img and img.get("src"):
            # /img/flags/nl.svg  →  NL
            iso = Path(img["src"]).stem.upper()
        else:
            iso = expected_country if expected_country != COUNTRY_ALL_SENTINEL else "??"
        country_name = country_cell.get_text(strip=True)

        proxy_type = cells[2].get_text(strip=True)
        anonymity = cells[3].get_text(strip=True)

        # speed: "359 ms" or "< 100 ms"
        speed_text = cells[4].get_text(strip=True)
        ping_ms = parse_ping(speed_text)

        results.append(Proxy(
            host=host,
            port=port,
            type=proxy_type,
            country=iso,
            country_name=country_name,
            anonymity=anonymity,
            ping_ms=ping_ms,
        ))

    return results


def parse_ping(text: str) -> int:
    """Extract integer ms from strings like '359 ms', '< 100 ms', '1.2 s'."""
    text = text.strip().lower().replace(",", ".")
    try:
        if "s" in text and "ms" not in text:
            # seconds
            num = float("".join(c for c in text if c.isdigit() or c == "."))
            return int(num * 1000)
        else:
            num = float("".join(c for c in text if c.isdigit() or c == "."))
            return int(num)
    except ValueError:
        return 9999

# ---------------------------------------------------------------------------
# Connectivity check  (TCP connect)
# ---------------------------------------------------------------------------

async def check_proxy_alive(proxy: Proxy, timeout: float = 5.0) -> tuple[bool, Optional[int]]:
    """TCP-connect to host:port and measure latency."""
    loop = asyncio.get_event_loop()
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port),
            timeout=timeout,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, elapsed_ms
    except Exception:
        return False, None


async def check_all(proxies: list[Proxy], concurrency: int = 100) -> list[Proxy]:
    sem = asyncio.Semaphore(concurrency)

    async def _check(p: Proxy) -> Proxy:
        async with sem:
            alive, ms = await check_proxy_alive(p)
            p.alive = alive
            p.check_ping_ms = ms
            return p

    tasks = [asyncio.create_task(_check(p)) for p in proxies]
    results = await asyncio.gather(*tasks)
    return list(results)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    """Load existing proxy state from JSON."""
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: v for k, v in data.items()}
        except Exception as exc:
            log.warning("Could not load state from %s: %s", path, exc)
    return {}


def save_state(state: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def merge_proxies(
    existing: dict,          # key → dict (proxy serialised)
    fresh: list[Proxy],
    ping_threshold: int,
) -> dict:
    """
    Merge freshly fetched+checked proxies with existing state.

    Rules:
    - Proxies that are alive AND ping_ms <= threshold are kept/updated.
    - Proxies that are dead are removed from active set.
    - first_seen is preserved from existing entry.
    """
    now = datetime.utcnow().isoformat()
    updated: dict = {}

    for p in fresh:
        if not p.alive:
            continue
        effective_ping = p.check_ping_ms if p.check_ping_ms is not None else p.ping_ms
        if effective_ping > ping_threshold:
            continue

        d = asdict(p)
        if p.key() in existing:
            d["first_seen"] = existing[p.key()].get("first_seen", now)
        d["last_seen"] = now
        d["check_ping_ms"] = p.check_ping_ms
        updated[p.key()] = d

    return updated


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_outputs(state: dict, out_dir: Path, proxy_type: str) -> None:
    """Write multiple output formats from current state."""
    out_dir.mkdir(parents=True, exist_ok=True)
    alive = [v for v in state.values() if v.get("alive")]

    # 1. proxies.txt  —  plain host:port, one per line (most universal)
    _write_plain(alive, out_dir / "proxies.txt")

    # 2. proxies.json  —  full detail
    _write_json(alive, out_dir / "proxies.json")

    # 3. proxies_by_country/  —  per-country plain files
    _write_by_country(alive, out_dir / "by_country")

    # 4. proxies_xray.json  —  Xray/V2Ray outbound array format
    _write_xray(alive, out_dir / "proxies_xray.json", proxy_type)

    log.info(
        "Saved %d alive proxies → %s  (txt / json / by_country / xray)",
        len(alive), out_dir,
    )


def _write_plain(proxies: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(f"{p['host']}:{p['port']}\n")


def _write_json(proxies: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(proxies, f, ensure_ascii=False, indent=2)


def _write_by_country(proxies: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    by_country: dict[str, list[dict]] = {}
    for p in proxies:
        iso = p.get("country", "XX").upper()
        by_country.setdefault(iso, []).append(p)

    for iso, entries in by_country.items():
        path = out_dir / f"{iso}.txt"
        with open(path, "w", encoding="utf-8") as f:
            for p in entries:
                f.write(f"{p['host']}:{p['port']}\n")


def _write_xray(proxies: list[dict], path: Path, proxy_type: str) -> None:
    """
    Xray outbound config array.
    Each entry is a minimal Socks outbound that can be referenced by tag.
    Supports SOCKS5/SOCKS4; for HTTP/HTTPS uses http protocol.
    """
    outbounds = []
    for i, p in enumerate(proxies):
        ptype = p.get("type", proxy_type).upper()
        tag = f"proxy_{p['country']}_{i:04d}"

        if "SOCKS" in ptype:
            version = "5" if "5" in ptype else "4"
            entry = {
                "tag": tag,
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": p["host"],
                        "port": p["port"],
                        "version": version,
                    }]
                }
            }
        else:
            entry = {
                "tag": tag,
                "protocol": "http",
                "settings": {
                    "servers": [{
                        "address": p["host"],
                        "port": p["port"],
                    }]
                }
            }
        outbounds.append(entry)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(outbounds, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run_once(
    session: aiohttp.ClientSession,
    countries: list[str],
    proxy_type: str,
    ping_threshold: int,
    state_path: Path,
    out_dir: Path,
    proxy_pool: list[Proxy],
) -> None:
    state = load_state(state_path)
    all_fresh: list[Proxy] = []
    first_request = True

    for country in countries:
        types_to_fetch = (
            ["HTTP", "HTTPS", "SOCKS4", "SOCKS5"]
            if proxy_type == TYPE_ALL_SENTINEL
            else [proxy_type]
        )
        for ptype in types_to_fetch:
            url = build_url(ptype, country)
            log.info("Fetching %s", url)
            if first_request or not proxy_pool:
                # first request always direct — verified pool not ready yet
                html = await fetch_page(session, url)
                first_request = False
            else:
                html = await fetch_with_rotation(session, url, proxy_pool)
            if html:
                parsed = parse_proxies(html, country)
                log.info("  Parsed %d entries", len(parsed))
                all_fresh.extend(parsed)
            await asyncio.sleep(1)  # polite delay between requests

    if not all_fresh:
        log.warning("Nothing fetched, skipping update")
        return

    # deduplicate by key
    seen: dict[str, Proxy] = {}
    for p in all_fresh:
        seen[p.key()] = p
    unique = list(seen.values())

    log.info("Checking %d unique proxies (TCP connect)…", len(unique))
    checked = await check_all(unique)

    alive_count = sum(1 for p in checked if p.alive)
    log.info("Alive: %d / %d", alive_count, len(checked))

    new_state = merge_proxies(state, checked, ping_threshold)
    save_state(new_state, state_path)
    write_outputs(new_state, out_dir, proxy_type)

    # update pool in-place for the caller
    proxy_pool.clear()
    proxy_pool.extend(p for p in checked if p.alive)


async def main_loop(args: argparse.Namespace) -> None:
    countries: list[str] = [c.upper() for c in args.countries]
    proxy_type: str = args.type.upper()
    ping_threshold: int = args.ping
    update_interval: int = args.update
    out_dir = Path(args.output)
    state_path = out_dir / "state.json"

    log.info("=== proxy_harvester starting ===")
    log.info("Countries   : %s", countries)
    log.info("Type        : %s", proxy_type)
    log.info("Ping limit  : %d ms", ping_threshold)
    log.info("Update every: %d s", update_interval)
    log.info("Output dir  : %s", out_dir.resolve())

    proxy_pool: list[Proxy] = []  # alive proxies, updated each run

    connector = aiohttp.TCPConnector(limit=200, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            t0 = time.monotonic()
            try:
                await run_once(
                    session, countries, proxy_type,
                    ping_threshold, state_path, out_dir,
                    proxy_pool,
                )
            except Exception as exc:
                log.exception("Unhandled error in run_once: %s", exc)

            elapsed = time.monotonic() - t0
            sleep_for = max(0.0, update_interval - elapsed)
            log.info("Next update in %.0f s", sleep_for)
            await asyncio.sleep(sleep_for)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Harvest & verify free SOCKS/HTTP proxies from proxymania.su",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--countries", nargs="+", default=["NL"],
        metavar="CC",
        help=(
            "ISO country codes to fetch (e.g. NL DE US). "
            "Use ALL for all countries. Default: NL"
        ),
    )
    p.add_argument(
        "--type", default="SOCKS5",
        choices=["SOCKS5", "SOCKS4", "HTTP", "HTTPS", "ALL"],
        help="Proxy protocol type. Default: SOCKS5",
    )
    p.add_argument(
        "--ping", type=int, default=500,
        metavar="MS",
        help="Discard proxies with our TCP ping above this threshold (ms). Default: 500",
    )
    p.add_argument(
        "--update", type=int, default=30,
        metavar="SEC",
        help="Re-fetch interval in seconds. Default: 30",
    )
    p.add_argument(
        "--output", default="proxies",
        metavar="DIR",
        help="Output directory. Default: ./proxies",
    )
    p.add_argument(
        "--concurrency", type=int, default=100,
        metavar="N",
        help="Max simultaneous TCP checks. Default: 100",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="DEBUG level logging",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Graceful Ctrl+C
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _shutdown(sig, frame):
        log.info("Signal %s received, shutting down…", sig)
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        loop.run_until_complete(main_loop(args))
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()
        log.info("Bye.")
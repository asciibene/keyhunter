#!/usr/bin/env python3
"""
solana_key_hunter.py -- continuously hunt for leaked Solana private keys.

Sources
-------
  github     GitHub code search (needs GITHUB_TOKEN)
  gists      GitHub public gist firehose
  pastebin   Pastebin scraping API (needs PASTEBIN_KEY or whitelisted IP)
  dpaste     dpaste.org recent pastes (best effort)

For every candidate key it derives the Solana address, calls getAccountInfo,
and records the balance. Non-zero balances are highlighted and appended to
hits.txt as base58 + JSON-array (Phantom / Solflare importable).

Install
-------
    pip install requests base58 pynacl

Run
---
    export GITHUB_TOKEN=ghp_xxxxxxxx
    export SOLANA_RPC='https://mainnet.helius-rpc.com/?api-key=xxxx'
    python solana_key_hunter.py

Notes
-----
  * GitHub code search only indexes default branches and files under 384 KB,
    caps at 1000 results per query, and needs auth. Queries are rotated and
    biased toward recent pushes so the same window is not hammered forever.
  * Public RPC endpoints rate-limit aggressively. Bring your own.
  * A leaked key with zero balance usually means a sweeper bot already
    drained it, or the account was never funded.
"""

import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import base58
import requests
from nacl.signing import SigningKey

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
PASTEBIN_KEY = os.environ.get("PASTEBIN_KEY", "")
SOLANA_RPC = os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com")

RPC_FALLBACKS = [
    SOLANA_RPC,
    "https://api.mainnet-beta.solana.com",
    "https://rpc.ankr.com/solana",
    "https://solana.public-rpc.com",
]

UA = "solana-key-hunter/1.0 (+https://venice.ai)"
MAX_TEXT = 1_200_000
B58 = "1-9A-HJ-NP-Za-km-z"

RE_KEY64 = re.compile(rf"(?<![{B58}])[{B58}]{{86,90}}(?![{B58}])")
RE_KEY32 = re.compile(rf"(?<![{B58}])[{B58}]{{43,45}}(?![{B58}])")
RE_JSON_ARR = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
RE_CTX = re.compile(r"private|secret|keypair|signer|seed|wallet|solana", re.I)

PRINT_LOCK = threading.Lock()
WRITE_LOCK = threading.Lock()
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})

GITHUB_QUERIES = [
    '"privateKey" solana',
    '"secretKey" solana',
    '"SOLANA_PRIVATE_KEY"',
    '"PRIVATE_KEY" phantom',
    '"keypair" solana extension:json',
    'solana "private_key"',
    '"secret_key" solana',
    'filename:id.json solana',
    'filename:keypair.json',
    '"solana" "base58" private',
    '"keypair.json"',
    'solana "signer" "base58"',
]


# --------------------------------------------------------------------------- #
# DB
# --------------------------------------------------------------------------- #
class DB:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS hits (
                address      TEXT PRIMARY KEY,
                key_b58      TEXT NOT NULL,
                key_json     TEXT NOT NULL,
                kind         TEXT,
                lamports     INTEGER,
                exists_at    INTEGER,
                source       TEXT,
                url          TEXT,
                first_seen   TEXT,
                last_checked TEXT,
                checks       INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS seen_urls (url TEXT PRIMARY KEY, ts TEXT);
            """
        )
        self.conn.commit()

    def has_address(self, address):
        with self.lock:
            cur = self.conn.execute("SELECT 1 FROM hits WHERE address=?", (address,))
            return cur.fetchone() is not None

    def touch(self, address):
        with self.lock:
            self.conn.execute(
                "UPDATE hits SET checks=checks+1, last_checked=? WHERE address=?",
                (now_iso(), address),
            )
            self.conn.commit()

    def insert(self, row):
        with self.lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO hits
                   (address, key_b58, key_json, kind, lamports, exists_at,
                    source, url, first_seen, last_checked, checks)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1)""",
                row,
            )
            self.conn.commit()

    def url_seen(self, url):
        with self.lock:
            cur = self.conn.execute("SELECT 1 FROM seen_urls WHERE url=?", (url,))
            return cur.fetchone() is not None

    def mark_url(self, url):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO seen_urls (url, ts) VALUES (?,?)",
                (url, now_iso()),
            )
            self.conn.commit()

    def stats(self):
        with self.lock:
            cur = self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(lamports),0) FROM hits"
            )
            return cur.fetchone()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def extract_candidates(text):
    out = []
    for m in RE_JSON_ARR.finditer(text):
        try:
            arr = json.loads(m.group(0))
        except Exception:
            continue
        if len(arr) == 64 and all(isinstance(b, int) and 0 <= b <= 255 for b in arr):
            out.append((bytes(arr), "json"))
    for m in RE_KEY64.finditer(text):
        out.append((m.group(0), "b58-64"))
    for m in RE_KEY32.finditer(text):
        start = max(0, m.start() - 220)
        if RE_CTX.search(text[start:m.start() + 80]):
            out.append((m.group(0), "b58-32"))
    return out


def to_keypair(cand, kind):
    """-> (SigningKey, pubkey_half_matches|None, raw_bytes) or None."""
    if kind == "json":
        raw = cand
    else:
        try:
            raw = base58.b58decode(cand)
        except Exception:
            return None

    if len(raw) == 64:
        seed, pub = raw[:32], raw[32:]
        try:
            sk = SigningKey(seed)
        except Exception:
            return None
        return sk, bytes(sk.verify_key) == pub, raw

    if len(raw) == 32:
        try:
            sk = SigningKey(raw)
        except Exception:
            return None
        return sk, None, raw

    return None


# --------------------------------------------------------------------------- #
# RPC
# --------------------------------------------------------------------------- #
def rpc(method, params, timeout=15):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last = None
    for attempt in range(4):
        url = random.choice(RPC_FALLBACKS)
        try:
            r = SESSION.post(url, json=payload, timeout=timeout)
            if r.status_code == 429:
                time.sleep(2 + attempt * 3)
                continue
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                raise RuntimeError(str(data["error"]))
            return data["result"]
        except Exception as e:
            last = e
            time.sleep(1.5 + attempt)
    raise last if last else RuntimeError("rpc failed")


def check_account(address):
    """-> (lamports, exists). One call, no extra traffic."""
    res = rpc("getAccountInfo", [address, {"encoding": "base64", "commitment": "confirmed"}])
    value = (res or {}).get("value")
    if value is None:
        return 0, False
    return int(value.get("lamports") or 0), True


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def report(address, key_b58, key_json, lamports, exists, source, url, kind, args):
    sol = lamports / 1_000_000_000
    hot = lamports > 0
    with PRINT_LOCK:
        if hot:
            print("\n" + "=" * 78)
            print(f"  HIT  {sol:.9f} SOL   ({lamports} lamports)")
        else:
            print(f"\n---  empty  {address}  [{source}]")
        print(f"  address : {address}")
        print(f"  key     : {key_b58}")
        print(f"  json    : {key_json}")
        print(f"  format  : {kind}   account_exists={exists}")
        print(f"  source  : {url}")
        print(f"  explorer: https://solscan.io/account/{address}")
        if hot:
            print("=" * 78)
        sys.stdout.flush()

    if hot:
        with WRITE_LOCK:
            with open("hits.txt", "a") as f:
                f.write(
                    f"{now_iso()}\t{sol:.9f}\t{address}\t{key_b58}\t{key_json}\t{url}\n"
                )


# --------------------------------------------------------------------------- #
# Source enumeration (yields (url, source, headers))
# --------------------------------------------------------------------------- #
def gh_headers():
    h = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def iter_github(args):
    if not GITHUB_TOKEN:
        with PRINT_LOCK:
            print("[!] GITHUB_TOKEN unset -- code search will likely 401.")
    headers = gh_headers()
    queries = list(GITHUB_QUERIES)
    if args.queries_file:
        with open(args.queries_file) as f:
            queries += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    random.shuffle(queries)
    for q in queries[: args.queries_per_cycle]:
        days = random.randint(0, max(0, args.fresh_days))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        query = f"{q} pushed:>{cutoff}"
        for page in range(1, args.pages + 1):
            params = {
                "q": query,
                "per_page": 100,
                "page": page,
                "sort": "indexed",
                "order": "desc",
            }
            try:
                r = SESSION.get(
                    "https://api.github.com/search/code",
                    params=params,
                    headers=headers,
                    timeout=25,
                )
            except Exception as e:
                print(f"[!] github search error: {e}")
                break

            if r.status_code in (403, 429):
                reset = r.headers.get("X-RateLimit-Reset")
                wait = 30
                if reset:
                    wait = max(5, int(reset) - int(time.time()) + 2)
                print(f"[!] github rate limited, sleeping {wait}s")
                time.sleep(min(wait, 120))
                continue
            if r.status_code != 200:
                print(f"[!] github {r.status_code}: {r.text[:160]}")
                break

            items = r.json().get("items", [])
            if not items:
                break
            for it in items:
                repo = it.get("repository", {}).get("full_name")
                path, sha = it.get("path"), it.get("sha")
                if not repo or not path:
                    continue
                raw = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
                if not args.revisit and DB_REF.url_seen(raw):
                    continue
                yield raw, "github", {}
            time.sleep(args.github_delay)


def iter_gists(args):
    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = gh_headers()
    for page in range(1, 4):
        try:
            r = SESSION.get(
                "https://api.github.com/gists/public",
                params={"per_page": 100, "page": page, "since": since},
                headers=headers,
                timeout=25,
            )
        except Exception as e:
            print(f"[!] gist error: {e}")
            return
        if r.status_code != 200:
            print(f"[!] gists {r.status_code}")
            return
        batch = r.json()
        if not batch:
            return
        for g in batch:
            for fmeta in (g.get("files") or {}).values():
                raw = fmeta.get("raw_url")
                if not raw:
                    continue
                if not args.revisit and DB_REF.url_seen(raw):
                    continue
                yield raw, "gist", {}
        time.sleep(1.0)


def iter_pastebin(args):
    url = "https://scrape.pastebin.com/api_scraping.php?limit=100"
    if PASTEBIN_KEY:
        url += f"&api_dev_key={PASTEBIN_KEY}"
    try:
        r = SESSION.get(url, timeout=25)
    except Exception as e:
        print(f"[!] pastebin error: {e}")
        return
    if r.status_code != 200:
        print(f"[!] pastebin {r.status_code} (whitelist your IP for free scraping)")
        return
    try:
        items = r.json()
    except Exception:
        print("[!] pastebin returned non-JSON (IP not whitelisted?)")
        return
    for it in items or []:
        key = it.get("key")
        if not key:
            continue
        raw = f"https://pastebin.com/raw/{key}"
        if not args.revisit and DB_REF.url_seen(raw):
            continue
        yield raw, "pastebin", {}


def iter_dpaste(args):
    try:
        r = SESSION.get("https://dpaste.org/api/recent/?limit=50", timeout=20)
        if r.status_code != 200:
            return
        items = r.json()
    except Exception:
        return
    if not isinstance(items, list):
        return
    for it in items:
        pid = it.get("id") or it.get("slug")
        if not pid:
            continue
        raw = f"https://dpaste.org/{pid}/raw/"
        if not args.revisit and DB_REF.url_seen(raw):
            continue
        yield raw, "dpaste", {}


SOURCES = {
    "github": iter_github,
    "gists": iter_gists,
    "pastebin": iter_pastebin,
    "dpaste": iter_dpaste,
}


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #
DB_REF = None


def process(url, source, headers, args):
    try:
        r = SESSION.get(url, headers=headers, timeout=25)
        if r.status_code != 200:
            return
        ctype = r.headers.get("content-type", "")
        if any(b in ctype for b in ("image/", "audio/", "video/", "font/")):
            return
        text = r.text[:MAX_TEXT]
    except Exception:
        return
    finally:
        DB_REF.mark_url(url)

    if not any(t in text for t in ("solana", "Solana", "SOLANA", "keypair", "privateKey", "secretKey")):
        # cheap prefilter, but keep going if a raw 64-byte key is obviously present
        if not RE_KEY64.search(text):
            return

    seen = set()
    for cand, kind in extract_candidates(text):
        key = cand if isinstance(cand, str) else cand.hex()
        if key in seen:
            continue
        seen.add(key)

        kp = to_keypair(cand, kind)
        if not kp:
            continue
        sk, pub_ok, raw = kp
        address = base58.b58encode(bytes(sk.verify_key)).decode()
        key_b58 = base58.b58encode(raw).decode()
        key_json = json.dumps(list(raw))

        if DB_REF.has_address(address):
            DB_REF.touch(address)
            continue

        if args.no_balance:
            lamports, exists = 0, True
        else:
            try:
                lamports, exists = check_account(address)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[!] balance check failed {address}: {e}")
                continue

        DB_REF.insert(
            (
                address, key_b58, key_json, kind, lamports, int(exists),
                source, url, now_iso(), now_iso(),
            )
        )
        if lamports >= int(args.min_lamports):
            report(address, key_b58, key_json, lamports, exists, source, url, kind, args)


# --------------------------------------------------------------------------- #
# Cycle
# --------------------------------------------------------------------------- #
def run_cycle(args):
    chosen = [s for s in args.sources.split(",") if s in SOURCES]
    if not chosen:
        print("[!] no valid sources")
        return

    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for name in chosen:
            try:
                for url, source, headers in SOURCES[name](args):
                    pool.submit(process, url, source, headers, args)
            except Exception as e:
                print(f"[!] source {name} crashed: {e}")

    total, lamports = DB_REF.stats()
    print(
        f"\n[cycle done {now_iso()}] known keys={total} "
        f"total tracked lamports={lamports} ({lamports/1e9:.9f} SOL)"
    )


def main():
    p = argparse.ArgumentParser(description="Hunt for leaked Solana private keys")
    p.add_argument("--sources", default="github,gists,pastebin,dpaste")
    p.add_argument("--db", default="found_keys.db")
    p.add_argument("--interval", type=int, default=180, help="seconds between cycles")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--pages", type=int, default=2, help="github search pages per query")
    p.add_argument("--queries-per-cycle", type=int, default=4)
    p.add_argument("--queries-file", default=None, help="extra github queries, one per line")
    p.add_argument("--fresh-days", type=int, default=30, help="bias toward pushes within N days")
    p.add_argument("--github-delay", type=float, default=6.5, help="seconds between search calls")
    p.add_argument("--min-lamports", type=int, default=1, help="print only balances >= this")
    p.add_argument("--no-balance", action="store_true", help="skip RPC entirely")
    p.add_argument("--revisit", action="store_true", help="ignore URL dedupe")
    p.add_argument("--once", action="store_true")
    args = p.parse_args()

    global DB_REF
    DB_REF = DB(args.db)

    print(f"solana-key-hunter starting | sources={args.sources} | rpc={SOLANA_RPC}")
    print("ctrl-c to stop\n")

    try:
        while True:
            t0 = time.time()
            try:
                run_cycle(args)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"[!] cycle error: {e}")
            if args.once:
                break
            sleep = max(10, args.interval - (time.time() - t0))
            time.sleep(sleep + random.uniform(0, 10))
    except KeyboardInterrupt:
        total, lamports = DB_REF.stats()
        print(f"\nstopped. {total} keys tracked, {lamports/1e9:.9f} SOL seen in total.")


if __name__ == "__main__":
    main()

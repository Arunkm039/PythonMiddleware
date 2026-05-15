"""
NetSuite <-> Bank SFTP Bridge
==============================
Run:   python bridge.py
Test:  python bridge.py --test
Dashboard: http://localhost:8000  (requires login)

Multi-bank config: set BANKS_JSON env var to a JSON array of bank objects.
Single-bank fallback: use BANK_* env vars (same as before).
"""

import os, io, json, re, ssl, shutil, hashlib, asyncio, logging, argparse
import smtplib, uuid, secrets
from pathlib import Path
from datetime import datetime, timezone
from email.mime.text import MIMEText
from contextlib import asynccontextmanager
from urllib.parse import urlparse, unquote

import pyotp

from fastapi import FastAPI, Request, UploadFile, File, Form, Query, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

import bcrypt
import psycopg2
import psycopg2.pool
import psycopg2.extras
import uvicorn

try:
    import asyncssh
except ImportError:
    asyncssh = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s")
log = logging.getLogger("bridge")


# =====================================================================
#  CONFIG
# =====================================================================
CFG = {
    "MODE":          os.getenv("BRIDGE_MODE", "local"),
    "BANK_HOST":     os.getenv("BANK_HOST", ""),
    "BANK_PORT":     int(os.getenv("BANK_PORT", "22")),
    "BANK_USER":     os.getenv("BANK_USER", ""),
    "BANK_PASS":     os.getenv("BANK_PASS", ""),
    "BANK_KEY":      os.getenv("BANK_KEY", ""),
    "BANK_OUTBOUND_DIR": os.getenv("BANK_OUTBOUND_DIR", "/outbound"),
    "BANK_INBOUND_DIR":  os.getenv("BANK_INBOUND_DIR", "/inbound"),
    "BANK_ID":       os.getenv("BANK_ID", "bank"),
    "NS_HOST":       os.getenv("NS_HOST", ""),
    "NS_PORT":       int(os.getenv("NS_PORT", "22")),
    "NS_USER":       os.getenv("NS_USER", ""),
    "NS_PASS":       os.getenv("NS_PASS", ""),
    "NS_KEY":        os.getenv("NS_KEY", ""),
    "NS_OUTBOUND_DIR": os.getenv("NS_OUTBOUND_DIR", "/outbound"),
    "NS_INBOUND_DIR":  os.getenv("NS_INBOUND_DIR", "/inbound"),
    "PG_HOST":       os.getenv("PG_HOST", "localhost"),
    "PG_PORT":       int(os.getenv("PG_PORT", "5432")),
    "PG_DB":         os.getenv("PG_DB", "bridge"),
    "PG_USER":       os.getenv("PG_USER", "bridge"),
    "PG_PASS":       os.getenv("PG_PASS", "bridge"),
    "SMTP_HOST":     os.getenv("SMTP_HOST", "smtp.gmail.com"),
    "SMTP_PORT":     int(os.getenv("SMTP_PORT", "587")),
    "SMTP_USER":     os.getenv("SMTP_USER", ""),
    "SMTP_PASS":     os.getenv("SMTP_PASS", ""),
    "ALERT_TO":      os.getenv("ALERT_TO", ""),
    # Reduced default from 15s to 30s to lower SFTP churn on 1 vCPU
    "POLL_SECONDS":  int(os.getenv("POLL_SECONDS", "30")),
    "SFTP_TIMEOUT":  int(os.getenv("SFTP_TIMEOUT", "30")),
    # Reduced default from 100 to 50 to bound per-cycle memory on 1 vCPU
    "MAX_FILES_PER_CYCLE": int(os.getenv("MAX_FILES_PER_CYCLE", "50")),
    # Reduced default from 50 MB to 20 MB; configure higher if needed
    "MAX_UPLOAD_BYTES":    int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024))),
    "SFTP_KNOWN_HOSTS":    os.getenv("SFTP_KNOWN_HOSTS", ""),
    "BANKS_JSON":          os.getenv("BANKS_JSON", ""),
    "ADMIN_USER":          os.getenv("ADMIN_USER", "admin"),
    "ADMIN_PASS":          os.getenv("ADMIN_PASS", "admin"),
    "SESSION_SECRET":      os.getenv("SESSION_SECRET", secrets.token_hex(32)),
    "SESSION_HTTPS_ONLY":  os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true",
    # Bind to all interfaces by default; restrict via OCI security list / ufw
    # Set BIND_HOST=127.0.0.1 when running behind nginx (recommended for TLS)
    "BIND_HOST":           os.getenv("BIND_HOST", "0.0.0.0"),
    # When true: NS SFTP paths gain /<bank_id>/<account_id> sub-folders
    "SFTP_FOLDER_SEGREGATION": os.getenv("SFTP_FOLDER_SEGREGATION", "true").lower() == "true",
    # Max simultaneous SFTP connections — keeps resource use bounded on 1 vCPU
    "MAX_CONCURRENT_SFTP": int(os.getenv("MAX_CONCURRENT_SFTP", "2")),
    # Orphaned staging files older than this (hours) are removed by cleanup loop
    "STAGING_MAX_AGE_HOURS": int(os.getenv("STAGING_MAX_AGE_HOURS", "48")),
    # When true: bridge acts as SFTP server for NetSuite (NetSuite connects IN to bridge).
    # Bridge watches local data/netsuite/ dirs instead of dialling out to NS_HOST.
    # Bank side (SFTP client) is unaffected. Use with OpenSSH chroot on the same VM.
    "NS_SFTP_SERVER_MODE": os.getenv("NS_SFTP_SERVER_MODE", "false").lower() == "true",
    # Credentials for the chroot SFTP user NetSuite connects as (used only in server mode)
    "NS_SFTP_USER":    os.getenv("NS_SFTP_USER", "netsuite_sftp"),
    "NS_SFTP_PASS":    os.getenv("NS_SFTP_PASS", ""),
}

# Track whether SESSION_SECRET was explicitly provided (vs. ephemeral random)
_SESSION_SECRET_CONFIGURED = bool(os.getenv("SESSION_SECRET"))

BANKS: list[dict] = []
_SFTP_SEM: asyncio.Semaphore | None = None


def _load_banks_config() -> list[dict]:
    """
    Load multi-bank config. Priority: data/banks_config.json > BANKS_JSON env > BANK_* env vars.
    """
    # 1. Dashboard-managed config file takes precedence
    if BANKS_CONFIG_FILE.exists():
        try:
            banks = json.loads(BANKS_CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(banks, list) and banks:
                log.info("Loaded %d bank(s) from %s", len(banks), BANKS_CONFIG_FILE)
                return banks
        except Exception as e:
            log.error("Failed to read %s: %s — falling back to env vars", BANKS_CONFIG_FILE, e)

    # 2. BANKS_JSON env var
    raw = CFG.get("BANKS_JSON", "").strip()
    if raw:
        try:
            banks = json.loads(raw)
            if isinstance(banks, list) and banks:
                log.info("Loaded %d bank(s) from BANKS_JSON", len(banks))
                return banks
        except Exception as e:
            log.error("Failed to parse BANKS_JSON: %s — using single-bank env vars", e)

    # 3. Legacy single-bank env vars
    return [{
        "id":           CFG["BANK_ID"],
        "name":         CFG["BANK_ID"],
        "host":         CFG["BANK_HOST"],
        "port":         CFG["BANK_PORT"],
        "user":         CFG["BANK_USER"],
        "pass":         CFG["BANK_PASS"],
        "key":          CFG["BANK_KEY"],
        "outbound_dir": CFG["BANK_OUTBOUND_DIR"],
        "inbound_dir":  CFG["BANK_INBOUND_DIR"],
        "known_hosts":  CFG["SFTP_KNOWN_HOSTS"],
        "accounts":     [],
    }]


def _save_banks_config(banks: list[dict]):
    BANKS_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    BANKS_CONFIG_FILE.write_text(json.dumps(banks, indent=2), encoding="utf-8")


def _reload_banks():
    global BANKS
    BANKS = _load_banks_config()
    log.info("Banks reloaded: %s", [b["id"] for b in BANKS])
    _ensure_local_dirs()


# =====================================================================
#  DIRECTORIES
# =====================================================================
STAGING_DIR        = Path("data/staging")
UPLOAD_STAGING_DIR = Path("data/upload_staging")
ARCHIVE_DIR        = Path("data/processed")
ERROR_DIR          = Path("data/error")
NETSUITE_DIR       = Path("data/netsuite")
BANKS_CONFIG_FILE  = Path("data/banks_config.json")
GPG_HOME           = Path("data/gnupg")

# ACK/NACK live inside data/netsuite/<bank>/[<account>/]ACK|NACK/
# BROWSABLE_ROOTS exposes netsuite tree + archive/error for dashboard folder browser
BROWSABLE_ROOTS: dict[str, Path] = {
    "netsuite":  NETSUITE_DIR,
    "processed": ARCHIVE_DIR,
    "error":     ERROR_DIR,
}

# Whitelist pattern for safe filesystem/SFTP ID components
_UNSAFE_PATH_RE = re.compile(r"[^\w\-]")


def _safe_id(value: str) -> str:
    """Sanitize a bank/account ID for safe use in filesystem and SFTP paths.

    Prevents path traversal: strips non-word/hyphen chars, leading dots/underscores,
    and limits length. Returns '' for empty input (empty account_id is valid).
    """
    if not value:
        return ""
    safe = _UNSAFE_PATH_RE.sub("_", str(value))[:64].strip("._-")
    return safe or "x"


def _bank_local_dir(bank_id: str, account_id: str, kind: str) -> Path:
    p = Path("data/banks") / _safe_id(bank_id)
    if account_id:
        p = p / _safe_id(account_id)
    return p / kind


def _ns_local_dir(bank_id: str, account_id: str, kind: str) -> Path:
    p = Path("data/netsuite") / _safe_id(bank_id)
    if account_id:
        p = p / _safe_id(account_id)
    return p / kind


def _archive_file(src: Path, direction: str, original_name: str, bucket: Path,
                  bank_id: str = "", account_id: str = "") -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    target_dir = bucket / date_str
    if bank_id:
        target_dir = target_dir / _safe_id(bank_id)
    if account_id:
        target_dir = target_dir / _safe_id(account_id)
    target_dir = target_dir / direction
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / original_name
    if target.exists():
        stem, ext = target.stem, target.suffix
        target = target_dir / f"{stem}_{uuid.uuid4().hex[:8]}{ext}"
    shutil.move(str(src), str(target))
    return target


# =====================================================================
#  SECURITY HELPERS
# =====================================================================
_LOGIN_ATTEMPTS: dict = {}
_MFA_ATTEMPTS:   dict = {}
_LOGIN_LOCK: asyncio.Lock | None = None
_MAX_LOGIN_ATTEMPTS    = 5
_LOGIN_LOCKOUT_SECONDS = 300
_MAX_ATTEMPTS_DICT_SIZE = 10_000

# Constant-time dummy hash — prevents username enumeration via timing
_DUMMY_HASH: bytes = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt())


def _safe_next_url(url: str | None) -> str:
    """Only allow relative redirect paths — block open-redirect attacks."""
    if not url:
        return "/"
    # Decode percent-encoding before validation to catch encoded bypass attempts
    decoded = unquote(url[:512])
    parsed = urlparse(decoded)
    if parsed.scheme or parsed.netloc:
        return "/"
    path = re.sub(r"[^\w/\-_.~?&=#]", "", parsed.path or "/")
    # Collapse multiple leading slashes — prevents //host protocol-relative redirects
    path = re.sub(r"^/+", "/", path)
    return path or "/"


def _evict_attempts(d: dict) -> None:
    """Evict non-locked entries when dict exceeds size limit."""
    if len(d) < _MAX_ATTEMPTS_DICT_SIZE:
        return
    now = asyncio.get_event_loop().time()
    expired = [k for k, v in d.items() if v.get("until", 0) <= now]
    for k in expired[:_MAX_ATTEMPTS_DICT_SIZE // 2]:
        del d[k]


async def _check_rate_limit(username: str) -> bool:
    async with _LOGIN_LOCK:
        info = _LOGIN_ATTEMPTS.get(username)
        if not info:
            return True
        return info.get("until", 0) <= asyncio.get_event_loop().time()


async def _record_login_failure(username: str):
    async with _LOGIN_LOCK:
        _evict_attempts(_LOGIN_ATTEMPTS)
        info = _LOGIN_ATTEMPTS.get(username, {"count": 0, "until": 0})
        info["count"] = info.get("count", 0) + 1
        if info["count"] >= _MAX_LOGIN_ATTEMPTS:
            info["until"] = asyncio.get_event_loop().time() + _LOGIN_LOCKOUT_SECONDS
            log.warning("Login rate-limit triggered for: %s", username)
        _LOGIN_ATTEMPTS[username] = info


async def _clear_login_attempts(username: str):
    async with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(username, None)


async def _check_mfa_rate_limit(username: str) -> bool:
    async with _LOGIN_LOCK:
        info = _MFA_ATTEMPTS.get(username)
        if not info:
            return True
        return info.get("until", 0) <= asyncio.get_event_loop().time()


async def _record_mfa_failure(username: str):
    async with _LOGIN_LOCK:
        _evict_attempts(_MFA_ATTEMPTS)
        info = _MFA_ATTEMPTS.get(username, {"count": 0, "until": 0})
        info["count"] = info.get("count", 0) + 1
        if info["count"] >= _MAX_LOGIN_ATTEMPTS:
            info["until"] = asyncio.get_event_loop().time() + _LOGIN_LOCKOUT_SECONDS
            log.warning("MFA rate-limit triggered for: %s", username)
        _MFA_ATTEMPTS[username] = info


async def _clear_mfa_attempts(username: str):
    async with _LOGIN_LOCK:
        _MFA_ATTEMPTS.pop(username, None)


# =====================================================================
#  DATABASE
# =====================================================================
_TRANSFER_UPDATABLE = frozenset({
    "status", "error", "retries", "staged_path", "archived_path",
    "bank_id", "account_id", "updated_at",
})


class DB:
    def __init__(self):
        self.pool = None

    def connect(self):
        # Pool sized for 1 vCPU / 8 GB OCI instance
        self.pool = psycopg2.pool.ThreadedConnectionPool(
            1, 5,
            host=CFG["PG_HOST"], port=CFG["PG_PORT"],
            dbname=CFG["PG_DB"], user=CFG["PG_USER"], password=CFG["PG_PASS"],
            connect_timeout=5,
        )
        log.info("PostgreSQL connected (%s@%s/%s)", CFG["PG_USER"], CFG["PG_HOST"], CFG["PG_DB"])

    def init(self):
        self.connect()
        c = self.pool.getconn()
        try:
            with c.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS transfers (
                        id SERIAL PRIMARY KEY,
                        filename TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        size_bytes BIGINT DEFAULT 0,
                        sha256 TEXT,
                        content_sha256 TEXT,
                        error TEXT,
                        retries INTEGER DEFAULT 0,
                        staged_path TEXT,
                        archived_path TEXT,
                        bank_id TEXT NOT NULL DEFAULT 'bank',
                        account_id TEXT NOT NULL DEFAULT '',
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS transfer_logs (
                        id SERIAL PRIMARY KEY,
                        transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
                        message TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        mfa_secret TEXT,
                        mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                        role TEXT NOT NULL DEFAULT 'readonly',
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_login_at TIMESTAMPTZ
                    );
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'readonly';
                    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS content_sha256 TEXT;
                    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS staged_path TEXT;
                    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS archived_path TEXT;
                    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS bank_id TEXT NOT NULL DEFAULT 'bank';
                    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS account_id TEXT NOT NULL DEFAULT '';
                    CREATE INDEX IF NOT EXISTS idx_transfers_sha256 ON transfers(sha256);
                    CREATE INDEX IF NOT EXISTS idx_transfers_content_sha256 ON transfers(content_sha256);
                    CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
                    CREATE INDEX IF NOT EXISTS idx_transfers_bank ON transfers(bank_id, account_id);
                    CREATE INDEX IF NOT EXISTS idx_logs_tid ON transfer_logs(transfer_id);
                """)
            c.commit()
            log.info("Database ready")
        finally:
            self.pool.putconn(c)
        self.ensure_default_admin()

    def close(self):
        if self.pool:
            self.pool.closeall()

    def _c(self): return self.pool.getconn()
    def _p(self, c): self.pool.putconn(c)

    # --- Users ---
    def ensure_default_admin(self):
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM users")
                if cur.fetchone()[0] == 0:
                    hashed = bcrypt.hashpw(CFG["ADMIN_PASS"].encode(), bcrypt.gensalt()).decode()
                    cur.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                        (CFG["ADMIN_USER"], hashed),
                    )
                    c.commit()
                    log.warning("Default admin '%s' created — change ADMIN_PASS env var!", CFG["ADMIN_USER"])
                else:
                    cur.execute(
                        "UPDATE users SET role = 'admin' WHERE username = %s AND role != 'admin'",
                        (CFG["ADMIN_USER"],),
                    )
                    c.commit()
        finally:
            self._p(c)

    def verify_user(self, username: str, password: str) -> bool:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                # Always call bcrypt to prevent timing oracle for non-existent usernames
                stored = row[0].encode() if row else _DUMMY_HASH
                match = bcrypt.checkpw(password.encode(), stored)
                if not row or not match:
                    return False
                cur.execute("UPDATE users SET last_login_at = NOW() WHERE username = %s", (username,))
                c.commit()
                return True
        finally:
            self._p(c)

    def create_user(self, username: str, password: str, role: str = "readonly") -> None:
        if role not in ("admin", "readonly"):
            role = "readonly"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                    (username, hashed, role),
                )
            c.commit()
        finally:
            self._p(c)

    def list_users(self):
        c = self._c()
        try:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT username, role, mfa_enabled,
                           TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS created_at,
                           TO_CHAR(last_login_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS last_login_at
                    FROM users ORDER BY created_at
                """)
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._p(c)

    def get_user_role(self, username: str) -> str:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                return row[0] if row else "readonly"
        finally:
            self._p(c)

    def reset_password(self, username: str, new_password: str) -> bool:
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password_hash = %s, mfa_secret = NULL, mfa_enabled = FALSE WHERE username = %s",
                    (hashed, username),
                )
                updated = cur.rowcount > 0
            c.commit()
            return updated
        finally:
            self._p(c)

    def delete_user(self, username: str) -> bool:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username = %s", (username,))
                deleted = cur.rowcount > 0
            c.commit()
            return deleted
        finally:
            self._p(c)

    def delete_transfer(self, tid: int) -> bool:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("DELETE FROM transfers WHERE id = %s", (tid,))
                deleted = cur.rowcount > 0
            c.commit()
            return deleted
        finally:
            self._p(c)

    def get_user_mfa_state(self, username: str):
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if not row:
                    return False, None
                return bool(row[0]), row[1]
        finally:
            self._p(c)

    def save_mfa_secret(self, username: str, secret: str, enabled: bool = True) -> None:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE users SET mfa_secret = %s, mfa_enabled = %s WHERE username = %s",
                    (secret, enabled, username),
                )
            c.commit()
        finally:
            self._p(c)

    def verify_mfa_token(self, username: str, token: str) -> bool:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT mfa_secret FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if not row or not row[0]:
                    return False
                return pyotp.TOTP(row[0]).verify(token, valid_window=1)
        finally:
            self._p(c)

    # --- Transfers ---
    def insert_or_detect_duplicate(self, filename, direction, size, sha, content_sha,
                                    staged_path, bank_id="bank", account_id=""):
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (content_sha,))
                cur.execute("""
                    SELECT id, filename, status FROM transfers
                    WHERE content_sha256 = %s AND direction = %s
                      AND bank_id = %s AND account_id = %s
                    ORDER BY
                        CASE status
                            WHEN 'sent'         THEN 0
                            WHEN 'received'     THEN 1
                            WHEN 'transferring' THEN 2
                            WHEN 'pending'      THEN 3
                            WHEN 'duplicate'    THEN 4
                            WHEN 'failed'       THEN 5
                            ELSE 6
                        END, id
                    LIMIT 1
                """, (content_sha, direction, bank_id, account_id))
                existing = cur.fetchone()

                if existing:
                    dup_of, dup_name, dup_status = existing
                    cur.execute("""
                        INSERT INTO transfers
                          (filename, direction, size_bytes, sha256, content_sha256,
                           status, error, bank_id, account_id)
                        VALUES (%s,%s,%s,%s,%s,'duplicate',%s,%s,%s) RETURNING id
                    """, (filename, direction, size, sha, content_sha,
                          f"Same content as #{dup_of} ({dup_name}, status={dup_status})",
                          bank_id, account_id))
                    new_id = cur.fetchone()[0]
                    cur.execute(
                        "INSERT INTO transfer_logs (transfer_id, message) VALUES (%s, %s)",
                        (new_id, f"DUPLICATE: matches transfer #{dup_of} ({dup_name}). Skipped."),
                    )
                    c.commit()
                    log.warning("DUPLICATE: %s matches #%d (%s)", filename, dup_of, dup_name)
                    return new_id, dup_of

                cur.execute("""
                    INSERT INTO transfers
                      (filename, direction, size_bytes, sha256, content_sha256,
                       status, staged_path, bank_id, account_id)
                    VALUES (%s,%s,%s,%s,%s,'pending',%s,%s,%s) RETURNING id
                """, (filename, direction, size, sha, content_sha, staged_path, bank_id, account_id))
                new_id = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO transfer_logs (transfer_id, message) VALUES (%s, %s)",
                    (new_id, f"Discovered: {filename} ({size}B, bank={bank_id}, account={account_id or '-'})")
                )
                c.commit()
                return new_id, None
        finally:
            self._p(c)

    def update(self, tid: int, **f):
        if not f:
            return
        bad = set(f) - _TRANSFER_UPDATABLE
        if bad:
            raise ValueError(f"Non-updatable fields: {bad}")
        f["updated_at"] = datetime.now(timezone.utc)
        sql = ", ".join(f"{k} = %s" for k in f)
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(f"UPDATE transfers SET {sql} WHERE id = %s", list(f.values()) + [tid])
            c.commit()
        finally:
            self._p(c)

    def add_log(self, tid, msg):
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(
                    "INSERT INTO transfer_logs (transfer_id, message) VALUES (%s, %s)", (tid, msg)
                )
            c.commit()
        finally:
            self._p(c)

    def get(self, tid):
        c = self._c()
        try:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, filename, direction, status, size_bytes, sha256, content_sha256,
                           error, retries, staged_path, archived_path, bank_id, account_id,
                           TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS created_at,
                           TO_CHAR(updated_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS updated_at
                    FROM transfers WHERE id = %s
                """, (tid,))
                row = cur.fetchone()
                if not row:
                    return None
                rec = dict(row)
                cur.execute("""
                    SELECT message, TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS time
                    FROM transfer_logs WHERE transfer_id = %s ORDER BY created_at
                """, (tid,))
                rec["logs"] = [dict(r) for r in cur.fetchall()]
            return rec
        finally:
            self._p(c)

    def summary(self):
        c = self._c()
        try:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE status = 'sent')         AS sent,
                        COUNT(*) FILTER (WHERE status = 'received')     AS received,
                        COUNT(*) FILTER (WHERE status = 'failed')       AS failed,
                        COUNT(*) FILTER (WHERE status = 'pending')      AS pending,
                        COUNT(*) FILTER (WHERE status = 'transferring') AS transferring,
                        COUNT(*) FILTER (WHERE status = 'duplicate')    AS duplicate,
                        COUNT(*) FILTER (WHERE status = 'abandoned')    AS abandoned
                    FROM transfers
                """)
                return dict(cur.fetchone())
        finally:
            self._p(c)

    def list_transfers(self, status=None, direction=None, bank_id=None, account_id=None,
                       date_from=None, date_to=None,
                       sort_by="id", sort_dir="desc",
                       page=1, per_page=50):
        _SORT_COLS = {"id", "filename", "status", "size_bytes", "updated_at", "created_at"}
        if sort_by not in _SORT_COLS:
            sort_by = "id"
        sort_dir = "ASC" if sort_dir == "asc" else "DESC"
        where, params = [], []
        if status:
            where.append("status = %s"); params.append(status)
        if direction:
            where.append("direction = %s"); params.append(direction)
        if bank_id:
            where.append("bank_id = %s"); params.append(bank_id)
        if account_id:
            where.append("account_id = %s"); params.append(account_id)
        if date_from:
            where.append("updated_at::date >= %s"); params.append(date_from)
        if date_to:
            where.append("updated_at::date <= %s"); params.append(date_to)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        c = self._c()
        try:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) AS cnt FROM transfers {w}", params)
                total = cur.fetchone()["cnt"]
                cur.execute(f"""
                    SELECT id, filename, direction, status, size_bytes, sha256, content_sha256,
                           error, retries, bank_id, account_id,
                           TO_CHAR(updated_at, 'YYYY-MM-DD HH24:MI:SS UTC') AS updated_at
                    FROM transfers {w}
                    ORDER BY {sort_by} {sort_dir} LIMIT %s OFFSET %s
                """, params + [per_page, (page - 1) * per_page])
                rows = [dict(r) for r in cur.fetchall()]
            return rows, total
        finally:
            self._p(c)

    def notifications(self):
        c = self._c()
        try:
            with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, filename, status, error,
                           TO_CHAR(updated_at, 'HH24:MI:SS') AS time
                    FROM transfers WHERE status IN ('duplicate', 'failed')
                    ORDER BY id DESC LIMIT 10
                """)
                return [dict(r) for r in cur.fetchall()]
        finally:
            self._p(c)

    def get_active_staged_paths(self) -> set:
        c = self._c()
        try:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT staged_path FROM transfers "
                    "WHERE staged_path IS NOT NULL AND status IN ('pending','transferring','failed')"
                )
                return {row[0] for row in cur.fetchall() if row[0]}
        finally:
            self._p(c)


db = DB()


# =====================================================================
#  TRANSFER HELPERS
# =====================================================================
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalize_for_duplicate_hash(data: bytes) -> bytes:
    if b"\x00" in data:
        return data
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines).encode("utf-8")


def content_sha256_hex(data: bytes) -> str:
    return sha256_hex(canonicalize_for_duplicate_hash(data))


async def sftp_connect(host: str, port: int, user: str, password: str, key: str,
                        known_hosts: str | None = None):
    kw = {"host": host, "port": port, "username": user}
    kh = known_hosts or CFG["SFTP_KNOWN_HOSTS"] or None
    if kh is None and CFG["MODE"] != "local":
        # Without known_hosts the connection is vulnerable to MITM.
        # Set SFTP_KNOWN_HOSTS or per-bank known_hosts in production.
        log.warning("SFTP to %s: no known_hosts file configured — host key not verified", host)
    kw["known_hosts"] = kh
    if key:
        kw["client_keys"] = [key]
    elif password:
        kw["password"] = password
    conn = await asyncio.wait_for(asyncssh.connect(**kw), timeout=CFG["SFTP_TIMEOUT"])
    return conn, await conn.start_sftp_client()


def _find_bank_cfg(bank_id: str) -> dict | None:
    for b in BANKS:
        if b["id"] == bank_id:
            return b
    return None


def _sftp_remote_dir(base_dir: str, bank_id: str, account_id: str) -> str:
    """Build a segregated remote SFTP path: <base>/<bank_id>[/<account_id>].

    Super-folder  = base_dir   (e.g. /outbound)
    Bank-level    = bank_id    (e.g. /outbound/hsbc)
    Account-level = account_id (e.g. /outbound/hsbc/acc001)
    Only appends segments when SFTP_FOLDER_SEGREGATION=true (default).
    """
    if not CFG["SFTP_FOLDER_SEGREGATION"]:
        return base_dir
    parts = [base_dir.rstrip("/")]
    sid = _safe_id(bank_id)
    if sid:
        parts.append(sid)
    aid = _safe_id(account_id)
    if aid:
        parts.append(aid)
    return "/".join(parts)


async def _sftp_ensure_dir(sftp, path: str) -> None:
    """Best-effort remote mkdir. Ignores errors (dir exists or perms)."""
    try:
        await asyncio.wait_for(sftp.mkdir(path), timeout=CFG["SFTP_TIMEOUT"])
    except Exception:
        pass  # already exists, or server prohibits creation — sftp.put() surfaces real errors


# =====================================================================
#  ACK / NACK
# =====================================================================
def write_ack(tid: int, filename: str, archived_path: str = None,
               bank_id: str = "", account_id: str = ""):
    target_dir = _ns_local_dir(bank_id, account_id, "ACK")
    target_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[/\\]", "_", Path(filename).name)
    dest = target_dir / f"{tid}_{safe}"
    if archived_path and Path(archived_path).exists():
        shutil.copy2(archived_path, dest)
    else:
        dest.write_bytes(b"")  # placeholder if archive unavailable


def write_nack(tid: int, filename: str, direction: str, error: str,
                bank_id: str = "", account_id: str = "", source_path: str = None):
    target_dir = _ns_local_dir(bank_id, account_id, "NACK")
    target_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[/\\]", "_", Path(filename).name)
    dest = target_dir / f"{tid}_{safe}"
    if source_path and Path(source_path).exists():
        shutil.copy2(source_path, dest)
    else:
        dest.with_suffix(".error.txt").write_text(
            f"transfer_id: {tid}\nfilename: {filename}\ndirection: {direction}\n"
            f"bank_id: {bank_id}\naccount_id: {account_id}\nerror: {error}\n"
            f"timestamp: {datetime.now(timezone.utc).isoformat()}\n",
            encoding="utf-8")


def _clear_nack_for(tid: int):
    """Remove any NACK copies for this transfer after it succeeds."""
    for p in NETSUITE_DIR.rglob(f"{tid}_*"):
        if "NACK" in p.parts:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass


# =====================================================================
#  PGP ENCRYPTION
# =====================================================================
def _pgp_decrypt_file(src: Path, dest: Path, bank_cfg: dict) -> bool:
    """Decrypt a PGP file received from bank using our private key.

    Returns True if decrypted, False if no pgp_private_key is configured.
    The private key must correspond to the public key we gave the bank.
    """
    import gnupg
    priv_key_path = bank_cfg.get("pgp_private_key", "").strip()
    if not priv_key_path:
        return False
    key_file = Path(priv_key_path)
    if not key_file.exists():
        raise FileNotFoundError(f"PGP private key not found: {priv_key_path}")
    GPG_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=str(GPG_HOME.resolve()))
    gpg.import_keys(key_file.read_text(encoding="utf-8"))
    passphrase = bank_cfg.get("pgp_private_key_passphrase", "") or None
    with open(src, "rb") as f:
        result = gpg.decrypt_file(f, passphrase=passphrase, output=str(dest))
    if not result.ok:
        raise RuntimeError(f"PGP decryption failed ({result.status}): {result.stderr.strip()}")
    log.info("PGP decrypted %s → %s", src.name, dest.name)
    return True


def _pgp_encrypt_file(src: Path, dest: Path, pubkey_path: str) -> None:
    """Encrypt src with the PGP public key at pubkey_path; write binary output to dest."""
    import gnupg
    key_file = Path(pubkey_path)
    if not key_file.exists():
        raise FileNotFoundError(f"PGP public key not found: {pubkey_path}")
    GPG_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=str(GPG_HOME.resolve()))
    key_data = key_file.read_text(encoding="utf-8")
    import_result = gpg.import_keys(key_data)
    if not import_result.fingerprints:
        raise RuntimeError(f"No valid PGP key loaded from {pubkey_path}")
    fingerprint = import_result.fingerprints[0]
    with open(src, "rb") as f:
        encrypted = gpg.encrypt_file(
            f,
            recipients=[fingerprint],
            always_trust=True,
            output=str(dest),
            armor=False,  # binary .pgp output; set armor=True for ASCII-armored .asc
        )
    if not encrypted.ok:
        raise RuntimeError(f"PGP encryption failed ({encrypted.status}): {encrypted.stderr.strip()}")
    log.info("PGP encrypted %s → %s [key fingerprint: %s]", src.name, dest.name, fingerprint[-16:])


# =====================================================================
#  ALERTS
# =====================================================================
def _send_alert_sync(subject: str, body: str, kind: str = "failure"):
    if not CFG["SMTP_USER"]:
        return
    try:
        prefix = "[Bridge:ACK]" if kind == "success" else "[Bridge:NACK]"
        msg = MIMEText(body)
        msg["Subject"] = f"{prefix} {subject}"
        msg["From"]    = CFG["SMTP_USER"]
        msg["To"]      = CFG["ALERT_TO"]
        ctx = ssl.create_default_context()
        with smtplib.SMTP(CFG["SMTP_HOST"], CFG["SMTP_PORT"], timeout=10) as s:
            s.starttls(context=ctx)
            s.login(CFG["SMTP_USER"], CFG["SMTP_PASS"])
            s.send_message(msg)
    except Exception as e:
        log.error("Alert email failed: %s", e)


async def send_alert(subject: str, body: str, kind: str = "failure"):
    await asyncio.to_thread(_send_alert_sync, subject, body, kind)


# =====================================================================
#  QR CODE
# =====================================================================
def _make_totp_qr_svg(uri: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg as svg_mod
        img = qrcode.make(uri, image_factory=svg_mod.SvgPathFillImage)
        buf = io.BytesIO()
        img.save(buf)
        svg_str = buf.getvalue().decode("utf-8")
        if "<?xml" in svg_str:
            svg_str = svg_str[svg_str.index("<svg"):]
        return svg_str
    except Exception as e:
        log.warning("QR code generation failed: %s", e)
        return ""


# =====================================================================
#  TRANSFER LOGIC
# =====================================================================
async def _deliver(tid: int, filepath: Path, direction: str, fname: str,
                   bank_cfg: dict, account_cfg: dict | None = None):
    bank_id    = bank_cfg["id"]
    account_id = (account_cfg or {}).get("id", "")
    sem        = _SFTP_SEM or asyncio.Semaphore(1)

    if direction == "outbound":
        pgp_key_path = bank_cfg.get("pgp_public_key", "").strip()
        enc_path = None
        try:
            if pgp_key_path:
                enc_path   = filepath.with_name(filepath.name + ".pgp")
                await asyncio.to_thread(_pgp_encrypt_file, filepath, enc_path, pgp_key_path)
                await asyncio.to_thread(db.add_log, tid, f"PGP encrypted as {fname}.pgp")
                send_path  = enc_path
                send_fname = fname + ".pgp"
            else:
                send_path  = filepath
                send_fname = fname

            if CFG["MODE"] == "local":
                dest = _bank_local_dir(bank_id, account_id, "inbound")
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(send_path, dest / send_fname)
            else:
                if account_cfg and account_cfg.get("inbound_dir"):
                    remote_dir = account_cfg["inbound_dir"]
                else:
                    remote_dir = bank_cfg.get("inbound_dir", "/inbound")
                async with sem:
                    conn, sftp = await sftp_connect(
                        bank_cfg["host"], bank_cfg.get("port", 22),
                        bank_cfg.get("user", ""), bank_cfg.get("pass", ""),
                        bank_cfg.get("key", ""), bank_cfg.get("known_hosts", ""))
                    try:
                        await _sftp_ensure_dir(sftp, remote_dir)
                        await asyncio.wait_for(
                            sftp.put(str(send_path), f"{remote_dir}/{send_fname}"),
                            timeout=CFG["SFTP_TIMEOUT"])
                    finally:
                        sftp.exit(); conn.close()
        finally:
            if enc_path is not None:
                enc_path.unlink(missing_ok=True)
        new_status  = "sent"
        deliver_msg = f"Delivered to bank [{bank_id}]" + (" [PGP]" if pgp_key_path else "")
    else:
        # Inbound: bank → NetSuite
        # Decrypt if bank encrypted the file with our public key, detect NACK responses
        is_nack     = False
        dec_path    = None
        try:
            actual_fname    = fname
            actual_filepath = filepath

            if fname.lower().endswith(".pgp"):
                dec_fname = fname[:-4]               # strip .pgp from original bank filename
                dec_path  = filepath.with_suffix("")  # local temp path (UUID prefix OK here)
                try:
                    decrypted = await asyncio.to_thread(
                        _pgp_decrypt_file, filepath, dec_path, bank_cfg)
                    if decrypted:
                        actual_fname    = dec_fname   # original bank name, no UUID prefix
                        actual_filepath = dec_path
                        await asyncio.to_thread(db.add_log, tid, f"PGP decrypted → {actual_fname}")
                    else:
                        dec_path = None   # no private key configured — deliver as-is
                except Exception as e:
                    log.warning("PGP decryption skipped for %s: %s — delivering encrypted", fname, e)
                    await asyncio.to_thread(db.add_log, tid, f"PGP decryption skipped: {e}")
                    dec_path = None

            # Bank NACK responses contain "_Nack" in their filename; route to NACK dir
            is_nack   = "_nack" in actual_fname.lower()
            ns_subdir = "NACK" if is_nack else "inbound"

            if CFG["MODE"] == "local" or CFG["NS_SFTP_SERVER_MODE"]:
                dest_dir = _ns_local_dir(bank_id, account_id, ns_subdir)
                dest_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(actual_filepath, dest_dir / actual_fname)
            else:
                remote_base = _sftp_remote_dir(CFG["NS_INBOUND_DIR"], bank_id, account_id)
                remote_dir  = f"{remote_base}/NACK" if is_nack else remote_base
                async with sem:
                    conn, sftp = await sftp_connect(
                        CFG["NS_HOST"], CFG["NS_PORT"],
                        CFG["NS_USER"], CFG["NS_PASS"], CFG["NS_KEY"])
                    try:
                        await _sftp_ensure_dir(sftp, remote_dir)
                        await asyncio.wait_for(
                            sftp.put(str(actual_filepath), f"{remote_dir}/{actual_fname}"),
                            timeout=CFG["SFTP_TIMEOUT"])
                    finally:
                        sftp.exit(); conn.close()
        finally:
            if dec_path is not None:
                dec_path.unlink(missing_ok=True)

        new_status  = "received"
        label       = " [NACK]" if is_nack else ""
        deliver_msg = f"Delivered to NetSuite{label} (from [{bank_id}])"

    await asyncio.to_thread(db.add_log, tid, deliver_msg)

    archived_str = None
    try:
        archived = await asyncio.to_thread(
            _archive_file, filepath, direction, fname, ARCHIVE_DIR, bank_id, account_id)
        archived_str = str(archived.resolve())
        await asyncio.to_thread(db.add_log, tid, f"Archived to {archived}")
    except Exception as e:
        log.warning("Could not archive %s: %s (deleting instead)", filepath, e)
        filepath.unlink(missing_ok=True)

    await asyncio.to_thread(
        db.update, tid, status=new_status, staged_path=None,
        archived_path=archived_str, error=None)

    await send_alert(
        f"{deliver_msg}: {fname}",
        f"Transfer #{tid}\nFile: {fname}\nBank: {bank_id}\nAccount: {account_id or '-'}\n"
        f"Direction: {direction}\nArchived: {archived_str or 'n/a'}",
        kind="success",
    )
    if direction == "outbound":
        await asyncio.to_thread(write_ack, tid, fname, archived_str, bank_id, account_id)
        await asyncio.to_thread(_clear_nack_for, tid)


async def process_file(filepath: Path, direction: str, original_name: str = None,
                        bank_cfg: dict = None, account_cfg: dict = None):
    bank_cfg   = bank_cfg or (BANKS[0] if BANKS else {"id": "bank"})
    bank_id    = bank_cfg["id"]
    account_id = (account_cfg or {}).get("id", "")
    # Strip directory components and control chars from filename
    raw_name   = original_name or filepath.name
    fname      = re.sub(r"[^\w\-. ]", "_", Path(raw_name).name)[:255] or "upload.bin"

    data        = await asyncio.to_thread(filepath.read_bytes)
    sha         = sha256_hex(data)
    content_sha = content_sha256_hex(data)
    log.info("%-9s %s (%dB, bank=%s, sha=%s...)", direction.upper(), fname, len(data), bank_id, sha[:16])

    tid, dup_of = await asyncio.to_thread(
        db.insert_or_detect_duplicate,
        fname, direction, len(data), sha, content_sha,
        str(filepath.resolve()), bank_id, account_id)

    if dup_of is not None:
        await send_alert(f"Duplicate blocked: {fname}",
                         f"Matches transfer #{dup_of} (bank={bank_id})")
        filepath.unlink(missing_ok=True)
        return

    await asyncio.to_thread(db.update, tid, status="transferring")
    await asyncio.to_thread(db.add_log, tid, "Transferring...")

    try:
        await _deliver(tid, filepath, direction, fname, bank_cfg, account_cfg)
    except Exception as e:
        log.error("Transfer #%d failed [bank=%s file=%s]: %s", tid, bank_id, fname, e, exc_info=True)
        await asyncio.to_thread(db.update, tid, status="failed", error=str(e))
        await asyncio.to_thread(db.add_log, tid, f"Failed: {e}")
        await send_alert(f"Transfer failed: {fname}", f"Bank: {bank_id}\nError: {e}")
        await asyncio.to_thread(write_nack, tid, fname, direction, str(e), bank_id, account_id,
                                source_path=str(filepath))


async def retry_transfer(tid: int) -> tuple[bool, str]:
    rec = await asyncio.to_thread(db.get, tid)
    if not rec:
        return False, "Transfer not found"
    if rec["status"] != "failed":
        return False, f"Cannot retry — status is '{rec['status']}' (only 'failed' transfers can be retried)"

    staged = rec.get("staged_path")
    if not staged:
        return False, "No staged file on record — please re-upload"

    staged_path = Path(staged)
    if not staged_path.exists():
        return False, "Staged file no longer exists — please re-upload"

    bank_id    = rec.get("bank_id", "bank")
    account_id = rec.get("account_id", "")
    bank_cfg   = _find_bank_cfg(bank_id) or {"id": bank_id}
    account_cfg = None
    if account_id:
        for acc in bank_cfg.get("accounts", []):
            if acc.get("id") == account_id:
                account_cfg = acc
                break
        if account_cfg is None:
            account_cfg = {"id": account_id}

    attempt = (rec["retries"] or 0) + 1
    await asyncio.to_thread(db.update, tid, status="transferring", retries=attempt, error=None)
    await asyncio.to_thread(db.add_log, tid, f"Retry #{attempt}: re-attempting")

    try:
        await _deliver(tid, staged_path, rec["direction"], rec["filename"], bank_cfg, account_cfg)
        await asyncio.to_thread(db.add_log, tid, f"Retry #{attempt} succeeded")
        return True, "Transfer succeeded"
    except Exception as e:
        log.error("Retry #%d failed [bank=%s file=%s]: %s", attempt, bank_id, rec["filename"], e, exc_info=True)
        await asyncio.to_thread(db.update, tid, status="failed", error=str(e))
        await asyncio.to_thread(db.add_log, tid, f"Retry #{attempt} failed: {e}")
        await send_alert(f"Retry failed: {rec['filename']}", f"Bank: {bank_id}\nError: {e}")
        await asyncio.to_thread(write_nack, tid, rec["filename"], rec["direction"], str(e), bank_id, account_id,
                                source_path=str(staged_path))
        return False, "Transfer failed — check server logs"


# =====================================================================
#  POLLING
# =====================================================================
def _stage_local(src: Path) -> Path:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    stamp  = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    staged = STAGING_DIR / f"{stamp}_{uuid.uuid4().hex}_{src.name}"
    shutil.move(str(src), str(staged))
    return staged


async def _poll_cycle(cap: int):
    processed = 0
    sem = _SFTP_SEM or asyncio.Semaphore(1)

    for bank_cfg in BANKS:
        bank_id  = bank_cfg["id"]
        accounts = bank_cfg.get("accounts") or [{"id": ""}]

        for account_cfg in accounts:
            account_id = account_cfg.get("id", "")
            if processed >= cap:
                return

            # ── NetSuite → Bank (outbound) ──────────────────────────────
            try:
                if CFG["MODE"] == "local" or CFG["NS_SFTP_SERVER_MODE"]:
                    # NS_SFTP_SERVER_MODE: NetSuite drops files here via SFTP into bridge's server
                    d = _ns_local_dir(bank_id, account_id, "outbound")
                    if d.exists():
                        for f in sorted(d.iterdir()):
                            if processed >= cap:
                                break
                            if f.is_file() and not f.name.startswith("."):
                                staged = await asyncio.to_thread(_stage_local, f)
                                await process_file(staged, "outbound", original_name=f.name,
                                                   bank_cfg=bank_cfg, account_cfg=account_cfg)
                                processed += 1
                else:
                    if CFG["NS_HOST"]:
                        # Segregated poll dir: /outbound/<bank_id>[/<account_id>]
                        ns_out_dir = _sftp_remote_dir(CFG["NS_OUTBOUND_DIR"], bank_id, account_id)
                        async with sem:
                            conn, sftp = await sftp_connect(
                                CFG["NS_HOST"], CFG["NS_PORT"],
                                CFG["NS_USER"], CFG["NS_PASS"], CFG["NS_KEY"])
                            try:
                                STAGING_DIR.mkdir(parents=True, exist_ok=True)
                                entries = await asyncio.wait_for(
                                    sftp.readdir(ns_out_dir),
                                    timeout=CFG["SFTP_TIMEOUT"])
                                for e in entries:
                                    if processed >= cap:
                                        break
                                    # Strip directory components to prevent path traversal
                                    safe_fname = Path(e.filename).name
                                    if not safe_fname or safe_fname.startswith("."):
                                        continue
                                    local = STAGING_DIR / f"{uuid.uuid4().hex}_{safe_fname}"
                                    await asyncio.wait_for(
                                        sftp.get(f"{ns_out_dir}/{safe_fname}", str(local)),
                                        timeout=CFG["SFTP_TIMEOUT"])
                                    await asyncio.wait_for(
                                        sftp.remove(f"{ns_out_dir}/{safe_fname}"),
                                        timeout=CFG["SFTP_TIMEOUT"])
                                    await process_file(local, "outbound", original_name=safe_fname,
                                                       bank_cfg=bank_cfg, account_cfg=account_cfg)
                                    processed += 1
                            finally:
                                sftp.exit(); conn.close()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("NS poll error (bank=%s, acct=%s): %s", bank_id, account_id or "-", e)
                await send_alert(f"NetSuite SFTP unreachable [{bank_id}]", f"Error: {e}")

            if processed >= cap:
                return

            # ── Bank → NetSuite (inbound) ───────────────────────────────
            try:
                if CFG["MODE"] == "local":
                    d = _bank_local_dir(bank_id, account_id, "outbound")
                    if d.exists():
                        for f in sorted(d.iterdir()):
                            if processed >= cap:
                                break
                            if f.is_file() and not f.name.startswith("."):
                                staged = await asyncio.to_thread(_stage_local, f)
                                await process_file(staged, "inbound", original_name=f.name,
                                                   bank_cfg=bank_cfg, account_cfg=account_cfg)
                                processed += 1
                else:
                    host = bank_cfg.get("host", "")
                    if host:
                        if account_cfg and account_cfg.get("outbound_dir"):
                            remote_dir = account_cfg["outbound_dir"]
                        else:
                            remote_dir = bank_cfg.get("outbound_dir", "/outbound")
                        async with sem:
                            conn, sftp = await sftp_connect(
                                host, bank_cfg.get("port", 22),
                                bank_cfg.get("user", ""), bank_cfg.get("pass", ""),
                                bank_cfg.get("key", ""), bank_cfg.get("known_hosts", ""))
                            try:
                                STAGING_DIR.mkdir(parents=True, exist_ok=True)
                                entries = await asyncio.wait_for(
                                    sftp.readdir(remote_dir), timeout=CFG["SFTP_TIMEOUT"])
                                for e in entries:
                                    if processed >= cap:
                                        break
                                    safe_fname = Path(e.filename).name
                                    if not safe_fname or safe_fname.startswith("."):
                                        continue
                                    local = STAGING_DIR / f"{uuid.uuid4().hex}_{safe_fname}"
                                    await asyncio.wait_for(
                                        sftp.get(f"{remote_dir}/{safe_fname}", str(local)),
                                        timeout=CFG["SFTP_TIMEOUT"])
                                    await asyncio.wait_for(
                                        sftp.remove(f"{remote_dir}/{safe_fname}"),
                                        timeout=CFG["SFTP_TIMEOUT"])
                                    await process_file(local, "inbound", original_name=safe_fname,
                                                       bank_cfg=bank_cfg, account_cfg=account_cfg)
                                    processed += 1
                            finally:
                                sftp.exit(); conn.close()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("Bank poll error (bank=%s, acct=%s): %s", bank_id, account_id or "-", e)
                await send_alert(f"Bank SFTP unreachable [{bank_id}]", f"Error: {e}")

    if processed:
        log.info("Poll cycle: processed %d file(s)", processed)


async def poll_loop():
    while True:
        try:
            await _poll_cycle(CFG["MAX_FILES_PER_CYCLE"])
        except asyncio.CancelledError:
            log.info("Poll loop cancelled — shutting down")
            raise
        except Exception as e:
            log.error("Poll cycle error: %s", e)
        try:
            await asyncio.sleep(CFG["POLL_SECONDS"])
        except asyncio.CancelledError:
            log.info("Poll sleep cancelled — shutting down")
            raise


async def _staging_cleanup_loop():
    """Hourly: remove orphaned staging files older than STAGING_MAX_AGE_HOURS."""
    while True:
        try:
            await asyncio.sleep(3600)
            cutoff = datetime.now(timezone.utc).timestamp() - CFG["STAGING_MAX_AGE_HOURS"] * 3600
            active = await asyncio.to_thread(db.get_active_staged_paths)
            for d in (STAGING_DIR, UPLOAD_STAGING_DIR):
                if not d.exists():
                    continue
                for f in d.iterdir():
                    if f.is_file() and f.stat().st_mtime < cutoff and str(f.resolve()) not in active:
                        log.warning("Removing orphaned staging file: %s", f.name)
                        f.unlink(missing_ok=True)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("Staging cleanup error: %s", e)


# =====================================================================
#  FASTAPI
# =====================================================================
@asynccontextmanager
async def lifespan(app):
    global _LOGIN_LOCK, _SFTP_SEM
    _LOGIN_LOCK = asyncio.Lock()
    _SFTP_SEM   = asyncio.Semaphore(CFG["MAX_CONCURRENT_SFTP"])
    if not _SESSION_SECRET_CONFIGURED:
        log.info(
            "SESSION_SECRET not set — auto-generating a random secret. "
            "Sessions will reset on restart. Set SESSION_SECRET env var to persist sessions.")
    if not BANKS:
        BANKS.extend(_load_banks_config())
    _ensure_local_dirs()
    await asyncio.to_thread(db.init)
    poll_task    = asyncio.create_task(poll_loop())
    cleanup_task = asyncio.create_task(_staging_cleanup_loop())
    ns_mode = "sftp-server (NetSuite connects IN)" if CFG["NS_SFTP_SERVER_MODE"] else ("local" if CFG["MODE"] == "local" else "sftp-client (bridge dials out)")
    log.info("Poller started (every %ds, mode=%s, ns=%s, banks=%d, segregation=%s)",
             CFG["POLL_SECONDS"], CFG["MODE"], ns_mode, len(BANKS), CFG["SFTP_FOLDER_SEGREGATION"])
    yield
    poll_task.cancel()
    cleanup_task.cancel()
    for t in (poll_task, cleanup_task):
        try:
            await t
        except asyncio.CancelledError:
            pass
    await asyncio.to_thread(db.close)


app = FastAPI(title="Bridge", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=CFG["SESSION_SECRET"],
    session_cookie="bridge_session",
    max_age=8 * 60 * 60,
    https_only=CFG["SESSION_HTTPS_ONLY"],
    same_site="strict",
)
templates = Jinja2Templates(directory="templates")


# --- Auth dependencies ---
def require_auth_api(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin_api(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if request.session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")
    return user


# --- Login / logout ---
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None, next: str = "/"):
    if request.session.get("user"):
        return RedirectResponse(_safe_next_url(next), status_code=302)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error, "next": next})


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    next_url = _safe_next_url(next)

    if not await _check_rate_limit(username):
        log.warning("Login rate-limited: %s", username)
        return RedirectResponse(
            f"/login?error=Too+many+failed+attempts.+Try+again+later.&next={next_url}",
            status_code=303)

    ok = await asyncio.to_thread(db.verify_user, username, password)
    if ok:
        await _clear_login_attempts(username)
        mfa_enabled, _ = await asyncio.to_thread(db.get_user_mfa_state, username)
        request.session["mfa_pending"] = username
        request.session["mfa_next"]    = next_url
        return RedirectResponse("/mfa-setup" if not mfa_enabled else "/mfa-verify",
                                 status_code=303)

    await _record_login_failure(username)
    log.warning("Login failed: %s", username)
    return RedirectResponse(
        f"/login?error=Invalid+credentials&next={next_url}", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    user = request.session.get("user")
    request.session.clear()
    if user:
        log.info("Logout: %s", user)
    return RedirectResponse("/login", status_code=303)


# --- MFA setup (first-login enrollment) ---
@app.get("/mfa-setup", response_class=HTMLResponse)
async def mfa_setup_page(request: Request):
    username = request.session.get("mfa_pending")
    if not username:
        return RedirectResponse("/login", status_code=302)
    if "mfa_setup_secret" not in request.session:
        request.session["mfa_setup_secret"] = pyotp.random_base32()
    secret  = request.session["mfa_setup_secret"]
    uri     = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Bridge")
    qr_svg  = _make_totp_qr_svg(uri)
    return templates.TemplateResponse(
        "mfa_setup.html",
        {"request": request, "username": username, "secret": secret,
         "uri": uri, "qr_svg": qr_svg})


@app.post("/mfa-setup")
async def mfa_setup_submit(request: Request, token: str = Form(...)):
    username = request.session.get("mfa_pending")
    if not username:
        return RedirectResponse("/login", status_code=302)
    if not await _check_mfa_rate_limit(username):
        log.warning("MFA setup rate-limited: %s", username)
        request.session.clear()
        return RedirectResponse("/login?error=Too+many+MFA+attempts.+Please+log+in+again.",
                                 status_code=303)
    secret = request.session.get("mfa_setup_secret")
    if not secret:
        return RedirectResponse("/mfa-setup", status_code=303)
    if pyotp.TOTP(secret).verify(token, valid_window=1):
        await _clear_mfa_attempts(username)
        await asyncio.to_thread(db.save_mfa_secret, username, secret, True)
        next_url = request.session.pop("mfa_next", "/")
        request.session.pop("mfa_pending",      None)
        request.session.pop("mfa_setup_secret", None)
        request.session["user"]     = username
        request.session["role"]     = await asyncio.to_thread(db.get_user_role, username)
        request.session["login_at"] = datetime.now(timezone.utc).isoformat()
        log.info("MFA enrolled + login: %s", username)
        return RedirectResponse(next_url or "/", status_code=303)
    await _record_mfa_failure(username)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Bridge")
    return templates.TemplateResponse(
        "mfa_setup.html",
        {"request": request, "username": username, "secret": secret,
         "uri": uri, "qr_svg": _make_totp_qr_svg(uri), "error": "Invalid code — try again."},
        status_code=400)


# --- MFA verify (every subsequent login) ---
@app.get("/mfa-verify", response_class=HTMLResponse)
async def mfa_verify_page(request: Request):
    username = request.session.get("mfa_pending")
    if not username:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(
        "mfa_verify.html", {"request": request, "username": username})


@app.post("/mfa-verify")
async def mfa_verify_submit(request: Request, token: str = Form(...)):
    username = request.session.get("mfa_pending")
    if not username:
        return RedirectResponse("/login", status_code=302)
    if not await _check_mfa_rate_limit(username):
        log.warning("MFA verify rate-limited: %s", username)
        request.session.clear()
        return RedirectResponse("/login?error=Too+many+MFA+attempts.+Please+log+in+again.",
                                 status_code=303)
    ok = await asyncio.to_thread(db.verify_mfa_token, username, token)
    if ok:
        await _clear_mfa_attempts(username)
        next_url = request.session.pop("mfa_next", "/")
        request.session.pop("mfa_pending", None)
        request.session["user"]     = username
        request.session["role"]     = await asyncio.to_thread(db.get_user_role, username)
        request.session["login_at"] = datetime.now(timezone.utc).isoformat()
        log.info("MFA verified, login: %s", username)
        return RedirectResponse(next_url or "/", status_code=303)
    await _record_mfa_failure(username)
    log.warning("MFA failed: %s", username)
    return templates.TemplateResponse(
        "mfa_verify.html",
        {"request": request, "username": username, "error": "Invalid code — try again."},
        status_code=400)


# --- Dashboard ---
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login", status_code=302)
    role = request.session.get("role", "readonly")
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "user": user, "role": role})


# --- API ---
@app.get("/api/me")
async def api_me(request: Request, user: str = Depends(require_auth_api)):
    return {"user": user, "role": request.session.get("role", "readonly")}


@app.get("/api/banks")
async def api_banks(user: str = Depends(require_auth_api)):
    return [
        {
            "id":       b["id"],
            "name":     b.get("name", b["id"]),
            "accounts": [{"id": a["id"], "name": a.get("name", a["id"])}
                         for a in b.get("accounts", []) if a.get("id")],
        }
        for b in BANKS
    ]


@app.get("/api/summary")
async def api_summary(user: str = Depends(require_auth_api)):
    return await asyncio.to_thread(db.summary)


@app.get("/api/transfers")
async def api_transfers(
    status:     str | None = Query(None),
    direction:  str | None = Query(None),
    bank_id:    str | None = Query(None),
    account_id: str | None = Query(None),
    date_from:  str | None = Query(None),
    date_to:    str | None = Query(None),
    sort_by:    str = Query("id"),
    sort_dir:   str = Query("desc"),
    page:       int = Query(1, ge=1),
    per_page:   int = Query(50, ge=1, le=200),
    user: str = Depends(require_auth_api),
):
    rows, total = await asyncio.to_thread(
        db.list_transfers, status, direction, bank_id, account_id,
        date_from, date_to, sort_by, sort_dir, page, per_page)
    return {"items": rows, "total": total, "page": page, "per_page": per_page}


@app.get("/api/transfers/{tid}")
async def api_detail(tid: int, user: str = Depends(require_auth_api)):
    r = await asyncio.to_thread(db.get, tid)
    return r if r else JSONResponse({"error": "not found"}, 404)


@app.get("/api/notifications")
async def api_notifications(user: str = Depends(require_auth_api)):
    return await asyncio.to_thread(db.notifications)


@app.post("/api/transfers/{tid}/retry")
async def api_retry(tid: int, user: str = Depends(require_admin_api)):
    log.info("Retry by %s for #%d", user, tid)
    ok, message = await retry_transfer(tid)
    if ok:
        return {"ok": True, "message": message}
    return JSONResponse({"ok": False, "message": message}, status_code=400)


@app.post("/api/transfers/{tid}/abandon")
async def api_abandon(tid: int, user: str = Depends(require_admin_api)):
    rec = await asyncio.to_thread(db.get, tid)
    if not rec:
        return JSONResponse({"error": "not found"}, status_code=404)
    if rec["status"] != "failed":
        return JSONResponse(
            {"ok": False, "message": f"Only 'failed' can be abandoned (current: {rec['status']})"},
            status_code=400)

    staged     = rec.get("staged_path")
    bank_id    = rec.get("bank_id", "")
    account_id = rec.get("account_id", "")
    archived_str = None
    if staged and Path(staged).exists():
        try:
            archived = await asyncio.to_thread(
                _archive_file, Path(staged), rec["direction"], rec["filename"],
                ERROR_DIR, bank_id, account_id)
            archived_str = str(archived.resolve())
        except Exception as e:
            log.error("Could not move %s to error dir: %s", staged, e)

    await asyncio.to_thread(
        db.update, tid, status="abandoned", staged_path=None, archived_path=archived_str)
    where = f"moved to {archived_str}" if archived_str else "no staged file"
    await asyncio.to_thread(db.add_log, tid, f"Abandoned by {user} ({where})")
    log.warning("Abandoned by %s: #%d (%s) — %s", user, tid, rec["filename"], where)
    return {"ok": True, "archived_path": archived_str}


@app.delete("/api/transfers/{tid}")
async def api_delete_transfer(tid: int, user: str = Depends(require_admin_api)):
    rec = await asyncio.to_thread(db.get, tid)
    if not rec:
        return JSONResponse({"error": "not found"}, status_code=404)
    staged = rec.get("staged_path")
    if staged:
        try:
            Path(staged).unlink(missing_ok=True)
        except Exception as e:
            log.warning("Could not delete staged file %s: %s", staged, e)
    deleted = await asyncio.to_thread(db.delete_transfer, tid)
    if deleted:
        log.info("Transfer #%d deleted by %s (%s)", tid, user, rec["filename"])
        return {"ok": True, "message": f"Transfer #{tid} deleted"}
    return JSONResponse({"ok": False, "message": "Transfer not found"}, status_code=404)


@app.post("/api/upload")
async def api_upload(
    file:       UploadFile = File(...),
    direction:  str = Form("outbound"),
    bank_id:    str = Form(""),
    account_id: str = Form(""),
    user: str = Depends(require_auth_api),
):
    if direction not in ("outbound", "inbound"):
        raise HTTPException(status_code=400, detail="direction must be 'outbound' or 'inbound'")

    content = await file.read(CFG["MAX_UPLOAD_BYTES"] + 1)
    if len(content) > CFG["MAX_UPLOAD_BYTES"]:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {CFG['MAX_UPLOAD_BYTES'] // (1024 * 1024)}MB limit")

    safe_name   = re.sub(r"[^\w\-. ]", "_", Path(file.filename or "upload.bin").name)[:255]
    unique_name = (f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
                   f"_{uuid.uuid4().hex}_{safe_name}")
    UPLOAD_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_STAGING_DIR / unique_name
    dest.write_bytes(content)

    eff_bank_id = bank_id or (BANKS[0]["id"] if BANKS else "bank")
    b_cfg       = _find_bank_cfg(eff_bank_id) or {"id": eff_bank_id}
    a_cfg       = None
    if account_id:
        for acc in b_cfg.get("accounts", []):
            if acc.get("id") == account_id:
                a_cfg = acc
                break
        if a_cfg is None:
            a_cfg = {"id": account_id}

    log.info("Upload by %s: %s -> %s (bank=%s, acct=%s)",
             user, safe_name, direction, eff_bank_id, account_id or "-")
    await process_file(dest, direction, original_name=safe_name,
                       bank_cfg=b_cfg, account_cfg=a_cfg)
    return {"queued": safe_name, "stored_as": unique_name,
            "direction": direction, "bank_id": eff_bank_id}


@app.get("/api/users")
async def api_list_users(user: str = Depends(require_admin_api)):
    return await asyncio.to_thread(db.list_users)


@app.post("/api/users")
async def api_create_user(request: Request, user: str = Depends(require_admin_api)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Invalid JSON"}, status_code=400)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role     = body.get("role", "readonly")
    if role not in ("admin", "readonly"):
        return JSONResponse({"ok": False, "message": "role must be 'admin' or 'readonly'"}, status_code=400)
    if not username or not password:
        return JSONResponse({"ok": False, "message": "username and password required"}, status_code=400)
    if len(password) < 8:
        return JSONResponse({"ok": False, "message": "Password must be at least 8 characters"}, status_code=400)
    try:
        await asyncio.to_thread(db.create_user, username, password, role)
        log.info("User created by %s: %s (role=%s)", user, username, role)
        return {"ok": True, "message": f"User '{username}' created with role '{role}'"}
    except Exception as e:
        if "unique" in str(e).lower():
            return JSONResponse({"ok": False, "message": f"Username '{username}' already exists"}, status_code=409)
        log.error("Create user error: %s", e)
        return JSONResponse({"ok": False, "message": "Failed to create user"}, status_code=500)


@app.delete("/api/users/{target_username}")
async def api_delete_user(target_username: str, user: str = Depends(require_admin_api)):
    if target_username == user:
        return JSONResponse({"ok": False, "message": "Cannot delete your own account"}, status_code=400)
    deleted = await asyncio.to_thread(db.delete_user, target_username)
    if deleted:
        log.info("User deleted by %s: %s", user, target_username)
        return {"ok": True}
    return JSONResponse({"ok": False, "message": "User not found"}, status_code=404)


@app.post("/api/users/{target_username}/reset-password")
async def api_reset_password(
    target_username: str, request: Request, user: str = Depends(require_admin_api)
):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Invalid JSON"}, status_code=400)
    new_password = body.get("password") or ""
    if len(new_password) < 8:
        return JSONResponse({"ok": False, "message": "Password must be at least 8 characters"}, status_code=400)
    updated = await asyncio.to_thread(db.reset_password, target_username, new_password)
    if not updated:
        return JSONResponse({"ok": False, "message": "User not found"}, status_code=404)
    log.info("Password reset by %s for: %s (MFA cleared)", user, target_username)
    return {"ok": True,
            "message": f"Password reset for '{target_username}'. MFA re-enrolled on next login."}


@app.get("/api/health")
async def health():
    try:
        await asyncio.to_thread(db.summary)
        return {"status": "ok", "postgres": True}
    except Exception:
        return {"status": "degraded", "postgres": False}


@app.get("/api/banks-config")
async def api_banks_config_get(_user: str = Depends(require_admin_api)):
    """Return full bank configs. Passwords are masked for display."""
    def _masked(banks):
        result = []
        for b in banks:
            bc = {k: v for k, v in b.items() if k != "pass"}
            bc["has_password"] = bool(b.get("pass"))
            bc["accounts"] = b.get("accounts", [])
            result.append(bc)
        return result
    return await asyncio.to_thread(_masked, BANKS)


@app.post("/api/banks-config")
async def api_banks_config_create(request: Request, _user: str = Depends(require_admin_api)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Invalid JSON body"}, status_code=400)
    try:
        bank_id = _safe_id(body.get("id", "").strip())
        if not bank_id:
            return JSONResponse({"ok": False, "message": "Bank ID is required"}, status_code=400)
        if any(b["id"] == bank_id for b in BANKS):
            return JSONResponse({"ok": False, "message": f"Bank '{bank_id}' already exists"}, status_code=409)

        new_bank = {
            "id":                          bank_id,
            "host":                        body.get("host", "").strip(),
            "port":                        int(body.get("port", 22)),
            "user":                        body.get("user", "").strip(),
            "pass":                        body.get("pass", ""),
            "key":                         body.get("key", "").strip(),
            "inbound_dir":                 body.get("inbound_dir", "/inbound").strip(),
            "outbound_dir":                body.get("outbound_dir", "/outbound").strip(),
            "accounts":                    body.get("accounts", []),
            "pgp_public_key":              body.get("pgp_public_key", "").strip(),
            "pgp_private_key":             body.get("pgp_private_key", "").strip(),
            "pgp_private_key_passphrase":  body.get("pgp_private_key_passphrase", ""),
        }
        updated = BANKS + [new_bank]
        await asyncio.to_thread(_save_banks_config, updated)
        await asyncio.to_thread(_reload_banks)
        log.info("Bank '%s' created by %s", bank_id, _user)
        return {"ok": True, "message": f"Bank '{bank_id}' created"}
    except Exception as e:
        log.error("Create bank error: %s", e, exc_info=True)
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.put("/api/banks-config/{bank_id}")
async def api_banks_config_update(bank_id: str, request: Request, _user: str = Depends(require_admin_api)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Invalid JSON body"}, status_code=400)
    try:
        safe_id = _safe_id(bank_id)
        existing = next((b for b in BANKS if b["id"] == safe_id), None)
        if not existing:
            return JSONResponse({"ok": False, "message": f"Bank '{safe_id}' not found"}, status_code=404)

        updated_bank = {
            "id":                         safe_id,
            "host":                       body.get("host", existing["host"]).strip(),
            "port":                       int(body.get("port", existing.get("port", 22))),
            "user":                       body.get("user", existing["user"]).strip(),
            "pass":                       body.get("pass") or existing.get("pass", ""),
            "key":                        body.get("key", existing.get("key", "")).strip(),
            "inbound_dir":                body.get("inbound_dir", existing.get("inbound_dir", "/inbound")).strip(),
            "outbound_dir":               body.get("outbound_dir", existing.get("outbound_dir", "/outbound")).strip(),
            "accounts":                   body.get("accounts", existing.get("accounts", [])),
            "pgp_public_key":             body.get("pgp_public_key", existing.get("pgp_public_key", "")).strip(),
            "pgp_private_key":            body.get("pgp_private_key", existing.get("pgp_private_key", "")).strip(),
            "pgp_private_key_passphrase": body.get("pgp_private_key_passphrase", existing.get("pgp_private_key_passphrase", "")),
        }
        updated = [updated_bank if b["id"] == safe_id else b for b in BANKS]
        await asyncio.to_thread(_save_banks_config, updated)
        await asyncio.to_thread(_reload_banks)
        log.info("Bank '%s' updated by %s", safe_id, _user)
        return {"ok": True, "message": f"Bank '{safe_id}' updated"}
    except Exception as e:
        log.error("Update bank error: %s", e, exc_info=True)
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.delete("/api/banks-config/{bank_id}")
async def api_banks_config_delete(bank_id: str, user: str = Depends(require_admin_api)):
    try:
        safe_id = _safe_id(bank_id)
        if not any(b["id"] == safe_id for b in BANKS):
            return JSONResponse({"ok": False, "message": f"Bank '{safe_id}' not found"}, status_code=404)
        updated = [b for b in BANKS if b["id"] != safe_id]
        await asyncio.to_thread(_save_banks_config, updated)
        await asyncio.to_thread(_reload_banks)

        def _remove_bank_dirs(bid: str):
            for d in (NETSUITE_DIR / bid, Path("data/banks") / bid):
                if d.exists():
                    shutil.rmtree(d)
                    log.info("Removed bank directory: %s", d)

        await asyncio.to_thread(_remove_bank_dirs, safe_id)
        log.info("Bank '%s' deleted by %s", safe_id, user)
        return {"ok": True, "message": f"Bank '{safe_id}' deleted"}
    except Exception as e:
        log.error("Delete bank error: %s", e, exc_info=True)
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


def _resolve_browsable_path(path: str):
    """Resolve and validate a browsable path against BROWSABLE_ROOTS. Raises HTTPException on invalid input."""
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        raise HTTPException(status_code=400, detail="Invalid path")
    root_name = parts[0]
    if root_name not in BROWSABLE_ROOTS:
        raise HTTPException(status_code=400, detail="Unknown root")
    base   = BROWSABLE_ROOTS[root_name].resolve()
    sub    = Path(*parts[1:]) if len(parts) > 1 else Path(".")
    target = (base / sub).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")
    return target


@app.get("/api/download")
async def api_download(path: str = Query(...), _user: str = Depends(require_auth_api)):
    def _resolve():
        target = _resolve_browsable_path(path)
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        return target
    target = await asyncio.to_thread(_resolve)
    return FileResponse(path=str(target), filename=target.name,
                        media_type="application/octet-stream")


@app.get("/api/file-content")
async def api_file_content(path: str = Query(...), _user: str = Depends(require_auth_api)):
    def _read():
        target = _resolve_browsable_path(path)
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        size = target.stat().st_size
        if size > 1024 * 1024:
            return {"content": None, "truncated": True, "size": size, "filename": target.name, "lines": 0}
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
            lines   = content.splitlines()
            return {
                "content":   "\n".join(lines[:200]),
                "truncated": len(lines) > 200,
                "size":      size,
                "filename":  target.name,
                "lines":     len(lines),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Cannot read file: {e}")
    return await asyncio.to_thread(_read)


@app.get("/api/folders")
async def api_folders(path: str = Query(""), _user=Depends(require_auth_api)):
    """
    Browse the local data directory tree.
    path="" → list the named roots (ACK, NACK, processed, error).
    path="ACK" or "ACK/2026-04-22/bankA/…" → list that subtree.
    Returns: {path, entries: [{name, type, size, mtime}]}
    
    """
    def _scan(rel: str):
        parts = [p for p in rel.strip("/").split("/") if p]
        if not parts:
            # Root listing — show named roots with their sizes
            items = []
            for name, base in BROWSABLE_ROOTS.items():
                if base.exists():
                    items.append({"name": name, "type": "dir", "size": None, "mtime": None})
            return {"path": "", "entries": items}

        root_name = parts[0]
        if root_name not in BROWSABLE_ROOTS:
            raise HTTPException(status_code=400, detail="Unknown root")
        base = BROWSABLE_ROOTS[root_name].resolve()
        sub  = Path(*parts[1:]) if len(parts) > 1 else Path(".")
        target = (base / sub).resolve()

        # Path traversal guard
        try:
            target.relative_to(base)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid path")

        if not target.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        if not target.is_dir():
            raise HTTPException(status_code=400, detail="Not a directory")

        entries = []
        for entry in sorted(target.iterdir(), key=lambda e: (e.is_file(), e.name)):
            stat  = entry.stat()
            entries.append({
                "name":  entry.name,
                "type":  "file" if entry.is_file() else "dir",
                "size":  stat.st_size if entry.is_file() else None,
                "mtime": int(stat.st_mtime),
            })
        return {"path": rel.strip("/"), "entries": entries}

    return await asyncio.to_thread(_scan, path)


# =====================================================================
#  CLI
# =====================================================================
def _ensure_local_dirs():
    """Create per-bank mirror directories on startup."""
    is_local = CFG["MODE"] == "local"
    is_ns_server = CFG.get("NS_SFTP_SERVER_MODE", False)
    if not is_local and not is_ns_server:
        return
    banks = BANKS if BANKS else _load_banks_config()
    for bank in banks:
        bid      = bank["id"]
        accounts = bank.get("accounts") or [{"id": ""}]
        for acc in accounts:
            aid = acc.get("id", "")
            ns_dirs = [
                _ns_local_dir(bid, aid, "outbound"),
                _ns_local_dir(bid, aid, "inbound"),
                _ns_local_dir(bid, aid, "ACK"),
                _ns_local_dir(bid, aid, "NACK"),
            ]
            bank_dirs = [
                _bank_local_dir(bid, aid, "outbound"),
                _bank_local_dir(bid, aid, "inbound"),
            ] if is_local else []
            for d in ns_dirs + bank_dirs:
                d.mkdir(parents=True, exist_ok=True)
    log.info("Mirror dirs ready under data/netsuite/%s", " and data/banks/" if is_local else "")


def generate_test_files():
    banks = BANKS if BANKS else _load_banks_config()
    for bank in banks:
        bid    = bank["id"]
        ns_out = _ns_local_dir(bid, "", "outbound")
        bk_out = _bank_local_dir(bid, "", "outbound")
        ns_out.mkdir(parents=True, exist_ok=True)
        bk_out.mkdir(parents=True, exist_ok=True)
        (ns_out / "ACH_001.txt").write_text("NACHA ACH BATCH payment data")
        (ns_out / "WIRE_887.csv").write_text("beneficiary,amount\nAcme,12500")
        (ns_out / "ACH_001_copy.txt").write_text("NACHA ACH BATCH payment data")
        (bk_out / "STMT_0414.bai").write_text("BAI2 STATEMENT data")
        (bk_out / "LOCKBOX_0414.txt").write_text("LOCKBOX data")
    log.info("Test files created for %d bank(s)", len(banks))


if __name__ == "__main__":
    if not BANKS:
        BANKS.extend(_load_banks_config())

    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    for d in [STAGING_DIR, UPLOAD_STAGING_DIR, ARCHIVE_DIR, ERROR_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    GPG_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    GPG_HOME.chmod(0o700)
    _ensure_local_dirs()

    if args.test:
        generate_test_files()

    uvicorn.run("bridge:app", host=CFG["BIND_HOST"], port=args.port, reload=False)

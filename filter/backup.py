"""Encrypted nightly backup "out of the house" (2.6, B3).

Every night (from 02:30 Copenhagen time, see `due`) the filter makes ONE
consistent, encrypted snapshot of everything a restore needs and writes it
to the optional mount /backup (Unraid: /mnt/user/backup/spamfilter on the
array, i.e. another disk than the nvme app dir):

  state/    every regular file of /appdata/state (users, 2FA, passkeys,
            settings, contacts.key, vapid_private.pem, smtp.password,
            imap-secrets/, removed-secrets/, admin-audit.jsonl ...); SQLite
            databases through the online backup API (consistent while the
            filter writes), never a file copy. Left out: transient files
            (heartbeat, -wal/-shm, temp files) and the backup key itself.
  config/   accounts.yml, site.yml (the local site configuration) and
            whatever else lives in /appdata/config
  appdata/  the readable rest of the app dir's own config (rspamd/local.d,
            unbound*.conf, redis.conf when readable); unreadable files are
            listed as skipped in the manifest (they are regenerated from
            state/redis.password + state/controller.password).
  redis/    dump.rdb: a fresh RDB of Bayes and bundled local fuzzy data (`redis-cli --rdb`, the
            replication snapshot: consistent, made by Redis itself).

Archive format (`spamfilter-<UTC stamp>.sfbak`, mode 0600):

  b"SFBACKUP" | u8 format (1) | u32 header length | header JSON
  | wrapped data key (48 bytes)
  | chunk*:  u32 length | AES-256-GCM ciphertext (+16 byte tag)

* The header (format, created, KDF salt, key id, chunk size) is plain JSON
  and authenticated: it is the AAD of the key wrap, so any change to it
  fails the unwrap.
* A random 32-byte data key encrypts the stream; it is wrapped with
  AES-256-GCM under KEK = HKDF-SHA256(backup key, salt). The backup key is
  32 random bytes in state/backup.key (0600, never in an archive, shown
  once by `sfctl backup-key show` for the owner's password manager).
* The stream is chunked (1 MiB): chunk n uses nonce = n (11 bytes) | last
  flag (1 byte) and AAD = sha256(prefix), so reordering, truncation,
  appending and bit flips are all detected. Memory use is one chunk.
* The plaintext stream starts with the manifest (u32 length + JSON: format,
  created, version, file list with size + sha256 + mode, skipped files,
  warnings), followed by the file contents in manifest order. Verify and
  restore check every sha256.

Retention: 14 daily + 8 weekly archives (newest per local day / ISO week);
pruning only after a successful run and only files matching the archive
name. No /backup mount -> nothing is written anywhere (never /appdata), the
status says so and the health pages warn; 48 h without a successful backup
-> the alert mail/push (engine alert_once 'backup').

The engine runs every backup in a child process (run_backup_isolated: a
close() on the live database would drop the engine's own SQLite locks).

Secrets never reach a log, the status file or the audit log: only file
names, counts, sizes and step names.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Iterable, Iterator

log = logging.getLogger("backup")

# ---------------------------------------------------------------- constants
MAGIC = b"SFBACKUP"
FORMAT = 1
CHUNK = 1 << 20
MAX_HEADER = 64 * 1024
MAX_MANIFEST = 8 * 1024 * 1024
WRAPPED_LEN = 32 + 16
KEY_LEN = 32
KEY_PREFIX = "SFBK1"
SUFFIX = ".sfbak"
ARCHIVE_RE = re.compile(r"^spamfilter-(\d{8}T\d{6}Z)\.sfbak$")
KEEP_DAILY = 14
KEEP_WEEKLY = 8
ALERT_AFTER_S = 48 * 3600
RUN_AT = (2, 30)                 # local time the nightly run may start
RETRY_S = 3600                   # after a failed run
MAX_ATTEMPTS_PER_DAY = 4
POLL_S = 60
FREE_MARGIN = 256 * 1024 * 1024  # bytes left free on /appdata while staging
REDIS_TIMEOUT_S = 900

KEY_FILE = "backup.key"
KEY_SHOWN_FILE = "backup-key-shown"
STATUS_FILE = "encrypted-backup-status.json"
LOCK_FILE = ".backup.lock"
WORK_PREFIX = ".backup-work-"
# Host-written (root, 0644) by deploy/backup-offsite.sh: the rclone upload.
OFFSITE_STATUS_FILE = "offsite-status.json"
DRILL_STATUS_FILE = "restore-drill.json"      # 2.12 (#11): the host's monthly restore drill
OFFSITE_STALE_S = 48 * 3600                  # 2.12 (#11): the copy out of the house is overdue

HKDF_INFO_WRAP = b"spamfilter-backup v1 key-wrap"
HKDF_INFO_ID = b"spamfilter-backup v1 key-id"

# Never archived: transient files, the key itself, status files.
STATE_SKIP_NAMES = frozenset({
    "heartbeat", "reload_requested", "boot_id", KEY_FILE, KEY_SHOWN_FILE, LOCK_FILE, STATUS_FILE,
    OFFSITE_STATUS_FILE, "backup-status.json", "host-status.json", "health.json",
})
STATE_SKIP_SUFFIXES = ("-wal", "-shm", "-journal", ".tmp", ".part", ".lock", ".new")
# Paths below state/ never archived: the GitHub token handed to the host's
# update helper (2.11.2, plain text for at most a minute - updates.py).
STATE_SKIP_PATHS = frozenset({"update/request.token"})
SQLITE_MAGIC = b"SQLite format 3\x00"
# App-dir files (relative to /appdata) that belong to a full restore.
APPDATA_EXTRA = ("redis-config/redis.conf", "unbound.conf", "unbound-forward-records.conf")
APPDATA_EXTRA_DIRS = ("rspamd/local.d",)
NAME_RE = re.compile(r"^(state|config|appdata|redis)/[A-Za-z0-9._@+=,~ -]+(/[A-Za-z0-9._@+=,~ -]+)*$")

# ---------------------------------------------------------------- paths
STATE_DIR = Path(os.environ.get("STATE_DIR", "/state"))
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/accounts.yml"))
SITE_CONFIG_NAME = "site.yml"   # config/site.yml (siteconfig.py) - backed up with the rest of config/
APPDATA = Path(os.environ.get("SF_APPDATA", "/appdata"))
BACKUP_DIR = Path(os.environ.get("SF_BACKUP_DIR") or "/backup")
# Only a real mount counts (an empty /backup inside the image would write
# the archives into the container layer). Tests turn this off.
REQUIRE_MOUNT = os.environ.get("SF_BACKUP_REQUIRE_MOUNT", "1") != "0"
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
VERSION = "?"


def configure(state_dir: str | Path | None = None, config_path: str | Path | None = None, *,
              appdata: str | Path | None = None, backup_dir: str | Path | None = None,
              version: str | None = None) -> None:
    """Point the module at the engine's paths (tests, sfctl)."""
    global STATE_DIR, CONFIG_PATH, APPDATA, BACKUP_DIR, VERSION
    if state_dir is not None:
        STATE_DIR = Path(state_dir)
    if config_path is not None:
        CONFIG_PATH = Path(config_path)
    if appdata is not None:
        APPDATA = Path(appdata)
    if backup_dir is not None:
        BACKUP_DIR = Path(backup_dir)
    if version is not None:
        VERSION = str(version)


class BackupError(Exception):
    """A failed backup / verify / restore. Danish text, safe to show (never
    a secret, never file content)."""


# ---------------------------------------------------------------- time helpers
try:
    from zoneinfo import ZoneInfo

    _TZ: Any = ZoneInfo("Europe/Copenhagen")
except Exception:  # noqa: BLE001 - tzdata missing: local time of the process
    _TZ = None


def _local(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, _TZ) if _TZ is not None else datetime.fromtimestamp(ts)


def _stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def stamp_ts(name: str) -> int | None:
    m = ARCHIVE_RE.match(name)
    if not m:
        return None
    try:
        return int(datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


# ---------------------------------------------------------------- key
def key_path() -> Path:
    return STATE_DIR / KEY_FILE


def format_key(key: bytes) -> str:
    """SFBK1-XXXX-XXXX-... (base32, groups of 4): easy to copy into a
    password manager and to type back in."""
    b32 = base64.b32encode(key).decode("ascii").rstrip("=")
    return KEY_PREFIX + "-" + "-".join(b32[i:i + 4] for i in range(0, len(b32), 4))


def parse_key(text: str) -> bytes:
    t = re.sub(r"[\s-]", "", str(text or "")).upper()
    if t.startswith(KEY_PREFIX):
        t = t[len(KEY_PREFIX):]
    if not t or not re.fullmatch(r"[A-Z2-7]+", t):
        raise BackupError("Nøglen har et forkert format (den starter med SFBK1-).")
    try:
        raw = base64.b32decode(t + "=" * (-len(t) % 8))
    except (ValueError, TypeError):
        raise BackupError("Nøglen har et forkert format (den starter med SFBK1-).") from None
    if len(raw) != KEY_LEN:
        raise BackupError("Nøglen har en forkert længde.")
    return raw


def key_id(key: bytes) -> str:
    return hmac.new(key, HKDF_INFO_ID, hashlib.sha256).hexdigest()[:16]


def load_key(*, create: bool = False) -> bytes | None:
    """The backup key from state/backup.key (None when missing and not
    created). A new key is written with O_EXCL, mode 0600."""
    p = key_path()
    try:
        if p.is_symlink():
            raise BackupError("state/backup.key er et symbolsk link – den bruges ikke.")
        return parse_key(p.read_text(encoding="ascii", errors="replace"))
    except FileNotFoundError:
        if not create:
            return None
    key = os.urandom(KEY_LEN)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return load_key(create=False)  # another process made it first
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(format_key(key) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    log.info("new backup key created (id %s)", key_id(key))
    return key


def key_status() -> dict[str, Any]:
    """{exists, key_id, created_at, shown_at} - never the key."""
    out: dict[str, Any] = {"exists": False, "key_id": None, "created_at": None, "shown_at": None}
    try:
        key = load_key(create=False)
    except BackupError:
        key = None
    if key is None:
        return out
    out.update(exists=True, key_id=key_id(key))
    with contextlib.suppress(OSError):
        out["created_at"] = int(key_path().stat().st_mtime)
    with contextlib.suppress(OSError, ValueError):
        out["shown_at"] = int((STATE_DIR / KEY_SHOWN_FILE).read_text().split()[0])
    return out


def mark_key_shown(now: float | None = None) -> None:
    p = STATE_DIR / KEY_SHOWN_FILE
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(f"{int(now if now is not None else time.time())}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


# ---------------------------------------------------------------- crypto
def _aes():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    return AESGCM


def _kek(key: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: PLC0415

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO_WRAP).derive(key)


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


class _ChunkWriter:
    """Buffers plaintext, writes full chunks; the final chunk (possibly
    empty) carries the last flag, so truncation is detected."""

    def __init__(self, out: BinaryIO, aead: Any, aad: bytes) -> None:
        self.out, self.aead, self.aad = out, aead, aad
        self.buf = bytearray()
        self.counter = 0
        self.written = 0

    def _emit(self, data: bytes, last: bool) -> None:
        ct = self.aead.encrypt(_nonce(self.counter, last), bytes(data), self.aad)
        self.out.write(struct.pack(">I", len(ct)))
        self.out.write(ct)
        self.written += 4 + len(ct)
        self.counter += 1

    def write(self, data: bytes) -> None:
        self.buf += data
        while len(self.buf) > CHUNK:  # strictly more: the rest may be the last chunk
            self._emit(self.buf[:CHUNK], False)
            del self.buf[:CHUNK]

    def close(self) -> None:
        self._emit(self.buf, True)
        self.buf = bytearray()


def _prefix(header: dict[str, Any]) -> bytes:
    hb = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return MAGIC + bytes([FORMAT]) + struct.pack(">I", len(hb)) + hb


@dataclass
class Entry:
    name: str          # path inside the archive (state/..., config/..., appdata/..., redis/...)
    path: Path         # staged plaintext file
    size: int = 0
    sha256: str = ""
    mode: int = 0o600


def encrypt_archive(out_path: Path, key: bytes, entries: list[Entry], manifest: dict[str, Any], *,
                    created: int) -> int:
    """Write the encrypted archive (entries must be hashed). Returns the
    size in bytes. Writes `<out>.part`, fsyncs and renames."""
    aesgcm = _aes()
    data_key = os.urandom(32)
    salt, wrap_nonce = os.urandom(16), os.urandom(12)
    header = {"format": FORMAT, "created": int(created), "cipher": "AES-256-GCM", "kdf": "HKDF-SHA256",
              "salt": base64.b64encode(salt).decode(), "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
              "key_id": key_id(key), "chunk": CHUNK}
    prefix = _prefix(header)
    wrapped = aesgcm(_kek(key, salt)).encrypt(wrap_nonce, data_key, prefix)
    aad = hashlib.sha256(prefix + wrapped).digest()
    mbytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    if len(mbytes) > MAX_MANIFEST:
        raise BackupError("For mange filer til én backup.")
    part = out_path.with_name(out_path.name + ".part")
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(prefix + wrapped)
            w = _ChunkWriter(out, aesgcm(data_key), aad)
            w.write(struct.pack(">I", len(mbytes)) + mbytes)
            for e in entries:
                with open(e.path, "rb") as fh:
                    while True:
                        block = fh.read(CHUNK)
                        if not block:
                            break
                        w.write(block)
            w.close()
            out.flush()
            os.fsync(out.fileno())
        os.chmod(part, 0o600)
        os.replace(part, out_path)
    except BaseException:
        with contextlib.suppress(OSError):
            part.unlink()
        raise
    with contextlib.suppress(OSError):
        dfd = os.open(out_path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    return out_path.stat().st_size


def read_header(fh: BinaryIO) -> tuple[dict[str, Any], bytes, bytes]:
    """(header, prefix bytes, wrapped key) - the header is NOT yet
    authenticated (that happens with the unwrap)."""
    head = fh.read(len(MAGIC) + 5)
    if len(head) < len(MAGIC) + 5 or head[:len(MAGIC)] != MAGIC:
        raise BackupError("Filen er ikke en spamfilter-backup (.sfbak).")
    if head[len(MAGIC)] != FORMAT:
        raise BackupError(f"Ukendt backupformat {head[len(MAGIC)]} – brug en nyere version af sfctl.")
    (hlen,) = struct.unpack(">I", head[len(MAGIC) + 1:])
    if not 0 < hlen <= MAX_HEADER:
        raise BackupError("Backupfilens header er beskadiget.")
    hb = fh.read(hlen)
    wrapped = fh.read(WRAPPED_LEN)
    if len(hb) != hlen or len(wrapped) != WRAPPED_LEN:
        raise BackupError("Backupfilen er afkortet.")
    try:
        header = json.loads(hb)
    except ValueError:
        raise BackupError("Backupfilens header er beskadiget.") from None
    if not isinstance(header, dict):
        raise BackupError("Backupfilens header er beskadiget.")
    return header, head + hb, wrapped


class _Plain:
    """Decrypting reader over the chunk stream (one chunk in memory)."""

    def __init__(self, fh: BinaryIO, aead: Any, aad: bytes, chunk: int) -> None:
        self.fh, self.aead, self.aad = fh, aead, aad
        self.max_ct = chunk + 16
        self.counter = 0
        self.buf = b""
        self.pos = 0
        self.done = False

    def _next(self) -> bool:
        if self.done:
            return False
        from cryptography.exceptions import InvalidTag  # noqa: PLC0415

        ln = self.fh.read(4)
        if len(ln) < 4:
            raise BackupError("Backupfilen er afkortet (sidste blok mangler).")
        (n,) = struct.unpack(">I", ln)
        if not 16 <= n <= self.max_ct:
            raise BackupError("Backupfilen er beskadiget (forkert bloklængde).")
        ct = self.fh.read(n)
        if len(ct) != n:
            raise BackupError("Backupfilen er afkortet.")
        last = self._at_eof()
        try:
            self.buf = self.aead.decrypt(_nonce(self.counter, last), ct, self.aad)
        except InvalidTag:
            raise BackupError(f"Backupfilen er ændret eller beskadiget (blok {self.counter + 1}).") from None
        self.pos = 0
        self.counter += 1
        self.done = last
        return True

    def _at_eof(self) -> bool:
        if hasattr(self.fh, "peek"):
            return not self.fh.peek(1)[:1]
        here = self.fh.tell()
        more = self.fh.read(1)
        self.fh.seek(here)
        return not more

    def read_exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if self.pos >= len(self.buf) and not self._next():
                raise BackupError("Backupfilen er afkortet (indholdet mangler).")
            take = min(n - len(out), len(self.buf) - self.pos)
            out += self.buf[self.pos:self.pos + take]
            self.pos += take
        return bytes(out)

    def iter_exact(self, n: int) -> Iterator[bytes]:
        left = n
        while left > 0:
            if self.pos >= len(self.buf) and not self._next():
                raise BackupError("Backupfilen er afkortet (indholdet mangler).")
            take = min(left, len(self.buf) - self.pos)
            yield self.buf[self.pos:self.pos + take]
            self.pos += take
            left -= take

    def finish(self) -> None:
        """The stream must end exactly here (no trailing data)."""
        while self.pos >= len(self.buf):
            if not self._next():
                return
        raise BackupError("Backupfilen har ukendt ekstra indhold.")


def _safe_name(name: Any) -> str:
    n = str(name or "")
    if not NAME_RE.match(n) or any(p in ("..", ".") for p in PurePosixPath(n).parts):
        raise BackupError("Backupfilen indeholder et ugyldigt filnavn.")
    return n


class Archive:
    """Open an archive for reading: authenticates the header with the key,
    then streams the manifest and the files."""

    def __init__(self, path: Path, key: bytes) -> None:
        self.path = Path(path)
        self.fh = open(self.path, "rb")  # noqa: SIM115 - closed in close()
        try:
            self.header, prefix, wrapped = read_header(self.fh)
            want = self.header.get("key_id")
            if want and want != key_id(key):
                raise BackupError(f"Forkert nøgle: backuppen er lavet med nøgle-id {str(want)[:16]}, "
                                  f"denne nøgle har id {key_id(key)}.")
            from cryptography.exceptions import InvalidTag  # noqa: PLC0415

            try:
                salt = base64.b64decode(str(self.header["salt"]))
                wrap_nonce = base64.b64decode(str(self.header["wrap_nonce"]))
                chunk = int(self.header.get("chunk") or CHUNK)
            except (KeyError, ValueError, TypeError):
                raise BackupError("Backupfilens header er beskadiget.") from None
            if not (len(salt) == 16 and len(wrap_nonce) == 12 and 1024 <= chunk <= 16 * CHUNK):
                raise BackupError("Backupfilens header er beskadiget.")
            try:
                data_key = _aes()(_kek(key, salt)).decrypt(wrap_nonce, wrapped, prefix)
            except InvalidTag:
                raise BackupError("Forkert nøgle, eller backupfilens header er ændret.") from None
            aad = hashlib.sha256(prefix + wrapped).digest()
            self.plain = _Plain(self.fh, _aes()(data_key), aad, chunk)
            (mlen,) = struct.unpack(">I", self.plain.read_exact(4))
            if not 0 < mlen <= MAX_MANIFEST:
                raise BackupError("Backupfilens indholdsliste er beskadiget.")
            try:
                self.manifest = json.loads(self.plain.read_exact(mlen))
            except ValueError:
                raise BackupError("Backupfilens indholdsliste er beskadiget.") from None
            if not isinstance(self.manifest, dict) or not isinstance(self.manifest.get("files"), list):
                raise BackupError("Backupfilens indholdsliste er beskadiget.")
            if int(self.manifest.get("created") or -1) != int(self.header.get("created") or -2):
                raise BackupError("Backupfilens header og indholdsliste passer ikke sammen.")
        except BaseException:
            self.fh.close()
            raise

    def files(self) -> Iterator[tuple[dict[str, Any], Iterator[bytes]]]:
        for f in self.manifest["files"]:
            if not isinstance(f, dict):
                raise BackupError("Backupfilens indholdsliste er beskadiget.")
            _safe_name(f.get("name"))
            size = int(f.get("size") or 0)
            if size < 0:
                raise BackupError("Backupfilens indholdsliste er beskadiget.")
            yield f, self.plain.iter_exact(size)
        self.plain.finish()

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> "Archive":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _mkdirs(path: Path) -> None:
    """mkdir -p with 0700 on EVERY level it creates (os.makedirs only sets
    the mode of the last one)."""
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700)


def _key_or_state(key: bytes | None) -> bytes:
    if key is not None:
        return key
    k = load_key(create=False)
    if k is None:
        raise BackupError("Der er ingen backupnøgle i state/backup.key – brug --ask-key med nøglen fra "
                          "din kode-manager.")
    return k


def peek(path: Path) -> dict[str, Any]:
    """Header only (no key needed): created, key id, format."""
    with open(path, "rb") as fh:
        header, _p, _w = read_header(fh)
    return header


def verify(path: Path, key: bytes | None = None) -> dict[str, Any]:
    """Decrypt everything to nowhere and check every sha256."""
    peek(path)  # "not an archive" before "no key"
    k = _key_or_state(key)
    n = total = 0
    names: set[str] = set()
    with Archive(path, k) as ar:
        for f, chunks in ar.files():
            names.add(str(f.get("name") or ""))
            h = hashlib.sha256()
            for c in chunks:
                h.update(c)
                total += len(c)
            if not hmac.compare_digest(h.hexdigest(), str(f.get("sha256") or "")):
                raise BackupError(f"Kontrolsummen passer ikke for {f.get('name')}.")
            n += 1
        manifest = ar.manifest
    return {"ok": True, "files": n, "bytes": total, "created": manifest.get("created"),
            "version": manifest.get("version"), "skipped": manifest.get("skipped") or [],
            "warnings": manifest.get("warnings") or [], "redis": bool(manifest.get("redis")),
            # the local site configuration (own domains, webshops ...) is part of config/
            "site_config": f"config/{SITE_CONFIG_NAME}" in names,
            "learning_stores": manifest.get("learning_stores")}


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def restore(path: Path, to_dir: Path, key: bytes | None = None) -> dict[str, Any]:
    """Restore into a NEW (or empty) directory for a manual swap. Never into
    the live state/config/app dir. Files 0600, dirs 0700; any check that
    fails removes what this call wrote."""
    peek(path)
    k = _key_or_state(key)
    given = Path(os.path.abspath(to_dir))
    # realpath on both sides: a symlink (or "..") in --to must not lead the
    # restore into the live installation, and the live dirs may be symlinks.
    dest = Path(os.path.realpath(to_dir))
    live = {Path(f(p)) for p in (STATE_DIR, CONFIG_PATH.parent, APPDATA) for f in (os.path.abspath, os.path.realpath)}
    for d in (given, dest):
        for p in live:
            if d == p or _inside(d, p) or _inside(p, d):
                raise BackupError(f"{given} er (en del af) den kørende installation – vælg en ny mappe, "
                                  "fx /tmp/gendan.")
    created = False
    if given.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise BackupError(f"{given} findes og er ikke en mappe.")
    if dest.exists():
        if any(dest.iterdir()):
            raise BackupError(f"{dest} er ikke tom – gendan altid til en ny, tom mappe.")
    else:
        _mkdirs(dest)
        created = True
    written: list[Path] = []
    try:
        n = total = 0
        with Archive(path, k) as ar:
            for f, chunks in ar.files():
                name = _safe_name(f.get("name"))
                target = dest.joinpath(*PurePosixPath(name).parts)
                if not _inside(Path(os.path.abspath(target)), dest):
                    raise BackupError("Backupfilen indeholder et ugyldigt filnavn.")
                _mkdirs(target.parent)
                h = hashlib.sha256()
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                written.append(target)
                with os.fdopen(fd, "wb") as out:
                    for c in chunks:
                        h.update(c)
                        out.write(c)
                        total += len(c)
                if not hmac.compare_digest(h.hexdigest(), str(f.get("sha256") or "")):
                    raise BackupError(f"Kontrolsummen passer ikke for {name}.")
                n += 1
            manifest = ar.manifest
    except BaseException:
        for p in reversed(written):
            with contextlib.suppress(OSError):
                p.unlink()
        if created:
            shutil.rmtree(dest, ignore_errors=True)
        raise
    return {"ok": True, "files": n, "bytes": total, "to": str(dest), "created": manifest.get("created"),
            "skipped": manifest.get("skipped") or [], "redis": bool(manifest.get("redis"))}


def learning_stores(work: Path, redis_ok: bool) -> dict[str, Any]:
    """Authenticated inventory of the bundled local fuzzy Redis profile.

    A declaration is not live configuration introspection. Custom backends
    cannot be called covered just because a Redis snapshot succeeded.
    """
    worker = work / 'appdata/rspamd/local.d/worker-fuzzy.inc'
    backend = 'unknown'
    if worker.is_file():
        text = re.sub(r'#[^\n]*', '', worker.read_text())
        values = re.findall(r'\bbackend\s*=\s*["\']?([A-Za-z_]+)', text)
        if values == ['redis'] and not re.search(r'\b(?:servers|read_servers|write_servers)\s*=', text):
            backend = 'redis'
        else:
            backend = 'custom_or_unknown'
    return {'bayes': 'redis/dump.rdb' if redis_ok else None,
            'local_fuzzy': {'backend': backend,
                            'snapshot': 'redis/dump.rdb' if backend == 'redis' and redis_ok else None,
                            'basis': 'saved_local_config_only'}}


# ---------------------------------------------------------------- snapshot
def _is_sqlite(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def _skip_state(rel: PurePosixPath) -> bool:
    name = rel.name
    if any(part.startswith(".") for part in rel.parts):
        return True  # temp files, our own work dirs
    if len(rel.parts) == 1 and name in STATE_SKIP_NAMES:
        return True
    if rel.as_posix() in STATE_SKIP_PATHS:
        return True
    return name.endswith(STATE_SKIP_SUFFIXES)


def _walk(root: Path) -> Iterator[Path]:
    """Regular files below root, never following a symlink."""
    try:
        items = sorted(root.iterdir())
    except OSError:
        return
    for p in items:
        if p.is_symlink():
            continue
        if p.is_dir():
            yield from _walk(p)
        elif p.is_file():
            yield p


def sqlite_snapshot(src: Path, dst: Path) -> None:
    """Online backup API: a consistent copy while the filter writes."""
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    try:
        s.execute("PRAGMA busy_timeout=30000")
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        d = sqlite3.connect(dst)
        try:
            s.backup(d)
            d.execute("PRAGMA journal_mode=DELETE")
            res = d.execute("PRAGMA quick_check").fetchone()
            if not res or res[0] != "ok":
                raise BackupError(f"Databasekopien af {src.name} består ikke kontrollen.")
        finally:
            d.close()
    finally:
        s.close()


def redis_dump_cli(dest: Path) -> tuple[bool, str]:
    """A fresh RDB of Redis via `redis-cli --rdb` (the replication snapshot,
    made by Redis itself). The password goes through REDISCLI_AUTH, never
    the command line or a log. (ok, short reason)."""
    cli = shutil.which("redis-cli")
    if not cli:
        return False, "redis-cli findes ikke i containeren"
    try:
        pw = (STATE_DIR / "redis.password").read_text().strip()
    except OSError:
        return False, "state/redis.password kan ikke læses"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp", "REDISCLI_AUTH": pw}
    try:
        proc = subprocess.run([cli, "-h", REDIS_HOST, "-p", str(REDIS_PORT), "--no-auth-warning", "--rdb", str(dest)],
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, timeout=REDIS_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        return False, "Redis svarede ikke i tide"
    except OSError as ex:
        return False, f"redis-cli kunne ikke starte ({type(ex).__name__})"
    if proc.returncode != 0:
        return False, f"redis-cli --rdb fejlede (exit {proc.returncode})"
    try:
        with open(dest, "rb") as fh:
            if fh.read(5) != b"REDIS":
                return False, "Redis-snapshottet er ikke en RDB-fil"
    except OSError:
        return False, "Redis-snapshottet mangler"
    return True, ""


# Replaced in tests.
redis_dump: Callable[[Path], tuple[bool, str]] = redis_dump_cli


def _copy_into(src: Path, dst: Path) -> None:
    _mkdirs(dst.parent)
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out, open(src, "rb") as fh:
        shutil.copyfileobj(fh, out, CHUNK)


def _hash(e: Entry) -> None:
    h = hashlib.sha256()
    n = 0
    with open(e.path, "rb") as fh:
        while block := fh.read(CHUNK):
            h.update(block)
            n += len(block)
    e.size, e.sha256 = n, h.hexdigest()


def stage(work: Path) -> tuple[list[Entry], list[dict[str, str]], list[str], bool]:
    """Copy everything into the private work dir. Returns (entries,
    skipped [{name, why}], warnings, redis_ok)."""
    entries: list[Entry] = []
    skipped: list[dict[str, str]] = []
    warnings: list[str] = []

    def add(name: str, src: Path, *, sqlite: bool = False) -> None:
        try:
            _safe_name(name)
        except BackupError:
            skipped.append({"name": name[:200], "why": "ugyldigt filnavn"})
            return
        dst = work.joinpath(*PurePosixPath(name).parts)
        try:
            mode = src.stat().st_mode & 0o777
            if sqlite:
                _mkdirs(dst.parent)
                sqlite_snapshot(src, dst)
            else:
                _copy_into(src, dst)
        except PermissionError:
            skipped.append({"name": name, "why": "ingen adgang"})
            with contextlib.suppress(OSError):
                dst.unlink()
            return
        except FileNotFoundError:
            return  # vanished meanwhile (temp file)
        entries.append(Entry(name=name, path=dst, mode=mode))

    state = STATE_DIR
    for p in _walk(state):
        rel = PurePosixPath(p.relative_to(state).as_posix())
        if _skip_state(rel):
            continue
        add(f"state/{rel}", p, sqlite=_is_sqlite(p))
    cfg = CONFIG_PATH.parent
    if not (cfg / CONFIG_PATH.name).is_file():
        raise BackupError(f"{CONFIG_PATH} findes ikke – intet at tage backup af.")
    for p in _walk(cfg):
        rel = PurePosixPath(p.relative_to(cfg).as_posix())
        if any(part.startswith(".") for part in rel.parts) or rel.name.endswith(STATE_SKIP_SUFFIXES):
            continue
        add(f"config/{rel}", p)
    for rel_s in APPDATA_EXTRA:
        p = APPDATA / rel_s
        if p.is_file() and not p.is_symlink():
            if os.access(p, os.R_OK):
                add(f"appdata/{rel_s}", p)
            else:
                skipped.append({"name": f"appdata/{rel_s}", "why": "ingen adgang"})
    for rel_d in APPDATA_EXTRA_DIRS:
        root = APPDATA / rel_d
        for p in _walk(root):
            rel = f"{rel_d}/{p.relative_to(root).as_posix()}"
            if os.access(p, os.R_OK):
                add(f"appdata/{rel}", p)
            else:
                skipped.append({"name": f"appdata/{rel}", "why": "ingen adgang"})
    rdb = work / "redis" / "dump.rdb"
    rdb.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        ok, why = redis_dump(rdb)
    except Exception as ex:  # noqa: BLE001 - a broken dump never loses the rest
        ok, why = False, f"Redis-snapshot fejlede ({type(ex).__name__})"
    if ok and rdb.is_file():
        os.chmod(rdb, 0o600)
        entries.append(Entry(name="redis/dump.rdb", path=rdb, mode=0o600))
    else:
        with contextlib.suppress(OSError):
            rdb.unlink()
        warnings.append(f"Bayes-data (Redis) er ikke med: {why}")
    for e in entries:
        _hash(e)
    return entries, skipped, warnings, bool(ok)


# ---------------------------------------------------------------- destination
def backup_mounted(path: Path | None = None) -> bool:
    """/backup is a real mount (the Unraid share), not a directory in the
    container layer."""
    p = Path(path or BACKUP_DIR)
    if not REQUIRE_MOUNT:
        return p.is_dir()
    target = os.path.abspath(p)
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) > 4 and parts[4].replace("\\040", " ") == target:
                    return True
        return False
    except OSError:
        return os.path.ismount(target)


def list_archives(directory: Path | None = None) -> list[dict[str, Any]]:
    """Archives in the destination, newest first: {name, path, ts, size}."""
    d = Path(directory or BACKUP_DIR)
    out = []
    try:
        items = list(d.iterdir())
    except OSError:
        return []
    for p in items:
        ts = stamp_ts(p.name)
        if ts is None or p.is_symlink() or not p.is_file():
            continue
        with contextlib.suppress(OSError):
            out.append({"name": p.name, "path": p, "ts": ts, "size": p.stat().st_size})
    out.sort(key=lambda a: a["ts"], reverse=True)
    return out


def retention_keep(archives: list[dict[str, Any]], *, daily: int = KEEP_DAILY,
                   weekly: int = KEEP_WEEKLY) -> set[str]:
    """Names to keep: the newest archive of each of the newest `daily`
    local days, plus the newest of each of the newest `weekly` ISO weeks."""
    keep: set[str] = set()
    days: set[Any] = set()
    weeks: set[Any] = set()
    for a in sorted(archives, key=lambda a: a["ts"], reverse=True):
        loc = _local(a["ts"])
        day = loc.date()
        week = loc.isocalendar()[:2]
        if day not in days and len(days) < daily:
            days.add(day)
            keep.add(a["name"])
        if week not in weeks and len(weeks) < weekly:
            weeks.add(week)
            keep.add(a["name"])
    return keep


def prune(directory: Path | None = None, *, protect: Iterable[str] = (), now: float | None = None) -> list[str]:
    """Delete archives outside the retention (only our own file names) and
    stale .part files. Returns the deleted names."""
    d = Path(directory or BACKUP_DIR)
    archives = list_archives(d)
    keep = retention_keep(archives) | set(protect)
    gone = []
    for a in archives:
        if a["name"] not in keep:
            with contextlib.suppress(OSError):
                a["path"].unlink()
                gone.append(a["name"])
    t = time.time() if now is None else now
    with contextlib.suppress(OSError):
        for p in d.iterdir():
            if p.name.endswith(SUFFIX + ".part") and ARCHIVE_RE.match(p.name[:-5]) and not p.is_symlink():
                with contextlib.suppress(OSError):
                    if t - p.stat().st_mtime > 3600:
                        p.unlink()
    return gone


# ---------------------------------------------------------------- status
def status_path() -> Path:
    return STATE_DIR / STATUS_FILE


def read_status() -> dict[str, Any]:
    try:
        data = json.loads(status_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_status(data: dict[str, Any]) -> None:
    p = status_path()
    tmp = p.with_name(f".{p.name}.{os.getpid()}.{threading.get_ident()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, p)


def _read_host_json(name: str) -> dict[str, Any]:
    try:
        data = json.loads((STATE_DIR / name).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def read_offsite() -> dict[str, Any]:
    """offsite-status.json written by deploy/backup-offsite.sh on the host."""
    return _read_host_json(OFFSITE_STATUS_FILE)


def read_drill() -> dict[str, Any]:
    """restore-drill.json (2.12, #11) written by deploy/backup-offsite.sh."""
    return _read_host_json(DRILL_STATUS_FILE)


def summary(now: float | None = None) -> dict[str, Any]:
    """Everything the UI / sfctl doctor / the alert need, never a secret:
    {state: ok|failed|no_mount|never|running, tone, text, last_ok_ts,
    age_s, alert, archives, offsite{...}, key{...}}."""
    t = time.time() if now is None else now
    st = read_status()
    last_ok = st.get("last_ok_ts")
    age = int(t - float(last_ok)) if isinstance(last_ok, (int, float)) else None
    since = st.get("since") if isinstance(st.get("since"), (int, float)) else None
    alert = (age is not None and age > ALERT_AFTER_S) or (age is None and since is not None
                                                           and t - float(since) > ALERT_AFTER_S)
    mounted = backup_mounted()
    if not st:
        state = "never"
    elif st.get("skipped") == "no_mount":
        state = "no_mount"
    elif st.get("ok"):
        state = "ok"
    else:
        state = "failed"
    if not mounted and state == "never":
        state = "no_mount"
    texts = {
        "ok": "Seneste krypterede backup lykkedes",
        "failed": "Seneste krypterede backup fejlede",
        "no_mount": "Ingen backup-placering: /backup er ikke monteret",
        "never": "Der er ikke lavet en krypteret backup endnu",
    }
    tone = "ok" if state == "ok" and not alert else "bad" if alert or state == "failed" else "warn"
    if state == "ok" and st.get("warnings"):
        tone = "warn" if tone == "ok" else tone
    out = {
        "state": state, "tone": tone, "text": texts[state], "ts": st.get("ts"), "archive": st.get("archive"),
        "size": st.get("size"), "error": st.get("error"), "warnings": st.get("warnings") or [],
        "files": st.get("files"), "learning_stores": st.get("learning_stores"), "last_ok_ts": last_ok, "last_ok_archive": st.get("last_ok_archive"),
        "age_s": age, "alert": bool(alert), "mounted": mounted, "dest": str(BACKUP_DIR),
        "pruned": st.get("pruned") or [], "key": key_status(),
    }
    out["archives"] = len(list_archives()) if mounted else 0
    off = read_offsite()
    if off:
        ots = off.get("ts")
        out["offsite"] = {"ok": bool(off.get("ok")), "ts": ots, "remote": off.get("remote"),
                          "error": off.get("error"), "files": off.get("files"),
                          "age_s": int(t - float(ots)) if isinstance(ots, (int, float)) else None,
                          "skipped": off.get("skipped")}
        oa = out["offsite"]["age_s"]
        out["offsite"]["stale"] = bool(not off.get("skipped") and oa is not None and oa > OFFSITE_STALE_S)
    else:
        out["offsite"] = None
    dr = read_drill()
    if dr:
        dts = dr.get("ts")
        every = dr.get("every_days") if isinstance(dr.get("every_days"), int) and dr.get("every_days") > 0 else 30
        dage = int(t - float(dts)) if isinstance(dts, (int, float)) else None
        out["drill"] = {"ok": bool(dr.get("ok")), "ts": dts, "archive": dr.get("archive"), "error": dr.get("error"),
                        "detail": dr.get("detail"), "age_s": dage, "every_days": every,
                        "overdue": dage is not None and dage > (every + 5) * 86400}
    else:
        out["drill"] = None
    return out


# ---------------------------------------------------------------- run
@contextlib.contextmanager
def _lock() -> Iterator[None]:
    fd = os.open(STATE_DIR / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as ex:
            if ex.errno in (errno.EAGAIN, errno.EACCES):
                raise BackupError("En backup kører allerede.") from None
            raise
        yield
    finally:
        os.close(fd)


def _cleanup_work() -> None:
    with contextlib.suppress(OSError):
        for p in STATE_DIR.iterdir():
            if p.name.startswith(WORK_PREFIX) and p.is_dir() and not p.is_symlink():
                shutil.rmtree(p, ignore_errors=True)


def _staging_estimate() -> int:
    total = 0
    for p in _walk(STATE_DIR):
        with contextlib.suppress(OSError):
            total += p.stat().st_size
    return total


def run_backup(*, reason: str = "nightly", now: float | None = None) -> dict[str, Any]:
    """Make one encrypted backup. Never raises for an expected failure:
    the result (also written to the status file) says what happened."""
    t0 = time.time() if now is None else now
    started = time.monotonic()
    prev = read_status()
    st: dict[str, Any] = {
        "ts": int(t0), "reason": str(reason)[:20], "ok": False, "skipped": None, "archive": None, "size": None,
        "error": None, "warnings": [], "files": None, "duration_s": None, "dest": str(BACKUP_DIR),
        "last_ok_ts": prev.get("last_ok_ts"), "last_ok_archive": prev.get("last_ok_archive"),
        "since": prev.get("since") or int(t0), "pruned": [],
    }
    day = _local(t0).date().isoformat()
    st["attempt_day"] = day
    st["attempts_today"] = (int(prev.get("attempts_today") or 0) + 1) if prev.get("attempt_day") == day else 1

    def finish(**kw: Any) -> dict[str, Any]:
        st.update(kw)
        st["duration_s"] = round(time.monotonic() - started, 1)
        with contextlib.suppress(OSError):
            write_status(st)
        return st

    if not backup_mounted():
        log.warning("encrypted backup skipped: %s is not mounted", BACKUP_DIR)
        return finish(skipped="no_mount", error=f"{BACKUP_DIR} er ikke monteret – tilføj stien i Unraid-skabelonen "
                                                  "(Backup-placering) eller kør deploy/aio/update.sh")
    if not os.access(BACKUP_DIR, os.W_OK | os.X_OK):
        return finish(error=f"{BACKUP_DIR} kan ikke skrives af filteret (uid {os.getuid()})")
    try:
        with _lock():
            _cleanup_work()
            key = load_key(create=True)
            assert key is not None
            need = _staging_estimate() + FREE_MARGIN
            free = shutil.disk_usage(STATE_DIR).free
            if free < need:
                raise BackupError(f"For lidt fri plads til den midlertidige kopi i app-mappen "
                                  f"({free // 2**20} MB fri, {need // 2**20} MB nødvendig)")
            work = STATE_DIR / f"{WORK_PREFIX}{_stamp(t0)}-{os.getpid()}"
            work.mkdir(mode=0o700)
            try:
                entries, skipped, warnings, redis_ok = stage(work)
                stores = learning_stores(work, redis_ok)
                if stores['local_fuzzy']['backend'] == 'custom_or_unknown':
                    warnings.append('Lokal fuzzy-backend afviger fra Redis-profilen; fuzzy-data er ikke dokumenteret medtaget.')
                elif stores['local_fuzzy']['backend'] == 'unknown':
                    warnings.append('Lokal fuzzy-konfiguration kunne ikke verificeres; Redis-kopien er ikke et fuzzy-gendannelsesbevis.')
                staged = sum(e.size for e in entries)
                dfree = shutil.disk_usage(BACKUP_DIR).free
                if dfree < staged + 64 * 2**20:
                    raise BackupError(f"For lidt fri plads på {BACKUP_DIR} ({dfree // 2**20} MB fri)")
                created = int(t0)
                manifest = {
                    "format": FORMAT, "created": created, "version": VERSION, "reason": st["reason"],
                    "files": [{"name": e.name, "size": e.size, "sha256": e.sha256, "mode": e.mode} for e in entries],
                    "skipped": skipped, "warnings": warnings, "redis": redis_ok, "learning_stores": stores,
                }
                name = f"spamfilter-{_stamp(t0)}{SUFFIX}"
                out = BACKUP_DIR / name
                if out.exists():
                    raise BackupError(f"{name} findes allerede")
                size = encrypt_archive(out, key, entries, manifest, created=created)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            # Read back what is on disk before calling it a success.
            verify(out, key)
            pruned = (prune(protect=[name], now=t0) if redis_ok and
                      stores['local_fuzzy']['backend'] != 'custom_or_unknown' else [])
    except BackupError as ex:
        log.warning("encrypted backup failed: %s", ex)
        return finish(error=str(ex)[:300])
    except Exception as ex:  # noqa: BLE001 - the status must say it failed, never crash the caller
        log.warning("encrypted backup failed: %s", type(ex).__name__)
        return finish(error=f"uventet fejl ({type(ex).__name__})")
    log.info("encrypted backup %s: %d files, %d bytes%s", name, len(entries), size,
             f", {len(warnings)} warning(s)" if warnings else "")
    # Bayes missing = not a full success (the 48 h alert keeps watching).
    full = redis_ok and stores['local_fuzzy']['backend'] != 'custom_or_unknown'
    return finish(ok=full, archive=name, size=size, files=len(entries), warnings=warnings,
                  error=None if full else warnings[0][:300], pruned=pruned,
                  last_ok_ts=int(t0) if full else st["last_ok_ts"],
                  last_ok_archive=name if full else st["last_ok_archive"], learning_stores=stores)


# ---------------------------------------------------------------- schedule
def due(now: float, st: dict[str, Any] | None = None) -> bool:
    """Nightly from RUN_AT (local), catching up later in the day when the
    container was down; a failed run is retried hourly (MAX_ATTEMPTS_PER_DAY)."""
    st = read_status() if st is None else st
    loc = _local(now)
    if (loc.hour, loc.minute) < RUN_AT:
        return False
    day = loc.date().isoformat()
    if st.get("attempt_day") != day:
        return True
    if st.get("ok"):
        return False
    if int(st.get("attempts_today") or 0) >= MAX_ATTEMPTS_PER_DAY:
        return False
    try:
        return now - float(st.get("ts") or 0) >= RETRY_S
    except (TypeError, ValueError):
        return True


ALERT_KEY = "backup"


def alert_text(s: dict[str, Any]) -> tuple[str, str]:
    subject = "Spamfilter: ingen krypteret backup i over 48 timer"
    if s.get("last_ok_ts"):
        when = _local(float(s["last_ok_ts"])).strftime("%d.%m.%Y kl. %H:%M")
        first = f"Den seneste vellykkede krypterede backup er fra {when}."
    else:
        first = "Der er endnu ikke lavet en vellykket krypteret backup."
    why = str(s.get("error") or s.get("text") or "")[:300]
    text = (f"{first}\n\nSeneste forsøg: {why or 'ukendt'}\n\n"
            "Se WebUI → Drift → Krypteret backup, eller kør: docker exec -it spamfilter sfctl doctor\n"
            "Ingen mail er slettet eller flyttet på grund af dette.")
    return subject, text


def check_alert(engine: Any, conn: sqlite3.Connection, now: float | None = None) -> bool:
    """alert_once (mail + push) when 48 h passed without a success; cleared
    again by the next success. True when an alert was queued."""
    s = summary(now)
    if s["alert"]:
        subject, text = alert_text(s)
        episode = str(s.get("last_ok_ts") or "never")
        return bool(engine.alert_once(conn, ALERT_KEY, episode, subject, text))
    if s["state"] == "ok":
        engine.alert_clear(conn, ALERT_KEY)
    return False


ALERT_CHECK_S = 600


def _loop(engine: Any) -> None:
    lg = logging.getLogger("backup")
    last_check = 0.0
    while not engine.SHUTDOWN.wait(POLL_S):
        try:
            ran = False
            if due(time.time()):
                lg.info("encrypted backup starting")
                run_nightly(reason="nightly")
                ran = True
            if ran or time.monotonic() - last_check >= ALERT_CHECK_S:
                last_check = time.monotonic()
                conn = engine._open_conn()
                try:
                    check_alert(engine, conn)
                finally:
                    conn.close()
        except Exception as ex:  # noqa: BLE001 - the scheduler never takes the engine down
            lg.warning("backup scheduler: %s", type(ex).__name__)


# ---------------------------------------------------------------- isolation
CHILD_TIMEOUT_S = 3600


def run_backup_isolated(*, reason: str = "nightly") -> dict[str, Any]:
    """run_backup in a child process; the engine never runs it itself.

    The snapshot opens and closes the live SQLite files (header sniff,
    online backup). On Linux a close() drops EVERY POSIX lock the process
    holds on that file, including the locks of the engine's own open
    connections. Another process (the host backup, sfctl, the WebUI) then
    sees the database as unused, checkpoints it and deletes the WAL while
    the engine still writes to it: the database breaks (3 Nov 2026, damaged
    trees in mail_outbox and login_attempts). A child process holds no other
    connection, so its close() costs nothing. The child writes the status
    file itself; this returns it."""
    cmd = [sys.executable, "-s", str(Path(__file__).resolve()), "--reason", str(reason)[:20],
           "--state-dir", str(STATE_DIR), "--config", str(CONFIG_PATH), "--appdata", str(APPDATA),
           "--backup-dir", str(BACKUP_DIR), "--version", str(VERSION)]
    env = dict(os.environ, SF_BACKUP_REQUIRE_MOUNT="1" if REQUIRE_MOUNT else "0")
    try:
        proc = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, timeout=CHILD_TIMEOUT_S, check=False)
        if proc.returncode != 0:
            log.warning("encrypted backup: the backup process exited with %s", proc.returncode)
    except subprocess.TimeoutExpired:
        log.warning("encrypted backup: the backup process did not finish within %ds", CHILD_TIMEOUT_S)
    except OSError as ex:
        log.warning("encrypted backup: the backup process could not start (%s)", type(ex).__name__)
    return read_status()


# Replaced in tests.
run_nightly: Callable[..., dict[str, Any]] = run_backup_isolated


def main(argv: list[str] | None = None) -> int:
    """Entry point of the child process (run_backup_isolated)."""
    import argparse  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="backup.py")
    ap.add_argument("--reason", default="nightly")
    for opt in ("--state-dir", "--config", "--appdata", "--backup-dir", "--version"):
        ap.add_argument(opt)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    configure(a.state_dir, a.config, appdata=a.appdata, backup_dir=a.backup_dir, version=a.version)
    st = run_backup(reason=a.reason)
    return 0 if st.get("ok") else 1


def enabled() -> bool:
    """Only the all-in-one container (redis-cli, /backup) or an explicit
    SF_BACKUP_DIR runs the nightly job."""
    return os.environ.get("SPAMFILTER_AIO") == "1" or bool(os.environ.get("SF_BACKUP_DIR"))


def start(engine: Any) -> bool:
    """Start the nightly scheduler thread (the engine's main())."""
    if not enabled():
        return False
    configure(engine.STATE_DIR, engine.CONFIG_PATH, version=getattr(engine, "VERSION", None))
    threading.Thread(target=_loop, args=(engine,), name="backup-nightly", daemon=True).start()
    return True


if __name__ == "__main__":
    sys.exit(main())

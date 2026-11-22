"""Standards-based Web Push for the spamfilter (2.5.0).

No third-party push service account and no push library: this module
implements the three RFCs on top of the `cryptography` package and sends
with `requests`:

  * RFC 8030 (Generic Event Delivery Using HTTP Push): one HTTP POST per
    message to the subscription's endpoint, with the TTL, Urgency and Topic
    headers.
  * RFC 8291 (Message Encryption for Web Push): the payload is encrypted
    end to end for the browser ("aes128gcm" content coding, RFC 8188) with
    an ephemeral P-256 key per message; the push service only ever sees
    ciphertext.
  * RFC 8292 (VAPID): the application server identifies itself with one
    long-lived P-256 key pair and a short ES256 JWT per request
    (aud = the push service origin, exp <= 12 h, sub = mailto:/https:).

The VAPID private key is generated once into STATE_DIR/vapid_private.pem
(PKCS#8 PEM, mode 0600, owner uid 10099), never rendered, logged or sent
anywhere; only the public key leaves the process (the browser needs it as
`applicationServerKey`). Rotating it (sfctl push-reset) invalidates every
existing subscription.

Endpoints are validated against an allowlist of the known browser push
services (https only, port 443, no user info) before ANY request is made,
so a forged subscription can never make the filter call an internal
address (SSRF). Requests never follow redirects and always time out.

This module has no database and no knowledge of users: push.py owns the
subscriptions, the queue and the routing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE_NAME = "vapid_private.pem"
OWNER_UID = 10099
OWNER_GID = 10099

JWT_LIFETIME = 12 * 3600          # RFC 8292 allows 24 h; Apple rejects more than a day
RECORD_SIZE = 4096                # one aes128gcm record (RFC 8188 rs)
MAX_PLAINTEXT = 3072              # our payloads are ~200 bytes; far below rs - 17
PAD_BLOCK = 128                   # pad the plaintext to a multiple of this (length hiding)
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
ENDPOINT_MAX = 1024
URGENCIES = ("very-low", "low", "normal", "high")
_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# Known browser push services (RFC 8030 push resources). Exact host or a
# sub-domain of the suffix; nothing else is ever contacted.
#   Apple (Safari / iOS web apps)       web.push.apple.com
#   Google (Chrome, Edge on Android)    fcm.googleapis.com
#   Mozilla (Firefox)                   updates.push.services.mozilla.com
#   Microsoft (Edge on Windows)         *.notify.windows.com
ALLOWED_PUSH_HOSTS = ("web.push.apple.com", "fcm.googleapis.com", "updates.push.services.mozilla.com")
ALLOWED_PUSH_SUFFIXES = ("notify.windows.com",)   # sub-domains only (wns2-*.notify.windows.com)
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# RFC 8292 sub: a mailto: or https: URL. Apple also refuses reserved TLDs.
_RESERVED_TLDS = ("local", "localhost", "invalid", "test", "example", "internal", "lan", "home", "arpa")
_MAILTO_RE = re.compile(r"^mailto:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63})$")


class PushError(Exception):
    """Invalid input (subscription, key, payload). `code` is machine-readable."""

    def __init__(self, code: str, text: str = "") -> None:
        super().__init__(text or code)
        self.code = code


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    s = "".join(str(text or "").split())
    if not re.fullmatch(r"[A-Za-z0-9_\-+/]*={0,2}", s):
        raise PushError("invalid_base64")
    s = s.rstrip("=").replace("+", "-").replace("/", "_")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError) as ex:
        raise PushError("invalid_base64") from ex


# ---------------------------------------------------------------------------
# Endpoint allowlist (SSRF guard)
# ---------------------------------------------------------------------------


def endpoint_host(endpoint: str) -> str:
    """Lowercase host of an endpoint ('' when unparsable) - for logs and UI."""
    try:
        return (urlsplit(str(endpoint or "")).hostname or "").lower()
    except ValueError:
        return ""


def host_allowed(host: str) -> bool:
    h = str(host or "").lower().rstrip(".")
    if not h or len(h) > 253 or not all(_HOST_LABEL.match(p) for p in h.split(".")):
        return False
    if h in ALLOWED_PUSH_HOSTS:
        return True
    return any(h.endswith("." + suffix) for suffix in ALLOWED_PUSH_SUFFIXES)


def validate_endpoint(endpoint: Any) -> str:
    """The endpoint itself when it is an https URL on a known push service
    (port 443, no user info, no fragment, printable ASCII); else PushError."""
    if not isinstance(endpoint, str):
        raise PushError("invalid_endpoint")
    ep = endpoint.strip()
    if not ep or len(ep) > ENDPOINT_MAX or any(ord(c) <= 32 or ord(c) >= 127 for c in ep):
        raise PushError("invalid_endpoint")
    try:
        parts = urlsplit(ep)
        port = parts.port
    except ValueError as ex:
        raise PushError("invalid_endpoint") from ex
    if parts.scheme != "https" or parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise PushError("invalid_endpoint")
    if port not in (None, 443) or parts.fragment or not parts.path.startswith("/"):
        raise PushError("invalid_endpoint")
    if not host_allowed(parts.hostname or ""):
        raise PushError("endpoint_not_allowed")
    return ep


def audience(endpoint: str) -> str:
    """RFC 8292 'aud': the origin of the push resource."""
    parts = urlsplit(endpoint)
    return f"https://{(parts.hostname or '').lower()}"


# ---------------------------------------------------------------------------
# Subscription keys
# ---------------------------------------------------------------------------


def load_public_point(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != 65 or raw[0] != 0x04:
        raise PushError("invalid_p256dh")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as ex:
        raise PushError("invalid_p256dh") from ex


def validate_keys(p256dh: Any, auth: Any) -> tuple[str, str]:
    """(p256dh, auth) as canonical base64url; PushError when the browser
    key is not a P-256 point or the auth secret is not 16 bytes."""
    if not isinstance(p256dh, str) or not isinstance(auth, str) or len(p256dh) > 200 or len(auth) > 100:
        raise PushError("invalid_keys")
    pub = b64u_decode(p256dh)
    load_public_point(pub)
    sec = b64u_decode(auth)
    if len(sec) != 16:
        raise PushError("invalid_auth")
    return b64u(pub), b64u(sec)


# ---------------------------------------------------------------------------
# VAPID key pair
# ---------------------------------------------------------------------------


def key_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / KEY_FILE_NAME


def _private_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _chown_owner(path: Path) -> None:
    # Only root can (and needs to) hand the file to the container user;
    # the filter itself already runs as 10099.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(path, OWNER_UID, OWNER_GID)
        except OSError:
            pass


def _write_key_atomic(path: Path, pem: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not replace:
        # O_EXCL: two processes racing to create the key keep the first one.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, pem)
            os.fsync(fd)
        finally:
            os.close(fd)
        _chown_owner(path)
        return
    fd, tmp = tempfile.mkstemp(prefix=".vapid-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, pem)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        _chown_owner(Path(tmp))
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_private_key(state_dir: str | Path, *, create: bool = True) -> ec.EllipticCurvePrivateKey | None:
    """The VAPID private key; generated (0600) on first use when create=True."""
    path = key_path(state_dir)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        if not create:
            return None
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            _write_key_atomic(path, _private_pem(key), replace=False)
        except FileExistsError:
            data = path.read_bytes()
        else:
            return key
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PushError("invalid_vapid_key")
    return key


def rotate_key(state_dir: str | Path) -> ec.EllipticCurvePrivateKey:
    """Replace the VAPID key pair (every existing subscription stops working)."""
    key = ec.generate_private_key(ec.SECP256R1())
    _write_key_atomic(key_path(state_dir), _private_pem(key), replace=True)
    return key


def public_key_bytes(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def public_key_b64(key: ec.EllipticCurvePrivateKey) -> str:
    """applicationServerKey for pushManager.subscribe() (base64url, 65 bytes)."""
    return b64u(public_key_bytes(key))


def key_fingerprint(key: ec.EllipticCurvePrivateKey) -> str:
    """Short, non-secret id of the key pair (sfctl push-status)."""
    return hashlib.sha256(public_key_bytes(key)).hexdigest()[:12]


# ---------------------------------------------------------------------------
# VAPID JWT (RFC 8292 + RFC 7515/7518 ES256)
# ---------------------------------------------------------------------------


def valid_subject(sub: Any) -> bool:
    s = str(sub or "")
    m = _MAILTO_RE.match(s)
    if m:
        return m.group(1).rsplit(".", 1)[-1].lower() not in _RESERVED_TLDS
    if s.startswith("https://"):
        host = endpoint_host(s)
        return bool(host) and "." in host and host.rsplit(".", 1)[-1] not in _RESERVED_TLDS
    return False


def vapid_jwt(key: ec.EllipticCurvePrivateKey, aud: str, sub: str, *, now: float | None = None,
              lifetime: int = JWT_LIFETIME) -> str:
    if not valid_subject(sub):
        raise PushError("invalid_subject")
    lifetime = max(60, min(int(lifetime), JWT_LIFETIME))
    t = int(time.time() if now is None else now)
    header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64u(json.dumps({"aud": aud, "exp": t + lifetime, "sub": sub}, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode("ascii")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{header}.{claims}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def verify_jwt(token: str, public_key: bytes) -> dict:
    """Verify an ES256 JWT with a raw public key; the claims (tests, doctor)."""
    try:
        header_b, claims_b, sig_b = token.split(".")
    except ValueError as ex:
        raise PushError("invalid_jwt") from ex
    sig = b64u_decode(sig_b)
    if len(sig) != 64:
        raise PushError("invalid_jwt")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        load_public_point(public_key).verify(der, f"{header_b}.{claims_b}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except Exception as ex:  # noqa: BLE001 - InvalidSignature
        raise PushError("invalid_jwt") from ex
    header = json.loads(b64u_decode(header_b))
    if header != {"typ": "JWT", "alg": "ES256"}:
        raise PushError("invalid_jwt")
    return json.loads(b64u_decode(claims_b))


def authorization_header(key: ec.EllipticCurvePrivateKey, endpoint: str, sub: str, *,
                         now: float | None = None) -> str:
    """RFC 8292 section 3: `vapid t=<JWT>, k=<public key>`."""
    return f"vapid t={vapid_jwt(key, audience(endpoint), sub, now=now)}, k={public_key_b64(key)}"


# ---------------------------------------------------------------------------
# RFC 8291 payload encryption (aes128gcm)
# ---------------------------------------------------------------------------


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf_expand_one(prk: bytes, info: bytes, length: int) -> bytes:
    # One HKDF-Expand block (all lengths here are <= 32 octets).
    return _hmac(prk, info + b"\x01")[:length]


def encrypt(plaintext: bytes, ua_public: bytes, auth_secret: bytes, *, salt: bytes | None = None,
            as_private: ec.EllipticCurvePrivateKey | None = None, record_size: int = RECORD_SIZE,
            pad_to: int = PAD_BLOCK) -> bytes:
    """Encrypt one push message (RFC 8291 section 3.4 + RFC 8188, single
    record). salt/as_private are only passed by tests (RFC 8291 appendix A);
    production uses a fresh random salt and a fresh ephemeral key."""
    if len(plaintext) > MAX_PLAINTEXT:
        raise PushError("payload_too_large")
    if len(auth_secret) != 16:
        raise PushError("invalid_auth")
    ua_key = load_public_point(ua_public)
    salt = secrets.token_bytes(16) if salt is None else salt
    if len(salt) != 16:
        raise PushError("invalid_salt")
    as_key = ec.generate_private_key(ec.SECP256R1()) if as_private is None else as_private
    as_public = public_key_bytes(as_key)
    ecdh_secret = as_key.exchange(ec.ECDH(), ua_key)
    prk_key = _hmac(auth_secret, ecdh_secret)
    key_info = b"WebPush: info\x00" + ua_public + as_public
    ikm = _hkdf_expand_one(prk_key, key_info, 32)
    prk = _hmac(salt, ikm)
    cek = _hkdf_expand_one(prk, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf_expand_one(prk, b"Content-Encoding: nonce\x00", 12)
    padded = plaintext + b"\x02"
    if pad_to and pad_to > 1:
        padded += b"\x00" * (-len(padded) % pad_to)
    if len(padded) + 16 > record_size:
        raise PushError("payload_too_large")
    ciphertext = AESGCM(cek).encrypt(nonce, padded, None)
    header = salt + record_size.to_bytes(4, "big") + bytes([len(as_public)]) + as_public
    return header + ciphertext


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth_secret: bytes) -> bytes:
    """The browser side of encrypt() (tests only: proves the round trip)."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public = body[21:21 + idlen]
    ciphertext = body[21 + idlen:]
    if rs < 18 or len(ciphertext) > rs:
        raise PushError("invalid_record")
    ua_public = public_key_bytes(ua_private)
    ecdh_secret = ua_private.exchange(ec.ECDH(), load_public_point(as_public))
    ikm = _hkdf_expand_one(_hmac(auth_secret, ecdh_secret), b"WebPush: info\x00" + ua_public + as_public, 32)
    prk = _hmac(salt, ikm)
    cek = _hkdf_expand_one(prk, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf_expand_one(prk, b"Content-Encoding: nonce\x00", 12)
    padded = AESGCM(cek).decrypt(nonce, ciphertext, None)
    end = padded.rstrip(b"\x00")
    if not end.endswith(b"\x02"):
        raise PushError("invalid_padding")
    return end[:-1]


# ---------------------------------------------------------------------------
# Delivery (RFC 8030)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SendResult:
    status: int            # HTTP status, 0 = no answer (timeout, DNS, TLS, ...)
    outcome: str           # 'ok' | 'gone' | 'retry' | 'rejected' | 'refused'
    retry_after: int = 0   # seconds (429/503 Retry-After, capped)
    detail: str = ""       # short, never the endpoint or the payload


# 2.5.0: reasons a push service gives when THIS subscription is bad (Apple
# BadDeviceToken & co., Mozilla errno 102/103, FCM's legacy names). Only
# these count towards deleting a device; every other 4xx is the service
# refusing OUR request (VAPID JWT, clock skew, 'sub', payload size) and
# would hit every device alike - never a reason to delete anything.
SUBSCRIPTION_REASONS = frozenset({
    "BadDeviceToken", "DeviceTokenNotForTopic", "MissingDeviceToken", "Unregistered",
    "InvalidRegistration", "NotRegistered", "102", "103",
})


def classify(status: int, reason: str = "") -> str:
    if status in (200, 201, 202):
        return "ok"
    if status in (404, 410):
        return "gone"           # subscription expired or unsubscribed: delete it
    if status == 429 or status >= 500 or status == 0:
        return "retry"          # back off and try again later
    if reason in SUBSCRIPTION_REASONS:
        return "rejected"       # this subscription is bad: counts towards removing it
    return "refused"            # 400 / 401 / 403 / 413 ...: the service refuses our request (server-wide)


def _reason(resp: Any) -> str:
    """Apple/Mozilla answer {"reason": "BadJwtToken"} / {"errno": 102} style
    JSON; keep a short sanitised code only."""
    try:
        data = resp.json()
        reason = str(data.get("reason") or data.get("errno") or "")[:40] if isinstance(data, dict) else ""
    except Exception:  # noqa: BLE001
        reason = ""
    return re.sub(r"[^A-Za-z0-9_.-]", "", reason)


def _retry_after(value: Any) -> int:
    try:
        return max(0, min(int(str(value).strip()), 3600))
    except (TypeError, ValueError):
        return 0


def send(endpoint: str, p256dh: str, auth: str, payload: bytes, *, key: ec.EllipticCurvePrivateKey,
         subject: str, ttl: int = 3600, urgency: str = "normal", topic: str | None = None,
         session: Any = None, now: float | None = None) -> SendResult:
    """POST one encrypted message. Validates the endpoint first (SSRF),
    never follows redirects, always times out. Never raises for network
    problems (outcome 'retry'); PushError for invalid input."""
    ep = validate_endpoint(endpoint)
    ua_public = b64u_decode(p256dh)
    secret = b64u_decode(auth)
    body = encrypt(payload, ua_public, secret)
    headers = {
        "TTL": str(max(0, min(int(ttl), 4 * 7 * 86400))),
        "Urgency": urgency if urgency in URGENCIES else "normal",
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        "Authorization": authorization_header(key, ep, subject, now=now),
    }
    if topic and _TOPIC_RE.match(topic):
        headers["Topic"] = topic
    own = None
    if session is None:
        import requests  # noqa: PLC0415 - only the sender needs it

        # trust_env off: no proxy from the environment and no ~/.netrc
        # credentials that would replace our Authorization header.
        own = session = requests.Session()
        own.trust_env = False
    try:
        resp = session.post(ep, data=body, headers=headers, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                            allow_redirects=False)
    except Exception as ex:  # noqa: BLE001 - requests' exceptions: timeout, DNS, TLS, reset
        return SendResult(0, "retry", 0, type(ex).__name__)
    finally:
        if own is not None:
            own.close()
    status = int(getattr(resp, "status_code", 0) or 0)
    reason = _reason(resp) if 400 <= status < 500 and status not in (404, 410, 429) else ""
    outcome = classify(status, reason)
    retry = _retry_after((getattr(resp, "headers", None) or {}).get("Retry-After")) if outcome == "retry" else 0
    return SendResult(status, outcome, retry, reason)

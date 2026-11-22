"""Minimal WebAuthn (passkey) verification for the WebUI (2.6, B1).

Pure functions, no Flask, no database: passkeys.py owns storage, routes
and challenges. Deliberately small and strict instead of a dependency:

  * attestation format "none" only (we never trust attestation anyway:
    the options ask for attestation "none"), attStmt must be empty;
  * COSE keys ES256 (-7, EC2 P-256) and RS256 (-257, RSA >= 2048 bit);
  * a tiny CBOR decoder: definite lengths only, no tags, no floats, no
    duplicate map keys, bounded depth/sizes, strict UTF-8, no trailing
    bytes where the structure must end;
  * clientDataJSON: type, challenge (constant time), exact origin,
    crossOrigin must not be true;
  * authenticatorData: rpIdHash (constant time), UP and UV flags
    required, AT/ED consistent with the data, BS only with BE, no
    trailing bytes;
  * the signature counter must grow (unless the authenticator keeps
    none, i.e. stays 0) - the caller stores the new value atomically.

Signatures are verified with `cryptography` (already in the image for
web push). Every failure raises WebAuthnError with a short code that is
safe for the audit log (never key material or client data).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ALG_ES256 = -7
ALG_RS256 = -257
SUPPORTED_ALGS = (ALG_ES256, ALG_RS256)
ALG_NAMES = {ALG_ES256: "ES256", ALG_RS256: "RS256"}

# authenticatorData flags (WebAuthn L3 §6.1)
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80

CHALLENGE_BYTES = 32
MAX_CLIENT_DATA = 8 * 1024
MAX_ATTESTATION = 16 * 1024
MAX_AUTH_DATA = 4 * 1024
MAX_SIGNATURE = 1024
MAX_CRED_ID = 1023              # spec limit for credentialIdLength
MIN_CRED_ID = 16
MIN_RSA_BITS = 2048
CBOR_MAX_DEPTH = 6
CBOR_MAX_ITEMS = 64             # per array/map

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class WebAuthnError(Exception):
    """Verification failed. `code` is short and safe to log/audit."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64url_decode(text: Any, *, limit: int = 64 * 1024) -> bytes:
    """Strict unpadded (or correctly padded) base64url -> bytes."""
    if not isinstance(text, str) or len(text) > limit * 4 // 3 + 4:
        raise WebAuthnError("encoding")
    s = text.rstrip("=")
    if not _B64URL_RE.fullmatch(s) or len(s) % 4 == 1:
        raise WebAuthnError("encoding")
    try:
        out = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise WebAuthnError("encoding") from None
    if b64url_encode(out) != s:   # non-canonical trailing bits
        raise WebAuthnError("encoding")
    return out


# ---------------------------------------------------------------------------
# CBOR (RFC 8949) - the strict subset WebAuthn needs
# ---------------------------------------------------------------------------


def _cbor_head(data: bytes, pos: int) -> tuple[int, int, int]:
    if pos >= len(data):
        raise WebAuthnError("cbor")
    ib = data[pos]
    major, info = ib >> 5, ib & 0x1F
    pos += 1
    if info < 24:
        return major, info, pos
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None:            # 28-30 reserved, 31 = indefinite length
        raise WebAuthnError("cbor")
    if pos + size > len(data):
        raise WebAuthnError("cbor")
    return major, int.from_bytes(data[pos:pos + size], "big"), pos + size


def cbor_decode(data: bytes, pos: int = 0, *, _depth: int = 0) -> tuple[Any, int]:
    """Decode ONE item at `pos` -> (value, position after it)."""
    if _depth > CBOR_MAX_DEPTH:
        raise WebAuthnError("cbor")
    if pos < len(data) and data[pos] >> 5 == 7:
        info = data[pos] & 0x1F
        simple = {20: False, 21: True, 22: None}
        if info not in simple:  # floats, undefined, other simple values
            raise WebAuthnError("cbor")
        return simple[info], pos + 1
    major, arg, pos = _cbor_head(data, pos)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > len(data) - pos:
            raise WebAuthnError("cbor")
        raw = bytes(data[pos:pos + arg])
        pos += arg
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8", errors="strict"), pos
        except UnicodeDecodeError:
            raise WebAuthnError("cbor") from None
    if major == 4:
        if arg > CBOR_MAX_ITEMS:
            raise WebAuthnError("cbor")
        items = []
        for _ in range(arg):
            item, pos = cbor_decode(data, pos, _depth=_depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if arg > CBOR_MAX_ITEMS:
            raise WebAuthnError("cbor")
        out: dict[Any, Any] = {}
        for _ in range(arg):
            key, pos = cbor_decode(data, pos, _depth=_depth + 1)
            if isinstance(key, bool) or not isinstance(key, (int, str)) or key in out:
                raise WebAuthnError("cbor")
            out[key], pos = cbor_decode(data, pos, _depth=_depth + 1)
        return out, pos
    raise WebAuthnError("cbor")  # major 6: tags are not used by WebAuthn


def cbor_decode_all(data: bytes) -> Any:
    value, end = cbor_decode(data, 0)
    if end != len(data):
        raise WebAuthnError("cbor")
    return value


# ---------------------------------------------------------------------------
# COSE keys
# ---------------------------------------------------------------------------


def cose_public_key(cose: Any):
    """COSE_Key map (or its CBOR bytes) -> (cryptography public key, alg)."""
    key = cbor_decode_all(cose) if isinstance(cose, (bytes, bytearray)) else cose
    if not isinstance(key, dict):
        raise WebAuthnError("key")
    kty, alg = key.get(1), key.get(3)
    if alg == ALG_ES256:
        x, y = key.get(-2), key.get(-3)
        if kty != 2 or key.get(-1) != 1 or not isinstance(x, bytes) or not isinstance(y, bytes) \
                or len(x) != 32 or len(y) != 32:
            raise WebAuthnError("key")
        try:
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                ec.SECP256R1()).public_key()
        except ValueError:      # not a point on the curve
            raise WebAuthnError("key") from None
        return pub, alg
    if alg == ALG_RS256:
        n, e = key.get(-1), key.get(-2)
        if kty != 3 or not isinstance(n, bytes) or not isinstance(e, bytes) or not n or not e or len(e) > 8:
            raise WebAuthnError("key")
        ni, ei = int.from_bytes(n, "big"), int.from_bytes(e, "big")
        if ni.bit_length() < MIN_RSA_BITS or ni.bit_length() > 8192 or ei < 3 or ei % 2 == 0:
            raise WebAuthnError("key")
        try:
            return rsa.RSAPublicNumbers(ei, ni).public_key(), alg
        except ValueError:
            raise WebAuthnError("key") from None
    raise WebAuthnError("alg")


def _verify_signature(pub: Any, alg: int, signature: bytes, signed: bytes) -> None:
    if not isinstance(signature, bytes) or not 8 <= len(signature) <= MAX_SIGNATURE:
        raise WebAuthnError("signature")
    try:
        if alg == ALG_ES256:
            pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_RS256:
            pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("alg")
    except InvalidSignature:
        raise WebAuthnError("signature") from None
    except (ValueError, TypeError):   # malformed DER etc.
        raise WebAuthnError("signature") from None


# ---------------------------------------------------------------------------
# clientDataJSON + authenticatorData
# ---------------------------------------------------------------------------


def check_client_data(raw: bytes, *, kind: str, challenge: bytes, origin: str) -> dict:
    """Parse + check clientDataJSON (type, challenge, exact origin)."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CLIENT_DATA:
        raise WebAuthnError("client_data")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("client_data") from None
    if not isinstance(data, dict):
        raise WebAuthnError("client_data")
    if data.get("type") != kind:
        raise WebAuthnError("type")
    sent = data.get("challenge")
    try:
        got = b64url_decode(sent, limit=256)
    except WebAuthnError:
        raise WebAuthnError("challenge") from None
    if not challenge or not hmac.compare_digest(got, bytes(challenge)):
        raise WebAuthnError("challenge")
    if not isinstance(data.get("origin"), str) or not hmac.compare_digest(
            data["origin"].encode("utf-8"), str(origin).encode("utf-8")):
        raise WebAuthnError("origin")
    if data.get("crossOrigin") not in (None, False) or "topOrigin" in data:
        raise WebAuthnError("cross_origin")
    return data


@dataclass(frozen=True)
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes = b""
    credential_id: bytes = b""
    cose_key: bytes = b""          # the raw CBOR bytes of the COSE key

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backed_up(self) -> bool:
        return bool(self.flags & FLAG_BS)


def parse_auth_data(data: bytes) -> AuthData:
    if not isinstance(data, bytes) or not 37 <= len(data) <= MAX_AUTH_DATA:
        raise WebAuthnError("auth_data")
    flags = data[32]
    if flags & FLAG_BS and not flags & FLAG_BE:
        raise WebAuthnError("flags")
    sign_count = int.from_bytes(data[33:37], "big")
    pos = 37
    aaguid = cred_id = cose = b""
    if flags & FLAG_AT:
        if len(data) < pos + 18:
            raise WebAuthnError("auth_data")
        aaguid = data[pos:pos + 16]
        length = int.from_bytes(data[pos + 16:pos + 18], "big")
        pos += 18
        if not MIN_CRED_ID <= length <= MAX_CRED_ID or pos + length > len(data):
            raise WebAuthnError("auth_data")
        cred_id = data[pos:pos + length]
        pos += length
        start = pos
        key, pos = cbor_decode(data, pos)
        if not isinstance(key, dict):
            raise WebAuthnError("key")
        cose = data[start:pos]
    if flags & FLAG_ED:
        ext, pos = cbor_decode(data, pos)
        if not isinstance(ext, dict):
            raise WebAuthnError("auth_data")
    if pos != len(data):
        raise WebAuthnError("auth_data")
    return AuthData(data[:32], flags, sign_count, aaguid, cred_id, cose)


def _check_rp_and_flags(ad: AuthData, rp_id: str, *, require_uv: bool) -> None:
    if not hmac.compare_digest(ad.rp_id_hash, hashlib.sha256(rp_id.encode("ascii", "strict")).digest()):
        raise WebAuthnError("rp_id")
    if not ad.flags & FLAG_UP:
        raise WebAuthnError("user_present")
    if require_uv and not ad.flags & FLAG_UV:
        raise WebAuthnError("user_verified")


# ---------------------------------------------------------------------------
# Ceremonies
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Registration:
    credential_id: bytes
    public_key: bytes              # COSE_Key CBOR bytes (stored as is)
    alg: int
    sign_count: int
    aaguid: str                    # hex; all zeros for most passkeys
    backup_eligible: bool
    backed_up: bool


def verify_registration(*, client_data_json: bytes, attestation_object: bytes, challenge: bytes,
                        origin: str, rp_id: str, require_uv: bool = True) -> Registration:
    """navigator.credentials.create() result -> Registration (or raises)."""
    check_client_data(client_data_json, kind="webauthn.create", challenge=challenge, origin=origin)
    if not isinstance(attestation_object, bytes) or len(attestation_object) > MAX_ATTESTATION:
        raise WebAuthnError("attestation")
    att = cbor_decode_all(attestation_object)
    if not isinstance(att, dict) or set(att) != {"fmt", "attStmt", "authData"}:
        raise WebAuthnError("attestation")
    if att["fmt"] != "none" or att["attStmt"] != {}:
        raise WebAuthnError("attestation_format")
    if not isinstance(att["authData"], bytes):
        raise WebAuthnError("attestation")
    ad = parse_auth_data(att["authData"])
    _check_rp_and_flags(ad, rp_id, require_uv=require_uv)
    if not ad.flags & FLAG_AT or not ad.credential_id:
        raise WebAuthnError("auth_data")
    _pub, alg = cose_public_key(ad.cose_key)
    return Registration(ad.credential_id, ad.cose_key, alg, ad.sign_count, ad.aaguid.hex(),
                        ad.backup_eligible, ad.backed_up)


@dataclass(frozen=True)
class Assertion:
    sign_count: int
    user_verified: bool
    backed_up: bool


def verify_assertion(*, public_key: bytes, client_data_json: bytes, authenticator_data: bytes,
                     signature: bytes, challenge: bytes, origin: str, rp_id: str, stored_sign_count: int,
                     require_uv: bool = True) -> Assertion:
    """navigator.credentials.get() result for a STORED credential -> Assertion."""
    check_client_data(client_data_json, kind="webauthn.get", challenge=challenge, origin=origin)
    ad = parse_auth_data(authenticator_data)
    if ad.flags & FLAG_AT:
        raise WebAuthnError("auth_data")
    _check_rp_and_flags(ad, rp_id, require_uv=require_uv)
    pub, alg = cose_public_key(public_key)
    _verify_signature(pub, alg, signature, authenticator_data + hashlib.sha256(client_data_json).digest())
    stored = int(stored_sign_count or 0)
    if (ad.sign_count or stored) and ad.sign_count <= stored:
        # A counter that does not grow: a cloned authenticator (or a replay).
        raise WebAuthnError("counter")
    return Assertion(ad.sign_count, ad.user_verified, ad.backed_up)

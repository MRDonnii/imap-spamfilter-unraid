"""A software passkey authenticator for the tests (2.6, B1).

Builds exactly what a browser hands to the page after
navigator.credentials.create()/get(): clientDataJSON, a CBOR attestation
object (fmt "none") and authenticatorData + signature, with ES256 or
RS256 keys from `cryptography`. Knobs let the tests break every single
check (flags, rpIdHash, origin, type, counter, attestation ...).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

FILTER_DIR = Path(__file__).resolve().parent.parent / "filter"
if str(FILTER_DIR) not in sys.path:
    sys.path.insert(0, str(FILTER_DIR))

UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cbor(value: Any) -> bytes:
    """Minimal canonical CBOR encoder (ints, bytes, str, list, dict, bool, None)."""
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)

    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


@dataclass
class SoftAuthenticator:
    rp_id: str = "spam.example.dk"
    origin: str = "https://spam.example.dk"
    alg: int = -7
    sign_count: int = 0
    counter_step: int = 1
    flags: int = UP | UV | BE | BS
    cred_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    user_handle: bytes | None = None

    def __post_init__(self) -> None:
        if self.alg == -7:
            self.key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cose_key(self) -> dict:
        pub = self.key.public_key().public_numbers()
        if self.alg == -7:
            return {1: 2, 3: -7, -1: 1, -2: pub.x.to_bytes(32, "big"), -3: pub.y.to_bytes(32, "big")}
        n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
        return {1: 3, 3: -257, -1: n, -2: pub.e.to_bytes(3, "big")}

    def client_data(self, kind: str, challenge: str, *, origin: str | None = None, **extra: Any) -> bytes:
        data = {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        data.update(extra)
        return json.dumps(data).encode()

    def auth_data(self, *, attested: bool, flags: int | None = None, rp_id: str | None = None,
                  count: int | None = None, cose: dict | None = None, extensions: dict | None = None) -> bytes:
        f = self.flags if flags is None else flags
        if attested:
            f |= AT
        if extensions is not None:
            f |= ED
        out = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([f])
        out += struct.pack(">I", self.sign_count if count is None else count)
        if attested:
            out += b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id
            out += cbor(cose if cose is not None else self.cose_key())
        if extensions is not None:
            out += cbor(extensions)
        return out

    # -- navigator.credentials.create()
    def create(self, options: dict, *, fmt: str = "none", att_stmt: dict | None = None, origin: str | None = None,
               kind: str = "webauthn.create", challenge: str | None = None, **ad_kw: Any) -> dict:
        pk = options["publicKey"]
        self.user_handle = unb64u(pk["user"]["id"])
        cdj = self.client_data(kind, challenge or pk["challenge"], origin=origin)
        att = cbor({"fmt": fmt, "attStmt": att_stmt or {}, "authData": self.auth_data(attested=True, **ad_kw)})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att),
                             "transports": ["internal", "hybrid", "bogus"]}}

    # -- navigator.credentials.get()
    def get(self, options: dict, *, origin: str | None = None, kind: str = "webauthn.get",
            challenge: str | None = None, user_handle: bytes | None = None, tamper: bool = False,
            count: int | None = None, **ad_kw: Any) -> dict:
        pk = options["publicKey"]
        if count is None:
            self.sign_count += self.counter_step
            count = self.sign_count
        cdj = self.client_data(kind, challenge or pk["challenge"], origin=origin)
        ad = self.auth_data(attested=False, count=count, **ad_kw)
        signed = ad + hashlib.sha256(cdj).digest()
        if self.alg == -7:
            sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        else:
            sig = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        handle = user_handle if user_handle is not None else self.user_handle
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(ad), "signature": b64u(sig),
                             "userHandle": b64u(handle) if handle is not None else None}}

"""Fakes for the 2.5.0 push tests: a browser device (P-256 key + auth
secret, so the encrypted payload can be decrypted and inspected) and a
fake HTTP layer for webpush.send (no network, ever)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import webpush  # noqa: E402

_N = [0]


@dataclass
class Device:
    endpoint: str
    key: Any = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    secret: bytes = field(default_factory=lambda: os.urandom(16))

    @property
    def p256dh(self) -> str:
        return webpush.b64u(webpush.public_key_bytes(self.key))

    @property
    def auth(self) -> str:
        return webpush.b64u(self.secret)


def device(host: str = "web.push.apple.com") -> Device:
    _N[0] += 1
    return Device(f"https://{host}/dev{_N[0]}-{os.urandom(4).hex()}")


class FakeResponse:
    def __init__(self, status: int, headers: dict | None = None, reason: str | None = None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self.reason = reason

    def json(self):
        if self.reason is not None:
            return {"reason": self.reason}
        return {"reason": "BadJwtToken"} if self.status_code == 403 else {}


class FakePushService:
    """status_for: endpoint -> HTTP status (default 201). Records every
    request and decrypts it for the device that owns the endpoint."""

    def __init__(self, devices: list[Device] | None = None) -> None:
        self.devices = {d.endpoint: d for d in (devices or [])}
        self.status_for: dict[str, int] = {}
        self.reason_for: dict[str, str] = {}      # endpoint -> JSON 'reason' of a 4xx answer
        self.delay = 0.0                          # seconds per request (concurrency tests)
        self.calls: list[dict] = []

    def add(self, *devs: Device) -> None:
        for d in devs:
            self.devices[d.endpoint] = d

    def post(self, url, data=None, headers=None, timeout=None, allow_redirects=True):
        dev = self.devices.get(url)
        payload = None
        if dev is not None:
            payload = json.loads(webpush.decrypt(data, dev.key, dev.secret))
        self.calls.append({"url": url, "headers": headers, "payload": payload, "timeout": timeout,
                           "allow_redirects": allow_redirects})
        if self.delay:
            import time  # noqa: PLC0415

            time.sleep(self.delay)
        status = self.status_for.get(url, 201)
        return FakeResponse(status, {"Retry-After": "30"} if status in (429, 503) else {},
                            self.reason_for.get(url))

    def payloads(self, dev: Device) -> list[dict]:
        return [c["payload"] for c in self.calls if c["url"] == dev.endpoint]

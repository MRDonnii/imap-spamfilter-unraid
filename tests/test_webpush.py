"""2.5.0 push notifications - the protocol layer (filter/webpush.py).

RFC 8291 appendix A test vector, the round trip, VAPID (RFC 8292) JWT
structure + signature, the endpoint allowlist (SSRF guard), the key file
and the HTTP request (headers, no redirects, timeouts, status handling)
with a fake HTTP layer - nothing here touches the network.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "filter"))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import webpush as wp  # noqa: E402

d = wp.b64u_decode

# RFC 8291 section 5 / appendix A
RFC_PLAINTEXT = b"When I grow up, I want to be a watermelon"
RFC_AS_PRIVATE = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
RFC_AS_PUBLIC = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
RFC_UA_PRIVATE = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
RFC_UA_PUBLIC = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
RFC_AUTH = "BTBZMqHH6r4Tts7J_aSIgg"
RFC_SALT = "DGv6ra1nlYgDCS1FRnbzlw"
RFC_RESULT = ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
              "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
              "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")

APPLE = "https://web.push.apple.com/QGuQyavXutnMH9ofg5VkdQm0B3ZOnGsWj5mhGtzH0cU"
FCM = "https://fcm.googleapis.com/fcm/send/eXaMpLe:APA91bHyz"
MOZ = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABexample"
WNS = "https://wns2-db5p.notify.windows.com/w/?token=BQYAAABexample"


def _priv(b64: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(d(b64), "big"), ec.SECP256R1())


# ---------------------------------------------------------------------------
# RFC 8291
# ---------------------------------------------------------------------------


def test_rfc8291_appendix_a_vector():
    as_key = _priv(RFC_AS_PRIVATE)
    assert wp.public_key_b64(as_key) == RFC_AS_PUBLIC
    assert wp.public_key_b64(_priv(RFC_UA_PRIVATE)) == RFC_UA_PUBLIC
    out = wp.encrypt(RFC_PLAINTEXT, d(RFC_UA_PUBLIC), d(RFC_AUTH), salt=d(RFC_SALT), as_private=as_key, pad_to=0)
    assert wp.b64u(out) == RFC_RESULT
    # 86-octet header: salt, rs = 4096, idlen = 65, as_public
    assert out[:16] == d(RFC_SALT) and int.from_bytes(out[16:20], "big") == 4096 and out[20] == 65
    assert out[21:86] == d(RFC_AS_PUBLIC)
    # ... and the receiver (the browser) decrypts it.
    assert wp.decrypt(out, _priv(RFC_UA_PRIVATE), d(RFC_AUTH)) == RFC_PLAINTEXT


def test_round_trip_with_random_salt_key_and_padding():
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    payload = json.dumps({"title": "Farlig mail stoppet", "body": "æøå", "url": "/spam", "tag": "sf-threat"},
                         ensure_ascii=False).encode()
    a = wp.encrypt(payload, wp.public_key_bytes(ua), auth)
    b = wp.encrypt(payload, wp.public_key_bytes(ua), auth)
    assert a != b                                  # fresh salt + ephemeral key every time
    assert a[:16] != b[:16] and a[21:86] != b[21:86]
    assert (len(a) - 86 - 16) % wp.PAD_BLOCK == 0  # padded to a fixed block: length hiding
    assert wp.decrypt(a, ua, auth) == payload == wp.decrypt(b, ua, auth)


def test_encrypt_refuses_bad_input():
    ua = wp.public_key_bytes(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(wp.PushError):
        wp.encrypt(b"x" * (wp.MAX_PLAINTEXT + 1), ua, os.urandom(16))
    with pytest.raises(wp.PushError):
        wp.encrypt(b"x", ua, os.urandom(15))
    with pytest.raises(wp.PushError):
        wp.encrypt(b"x", b"\x04" + b"\x00" * 64, os.urandom(16))   # not a point on P-256


# ---------------------------------------------------------------------------
# VAPID (RFC 8292)
# ---------------------------------------------------------------------------


def test_vapid_jwt_structure_and_signature():
    key = ec.generate_private_key(ec.SECP256R1())
    now = 1_800_000_000
    token = wp.vapid_jwt(key, "https://web.push.apple.com", "mailto:ole@example.com", now=now)
    header_b, claims_b, sig_b = token.split(".")
    assert "=" not in token
    assert json.loads(d(header_b)) == {"typ": "JWT", "alg": "ES256"}
    claims = json.loads(d(claims_b))
    assert claims == {"aud": "https://web.push.apple.com", "exp": now + 12 * 3600, "sub": "mailto:ole@example.com"}
    assert len(d(sig_b)) == 64                                    # raw r||s, not DER
    assert wp.verify_jwt(token, wp.public_key_bytes(key)) == claims
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(wp.PushError):
        wp.verify_jwt(token, wp.public_key_bytes(other))
    tampered = header_b + "." + wp.b64u(json.dumps({**claims, "aud": "https://evil.example"}).encode()) + "." + sig_b
    with pytest.raises(wp.PushError):
        wp.verify_jwt(tampered, wp.public_key_bytes(key))


def test_vapid_lifetime_is_capped_at_12_hours_and_header_format():
    key = ec.generate_private_key(ec.SECP256R1())
    token = wp.vapid_jwt(key, "https://fcm.googleapis.com", "mailto:a@b.dk", now=100, lifetime=48 * 3600)
    assert json.loads(d(token.split(".")[1]))["exp"] == 100 + 12 * 3600
    hdr = wp.authorization_header(key, FCM, "mailto:a@b.dk", now=100)
    assert hdr.startswith("vapid t=") and f", k={wp.public_key_b64(key)}" in hdr
    jwt = hdr[len("vapid t="):].split(",")[0]
    assert wp.verify_jwt(jwt, wp.public_key_bytes(key))["aud"] == "https://fcm.googleapis.com"   # origin only
    assert len(d(wp.public_key_b64(key))) == 65


@pytest.mark.parametrize("sub,ok", [
    ("mailto:ole@example.com", True), ("https://spamfilter.example.org", True),
    ("mailto:spamfilter@hjemmeserver.invalid", False), ("mailto:x@host.local", False), ("mailto:x@y.test", False),
    ("mailto:ole@bynet", False), ("ole@example.com", False), ("http://example.com", False), ("", False),
    ("mailto:a@b.dk\r\nX: y", False),
])
def test_vapid_subject_rules(sub, ok):
    assert wp.valid_subject(sub) is ok
    if not ok:
        with pytest.raises(wp.PushError):
            wp.vapid_jwt(ec.generate_private_key(ec.SECP256R1()), "https://fcm.googleapis.com", sub)


def test_key_file_is_created_once_0600_and_rotates(tmp_path):
    assert wp.load_private_key(tmp_path, create=False) is None
    k1 = wp.load_private_key(tmp_path)
    path = tmp_path / "vapid_private.pem"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    k2 = wp.load_private_key(tmp_path)
    assert wp.public_key_b64(k1) == wp.public_key_b64(k2)            # never regenerated
    k3 = wp.rotate_key(tmp_path)
    assert wp.public_key_b64(k3) != wp.public_key_b64(k1)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert wp.public_key_b64(wp.load_private_key(tmp_path)) == wp.public_key_b64(k3)
    assert [p.name for p in tmp_path.iterdir()] == ["vapid_private.pem"]  # no temp file left


def test_key_file_with_another_curve_is_refused(tmp_path):
    from cryptography.hazmat.primitives import serialization

    other = ec.generate_private_key(ec.SECP384R1())
    (tmp_path / "vapid_private.pem").write_bytes(other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(wp.PushError):
        wp.load_private_key(tmp_path)


# ---------------------------------------------------------------------------
# Endpoint allowlist (SSRF)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", [APPLE, FCM, MOZ, WNS, "https://web.push.apple.com:443/abc"])
def test_known_push_services_are_allowed(endpoint):
    assert wp.validate_endpoint(endpoint) == endpoint


@pytest.mark.parametrize("endpoint,code", [
    ("http://fcm.googleapis.com/fcm/send/x", "invalid_endpoint"),          # not https
    ("https://fcm.googleapis.com:8443/fcm/send/x", "invalid_endpoint"),    # other port
    ("https://user:pw@fcm.googleapis.com/fcm/send/x", "invalid_endpoint"),  # user info
    ("https://fcm.googleapis.com@192.168.1.10/x", "invalid_endpoint"),
    ("https://192.168.1.10/fcm/send/x", "endpoint_not_allowed"),
    ("https://127.0.0.1/x", "endpoint_not_allowed"),
    ("https://[::1]/x", "endpoint_not_allowed"),
    ("https://localhost/x", "endpoint_not_allowed"),
    ("https://spamfilter-unbound/x", "endpoint_not_allowed"),
    ("https://fcm.googleapis.com.evil.example/x", "endpoint_not_allowed"),
    ("https://evilfcm.googleapis.com/x", "endpoint_not_allowed"),
    ("https://evil.example/fcm.googleapis.com", "endpoint_not_allowed"),
    ("https://notify.windows.com/w/?token=x", "endpoint_not_allowed"),       # sub-domains only
    ("https://x.notify.windows.com.evil.example/w", "endpoint_not_allowed"),
    ("https://permanently-removed.invalid/fcm/send/x", "endpoint_not_allowed"),
    ("https://web.push.apple.com/a#frag", "invalid_endpoint"),
    ("https://web.push.apple.com/a b", "invalid_endpoint"),
    ("https://web.push.apple.com/a\nb", "invalid_endpoint"),
    ("https://web.push.apple.com/" + "a" * 1100, "invalid_endpoint"),
    ("https://web.push.apple.com", "invalid_endpoint"),                      # no path
    ("file:///etc/passwd", "invalid_endpoint"), ("", "invalid_endpoint"),
])
def test_ssrf_endpoints_are_refused(endpoint, code):
    with pytest.raises(wp.PushError) as ei:
        wp.validate_endpoint(endpoint)
    assert ei.value.code == code


def test_validate_keys():
    ua = ec.generate_private_key(ec.SECP256R1())
    p = wp.b64u(wp.public_key_bytes(ua))
    a = wp.b64u(os.urandom(16))
    assert wp.validate_keys(p, a) == (p, a)
    assert wp.validate_keys(p + "=", a + "==") == (p, a)
    for bad_p, bad_a in ((p[:-4], a), (p, wp.b64u(os.urandom(12))), ("!!!", a), (p, None), (123, a),
                         (wp.b64u(b"\x04" + b"\x01" * 64), a)):
        with pytest.raises(wp.PushError):
            wp.validate_keys(bad_p, bad_a)


# ---------------------------------------------------------------------------
# HTTP (fake layer)
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int, headers: dict | None = None, body: dict | None = None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, status: int = 201, *, headers: dict | None = None, body: dict | None = None,
                 exc: Exception | None = None) -> None:
        self.status, self.headers, self.body, self.exc = status, headers, body, exc
        self.calls: list[dict] = []

    def post(self, url, data=None, headers=None, timeout=None, allow_redirects=True):
        self.calls.append({"url": url, "data": data, "headers": headers, "timeout": timeout,
                           "allow_redirects": allow_redirects})
        if self.exc is not None:
            raise self.exc
        return FakeResponse(self.status, self.headers, self.body)


def _sub():
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    return ua, auth, wp.b64u(wp.public_key_bytes(ua)), wp.b64u(auth)


def test_send_builds_an_rfc8030_request():
    key = ec.generate_private_key(ec.SECP256R1())
    ua, auth, p, a = _sub()
    s = FakeSession(201)
    payload = b'{"title":"T","body":"B","url":"/spam","tag":"sf-threat"}'
    res = wp.send(APPLE, p, a, payload, key=key, subject="mailto:ole@example.com", ttl=21600, urgency="high",
                  topic="sf-threat", session=s, now=time.time())
    assert res.outcome == "ok" and res.status == 201
    call = s.calls[0]
    assert call["url"] == APPLE and call["allow_redirects"] is False
    assert call["timeout"] == (wp.CONNECT_TIMEOUT, wp.READ_TIMEOUT)
    h = call["headers"]
    assert h["TTL"] == "21600" and h["Urgency"] == "high" and h["Topic"] == "sf-threat"
    assert h["Content-Encoding"] == "aes128gcm" and h["Content-Type"] == "application/octet-stream"
    jwt = h["Authorization"][len("vapid t="):].split(",")[0]
    claims = wp.verify_jwt(jwt, wp.public_key_bytes(key))
    assert claims["aud"] == "https://web.push.apple.com" and claims["sub"] == "mailto:ole@example.com"
    assert claims["exp"] - time.time() <= 12 * 3600 + 5
    assert payload not in call["data"] and b"sf-threat" not in call["data"]   # encrypted
    assert wp.decrypt(call["data"], ua, auth) == payload


def test_send_validates_the_endpoint_before_any_request():
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    s = FakeSession(201)
    with pytest.raises(wp.PushError):
        wp.send("https://192.168.1.10/x", p, a, b"{}", key=key, subject="mailto:a@b.dk", session=s)
    assert s.calls == []


@pytest.mark.parametrize("status,outcome", [(200, "ok"), (201, "ok"), (202, "ok"), (404, "gone"), (410, "gone"),
                                            (429, "retry"), (500, "retry"), (503, "retry"), (400, "refused"),
                                            (401, "refused"), (403, "refused"), (413, "refused")])
def test_status_classification(status, outcome):
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    s = FakeSession(status, headers={"Retry-After": "120"}, body={"reason": "BadJwtToken<script>"})
    res = wp.send(FCM, p, a, b"{}", key=key, subject="mailto:a@b.dk", session=s)
    assert res.outcome == outcome
    if outcome == "retry":
        assert res.retry_after == 120
    if outcome == "refused":
        assert res.detail == "BadJwtTokenscript"   # sanitised short code only


@pytest.mark.parametrize("status,body,outcome", [
    (400, {"reason": "BadDeviceToken"}, "rejected"),          # Apple: this device is bad
    (400, {"reason": "DeviceTokenNotForTopic"}, "rejected"),
    (400, {"code": 400, "errno": 102, "error": "Bad Request"}, "rejected"),   # Mozilla: invalid token
    (403, {"reason": "BadJwtToken"}, "refused"),              # our JWT: server-wide, never the device
    (400, {"reason": "BadExpirationDate"}, "refused"),
    (401, {"code": 401, "errno": 109}, "refused"),            # Mozilla: bad Authorization
    (400, None, "refused"),                                   # no reason given: never deletes
])
def test_only_per_subscription_reasons_count_against_the_device(status, body, outcome):
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    res = wp.send(APPLE, p, a, b"{}", key=key, subject="mailto:a@b.dk", session=FakeSession(status, body=body))
    assert res.outcome == outcome
    assert wp.classify(status, res.detail) == outcome


def test_network_errors_are_retry_and_never_raise():
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    res = wp.send(MOZ, p, a, b"{}", key=key, subject="mailto:a@b.dk", session=FakeSession(exc=TimeoutError("t")))
    assert res.outcome == "retry" and res.status == 0 and res.detail == "TimeoutError"


def test_bad_topic_and_urgency_are_not_passed_through():
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    s = FakeSession(201)
    wp.send(FCM, p, a, b"{}", key=key, subject="mailto:a@b.dk", urgency="panic", topic="bad topic\r\n", session=s)
    h = s.calls[0]["headers"]
    assert h["Urgency"] == "normal" and "Topic" not in h


def test_default_session_ignores_environment_proxies_and_netrc(monkeypatch):
    import requests

    seen = {}

    def fake_post(self, url, **kw):
        seen["trust_env"] = self.trust_env
        seen["allow_redirects"] = kw.get("allow_redirects")
        return FakeResponse(201)

    monkeypatch.setattr(requests.Session, "post", fake_post)
    key = ec.generate_private_key(ec.SECP256R1())
    _ua, _auth, p, a = _sub()
    assert wp.send(FCM, p, a, b"{}", key=key, subject="mailto:a@b.dk").outcome == "ok"
    assert seen == {"trust_env": False, "allow_redirects": False}

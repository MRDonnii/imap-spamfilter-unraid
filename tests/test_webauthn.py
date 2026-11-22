"""2.6 (B1): the minimal WebAuthn verifier (filter/webauthn.py).

Every check of a registration and an assertion is broken once with the
software authenticator from tests/fakes_webauthn.py; the strict CBOR
decoder and base64url get their own malformed inputs.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from fakes_webauthn import AT, BE, BS, ED, UP, UV, SoftAuthenticator, b64u, cbor, unb64u

import webauthn as wa  # noqa: E402

RP = "spam.example.dk"
ORIGIN = "https://spam.example.dk"


def reg_options(challenge: bytes) -> dict:
    return {"publicKey": {"challenge": b64u(challenge), "user": {"id": b64u(b"h" * 32)}}}


def register(auth: SoftAuthenticator, **kw):
    ch = secrets.token_bytes(32)
    cred = auth.create(reg_options(ch), **{k: v for k, v in kw.items() if k not in ("expect_origin", "expect_rp")})
    r = cred["response"]
    return wa.verify_registration(client_data_json=unb64u(r["clientDataJSON"]),
                                  attestation_object=unb64u(r["attestationObject"]), challenge=ch,
                                  origin=kw.get("expect_origin", ORIGIN), rp_id=kw.get("expect_rp", RP))


def assert_(auth: SoftAuthenticator, reg, *, stored: int = 0, **kw):
    ch = secrets.token_bytes(32)
    cred = auth.get({"publicKey": {"challenge": b64u(ch)}}, **kw)
    r = cred["response"]
    return wa.verify_assertion(public_key=reg.public_key, client_data_json=unb64u(r["clientDataJSON"]),
                               authenticator_data=unb64u(r["authenticatorData"]), signature=unb64u(r["signature"]),
                               challenge=ch, origin=ORIGIN, rp_id=RP, stored_sign_count=stored)


@pytest.mark.parametrize("alg", [-7, -257])
def test_register_and_assert_roundtrip(alg):
    auth = SoftAuthenticator(alg=alg)
    reg = register(auth)
    assert reg.credential_id == auth.cred_id and reg.alg == alg and reg.backup_eligible and reg.backed_up
    assert wa.cbor_decode_all(reg.public_key) == auth.cose_key()
    res = assert_(auth, reg, stored=0)
    assert res.sign_count == 1 and res.user_verified
    res2 = assert_(auth, reg, stored=res.sign_count)
    assert res2.sign_count == 2


def test_counter_zero_authenticators_are_fine_but_a_going_back_counter_is_not():
    auth = SoftAuthenticator(counter_step=0)          # e.g. iCloud Keychain: always 0
    reg = register(auth)
    assert assert_(auth, reg, stored=0).sign_count == 0
    auth2 = SoftAuthenticator()
    reg2 = register(auth2)
    assert_(auth2, reg2, stored=0)
    with pytest.raises(wa.WebAuthnError) as ex:
        assert_(auth2, reg2, stored=5, count=5)       # not greater than stored
    assert ex.value.code == "counter"
    with pytest.raises(wa.WebAuthnError):
        assert_(auth2, reg2, stored=7, count=0)       # dropped to 0 after having counted


@pytest.mark.parametrize("kw,code", [
    ({"origin": "https://evil.example"}, "origin"),
    ({"origin": "http://spam.example.dk"}, "origin"),
    ({"kind": "webauthn.get"}, "type"),
    ({"challenge": b64u(b"x" * 32)}, "challenge"),
    ({"challenge": "!!!"}, "challenge"),
    ({"rp_id": "evil.example"}, "rp_id"),
    ({"flags": UV}, "user_present"),
    ({"flags": UP}, "user_verified"),
    ({"flags": UP | UV | BS}, "flags"),                # BS without BE
    ({"fmt": "packed", "att_stmt": {"alg": -7, "sig": b"x"}}, "attestation_format"),
    ({"att_stmt": {"x": 1}}, "attestation_format"),
    ({"cose": {1: 2, 3: -8, -1: 6, -2: b"x" * 32}}, "alg"),                       # EdDSA: unsupported
    ({"cose": {1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}}, "key"),  # not on the curve
    ({"cose": {1: 3, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}}, "key"),  # kty does not fit alg
    ({"cose": {1: 3, 3: -257, -1: b"\xff" * 128, -2: b"\x01\x00\x01"}}, "key"),   # RSA-1024
])
def test_registration_checks(kw, code):
    with pytest.raises(wa.WebAuthnError) as ex:
        register(SoftAuthenticator(), **kw)
    assert ex.value.code == code


def test_registration_extensions_are_parsed_and_trailing_bytes_refused():
    auth = SoftAuthenticator()
    assert register(auth, extensions={"credProtect": 2}).credential_id == auth.cred_id
    ch = secrets.token_bytes(32)
    cred = auth.create(reg_options(ch))
    att = wa.cbor_decode_all(unb64u(cred["response"]["attestationObject"]))
    att["authData"] += b"\x00"
    with pytest.raises(wa.WebAuthnError) as ex:
        wa.verify_registration(client_data_json=unb64u(cred["response"]["clientDataJSON"]),
                               attestation_object=cbor(att), challenge=ch, origin=ORIGIN, rp_id=RP)
    assert ex.value.code == "auth_data"
    # An extra top-level key in the attestation object: refused.
    att = wa.cbor_decode_all(unb64u(cred["response"]["attestationObject"]))
    att["x"] = 1
    with pytest.raises(wa.WebAuthnError):
        wa.verify_registration(client_data_json=unb64u(cred["response"]["clientDataJSON"]),
                               attestation_object=cbor(att), challenge=ch, origin=ORIGIN, rp_id=RP)


def test_cross_origin_client_data_is_refused():
    auth = SoftAuthenticator()
    ch = secrets.token_bytes(32)
    for extra in ({"crossOrigin": True}, {"topOrigin": "https://evil.example"}):
        cdj = auth.client_data("webauthn.create", b64u(ch), **extra)
        with pytest.raises(wa.WebAuthnError) as ex:
            wa.check_client_data(cdj, kind="webauthn.create", challenge=ch, origin=ORIGIN)
        assert ex.value.code == "cross_origin"
    for bad in (b"", b"[]", b"\xff\xfe", b"{" * 9000):
        with pytest.raises(wa.WebAuthnError):
            wa.check_client_data(bad, kind="webauthn.create", challenge=ch, origin=ORIGIN)


@pytest.mark.parametrize("alg", [-7, -257])
def test_assertion_checks(alg):
    auth = SoftAuthenticator(alg=alg)
    reg = register(auth)
    for kw, code in (({"tamper": True}, "signature"), ({"origin": "https://evil.example"}, "origin"),
                     ({"kind": "webauthn.create"}, "type"), ({"rp_id": "evil.example"}, "rp_id"),
                     ({"flags": UP}, "user_verified"), ({"flags": UV}, "user_present"),
                     ({"challenge": b64u(b"z" * 32)}, "challenge")):
        with pytest.raises(wa.WebAuthnError) as ex:
            assert_(auth, reg, **kw)
        assert ex.value.code == code, kw
    # Attested credential data in an assertion is not expected.
    ch = secrets.token_bytes(32)
    cred = auth.get({"publicKey": {"challenge": b64u(ch)}})
    ad = auth.auth_data(attested=True, count=99)
    with pytest.raises(wa.WebAuthnError):
        wa.verify_assertion(public_key=reg.public_key, client_data_json=unb64u(cred["response"]["clientDataJSON"]),
                            authenticator_data=ad, signature=unb64u(cred["response"]["signature"]), challenge=ch,
                            origin=ORIGIN, rp_id=RP, stored_sign_count=0)


def test_signature_of_another_key_fails():
    a, b = SoftAuthenticator(), SoftAuthenticator()
    reg_a = register(a)
    register(b)
    b.cred_id = a.cred_id
    with pytest.raises(wa.WebAuthnError) as ex:
        assert_(b, reg_a)
    assert ex.value.code == "signature"


def test_uv_not_required_mode_only_when_asked():
    auth = SoftAuthenticator(flags=UP)
    ch = secrets.token_bytes(32)
    cred = auth.create(reg_options(ch))
    r = cred["response"]
    reg = wa.verify_registration(client_data_json=unb64u(r["clientDataJSON"]),
                                 attestation_object=unb64u(r["attestationObject"]), challenge=ch, origin=ORIGIN,
                                 rp_id=RP, require_uv=False)
    assert reg.backup_eligible is False


# --------------------------------------------------------------------- CBOR + base64url


@pytest.mark.parametrize("data", [
    b"",                         # nothing
    b"\x1f",                     # reserved additional info
    b"\x5f\x41a\xff",            # indefinite-length byte string
    b"\x9f\x01\xff",             # indefinite array
    b"\xc0\x00",                 # tag
    b"\xf9\x3c\x00",             # half float
    b"\xf7",                     # undefined
    b"\x42a",                    # truncated byte string
    b"\x62\xc3\x28",             # invalid UTF-8
    b"\xa2\x01\x01\x01\x02",     # duplicate map key
    b"\xa1\x41a\x01",            # bytes as map key
    b"\x81" * 10 + b"\x01",      # too deep
    b"\x19\x01",                 # truncated length
    b"\x01\x02",                 # trailing bytes
    b"\x98\x41" + b"\x01" * 65,  # too many items
])
def test_cbor_rejects_malformed(data):
    with pytest.raises(wa.WebAuthnError):
        wa.cbor_decode_all(data)


def test_cbor_decodes_what_webauthn_uses():
    value = {"fmt": "none", "attStmt": {}, 1: -7, -3: b"\x00\x01", "l": [1, True, False, None], "big": 2 ** 40}
    assert wa.cbor_decode_all(cbor(value)) == value


@pytest.mark.parametrize("text", ["a", "ab=c", "a+b/", "YQ==x", None, 5, "YR"])
def test_b64url_strict(text):
    with pytest.raises(wa.WebAuthnError):
        wa.b64url_decode(text)


def test_b64url_roundtrip():
    for n in range(0, 40):
        raw = secrets.token_bytes(n)
        assert wa.b64url_decode(wa.b64url_encode(raw)) == raw
    assert wa.b64url_decode("YQ==") == b"a"


def test_rp_id_hash_is_sha256_of_the_host():
    auth = SoftAuthenticator()
    ad = wa.parse_auth_data(auth.auth_data(attested=False, count=3))
    assert ad.rp_id_hash == hashlib.sha256(RP.encode()).digest() and ad.sign_count == 3
    assert ad.flags & (UP | UV | BE | BS) and not ad.flags & (AT | ED)

"""2.8 (A3): QR-code phishing (filter/qrscan.py). Decoding needs libzbar
(apt libzbar0; CI installs it) and the qrcode test package to draw codes."""

from __future__ import annotations

import io
import re
import sys
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
import qrscan  # noqa: E402

HAVE = qrscan.available()
needs_zbar = pytest.mark.skipif(not (HAVE["zbar"] and HAVE["pillow"]), reason="libzbar / Pillow missing")


def _png(text: str) -> bytes:
    qrcode = pytest.importorskip("qrcode")
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _mail(*parts, subject="Forny dit MitID") -> bytes:
    m = MIMEMultipart()
    m["Subject"], m["From"], m["To"] = subject, "x@evil.example", "ole@bynet.example"
    m.attach(MIMEText("Scan koden herunder.", "plain", "utf-8"))
    for p in parts:
        m.attach(p)
    return m.as_bytes()


def test_abused_tlds_equal_the_rspamd_map():
    text = (ROOT / "rspamd/local.d/maps.d/th_abused_tlds.re").read_text()
    line = next(x for x in text.splitlines() if x.startswith("/"))
    tlds = set(re.search(r"\(([^)]*)\)", line).group(1).split("|"))
    assert tlds == set(qrscan.ABUSED_TLDS)


@pytest.mark.parametrize("url,why", [
    ("http://192.168.1.5/login", "IP-adresse"),
    ("https://xn--mitd-xyz.dk/", "punycode"),
    ("https://bit.ly/3abc", "forkortet link"),
    ("https://mitid-forny.top/x", ".top"),
    ("https://mitid-forny.com/x", "mitid i et fremmed domæne"),
    ("https://gls-pakke.net/track", "gls i et fremmed domæne"),
    ("https://www.mitid.dk/", None),
    ("https://www.postnord.dk/track", None),
    ("https://eagles.com/", None),          # 'gls' inside a word does not count
    ("https://skateboard.dk/", None),       # neither does 'skat'
    ("https://vexar.example/", None),
    ("https://evil.top\\@mitid.dk/", ".top"),   # a browser treats '\\' as '/'
    ("http://2130706433/", "IP-adresse"),
    ("http://0x7f000001/", "IP-adresse"),
])
def test_suspicious_reason(url, why):
    assert qrscan.suspicious_reason(url) == why


def test_urls_in_payloads():
    assert qrscan.urls_in(["https://a.example/x.", "MEBKM:URL:www.b.example/y;;", "WIFI:S:home;;"]) == [
        "https://a.example/x", "http://www.b.example/y"]


class _Resp:
    def __init__(self, syms):
        self._s = syms

    def json(self):
        return {"symbols": {k: {"score": 1} for k in self._s}}


def _eng(bad=()):
    calls = []

    def post(url, data=None, headers=None, timeout=None):
        calls.append(data)
        return _Resp(bad)
    return SimpleNamespace(RSPAMD_LEARN_URL="http://127.0.0.1:11334", requests=SimpleNamespace(post=post),
                           _rspamd_password=lambda: "pw", calls=calls)


@needs_zbar
def test_qr_in_a_picture_to_a_listed_phish_scores_7():
    raw = _mail(MIMEImage(_png("https://mitid-forny.top/x"), "png"))
    eng = _eng(bad={"PHISHED_OPENPHISH"})
    syms, events = qrscan.judge(eng, raw, {"TH_LURE_SUBJECT"}, "on")
    assert [s["n"] for s in syms] == ["TH_QR_PHISH"] and syms[0]["s"] == 7.0
    assert syms[0]["o"][0] == "mitid-forny.top" and events[0][0] == "qr_hit"
    assert b"https://mitid-forny.top/x" in eng.calls[0]  # only the links go to rspamd


@needs_zbar
def test_suspicious_qr_with_lure_subject_and_shadow_mode():
    raw = _mail(MIMEImage(_png("https://bit.ly/zzz"), "png"))
    syms, _ = qrscan.judge(_eng(), raw, {"TH_LURE_SUBJECT"}, "on")
    assert [(s["n"], s["s"]) for s in syms] == [("TH_QR_SUSPICIOUS", 3.0), ("TH_QR_LURE", 2.0)]
    syms, events = qrscan.judge(_eng(), raw, {"TH_LURE_SUBJECT"}, "shadow")
    assert syms == [{"n": "TH_QR_TRIAL", "s": 0.0, "o": ["+5", "bit.ly", "forkortet link"]}]
    assert events[0][0] == "qr_trial"
    assert qrscan.judge(_eng(), raw, set(), "off") == ([], [])


@needs_zbar
def test_ordinary_qr_link_gives_nothing():
    raw = _mail(MIMEImage(_png("https://www.postnord.dk/track/123"), "png"))
    assert qrscan.judge(_eng(), raw, {"TH_LURE_SUBJECT"}, "on") == ([], [])


@needs_zbar
@pytest.mark.skipif(not HAVE["pdf"], reason="pdftoppm missing")
def test_qr_on_the_first_page_of_a_pdf():
    from PIL import Image
    png = Image.open(io.BytesIO(_png("https://dhl-told.click/pay")))
    buf = io.BytesIO()
    png.convert("RGB").save(buf, format="PDF")
    raw = _mail(MIMEApplication(buf.getvalue(), "pdf", Name="faktura.pdf"))
    syms, _ = qrscan.judge(_eng(), raw, set(), "on")
    assert syms and syms[0]["n"] == "TH_QR_SUSPICIOUS" and syms[0]["o"] == ["dhl-told.click", ".click"]


def test_hostile_pictures_are_ignored():
    bomb = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    assert qrscan.decode_image(bomb) == []
    assert qrscan.decode_image(b"x" * (qrscan.MAX_IMAGE_BYTES + 1)) == []
    assert qrscan.pdf_first_page(b"not a pdf") is None
    assert qrscan.payloads(b"") == [] and qrscan.payloads(b"garbage") == []

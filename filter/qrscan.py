"""QR-code phishing ("quishing", 2.8 A3) - spamfilter.

A mail with a picture of a QR code ("Forny dit MitID", "Din pakke venter")
has no link in its text, so no URL check sees it. This module reads QR
codes from the mail's images and from the first page of attached PDFs and
judges the links in them:

  * TH_QR_PHISH (+7): rspamd's own URL checks (SURBL, Spamhaus DBL,
    OpenPhish, Phishing Army, URLhaus ...) flag the link - checked by
    sending rspamd a tiny synthetic text mail that only contains the links
    (check only: nothing is learned).
  * TH_QR_SUSPICIOUS (+3): the link's host is an IP address, punycode, a
    URL shortener, on a TLD spam campaigns rotate through (the same list
    as rspamd's TH_FROM_ABUSED_TLD map, test-enforced), or carries a brand
    name (MitID, MobilePay, PostNord ...) without being the brand's domain.
    +2 more (TH_QR_LURE) with a lure subject (TH_LURE_SUBJECT).
  * A QR code alone, or one with an ordinary link, gives 0 points.

Mode (engine_state 'qr_mode' via trialmode.py): off | shadow (Prøv, the
default: only TH_QR_TRIAL 0 and the event qr_trial) | on.

Untrusted input, so: at most MAX_IMAGES pictures (each <= MAX_IMAGE_BYTES
and MAX_PIXELS after Pillow's decompression-bomb check), PDFs <= MAX_PDF_BYTES
rendered by pdftoppm (first page only, own temp dir, timeout), every
decoded payload capped. The zbar library is loaded directly with ctypes
(no pyzbar); without Pillow, libzbar or pdftoppm the part concerned is
skipped and the mail is scored as before.
"""

from __future__ import annotations

import contextlib
import ctypes
import email
import email.policy
import io
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

log = logging.getLogger("qrscan")

MAX_IMAGES = 3
MAX_PDFS = 2
MAX_IMAGE_BYTES = 5 * 2**20
MAX_PDF_BYTES = 10 * 2**20
MAX_PIXELS = 25_000_000
MAX_SIDE = 2400
MAX_URLS = 5
MAX_PAYLOAD = 2048
# Only ordinary picture decoders (never PSD/EPS/ICNS ... from hostile bytes).
PIL_FORMATS = ("PNG", "JPEG", "GIF", "BMP", "WEBP", "TIFF")
PDF_TIMEOUT_S = 15
RSPAMD_TIMEOUT_S = 15

SYMBOL_PHISH, SCORE_PHISH = "TH_QR_PHISH", 7.0
SYMBOL_SUSPICIOUS, SCORE_SUSPICIOUS = "TH_QR_SUSPICIOUS", 3.0
SYMBOL_LURE, SCORE_LURE = "TH_QR_LURE", 2.0
SYMBOL_TRIAL = "TH_QR_TRIAL"
EVENT_TRIAL = "qr_trial"
FEATURE = "qr"

# rspamd URL reputation symbols that mean "this link is known bad".
BAD_URL_SYMBOLS = frozenset({
    "PH_SURBL_MULTI", "MW_SURBL_MULTI", "ABUSE_SURBL", "CRACKED_SURBL", "DBL_PHISH", "DBL_MALWARE", "DBL_SPAM",
    "DBL_BOTNET", "DBL_ABUSE", "DBL_ABUSE_PHISH", "DBL_ABUSE_MALWARE", "DBL_ABUSE_BOTNET", "URIBL_BLACK",
    "RSPAMD_URIBL", "PHISHED_OPENPHISH", "PHISHED_PHISHTANK", "TH_PHISHARMY_URL", "URLHAUS_MALWARE_URL",
    "SEM_URIBL_FRESH15", "CLAM_PHISH",
})
# Keep equal to rspamd/local.d/maps.d/th_abused_tlds.re (tests/test_qrscan.py).
ABUSED_TLDS = frozenset({
    "homes", "guru", "help", "su", "xyz", "vip", "top", "icu", "cyou", "sbs", "cfd", "bond", "rest", "lol", "quest",
    "monster", "buzz", "autos", "boats", "yachts", "beauty", "hair", "makeup", "skin", "mom", "christmas", "watch",
    "pics", "day", "fun", "click", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "country", "stream", "loan",
    "racing", "win", "bid", "review", "date", "faith", "party", "science", "cricket", "accountant", "men", "kim",
    "xin",
})
SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "rebrand.ly", "s.id", "t.ly", "lnkd.in", "qrco.de", "qr.codes", "bl.ink", "short.io", "v.gd",
})
# Brand word in a host -> the brand's own registrable domains.
BRANDS: dict[str, tuple[str, ...]] = {
    "mitid": ("mitid.dk",), "nemid": ("nemid.nu",), "mobilepay": ("mobilepay.dk", "mobilepay.fi"),
    "postnord": ("postnord.dk", "postnord.com", "postnord.se"), "gls": ("gls-group.eu", "gls-group.com",
                                                                       "gls-denmark.com", "glsdanmark.dk"),
    "dao": ("dao.as", "dao365.dk"), "skat": ("skat.dk", "sktst.dk"), "borger": ("borger.dk",),
    "eboks": ("e-boks.dk", "e-boks.com"), "e-boks": ("e-boks.dk", "e-boks.com"),
    "danskebank": ("danskebank.dk", "danskebank.com"), "nordea": ("nordea.dk", "nordea.com"),
    "jyskebank": ("jyskebank.dk",), "sydbank": ("sydbank.dk",), "netflix": ("netflix.com",),
    "paypal": ("paypal.com", "paypal.dk"), "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com"), "outlook": ("outlook.com", "live.com"),
    "dhl": ("dhl.com", "dhl.dk", "dhl.de"), "bring": ("bring.com", "bring.dk"), "easypark": ("easypark.com",
                                                                                         "easypark.dk"),
}
_IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/gif", "image/bmp", "image/webp", "image/tiff")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]{2,500}")
_TRAIL = ".,;:!?)]}>"


# ---------------------------------------------------------------- zbar (ctypes)
class _Zbar:
    def __init__(self) -> None:
        lib = ctypes.CDLL("libzbar.so.0")
        lib.zbar_image_scanner_create.restype = ctypes.c_void_p
        lib.zbar_image_scanner_destroy.argtypes = [ctypes.c_void_p]
        lib.zbar_image_scanner_set_config.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        lib.zbar_image_create.restype = ctypes.c_void_p
        lib.zbar_image_destroy.argtypes = [ctypes.c_void_p]
        lib.zbar_image_set_format.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        lib.zbar_image_set_size.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
        lib.zbar_image_set_data.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
        lib.zbar_scan_image.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.zbar_scan_image.restype = ctypes.c_int
        lib.zbar_image_first_symbol.argtypes = [ctypes.c_void_p]
        lib.zbar_image_first_symbol.restype = ctypes.c_void_p
        lib.zbar_symbol_next.argtypes = [ctypes.c_void_p]
        lib.zbar_symbol_next.restype = ctypes.c_void_p
        lib.zbar_symbol_get_data.argtypes = [ctypes.c_void_p]
        lib.zbar_symbol_get_data.restype = ctypes.c_void_p
        lib.zbar_symbol_get_data_length.argtypes = [ctypes.c_void_p]
        lib.zbar_symbol_get_data_length.restype = ctypes.c_uint
        lib.zbar_symbol_get_type.argtypes = [ctypes.c_void_p]
        lib.zbar_symbol_get_type.restype = ctypes.c_int
        self.lib = lib
        self.lock = threading.Lock()

    def scan_gray(self, width: int, height: int, data: bytes) -> list[bytes]:
        lib = self.lib
        out: list[bytes] = []
        with self.lock:
            scanner = lib.zbar_image_scanner_create()
            # ZBAR_NONE (0), ZBAR_CFG_ENABLE (0) = 0: everything off, then QR (64) on.
            lib.zbar_image_scanner_set_config(scanner, 0, 0, 0)
            lib.zbar_image_scanner_set_config(scanner, 64, 0, 1)
            img = lib.zbar_image_create()
            buf = ctypes.create_string_buffer(data, len(data))
            try:
                lib.zbar_image_set_format(img, 0x30303859)  # fourcc 'Y800' (8-bit gray)
                lib.zbar_image_set_size(img, width, height)
                lib.zbar_image_set_data(img, ctypes.cast(buf, ctypes.c_void_p), len(data), None)
                if lib.zbar_scan_image(scanner, img) > 0:
                    sym = lib.zbar_image_first_symbol(img)
                    while sym and len(out) < MAX_URLS:
                        n = min(int(lib.zbar_symbol_get_data_length(sym)), MAX_PAYLOAD)
                        out.append(ctypes.string_at(lib.zbar_symbol_get_data(sym), n))
                        sym = lib.zbar_symbol_next(sym)
            finally:
                lib.zbar_image_set_data(img, None, 0, None)
                lib.zbar_image_destroy(img)
                lib.zbar_image_scanner_destroy(scanner)
        return out


_ZBAR: _Zbar | None = None
_ZBAR_TRIED = False
_ZBAR_LOCK = threading.Lock()


def _zbar() -> _Zbar | None:
    global _ZBAR, _ZBAR_TRIED
    with _ZBAR_LOCK:
        if not _ZBAR_TRIED:
            _ZBAR_TRIED = True
            try:
                _ZBAR = _Zbar()
            except (OSError, AttributeError) as ex:
                log.info("QR: libzbar not available (%s) - QR codes are not read", type(ex).__name__)
        return _ZBAR


def available() -> dict[str, bool]:
    try:
        import PIL.Image  # noqa: F401, PLC0415
        pil = True
    except ImportError:
        pil = False
    return {"pillow": pil, "zbar": _zbar() is not None, "pdf": shutil.which("pdftoppm") is not None}


# ---------------------------------------------------------------- decoding
def decode_image(data: bytes) -> list[str]:
    """QR payloads in one picture ([] for anything unreadable)."""
    zb = _zbar()
    if zb is None or not data or len(data) > MAX_IMAGE_BYTES:
        return []
    try:
        from PIL import Image  # noqa: PLC0415
    except ImportError:
        return []
    try:
        # Process-wide Pillow limit (nothing else in the filter opens pictures).
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS
        with Image.open(io.BytesIO(data), formats=PIL_FORMATS) as im:
            if im.width * im.height > MAX_PIXELS:
                return []
            im.seek(0)
            g = im.convert("L")
        if max(g.size) > MAX_SIDE:
            g.thumbnail((MAX_SIDE, MAX_SIDE))
        raw = zb.scan_gray(g.width, g.height, g.tobytes())
    except Exception as ex:  # noqa: BLE001 - Pillow raises many kinds for hostile input
        log.debug("QR: picture not readable (%s)", type(ex).__name__)
        return []
    return [p.decode("utf-8", "replace")[:MAX_PAYLOAD] for p in raw]


def _pdf_limits() -> None:
    """pdftoppm on a hostile PDF: 512 MB memory, 10 s CPU, 64 MB output."""
    import resource  # noqa: PLC0415 - POSIX only, child process

    resource.setrlimit(resource.RLIMIT_AS, (512 * 2**20, 512 * 2**20))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 2**20, 64 * 2**20))


def pdf_first_page(data: bytes) -> bytes | None:
    """PNG of a PDF's first page (pdftoppm), None when not possible."""
    exe = shutil.which("pdftoppm")
    if exe is None or not data or len(data) > MAX_PDF_BYTES or not data[:1024].lstrip().startswith(b"%PDF"):
        return None
    with tempfile.TemporaryDirectory(prefix="sf-qr-") as td:
        src, out = Path(td) / "in.pdf", Path(td) / "page"
        src.write_bytes(data)
        try:
            subprocess.run([exe, "-f", "1", "-l", "1", "-r", "110", "-scale-to", "1700", "-cropbox", "-png",
                            "-singlefile", str(src), str(out)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=PDF_TIMEOUT_S, check=False, preexec_fn=_pdf_limits)
        except (OSError, subprocess.SubprocessError):
            return None
        png = out.with_suffix(".png")
        with contextlib.suppress(OSError):
            if png.is_file() and png.stat().st_size <= MAX_IMAGE_BYTES * 4:
                return png.read_bytes()
    return None


def payloads(raw: bytes | None) -> list[str]:
    """Every QR payload in the mail's pictures and PDFs (bounded)."""
    if not raw:
        return []
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception:  # noqa: BLE001
        return []
    found: list[str] = []
    pictures = pdfs = 0
    for part in msg.walk():
        if pictures >= MAX_IMAGES or len(found) >= MAX_URLS:
            break
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        name = (part.get_filename() or "").lower()
        is_pdf = ctype == "application/pdf" or name.endswith(".pdf")
        if not (ctype in _IMAGE_TYPES or is_pdf):
            continue
        if is_pdf:
            if pdfs >= MAX_PDFS:
                continue
            pdfs += 1
        pictures += 1  # counted before decoding: a part that fails still uses its slot
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            continue
        if is_pdf:
            data = pdf_first_page(data) or b""
        if not data:
            continue
        for p in decode_image(data):
            if p not in found:
                found.append(p)
    return found[:MAX_URLS]


def urls_in(items: Iterable[str]) -> list[str]:
    """http(s) links in QR payloads (also MEBKM/URLTO: and bare www.)."""
    out: list[str] = []
    for text in items or ():
        for m in _URL_RE.finditer(str(text)):
            u = m.group(0).rstrip(_TRAIL)
            if u.lower().startswith("www."):
                u = "http://" + u
            if u not in out:
                out.append(u[:500])
    return out[:MAX_URLS]


# ---------------------------------------------------------------- judging
def host_of(url: str) -> str:
    """The host a browser would open: '\\' counts as '/' ("evil.top\\@mitid.dk")."""
    try:
        return (urlsplit(str(url).replace("\\", "/")).hostname or "").strip(".").lower()
    except ValueError:
        return ""


def _under(host: str, dom: str) -> bool:
    return host == dom or host.endswith("." + dom)


def suspicious_reason(url: str) -> str | None:
    """Why a QR link's host is suspicious, else None."""
    host = host_of(url)
    if not host:
        return "ugyldig adresse"
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(host)
        return "IP-adresse"
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*", host):
        return "IP-adresse"  # 2130706433, 0x7f000001, 0177.0.0.1
    if "xn--" in host:
        return "punycode"
    if any(_under(host, s) for s in SHORTENERS):
        return "forkortet link"
    tld = host.rsplit(".", 1)[-1]
    if tld in ABUSED_TLDS:
        return f".{tld}"
    # Short brand words only as a whole label part ("gls-pakke.top", not
    # "eagles"/"skateboard"); six letters or more also inside a word.
    parts = set(re.split(r"[.\-_]", host))
    flat = host.replace("-", "")
    for word, owns in BRANDS.items():
        w = word.replace("-", "")
        hit = w in parts or word in parts or (len(w) >= 6 and w in flat)
        if hit and not any(_under(host, d) for d in owns):
            return f"{word} i et fremmed domæne"
    return None


def rspamd_bad(eng: Any, urls: list[str]) -> list[str]:
    """The bad-URL symbols rspamd gives a synthetic mail with only `urls`."""
    base = getattr(eng, "RSPAMD_LEARN_URL", None)
    req = getattr(eng, "requests", None)
    pw = getattr(eng, "_rspamd_password", None)
    if not urls or not base or req is None or not callable(pw):
        return []
    body = ("From: qr-check@localhost\r\nTo: qr-check@localhost\r\nSubject: qr\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            + "\r\n".join(urls) + "\r\n").encode()
    try:
        r = req.post(f"{base}/checkv2", data=body, headers={"Password": pw(), "IP": "127.0.0.1"},
                     timeout=RSPAMD_TIMEOUT_S)
        sy = (r.json() or {}).get("symbols") or {}
    except Exception as ex:  # noqa: BLE001 - optional
        log.warning("QR: rspamd URL check failed (%s)", type(ex).__name__)
        return []
    return sorted(set(sy) & BAD_URL_SYMBOLS)


def judge(eng: Any, raw: bytes | None, names: Iterable[str], mode: str) -> tuple[list[dict], list[tuple[str, str]]]:
    """(symbols, events) for one mail. Off -> nothing; shadow -> only
    TH_QR_TRIAL (0) + qr_trial with what 'on' would have given."""
    if mode not in ("shadow", "on"):
        return [], []
    links = urls_in(payloads(raw))
    if not links:
        return [], []
    bad = rspamd_bad(eng, links)
    syms: list[dict] = []
    if bad:
        syms.append({"n": SYMBOL_PHISH, "s": SCORE_PHISH, "o": [host_of(links[0])[:120], *bad[:2]]})
    else:
        reasons = [(u, r) for u in links if (r := suspicious_reason(u))]
        if reasons:
            u, r = reasons[0]
            syms.append({"n": SYMBOL_SUSPICIOUS, "s": SCORE_SUSPICIOUS, "o": [host_of(u)[:120], r]})
            if "TH_LURE_SUBJECT" in set(names or ()):
                syms.append({"n": SYMBOL_LURE, "s": SCORE_LURE, "o": [host_of(u)[:120]]})
    if not syms:
        return [], []
    detail = " ".join(f"{s['n']}+{s['s']:g}" for s in syms) + " " + json.dumps(syms[0]["o"], ensure_ascii=False)
    if mode == "shadow":
        return ([{"n": SYMBOL_TRIAL, "s": 0.0, "o": [f"+{sum(s['s'] for s in syms):g}", *syms[0]["o"][:2]]}],
                [(EVENT_TRIAL, detail[:300])])
    return syms, [("qr_hit", detail[:300])]

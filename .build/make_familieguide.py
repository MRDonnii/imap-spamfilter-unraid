#!/usr/bin/env python3
"""Render FAMILIEGUIDE.md to filter/familieguide.pdf (A4, Danish).

    .build/make-familieguide.sh            # or: .venv/bin/python .build/make_familieguide.py
    .venv/bin/python .build/make_familieguide.py --html /tmp/guide.html   # HTML only

A tiny Markdown converter (the subset the guide uses: headings,
paragraphs, bullet and numbered lists incl. one nested level, tables,
**bold** and `code`) builds a self-contained HTML page with print CSS; headless
Chrome prints it with --print-to-pdf. No network: the brand mark is
inlined as a data: URI. The guide must never contain mail addresses or
passwords - the script refuses to render one that does.
"""

from __future__ import annotations

import argparse
import base64
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "FAMILIEGUIDE.md"
TARGET = ROOT / "filter" / "familieguide.pdf"
MARK = ROOT / "filter" / "static" / "icon-192.png"
CHROME_CANDIDATES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(r"(?i)(adgangskode|password|kodeord)\s*[:=]\s*\S+")


class GuideError(Exception):
    pass


def check_private(text: str) -> None:
    """Refuse personal data: mail addresses or 'adgangskode: xyz'."""
    if EMAIL_RE.search(text):
        raise GuideError("FAMILIEGUIDE.md indeholder en mailadresse - fjern den først.")
    if SECRET_RE.search(text):
        raise GuideError("FAMILIEGUIDE.md ser ud til at indeholde en adgangskode - fjern den først.")


def inline(text: str) -> str:
    """Escape, then **bold** and `code`."""
    out = []
    for i, part in enumerate(re.split(r"(`[^`]+`)", text)):
        if i % 2:
            out.append(f"<code>{html.escape(part[1:-1])}</code>")
            continue
        esc = html.escape(part, quote=False)
        esc = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", esc)
        out.append(esc)
    return "".join(out)


_LIST_RE = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")


def _list_html(items: list[tuple[int, str, str]]) -> str:
    """items: (indent, marker, text) -> nested <ul>/<ol> (indent groups)."""
    def build(pos: int, indent: int) -> tuple[str, int]:
        kind = "ol" if items[pos][1][0].isdigit() else "ul"
        parts = [f"<{kind}>"]
        while pos < len(items) and items[pos][0] >= indent:
            ind, _m, text = items[pos]
            if ind > indent:
                sub, pos = build(pos, ind)
                parts[-1] = parts[-1][: -len("</li>")] + sub + "</li>"
                continue
            parts.append(f"<li>{inline(text)}</li>")
            pos += 1
        parts.append(f"</{kind}>")
        return "".join(parts), pos

    out, pos = [], 0
    while pos < len(items):
        chunk, pos = build(pos, items[pos][0])
        out.append(chunk)
    return "".join(out)


def _table_html(rows: list[str]) -> str:
    def cells(line: str) -> list[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    head = cells(rows[0])
    body = [cells(r) for r in rows[2:]] if len(rows) > 1 and re.match(r"^\s*\|?\s*:?-{3,}", rows[1]) else \
        [cells(r) for r in rows[1:]]
    th = "".join(f"<th>{inline(c)}</th>" for c in head)
    trs = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in body)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"


def md_to_html(text: str) -> tuple[str, str]:
    """-> (title, body_html). The first '# ' heading is the title."""
    lines = text.replace("\r\n", "\n").split("\n")
    title, out, para, i = "", [], [], 0

    def flush() -> None:
        if para:
            out.append("<p>" + "<br>".join(inline(p) for p in para) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            flush()
            i += 1
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            flush()
            level = len(m.group(1))
            if level == 1 and not title:
                title = m.group(2).strip()
            else:
                out.append(f"<h{level}>{inline(m.group(2).strip())}</h{level}>")
            i += 1
            continue
        if line.lstrip().startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.append(_table_html(rows))
            continue
        if _LIST_RE.match(line):
            flush()
            items = []
            while i < len(lines) and (m2 := _LIST_RE.match(lines[i])):
                items.append((len(m2.group(1).expandtabs(4)), m2.group(2), m2.group(3)))
                i += 1
            out.append(_list_html(items))
            continue
        para.append(line.strip())
        i += 1
    flush()
    return title, "\n".join(out)


CSS = """
@page { size: A4; margin: 16mm 17mm 16mm 17mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font-family: "Ubuntu Sans", "Ubuntu", "Noto Sans", "Liberation Sans", "DejaVu Sans", sans-serif;
  font-size: 10.6pt; line-height: 1.5; color: #1e293b; }
.top { display: flex; align-items: center; gap: 14px; padding: 16px 18px; border-radius: 16px; color: #fff;
  background: linear-gradient(120deg, #7c3aed 0%, #4f46e5 45%, #06b6d4 100%); margin-bottom: 18px; }
.top img { width: 46px; height: 46px; border-radius: 12px; flex: none; box-shadow: 0 2px 8px rgba(15,23,42,.25); }
.top h1 { margin: 0; font-size: 19pt; line-height: 1.2; font-weight: 700; letter-spacing: -.01em; }
.top p { margin: 3px 0 0; font-size: 10pt; opacity: .92; }
h2 { font-size: 13pt; margin: 18px 0 7px; padding-left: 10px; border-left: 4px solid #7c3aed; color: #0f172a;
  break-after: avoid; page-break-after: avoid; }
h3 { font-size: 11pt; margin: 14px 0 6px; color: #0f172a; break-after: avoid; }
p { margin: 0 0 8px; }
ul, ol { margin: 0 0 9px; padding-left: 21px; }
li { margin: 2px 0; }
li > ul, li > ol { margin: 3px 0 2px; }
strong { color: #0f172a; font-weight: 700; }
code { font-family: "Ubuntu Mono", "DejaVu Sans Mono", monospace; font-size: 9.6pt; background: #eef2ff;
  color: #3730a3; border-radius: 5px; padding: 1px 5px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; margin: 4px 0 10px; font-size: 9.8pt;
  border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; break-inside: avoid; }
th { text-align: left; background: #f1f5f9; color: #0f172a; font-weight: 700; padding: 7px 9px;
  border-bottom: 1px solid #cbd5e1; }
td { padding: 7px 9px; vertical-align: top; border-top: 1px solid #e2e8f0; }
tbody tr:first-child td { border-top: 0; }
th + th, td + td { border-left: 1px solid #e2e8f0; }
h2, table, ul, ol { break-inside: avoid-page; }
.end { margin-top: 16px; padding: 11px 14px; border-radius: 12px; background: #ecfdf5; border: 1px solid #a7f3d0;
  color: #065f46; font-weight: 700; display: flex; align-items: center; gap: 9px; break-inside: avoid; }
.end svg { width: 18px; height: 18px; flex: none; }
.foot { margin-top: 14px; font-size: 8.4pt; color: #64748b; text-align: center; }
"""

SHIELD = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
          'stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
          '<path d="m9 12 2 2 4-4"/></svg>')


def build_html(md_text: str, *, mark: Path | None = MARK) -> str:
    check_private(md_text)
    title, body = md_to_html(md_text)
    # The guide's last line ("Spamfilteret sletter aldrig noget.") becomes
    # the green closing box.
    closing = ""
    m = re.search(r"<p>([^<]*sletter aldrig[^<]*)</p>\s*$", body)
    if m:
        closing = f'<div class="end">{SHIELD}<span>{m.group(1)}</span></div>'
        body = body[: m.start()].rstrip()
    img = ""
    if mark is not None and mark.is_file():
        data = base64.b64encode(mark.read_bytes()).decode("ascii")
        img = f'<img src="data:image/png;base64,{data}" alt="">'
    head_title, _, sub = (title or "Spamfilteret").partition(" – ")
    return ("<!doctype html><html lang=\"da\"><head><meta charset=\"utf-8\">"
            f"<title>{html.escape(title or 'Spamfilteret')}</title><style>{CSS}</style></head><body>"
            f'<header class="top">{img}<div><h1>{html.escape(head_title)}</h1>'
            + (f"<p>{html.escape(sub[:1].upper() + sub[1:])}</p>" if sub else "") + "</div></header>"
            f"<main>{body}{closing}</main>"
            '<p class="foot">Spamfilteret · Hjælp i webadministrationen under “Hjælp”</p>'
            "</body></html>\n")


def find_chrome() -> str:
    env = os.environ.get("CHROME")
    if env:
        return env
    for name in CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    raise GuideError("Fandt ikke Google Chrome/Chromium (sæt CHROME=/sti/til/chrome).")


def render_pdf(html_text: str, target: Path, *, chrome: str | None = None) -> Path:
    chrome = chrome or find_chrome()
    with tempfile.TemporaryDirectory(prefix="familieguide-") as tmp:
        src = Path(tmp) / "guide.html"
        src.write_text(html_text, encoding="utf-8")
        out = Path(tmp) / "guide.pdf"
        cmd = [chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
               "--no-default-browser-check", f"--user-data-dir={Path(tmp) / 'profile'}",
               "--no-pdf-header-footer", "--hide-scrollbars", "--run-all-compositor-stages-before-draw",
               "--virtual-time-budget=2000", f"--print-to-pdf={out}", src.as_uri()]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        data = out.read_bytes()
    if not data.startswith(b"%PDF-"):
        raise GuideError("Chrome lavede ikke en PDF.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lav filter/familieguide.pdf ud fra FAMILIEGUIDE.md")
    ap.add_argument("--source", type=Path, default=SOURCE)
    ap.add_argument("--out", type=Path, default=TARGET)
    ap.add_argument("--html", type=Path, help="skriv kun HTML hertil (ingen PDF)")
    args = ap.parse_args(argv)
    try:
        page = build_html(args.source.read_text(encoding="utf-8"))
        if args.html:
            args.html.write_text(page, encoding="utf-8")
            print(f"HTML skrevet: {args.html}")
            return 0
        path = render_pdf(page, args.out)
    except (GuideError, OSError, subprocess.SubprocessError) as ex:
        print(f"Fejl: {ex}", file=sys.stderr)
        return 1
    print(f"PDF skrevet: {path} ({path.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

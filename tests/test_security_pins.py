"""2.11.1: the packages with known vulnerabilities in the pinned base image
(certifi, urllib3, Werkzeug, Flask, dnspython) are pinned to patched
versions, both images replace them, and the tests run against them."""
from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REQ = (ROOT / "filter" / "requirements.txt").read_text()
PINS = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)$", REQ, re.M))

# Lowest versions without a known vulnerability (OSV, 2026-11-21); the
# versions in the pinned upstream base are below every one of them.
FIXED = {"certifi": "2026.10.18", "urllib3": "2.8.0", "Werkzeug": "3.1.9", "Flask": "3.1.3", "dnspython": "2.9.2"}
BASE = {"certifi": "2026.5.20", "urllib3": "2.7.0", "Werkzeug": "3.1.8", "Flask": "3.1.2", "dnspython": None}


def _v(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in s.split("."))


@pytest.mark.parametrize("name", sorted(FIXED))
def test_pinned_at_or_above_the_fixed_version(name):
    assert name in PINS, name
    assert _v(PINS[name]) >= _v(FIXED[name])
    if BASE[name]:
        assert _v(BASE[name]) < _v(FIXED[name])


@pytest.mark.parametrize("name", sorted(FIXED))
def test_tests_run_against_the_pinned_version(name):
    # CI installs filter/requirements.txt, so this holds there. A local venv
    # made before 2.11.1 still has the base versions: refresh it with
    # `pip install -r filter/requirements.txt` (or put a directory with the
    # pinned wheels first on PYTHONPATH) - deliberately no skip outside CI.
    got = importlib.metadata.version(name)
    assert got == PINS[name], (
        f"{name} {got} is installed, requirements.txt pins {PINS[name]}: "
        "update the test environment with pip install -r filter/requirements.txt")


@pytest.mark.parametrize("path", [ROOT / "filter" / "Dockerfile.unraid", ROOT / "deploy" / "aio" / "Dockerfile"])
def test_images_replace_the_vulnerable_base_packages(path):
    text = path.read_text()
    grep = "grep -E '^(certifi|urllib3|Werkzeug|Flask)==' /tmp/requirements.txt > /tmp/requirements-sec.txt"
    assert grep in text
    assert 'test "$(wc -l < /tmp/requirements-sec.txt)" -eq 4' in text
    assert "--no-deps --only-binary=:all: \\\n        -r /tmp/requirements-sec.txt" in text
    assert "assert got == want, got" in text                 # installed versions checked at build time
    run = text[text.index(grep):]
    assert run.index("requirements-sec.txt; \\") < run.index("rm -f /tmp/requirements.txt")

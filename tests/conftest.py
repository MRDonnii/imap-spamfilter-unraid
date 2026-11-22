"""Suite-wide guards (2.5.0).

Push notifications must never leave the test process: the hard rule is no
real push service, ever. Engine hooks call push._kick(), which starts the
background sender when push.AUTO_WORKER is on; a sender left running by
one test would later pick up another test's queue (push's paths are module
globals) and POST with a real requests.Session. So, for every test:

  * push.AUTO_WORKER is off (tests that want the thread start it
    themselves with push.ensure_worker());
  * any sender thread still alive after the test is stopped;
  * requests refuses the push services' hosts outright (belt and braces:
    webpush.send turns that into a 'retry', nothing is sent).
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit

import pytest

# 2.13: phishsignals never asks a real domain registry (RDAP) in tests.
os.environ["SF_RDAP"] = "0"
# The local site configuration (config/site.yml on a server) comes from a
# neutral fixture: every module that reads siteconfig at import sees it.
os.environ["SITE_CONFIG_PATH"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site.yml")

PUSH_HOSTS = ("web.push.apple.com", "fcm.googleapis.com", "updates.push.services.mozilla.com",
              "notify.windows.com")


def _is_push_host(url: object) -> bool:
    try:
        host = (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return False
    return any(host == h or host.endswith("." + h) for h in PUSH_HOSTS)


@pytest.fixture(autouse=True)
def _push_stays_offline(monkeypatch):
    push = sys.modules.get("push")
    if push is not None:
        monkeypatch.setattr(push, "AUTO_WORKER", False)
    try:
        import requests
    except ImportError:  # pragma: no cover - requests is in the venv
        requests = None
    if requests is not None:
        real = requests.Session.request

        def guarded(self, method, url, *args, **kwargs):
            if _is_push_host(url):
                raise requests.ConnectionError("tests never contact a real push service")
            return real(self, method, url, *args, **kwargs)

        monkeypatch.setattr(requests.Session, "request", guarded)
    yield
    push = sys.modules.get("push")
    if push is not None and push.worker_alive():
        push.stop_worker()


@pytest.fixture(autouse=True)
def _trialmode_cache_per_test():
    """2.8: trialmode caches the Fra/Prøv/Til mode per feature for 30 s;
    every test starts with its own database, so it starts uncached."""
    tm = sys.modules.get("trialmode")
    if tm is not None:
        tm._CACHE.clear()
    yield

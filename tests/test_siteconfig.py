"""Local site configuration (config/site.yml, siteconfig.py, aio_render.py
site, Indstillinger -> Lokal opsætning).

  * no personal value lives in the program: the owner's domains, webshops,
    platform, forwarders and server name come from the local file;
  * a fresh install gets an empty file (setup_done: false); an update or a
    restart never writes, merges or resets an existing one;
  * a missing or broken file never crashes anything: empty values, a clear
    WebUI warning ("Lokal opsætning mangler"), and the contacts are not
    wiped for it;
  * the rspamd maps get the own domains at container start, the repository
    copies carry none.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
import siteconfig  # noqa: E402

AIO = ROOT / "deploy" / "aio"
FIXTURE = Path(__file__).with_name("site.yml")
sys.path.insert(0, str(AIO))
import aio_render  # noqa: E402
from test_ui_23 import env  # noqa: E402,F401 - the WebUI test env fixture

PY = sys.executable


# --------------------------------------------------------------- loading / validation
def test_fixture_is_the_loaded_config():
    assert siteconfig.site_path() == FIXTURE
    assert siteconfig.status() == "ok"
    assert siteconfig.server_name() == "Hjemmeserver"
    assert siteconfig.get_list("platform_domains") == ["vexar.example"]


def test_missing_file_is_empty_not_an_error(tmp_path):
    site = siteconfig.load(tmp_path / "nope.yml")
    assert site.status == "missing" and site.values == siteconfig.empty()
    assert site.list("mail_domains") == [] and site.get("server_name") == ""


def test_broken_yaml_is_invalid_not_a_crash(tmp_path):
    p = tmp_path / "site.yml"
    p.write_text("mail_domains: [a.example\n  : :\n")
    site = siteconfig.load(p)
    assert site.status == "invalid" and site.values == siteconfig.empty()
    p.write_text("- just\n- a list\n")
    assert siteconfig.load(p).status == "invalid"


def test_invalid_values_are_dropped_and_reported(tmp_path):
    p = tmp_path / "site.yml"
    p.write_text("mail_domains: [example.com, 'not a domain', '@example.org']\nadmin_email: nope\n"
                 "dns_forwarders: [192.168.1.1, evil]\nlan_url: 'javascript:alert(1)'\nunknown_key: 1\n")
    site = siteconfig.load(p)
    assert site.status == "ok"
    assert site.list("mail_domains") == ["example.com", "example.org"]
    assert site.get("admin_email") == "" and site.list("dns_forwarders") == ["192.168.1.1"]
    assert site.get("lan_url") == ""
    assert len(site.problems) == 4


def test_neutral_defaults_without_a_config(tmp_path):
    """A fresh install (empty config) names no server and no owner."""
    code = ("import siteconfig as s; print(s.brand(), '|', s.signature(), '|', s.msgid_domain(), '|', "
            "s.receipt_from(), '|', s.contacts_key_label().decode(), '|', s.own_domains())")
    env = dict(os.environ, SITE_CONFIG_PATH=str(tmp_path / "missing.yml"))
    out = subprocess.run([PY, "-c", code], cwd=ROOT / "filter", env=env, capture_output=True, text=True,
                         check=True).stdout.strip()
    assert out == ("Spamfilter | – Spamfilteret | spamfilter.invalid | Spamfilter <noreply@spamfilter.invalid> | "
                   "spamfilter-contacts-key: | []")


def test_save_keeps_other_keys_and_is_private(tmp_path):
    p = tmp_path / "site.yml"
    p.write_text("server_name: Gammel\nmail_domains: [example.com]\nfuture_key: behold\n")
    ok, problems = siteconfig.save({"server_name": "Ny"}, p)
    assert ok and not problems
    import yaml

    data = yaml.safe_load(p.read_text())
    assert data["server_name"] == "Ny" and data["mail_domains"] == ["example.com"] and data["future_key"] == "behold"
    assert (p.stat().st_mode & 0o777) == 0o600
    assert not [x for x in tmp_path.iterdir() if x.name.startswith(".site-")]


def test_save_refuses_invalid_values_and_leaves_the_file(tmp_path):
    p = tmp_path / "site.yml"
    p.write_text("server_name: Gammel\n")
    before = p.read_bytes()
    ok, problems = siteconfig.save({"mail_domains": "example.com\nikke et domæne"}, p)
    assert not ok and problems and p.read_bytes() == before


def test_seed_file_is_the_empty_config():
    assert (AIO / "site.seed.yml").read_text() == siteconfig.render_new()
    seed = siteconfig.load(AIO / "site.seed.yml")
    assert seed.status == "ok" and seed.get("setup_done") is False and seed.values == siteconfig.empty()


def test_rspamd_values_keep_the_platform_out_of_the_url_whitelist():
    v = siteconfig.rspamd_values(siteconfig.load(FIXTURE))
    assert v["surbl_whitelist"] == ["molt.example", "bynet.example", "pinsikbing.example", "gravisk.example"]
    assert "vexar.example" not in v["surbl_whitelist"]          # multi-tenant platform: never whitelisted
    assert v["brand_domains"] == ["molt.example", "bynet.example"]
    assert v["phishing_feed_exclusion"] == ["pinsikbing.example", "gravisk.example", "vexar.example"]
    assert set(v["phisharmy_exclusion"]) == {"pinsikbing.example", "gravisk.example", "vexar.example",
                                             "molt.example", "bynet.example"}
    assert v["dns_forwarders"] == ["192.168.1.1"]


# --------------------------------------------------------------- engine defaults
def test_engine_defaults_come_from_the_site_config():
    import campaigns
    import filter as eng
    import junkrules
    import lookalike
    import newsletters

    assert eng.DEFAULT_TRUSTED_FORWARDERS == ["mail.vexar.example", "203.0.113.109"]
    assert eng.DEFAULT_OWNER_PLATFORM_DOMAINS == ["vexar.example"]
    assert eng.DEFAULT_WEBSHOP_DOMAINS == ["pinsikbing.example", "gravisk.example", "vexar.example"]
    assert eng.DEFAULT_PROTECTED_DOMAINS == lookalike.DEFAULT_PROTECTED
    assert eng.RECEIPT_MSGID_DOMAIN == "hjemmeserver.spamfilter" and eng.OWN_MSGID_SUFFIX == "@hjemmeserver.spamfilter"
    assert junkrules.ALWAYS_THROUGH == ("vexar.example",) and newsletters.ALWAYS_INBOX_DOMAINS == ("vexar.example",)
    assert campaigns.ALWAYS_PROTECTED == ("vexar.example",)
    assert {"molt.example", "bynet.example"} <= campaigns.BRAND_DOMAINS


def test_engine_starts_without_a_site_config(tmp_path):
    """An update installed before the migration: the modules import, every
    owner list is empty, nothing raises."""
    code = ("import filter as e, campaigns as c, junkrules as j, newsletters as n, lookalike as l, mailcheck as m, "
            "dmarc as d, services as s, siteconfig as sc; "
            "print(sc.status(), e.DEFAULT_WEBSHOP_DOMAINS, e.DEFAULT_TRUSTED_FORWARDERS, j.ALWAYS_PROTECTED, "
            "n.ALWAYS_INBOX_DOMAINS, l.DEFAULT_PROTECTED, m.KNOWN_PROVIDERS, repr(d.DEFAULT_RUA), s.KNOWN_PROVIDERS)")
    env = dict(os.environ, SITE_CONFIG_PATH=str(tmp_path / "missing.yml"), STATE_DIR=str(tmp_path),
               PYTHONPATH=os.pathsep.join(p for p in (str(ROOT / "filter"), os.environ.get("PYTHONPATH", "")) if p))
    r = subprocess.run([PY, "-c", code], cwd=ROOT / "filter", env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-800:]
    assert r.stdout.strip() == "missing [] [] () () [] {} '' {}"


# --------------------------------------------------------------- WebUI warning
def test_banner_when_the_site_config_is_missing(monkeypatch):
    import ui_kit as kit

    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.Site(siteconfig.empty(), "missing"))
    html = kit.site_banner(True)
    assert "Lokal opsætning mangler" in html and "/settings/site" in html and "tone-bad" in html
    assert kit.site_banner(False) == ""                                   # a Bruger never sees it
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.Site(siteconfig.empty(), "invalid"))
    assert "Lokal opsætning kan ikke læses" in kit.site_banner(True)
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.Site(siteconfig.empty(), "ok"))
    assert "Gør opsætningen færdig" in kit.site_banner(True)              # fresh install: setup_done false
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.load(FIXTURE))
    assert kit.site_banner(True) == ""


def test_footer_names_the_server_from_the_site_config(monkeypatch):
    import ui_kit as kit

    assert kit._footer("2.13.0") == "Spamfilter 2.13.0 · Hjemmeserver"
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.Site(siteconfig.empty(), "missing"))
    assert kit._footer("2.13.0") == "Spamfilter 2.13.0"


# --------------------------------------------------------------- contacts are never wiped for it
def test_contacts_not_wiped_when_the_site_config_is_missing(tmp_path, monkeypatch):
    import sqlite3

    import contacts

    conn = sqlite3.connect(tmp_path / "db.sqlite")
    conn.execute("CREATE TABLE engine_state(key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)")
    conn.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, account TEXT, ts INTEGER, message_id TEXT, "
                 "event TEXT, detail TEXT)")
    contacts.ensure_schema(conn)
    contacts._KEY_CACHE.clear()
    contacts._KEY_CHECKED.clear()
    assert contacts.load_key(tmp_path, conn)                 # stores the key id (fixture label)
    conn.execute("INSERT INTO known_contacts(account, h, mask) VALUES('a', 'h1', 'x…@example.com')")
    conn.commit()
    contacts._KEY_CACHE.clear()
    contacts._KEY_CHECKED.clear()
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.Site(siteconfig.empty(), "missing"))
    assert contacts.load_key(tmp_path, conn)                 # other label -> other id, but no config: no wipe
    assert conn.execute("SELECT count(*) FROM known_contacts").fetchone()[0] == 1
    assert not conn.execute("SELECT 1 FROM events WHERE event='contacts_key_regenerated'").fetchone()
    contacts._KEY_CACHE.clear()
    contacts._KEY_CHECKED.clear()


# --------------------------------------------------------------- aio_render: never touches an existing file
def _fresh_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    (bundle / "rspamd").mkdir(parents=True)
    (bundle / "redis.conf.template").write_text("requirepass ${REDIS_PASSWORD}\n")
    (bundle / "rspamd" / "redis.conf.template").write_text('servers = "127.0.0.1:6379";\npassword = "${REDIS_PASSWORD}";\n')
    (bundle / "rspamd" / "worker-controller.inc.template").write_text('password = "${RSPAMD_PASSWORD}";\n')
    (bundle / "accounts.seed.yml").write_text((AIO / "accounts.seed.yml").read_text())
    (bundle / "site.seed.yml").write_text((AIO / "site.seed.yml").read_text())
    return bundle


def test_fresh_install_gets_the_empty_site_config(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    assert aio_render.init_appdata(app, _fresh_bundle(tmp_path), chown=False)
    site = app / "config" / "site.yml"
    assert site.read_text() == (AIO / "site.seed.yml").read_text()
    assert (site.stat().st_mode & 0o777) == 0o600
    assert siteconfig.load(site).get("setup_done") is False


def test_update_and_restart_leave_an_existing_site_config_byte_identical(tmp_path):
    """init (every container start), the site render and a second start on
    an EXISTING install: config/site.yml is read, never written."""
    app = tmp_path / "app"
    app.mkdir()
    bundle = _fresh_bundle(tmp_path)
    assert aio_render.init_appdata(app, bundle, chown=False)
    site = app / "config" / "site.yml"
    site.write_text(FIXTURE.read_text() + "# owner's own comment\nfuture_key: keep\n")
    os.utime(site, (1_700_000_000, 1_700_000_000))
    before = (site.read_bytes(), site.stat().st_mtime_ns, site.stat().st_mode)
    for _ in range(2):  # an update = a new container start, twice for good measure
        assert aio_render.init_appdata(app, bundle, chown=False) is False
        aio_render.render_site(site, tmp_path / "run" / "site")
        siteconfig.load(site)
    assert (site.read_bytes(), site.stat().st_mtime_ns, site.stat().st_mode) == before
    data = json.loads((tmp_path / "run" / "site" / "site.json").read_text())
    assert data["status"] == "ok" and "bynet.example" in data["brand_domains"]


def test_site_cli_with_a_missing_file_warns_and_succeeds(tmp_path, capsys):
    rc = aio_render.main(["site", "--config", str(tmp_path / "config" / "site.yml"), "--out", str(tmp_path / "out")])
    assert rc == 0
    assert "Lokal opsætning mangler" in capsys.readouterr().out
    data = json.loads((tmp_path / "out" / "site.json").read_text())
    assert data["status"] == "missing" and data["surbl_whitelist"] == [] and data["dns_forwarders"] == []
    assert not (tmp_path / "config" / "site.yml").exists()          # never created on an existing install


# --------------------------------------------------------------- rspamd maps get the own domains at start
def _local_d(tmp_path: Path) -> Path:
    src = tmp_path / "local.d"
    (src / "maps.d").mkdir(parents=True)
    for f in ("multimap.conf",):
        (src / f).write_text((ROOT / "rspamd" / "local.d" / f).read_text())
    for f in ("surbl-whitelist.inc.local", "th_brand_domains.map", "phishing_feed_exclusion.inc"):
        (src / "maps.d" / f).write_text((ROOT / "rspamd" / "local.d" / "maps.d" / f).read_text())
    (src / "redis.conf").write_text('servers = "spamfilter-redis:6379";\n')
    return src


def test_repository_maps_carry_no_own_domains():
    for f in ("surbl-whitelist.inc.local", "th_brand_domains.map", "phishing_feed_exclusion.inc"):
        text = (ROOT / "rspamd" / "local.d" / "maps.d" / f).read_text()
        for d in ("bynet", "molt", "pinsikbing", "gravisk", "vexar"):
            assert d not in text, (f, d)


def test_rspamd_render_adds_the_site_domains(tmp_path):
    src, dst = _local_d(tmp_path), tmp_path / "dst"
    aio_render.render_site(FIXTURE, tmp_path / "site")
    site = aio_render.load_site(tmp_path / "site" / "site.json")
    changes = aio_render.render_rspamd(src, dst, antivirus=False, site=site)
    surbl = (dst / "maps.d" / "surbl-whitelist.inc.local").read_text().splitlines()
    assert {"molt.example", "bynet.example", "pinsikbing.example", "gravisk.example"} <= set(surbl)
    assert "vexar.example" not in surbl
    brands = (dst / "maps.d" / "th_brand_domains.map").read_text().splitlines()
    assert {"molt.example", "bynet.example"} <= set(brands) and "pinsikbing.example" not in brands
    feed = (dst / "maps.d" / "phishing_feed_exclusion.inc").read_text().splitlines()
    assert "https://vexar.example/" in feed and "https://www.pinsikbing.example/" in feed
    mm = (dst / "multimap.conf").read_text()
    assert "(?!(www[.])?(pinsikbing[.]example|gravisk[.]example|vexar[.]example|molt[.]example|bynet[.]example|hubs[.]ly" in mm
    assert changes["multimap.conf"] == 5
    # the app dir copy is never modified
    assert "bynet" not in (src / "maps.d" / "surbl-whitelist.inc.local").read_text()


def test_rspamd_render_without_site_config_still_works(tmp_path):
    src, dst = _local_d(tmp_path), tmp_path / "dst"
    aio_render.render_site(tmp_path / "missing.yml", tmp_path / "site")
    site = aio_render.load_site(tmp_path / "site" / "site.json")
    aio_render.render_rspamd(src, dst, antivirus=False, site=site)
    assert (dst / "multimap.conf").read_text() == (src / "multimap.conf").read_text()
    assert (dst / "maps.d" / "surbl-whitelist.inc.local").read_text() == \
        (src / "maps.d" / "surbl-whitelist.inc.local").read_text()


def test_unbound_forwarder_from_the_site_config(tmp_path):
    base = tmp_path / "unbound.conf"
    base.write_text((ROOT / "deploy" / "unbound.conf").read_text())
    assert "forward-zone" not in "\n".join(l for l in base.read_text().splitlines() if not l.lstrip().startswith("#"))
    dst = tmp_path / "run" / "unbound.conf"
    aio_render.render_unbound(None, base, dst, tmp_path / "run",
                              site={"dns_forwarders": ["192.168.1.1", "bad;addr"]})
    text = dst.read_text()
    assert "forward-addr: 192.168.1.1" in text and "bad;addr" not in text
    # an app-dir forward-records file wins over the site config
    fwd = tmp_path / "fwd.conf"
    fwd.write_text('forward-zone:\n    name: "."\n    forward-addr: 192.168.1.53\n')
    aio_render.render_unbound(None, base, dst, tmp_path / "run", fwd, site={"dns_forwarders": ["192.168.1.1"]})
    assert "192.168.1.53" in dst.read_text() and "192.168.1.1" not in dst.read_text()


# --------------------------------------------------------------- the entrypoint wiring
def test_entrypoint_reads_the_site_config_as_the_filter_and_never_dies_on_it():
    text = (AIO / "sf-entrypoint").read_text()
    i_site = text.index('aio_render.py" site')
    i_rspamd = text.index('aio_render.py" rspamd')
    assert i_site < i_rspamd
    block = text[text.rindex("\n", 0, i_site - 40):i_rspamd]
    assert "as 10099 10099" in block and "||\n  log " in block and "die" not in block.split("||", 1)[1].split("\n")[1]
    assert '--site "$RUN_DIR/site/site.json"' in text
    assert "site.seed.yml" in (AIO / "lib-aio.sh").read_text()


@pytest.mark.parametrize("name", ["backup-and-verify.sh"])
def test_backup_verifies_the_site_config(name):
    text = (ROOT / "deploy" / name).read_text()
    assert 'test -s "$VERIFY/config/site.yml"' in text


# --------------------------------------------------------------- WebUI: Indstillinger -> Lokal opsætning
def _site_env(tmp_path, monkeypatch, request):
    import test_ui_23

    e = request.getfixturevalue("env")
    p = tmp_path / "site-ui.yml"
    p.write_text(FIXTURE.read_text())
    monkeypatch.setenv("SITE_CONFIG_PATH", str(p))
    monkeypatch.setattr(siteconfig, "CURRENT", siteconfig.CURRENT)   # a save reloads it: restored after the test
    return e, p, test_ui_23


def test_site_page_shows_and_saves_with_validation(tmp_path, monkeypatch, request):
    import dashboard
    from fakes_ui import post

    e, p, t = _site_env(tmp_path, monkeypatch, request)
    admin = t.client_for(e, "admin")
    html = t.body(admin.get("/settings/site"))
    assert "Lokal opsætning" in html and "bynet.example" in html and "Hjemmeserver" in html
    assert 'name="mail_domains"' in html and 'name="platform_domains"' in html
    before = p.read_bytes()
    r = post(admin, "/settings/site", {"mail_domains": "bynet.example\nikke et domæne", "server_name": "X"})
    assert r.status_code == 400 and not r.get_json()["ok"] and p.read_bytes() == before
    r = post(admin, "/settings/site", {"server_name": "Nyt navn", "mail_domains": "example.com\nexample.net",
                                       "admin_email": "admin@example.com", "domain_providers": "example.com = Udbyder"})
    assert r.get_json()["ok"], r.get_json()
    site = siteconfig.load(p)
    assert site.get("server_name") == "Nyt navn" and site.list("mail_domains") == ["example.com", "example.net"]
    assert site.get("domain_providers") == {"example.com": "Udbyder"} and site.get("setup_done") is True
    assert site.list("platform_domains") == ["vexar.example"]          # a field not posted is kept
    assert dashboard.RELOAD_FILE.exists()
    rec = t.audits(e, "site_config")[-1]
    assert rec["result"] == "ok" and "example.com" not in json.dumps(rec)   # key names, never values


def test_site_page_is_admin_only(tmp_path, monkeypatch, request):
    from fakes_ui import post

    e, p, t = _site_env(tmp_path, monkeypatch, request)
    anna = t.client_for(e, "anna")
    assert anna.get("/settings/site").status_code == 403
    before = p.read_bytes()
    assert post(anna, "/settings/site", {"server_name": "Hack"}).status_code == 403
    assert p.read_bytes() == before


def test_settings_page_links_to_the_site_card(tmp_path, monkeypatch, request):
    e, _p, t = _site_env(tmp_path, monkeypatch, request)
    html = t.body(t.client_for(e, "admin").get("/settings"))
    assert "Lokal opsætning" in html and "/settings/site" in html

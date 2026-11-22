"""'Byg Bayes op på ny' (services.bayes_rebuild_* + trainer) against the
REAL engine (filter.py), the RFC-accurate mailbox fake and the fake rspamd.

The rebuild switches every account to a NEW Bayes pool through the config
save path, archives the old pool's learned state (messages.learned_as,
learn_ledger, autolearn_log) per pool, and retrains from clean sources:
spam = the filter folder + provider spam folders + mail the old pool
learned as spam elsewhere; ham = only the users' own archive folders,
capped at ratio x spam. The old pool stays untouched in Redis; 'Gendan
tidligere Bayes' switches back. Nothing is ever moved or deleted."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services  # noqa: E402
import trainer  # noqa: E402
from fakes_services import make_message  # noqa: E402
from test_services import (  # noqa: E402,F401
    GIGA, SCAN, catch_spam, live, live_account, live_loop, live_mail, live_row,
)

ARCHIVE = ("INBOX.Arkiv", "INBOX.Arkiv.Kunder", "Arkiv 2024")
NEVER_HAM = ("Sent", "Sendte elementer", "Drafts", "Kladder", "Udbakke", "Outbox", "RSS Feeds",
             "Papirkurv", "Deleted Items", "Uønsket e-mail", "INBOX.spam", "Notes")


@pytest.fixture(autouse=True)
def fast_trainer(monkeypatch):
    monkeypatch.setattr(trainer, "MAX_PER_SECOND", 1e9)


class Saver:
    """dashboard.save_config stand-in: load, mutate, validate with the real
    engine, write, record the audit action."""

    def __init__(self, eng):
        self.eng = eng
        self.calls: list[tuple[str, str, str]] = []
        self.reject: str | None = None

    def __call__(self, mutator, actor, action, *, account="", detail=""):
        raw = yaml.safe_load(self.eng.CONFIG_PATH.read_text())
        if self.reject:
            raise ValueError(self.reject)
        result = mutator(raw)
        tmp = self.eng.CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))
        self.eng.load_account_configs(tmp)  # validation, raises on bad config
        tmp.replace(self.eng.CONFIG_PATH)
        self.calls.append((actor, action, detail))
        return result


def add(live, h, folder, msgid, *, days_ago=0.0, subject="Hej"):
    when = dt.datetime.fromtimestamp(live.clock.t - days_ago * 86400, dt.timezone.utc)
    return h.box.add(folder, make_message(msgid, subject=subject), internaldate=when)


def mailbox(live, caps=SCAN, *, spam=3, provider_spam=2, archive=(4, 3, 3), never_ham=1):
    """One mailbox with spam in Spamfilter + the provider's Junk, mail in the
    archive folders and in every folder that must never be ham."""
    folders = (*ARCHIVE, *NEVER_HAM, "Spamfilter")
    h = live_account(live, caps, extra_folders=folders)
    for i in range(spam):
        add(live, h, "Spamfilter", f"sf{i}@spam", days_ago=400 + i)  # any age
    for i in range(provider_spam):
        add(live, h, "Junk", f"pj{i}@spam", days_ago=i)
    for folder, n in zip(ARCHIVE, archive):
        tag = re.sub(r"\W", "", folder.lower())
        for i in range(n):
            add(live, h, folder, f"{tag}{i}@ham", days_ago=30 - i)
    for folder in ("INBOX", "Trash", *NEVER_HAM):
        tag = re.sub(r"\W", "", folder.lower())
        for i in range(never_ham):
            add(live, h, folder, f"{tag}{i}@never")
    h.box.writes.clear()
    return h


def only_filter_spam(h):
    for folder in ("INBOX.spam", "Uønsket e-mail"):
        h.box.folders.pop(folder, None)


def run_trainer(live):
    for _ in range(100):
        busy = trainer.run_pending_learn_list_once(engine=live.eng) is not None
        busy = trainer.run_pending_once(engine=live.eng) is not None or busy
        if not busy:
            return
    raise AssertionError("trainer never finished")


def learns(live, since=0):
    out = []
    for call in live.rspamd.learn_calls[since:]:
        m = re.search(rb"Message-ID: <([^>]+)>", call["data"])
        out.append((call["url"].rsplit("/", 1)[-1], call["headers"].get("Deliver-To"),
                    m.group(1).decode() if m else None))
    return out


def config(live):
    return yaml.safe_load(live.eng.CONFIG_PATH.read_text())


def db(live):
    conn = sqlite3.connect(live.eng.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Plan (dry run)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caps", [GIGA, SCAN], ids=["gigahost", "scannet"])
def test_plan_never_picks_inbox_sent_junk_or_trash_for_ham(live, caps):
    h = mailbox(live, caps)
    plan = services.bayes_rebuild_plan("admin", engine=live.eng)
    assert plan["ok"] and plan["code"] == "plan"
    assert (plan["pool_now"], plan["pool_new"]) == ("hjemmeserver", "hjemmeserver-r2")
    spam = {(s["folder"], s["kind"]): s["planned"] for s in plan["spam_sources"]}
    # Every spam folder counts (any age), also a mail client's own junk folder.
    assert spam == {("Spamfilter", "filter_junk"): 3, ("Junk", "provider_junk"): 2,
                    ("INBOX.spam", "spam_folder"): 1, ("Uønsket e-mail", "spam_folder"): 1}
    ham_folders = {s["folder"] for s in plan["ham_sources"]}
    assert ham_folders == set(ARCHIVE)
    for bad in ("INBOX", "Trash", "Junk", "Spamfilter", *NEVER_HAM):
        assert bad not in ham_folders, bad
    assert plan["expected_spam"] == 7 and plan["expected_ham"] == 10  # all 10 archive mails (<= 2 x 7)
    assert "Indbakke, Sendt, Uønsket" in plan["text"] and "hjemmeserver-r2" in plan["text"]
    assert any("mindst 200" in w for w in plan["warnings"])  # Bayes inactive until 200 of each
    assert h.box.writes == []  # LIST/STATUS only
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"  # nothing changed


def test_ham_folder_reason_units():
    acc = type("A", (), {"sent_folders": ["Sendt/Privat"], "spam_train": None, "trained_spam": None,
                         "ham_train": None, "trained_ham": None})()
    fmap = {"inbox": "INBOX", "junk": "INBOX.Spamfilter", "provider_junk": "INBOX.Junk",
            "trash": "INBOX.Trash"}

    def why(name, flags=()):
        return services.ham_folder_reason(acc, {"name": name, "delimiter": ".", "flags": list(flags)}, fmap)

    assert why("INBOX") == "inbox"
    assert why("INBOX.Spamfilter") == "junk" and why("INBOX.Spamfilter.Gemt") == "junk"
    assert why("INBOX.Junk") == "provider_junk" and why("INBOX.Trash.Gammel") == "trash"
    assert why("Sendt.Privat") == "sent"
    assert why("Arkiv", ["\\Sent"]) == "special" and why("Alle", ["\\All"]) == "special"
    for name in ("INBOX.Sent", "Sent Items", "Sendte elementer", "INBOX.Drafts", "Kladder", "Udkast",
                 "Outbox", "Udbakke", "RSS Feeds", "Papirkurv", "Deleted Messages", "Slettet post",
                 "Uønsket e-mail", "Junk E-Mail", "Bulk Mail", "INBOX.spam", "Arkiv.Junk", "Notes"):
        assert why(name) == "name", name
    for name in ("INBOX.Arkiv", "Arkiv 2024", "Kunder.Faktura", "INBOX.Ordrer.vexar-shop"):
        assert why(name) is None, name


def test_ham_is_capped_at_ratio_and_spread_newest_first(live):
    h = mailbox(live, spam=2, provider_spam=0, archive=(40, 3, 1))
    only_filter_spam(h)
    plan = services.bayes_rebuild_plan("admin", engine=live.eng)
    assert plan["expected_spam"] == 2 and plan["expected_ham"] == 4  # 1:2
    alloc = {s["folder"]: s["planned"] for s in plan["ham_sources"]}
    assert alloc == {"INBOX.Arkiv": 2, "INBOX.Arkiv.Kunder": 1, "Arkiv 2024": 1}  # spread, not one folder
    plan = services.bayes_rebuild_plan("admin", ratio=1.0, engine=live.eng)
    assert plan["expected_ham"] == 2
    bad = services.bayes_rebuild_plan("admin", ratio=10, engine=live.eng)
    assert bad["ok"] is False and bad["code"] == "invalid"


def test_plan_survives_an_unreachable_mailbox(live, monkeypatch):
    mailbox(live)
    monkeypatch.setattr(live.eng, "connect", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    plan = services.bayes_rebuild_plan("admin", engine=live.eng)
    assert plan["ok"] and plan["expected_spam"] == 0 and plan["errors"][0]["account"] == "anna"
    assert any("kunne ikke læses" in w for w in plan["warnings"])
    res = services.bayes_rebuild_start("admin", confirm=True, engine=live.eng, save_config=Saver(live.eng))
    assert res["ok"] is False and res["code"] == "nothing"
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"


# ---------------------------------------------------------------------------
# Start, relearn, status
# ---------------------------------------------------------------------------


def _old_pool_history(live, h):
    """The old pool learned the Spamfilter mail as spam and an archive mail
    as ham, a user dragged an archive mail to spam earlier (now in an
    archive folder), and the engine knows an 'unlearnable' mail."""
    with db(live) as conn:
        now = int(live.clock.t) - 10
        for mid, folder, kind, extra in (
                ("sf0@spam", "Spamfilter", "spam", {}),
                ("inboxarkiv0@ham", "INBOX.Arkiv", "ham", {}),
                ("inboxarkivkunder0@ham", "INBOX.Arkiv.Kunder", "unlearnable", {}),
                ("dragged@spam", "Arkiv 2024", "spam", {"our_action": "user_junked"})):
            cols = {"account": "anna", "message_id": mid, "first_seen": now, "last_seen": now,
                    "current_folder": folder, "learned_as": kind, "learned_at": now, **extra}
            conn.execute(f"INSERT INTO messages({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                         list(cols.values()))
            if kind in ("spam", "ham"):
                conn.execute("INSERT INTO learn_ledger(account, message_id, kind, learned_at, source) "
                             "VALUES('anna', ?, ?, ?, 'test')", (mid, kind, now))
        conn.execute("INSERT INTO autolearn_log(account, message_id, kind, score, outcome, created_at) "
                     "VALUES('anna', 'sf0@spam', 'spam', 22.0, 'learned', ?)", (now,))
    add(live, h, "Arkiv 2024", "dragged@spam")


def test_start_switches_pool_archives_state_and_relearns_into_the_new_pool(live):
    h = mailbox(live)
    _old_pool_history(live, h)
    saver = Saver(live.eng)
    assert services.bayes_rebuild_start("admin", confirm=False, engine=live.eng,
                                        save_config=saver)["code"] == "confirm"
    assert saver.calls == []
    res = services.bayes_rebuild_start("admin", confirm=True, engine=live.eng, save_config=saver)
    assert res["ok"] and res["code"] == "started", res
    assert (res["pool_old"], res["pool_new"]) == ("hjemmeserver", "hjemmeserver-r2")
    assert "ikke aktiv, før der er lært mindst 200" in res["text"]
    # Config switched through the save path (audited).
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver-r2"
    assert saver.calls[0][:2] == ("admin", "bayes_rebuild") and "hjemmeserver->hjemmeserver-r2" in saver.calls[0][2]
    # The old pool's learned state is archived per pool and reset.
    with db(live) as conn:
        arch = {(r["src"], r["message_id"], r["kind"]) for r in conn.execute(
            "SELECT * FROM bayes_pool_archive WHERE pool='hjemmeserver'")}
        assert ("messages", "sf0@spam", "spam") in arch and ("ledger", "inboxarkiv0@ham", "ham") in arch
        assert ("messages", "inboxarkivkunder0@ham", "unlearnable") in arch
        assert ("autolearn", "sf0@spam", "spam") in arch
        assert conn.execute("SELECT COUNT(*) FROM messages WHERE learned_as IS NOT NULL").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM learn_ledger").fetchone()[0] == 0
        # autolearn_log is kept: a mail judged automatically once is never offered again.
        assert conn.execute("SELECT COUNT(*) FROM autolearn_log").fetchone()[0] == 1
        assert conn.execute("SELECT status FROM bayes_rebuilds").fetchone()[0] == "running"
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "running" and st["pool"] == "hjemmeserver-r2" and st["can_restore"]
    assert "Genopbygning i gang" in st["text"]

    before = len(live.rspamd.learn_calls)
    run_trainer(live)
    got = learns(live, before)
    # Every learn went to the NEW identity - including mail the old pool knew.
    assert got and {ident for _u, ident, _m in got} == {"hjemmeserver-r2"}
    spam = {m for u, _i, m in got if u == "learnspam"}
    ham = {m for u, _i, m in got if u == "learnham"}
    assert spam == {"sf0@spam", "sf1@spam", "sf2@spam", "pj0@spam", "pj1@spam", "inboxspam0@never",
                    "uønsketemail0@never", "dragged@spam"}
    assert "inboxarkiv0@ham" in ham and "inboxarkivkunder0@ham" in ham  # already/unlearnable reset
    assert not any(m.endswith("@never") for m in ham) and "dragged@spam" not in ham
    assert len(ham) <= 2 * len(spam)
    assert h.box.writes == []  # read-only: nothing moved, flagged or deleted
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "done" and st["learned_spam"] == 8 and st["learned_ham"] == len(ham)
    assert st["percent"] == 100 and "Genopbygningen er færdig" in st["text"]
    assert "ikke aktiv endnu" in st["text"] and "200" in st["text"]
    with db(live) as conn:
        assert conn.execute("SELECT learned_as FROM messages WHERE message_id='sf0@spam'").fetchone()[0] == "spam"
        ev = [r[0] for r in conn.execute("SELECT event FROM events WHERE account='*' ORDER BY id")]
        assert "bayes_rebuild_started" in ev and "bayes_rebuild_done" in ev


def test_second_start_is_refused_while_running_and_pool_names_never_repeat(live):
    mailbox(live)
    saver = Saver(live.eng)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)["ok"]
    again = services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    assert again["ok"] is False and again["code"] == "running"
    run_trainer(live)
    assert services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)["ok"]
    plan = services.bayes_rebuild_plan("admin", engine=live.eng)
    assert (plan["pool_now"], plan["pool_new"]) == ("hjemmeserver", "hjemmeserver-r3")


def test_rejected_config_changes_nothing(live):
    mailbox(live)
    saver = Saver(live.eng)
    saver.reject = "ugyldig"
    res = services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    assert res["ok"] is False and res["code"] == "rejected"
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"
    with db(live) as conn:
        assert conn.execute("SELECT status FROM bayes_rebuilds").fetchone()[0] == "failed"
        assert conn.execute("SELECT COUNT(*) FROM train_jobs").fetchone()[0] == 0
    assert services.bayes_rebuild_status(engine=live.eng)["can_restore"] is False


def test_runtime_ham_cap_follows_the_spam_really_learned(live):
    h = mailbox(live, spam=3, provider_spam=0, archive=(10, 0, 0))
    only_filter_spam(h)
    res = services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    assert res["expected_spam"] == 3 and res["expected_ham"] == 6
    # Two spam mails vanish before the trainer gets to them.
    box = h.box.folders["Spamfilter"]
    for uid in sorted(box.msgs)[:2]:
        del box.msgs[uid]
    run_trainer(live)
    got = learns(live)
    assert sum(u == "learnspam" for u, _i, _m in got) == 1
    assert sum(u == "learnham" for u, _i, _m in got) == 2  # 2 x 1, not the planned 6


def test_rebuild_skips_our_own_notices_in_an_archive(live):
    h = mailbox(live)
    with db(live) as conn:
        conn.execute("INSERT INTO daily_receipts(account, message_id, day, kind, items, sent_at) "
                     "VALUES('anna', 'threat-anna-1-abc@hjemmeserver.spamfilter', '2026-10-22', 'threat', 1, 1)")
    add(live, h, "INBOX.Arkiv", "threat-anna-1-abc@hjemmeserver.spamfilter")
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    run_trainer(live)
    assert "threat-anna-1-abc@hjemmeserver.spamfilter" not in {m for _u, _i, m in learns(live)}


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_switches_back_and_brings_the_old_state_back(live):
    h = mailbox(live)
    _old_pool_history(live, h)
    saver = Saver(live.eng)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    run_trainer(live)
    n_learns = len(live.rspamd.learn_calls)
    assert services.bayes_restore_previous("admin", confirm=False, engine=live.eng,
                                           save_config=saver)["code"] == "confirm"
    res = services.bayes_restore_previous("admin", confirm=True, engine=live.eng, save_config=saver)
    assert res["ok"] and res["code"] == "restored" and res["pool"] == "hjemmeserver"
    assert "hjemmeserver-r2 ligger urørt" in res["text"]
    assert config(live)["defaults"]["bayes_user"] == "hjemmeserver"
    assert saver.calls[-1][:2] == ("admin", "bayes_restore")
    assert len(live.rspamd.learn_calls) == n_learns  # Redis untouched: no learn, no delete
    with db(live) as conn:
        rows = {r["message_id"]: r["learned_as"] for r in conn.execute(
            "SELECT message_id, learned_as FROM messages WHERE learned_as IS NOT NULL")}
        assert rows == {"sf0@spam": "spam", "inboxarkiv0@ham": "ham", "inboxarkivkunder0@ham": "unlearnable",
                        "dragged@spam": "spam"}
        assert {r[0] for r in conn.execute("SELECT message_id FROM learn_ledger")} == {
            "sf0@spam", "inboxarkiv0@ham", "dragged@spam"}
        assert conn.execute("SELECT COUNT(*) FROM autolearn_log").fetchone()[0] == 1
        # The rebuilt pool's state is archived too (a later rebuild never reuses it).
        assert conn.execute("SELECT COUNT(*) FROM bayes_pool_archive WHERE pool='hjemmeserver-r2'").fetchone()[0] > 5
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "restored" and st["pool"] == "hjemmeserver" and st["can_restore"] is False
    again = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert again["ok"] is False and again["code"] == "nothing"
    # The old pool's 'already learned' guard works again: no relearn.
    live_mail(live, h, "INBOX", "new@x", score=0.5)
    live_loop(live, h)
    acc = live.eng.load_account_configs(live.eng.CONFIG_PATH)[0]
    raw = make_message("sf0@spam")
    assert live.eng.learn_message(h.db, acc, raw, "spam", "sf0@spam") == "already"


def test_restore_cancels_the_rebuild_jobs(live):
    mailbox(live)
    saver = Saver(live.eng)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    res = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert res["ok"]
    with db(live) as conn:
        assert {r[0] for r in conn.execute("SELECT status FROM train_jobs")} == {"cancelled"}
    run_trainer(live)
    assert learns(live) == []


def test_restore_refuses_when_the_config_changed_since(live):
    mailbox(live)
    saver = Saver(live.eng)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    saver(lambda raw: raw["defaults"].update(bayes_user="egen-pulje"), "admin", "edit")
    res = services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    assert res["ok"] is False and res["code"] == "changed"
    assert config(live)["defaults"]["bayes_user"] == "egen-pulje"


# ---------------------------------------------------------------------------
# bayes_stats per pool
# ---------------------------------------------------------------------------


def test_bayes_stats_reports_the_active_pool_after_a_rebuild(live, monkeypatch):
    mailbox(live)
    totals = {"spam": 290, "ham": 1436, "users": 1}
    real_get = services.requests.get

    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/stat"):
            return type("R", (), {"status_code": 200, "text": "", "json": lambda self: {"statfiles": [
                {"symbol": "BAYES_SPAM", "revision": totals["spam"], "users": totals["users"]},
                {"symbol": "BAYES_HAM", "revision": totals["ham"], "users": totals["users"]}]}})()
        return real_get(url, headers=headers, timeout=timeout)

    monkeypatch.setattr(services.requests, "get", fake_get)
    st = services.bayes_stats(engine=live.eng)
    assert (st["pool"], st["spam_learned"], st["ham_learned"], st["counts_source"]) == (
        "hjemmeserver", 290, 1436, "rspamd")
    saver = Saver(live.eng)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    totals.update(spam=290 + 250, ham=1436 + 480, users=2)
    st = services.bayes_stats(engine=live.eng)
    assert (st["pool"], st["spam_learned"], st["ham_learned"], st["counts_source"]) == (
        "hjemmeserver-r2", 250, 480, "pool")
    assert st["active"] is True and "Bayes er aktiv" in st["text"]
    assert (st["all_pools_spam"], st["all_pools_ham"]) == (540, 1916)
    services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)
    totals.update(spam=540 + 10, ham=1916 + 4)
    st = services.bayes_stats(engine=live.eng)
    assert (st["pool"], st["spam_learned"], st["ham_learned"]) == ("hjemmeserver", 300, 1440)


def test_bayes_stats_text_when_the_new_pool_is_still_small(live, monkeypatch):
    mailbox(live)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    st = services.bayes_stats(engine=live.eng)
    assert st["pool"] == "hjemmeserver-r2"
    assert st["active"] is False


# ---------------------------------------------------------------------------
# Schema: additive and rollback-safe
# ---------------------------------------------------------------------------


def test_services_ddl_matches_the_engine_schema():
    import filter as engine

    def norm(sql):
        return [ln.split("--")[0].strip() for ln in sql.strip().splitlines() if ln.split("--")[0].strip()]

    assert norm(services.BAYES_REBUILD_DDL) == norm(engine.BAYES_REBUILD_SCHEMA)


def _git_engine(ref: str, tmp_path: Path, name: str):
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "show", f"{ref}:filter/filter.py"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    path = tmp_path / f"{name}.py"
    path.write_text(out.stdout)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("ref,version", [("v2.2", "2.2"), ("HEAD", "HEAD")])
def test_older_engines_work_on_a_rebuilt_database(live, tmp_path, monkeypatch, ref, version):
    h = mailbox(live)
    _old_pool_history(live, h)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    run_trainer(live)
    old = _git_engine(ref, tmp_path, f"filter_rb_{version.replace('.', '')}")
    if old is None:
        pytest.skip(f"{ref} source not available (no git history)")
    try:
        # HEAD is the committed engine: the same version as the working tree,
        # or the previous release while a version bump is not committed yet
        # (then this is exactly the rollback case). Never newer.
        if version == "HEAD":
            def vt(v):
                return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
            assert vt(old.VERSION) <= vt(live.eng.VERSION), (old.VERSION, live.eng.VERSION)
        else:
            assert old.VERSION.startswith(version)
        assert old.SCORE_VERSION == live.eng.SCORE_VERSION
        monkeypatch.setattr(old, "STATE_DIR", live.eng.STATE_DIR)
        monkeypatch.setattr(old, "DB_PATH", live.eng.DB_PATH)
        monkeypatch.setattr(old, "_now", lambda: live.clock.t)
        old.init_db()
        live.rspamd.install(monkeypatch, old)
        monkeypatch.setattr(old, "RSPAMD_PASSWORD", "x")
        acc = old.load_account_configs(live.eng.CONFIG_PATH)[0]
        assert old.bayes_identity(acc) == "hjemmeserver-r2"  # the config the rebuild wrote
        odb = old.Db("anna")
        assert odb.get_message("sf0@spam")["learned_as"] == "spam"  # rebuilt pool's state
        # A mail the rebuild did not relearn reads as 'not learned yet' and is POSTed.
        n = len(live.rspamd.learn_calls)
        assert old.learn_message(odb, acc, make_message("dragged@spam"), "spam", "dragged@spam",
                                 bypass_rate=True) == "already"
        live.clock.t += 7 * 86400
        assert old.learn_message(odb, acc, make_message("inboxinbox0@x"), "ham", "inboxinbox0@x",
                                 bypass_rate=True) == "learned"
        assert learns(live, n)[-1][:2] == ("learnham", "hjemmeserver-r2")
        odb.close()
        # And the current code reads it all again.
        live.eng.init_db()
        st = services.bayes_rebuild_status(engine=live.eng)
        assert st["code"] == "done" and st["can_restore"]
    finally:
        sys.modules.pop(f"filter_rb_{version.replace('.', '')}", None)


def test_pool_switch_is_additive_only(live):
    mailbox(live)
    with db(live) as conn:
        trainer.ensure_train_columns(conn)
        trainer.ensure_learn_list_schema(conn)
        cols_before = {t: [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
                       for t in ("messages", "learn_ledger", "autolearn_log", "train_jobs")}
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    with db(live) as conn:
        for t, cols in cols_before.items():
            assert [r[1] for r in conn.execute(f"PRAGMA table_info({t})")] == cols, t
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"bayes_rebuilds", "bayes_rebuild_jobs", "bayes_pool_archive"} <= tables


def test_rebuild_jobs_are_linked_and_ordered_spam_first(live):
    mailbox(live)
    res = services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    with db(live) as conn:
        rows = conn.execute("SELECT j.role, t.kind, t.folder, t.min_age_days, t.seen_only, t.provider_filter "
                            "FROM bayes_rebuild_jobs j JOIN train_jobs t ON t.id=j.job_id "
                            "WHERE j.job_type='train' ORDER BY t.id").fetchall()
    roles = [r["role"] for r in rows]
    assert roles == sorted(roles, key=lambda r: r != "spam")  # every spam job before any ham job
    assert all(r["role"] == r["kind"] for r in rows)
    assert all((r["min_age_days"], r["seen_only"], r["provider_filter"]) == (0, 0, "any") for r in rows)
    assert res["jobs"] == len(rows)
    with db(live) as conn:
        plan = json.loads(conn.execute("SELECT plan FROM bayes_rebuilds").fetchone()[0])
    assert plan["pool_new"] == "hjemmeserver-r2" and plan["expected_spam"] == res["expected_spam"]


def test_status_warns_when_rspamd_says_already_learned_for_everything(live):
    h = mailbox(live, spam=22, provider_spam=0, archive=(5, 0, 0))
    only_filter_spam(h)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))
    live.rspamd.learn_status = 208  # a learn cache that is not per Bayes user
    run_trainer(live)
    st = services.bayes_rebuild_status(engine=live.eng)
    assert st["code"] == "done" and st["learned_spam"] == 0
    assert st["warnings"] and "allerede lært" in st["warnings"][0] and "allerede lært" in st["text"]


def test_restore_stops_a_running_rebuild_job_before_the_next_learn(live, monkeypatch):
    h = mailbox(live, spam=5, provider_spam=0, archive=(0, 0, 0))
    only_filter_spam(h)
    saver = Saver(live.eng)
    services.bayes_rebuild_start("admin", engine=live.eng, save_config=saver)
    real = live.eng.learn_message
    seen = []

    def learn_then_restore(*a, **k):
        out = real(*a, **k)
        seen.append(a[4])
        if len(seen) == 2:  # the owner restores while the job runs
            assert services.bayes_restore_previous("admin", engine=live.eng, save_config=saver)["ok"]
        return out

    monkeypatch.setattr(live.eng, "learn_message", learn_then_restore)
    run_trainer(live)
    assert len(seen) == 2  # nothing learned after the restore
    with db(live) as conn:
        assert conn.execute("SELECT status FROM train_jobs").fetchone()[0] == "cancelled"


def test_bayes_stats_says_so_when_the_pool_numbers_are_unknown(live, monkeypatch):
    mailbox(live)
    state = {"up": False}
    real_get = services.requests.get

    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/stat"):
            if not state["up"]:
                raise services.requests.ConnectionError("down")
            return type("R", (), {"status_code": 200, "text": "", "json": lambda self: {"statfiles": [
                {"symbol": "BAYES_SPAM", "revision": 600, "users": 2},
                {"symbol": "BAYES_HAM", "revision": 1500, "users": 2}]}})()
        return real_get(url, headers=headers, timeout=timeout)

    monkeypatch.setattr(services.requests, "get", fake_get)
    assert services.bayes_rebuild_start("admin", engine=live.eng, save_config=Saver(live.eng))["ok"]
    state["up"] = True
    st = services.bayes_stats(engine=live.eng)
    assert st["pool"] == "hjemmeserver-r2" and st["counts_source"] == "all_pools"
    assert "alle Bayes-puljer tilsammen" in st["text"]

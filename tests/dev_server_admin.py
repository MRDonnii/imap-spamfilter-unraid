"""Local preview of the WHOLE web UI incl. the administration pages.

    .venv/bin/python tests/dev_server_admin.py [--port 8099] [--state /tmp/sf-dev-admin]

Reuses UI-CORE's tests/dev_server.py seed (mail data, statuses, rules) and
adds what the admin pages need: a real accounts.yml (the YAML-backed fake
engine validates every write), IMAP secrets, folders, training and
calibration jobs, host-status/backup data, events and audit records.
2.3: a mail server (DevSMTP prints every mail instead of sending it;
--no-smtp previews without one) and 'Kode på mail' for inge and sofie.
Log in as admin / korrekt-hest-batteri-42. Never touches /state.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dev_server  # noqa: E402
from fakes_ui import TEST_PASSWORD, write_users  # noqa: E402
from fakes_ui_admin import (BACKUP, CALIBRATION_SCHEMA, HOST_STATUS, FakeAdminEngine,  # noqa: E402
                            FakeAdminServices)

SECRET = "imap-hemmelighed"
FOLDERS = {
    "gigahost": [{"name": "INBOX", "flags": [], "messages": 1832}, {"name": "Spamfilter", "flags": [], "messages": 41},
                 {"name": "Junk", "flags": [], "messages": 23}, {"name": "Sent", "flags": [], "messages": 912},
                 {"name": "Archive", "flags": [], "messages": 5210}, {"name": "Trash", "flags": [], "messages": 12}],
    "scannet": [{"name": "INBOX", "flags": [], "messages": 644}, {"name": "Junk", "flags": ["\\Junk"], "messages": 3},
                {"name": "Spamfilter", "flags": [], "messages": 18}, {"name": "Sent", "flags": ["\\Sent"], "messages": 210},
                {"name": "Trash", "flags": ["\\Trash"], "messages": 7}, {"name": "Arkiv", "flags": [], "messages": 1420}],
}
CAPS = {"gigahost": ["IMAP4rev1", "IDLE", "UIDPLUS", "LITERAL+", "NAMESPACE", "ID", "ENABLE"],
        "scannet": ["IMAP4rev1", "IDLE", "MOVE", "UIDPLUS", "SPECIAL-USE", "CONDSTORE", "QRESYNC", "ENABLE"]}


DISPLAY_NAMES = {"bynet": "Ole · BYnet", "molt": "Ole · Molt", "molt-inge": "Inge", "molt-handel": "Handel",
                 "molt-sofie": "Sofie"}


def seed_v21(state: Path, svc) -> None:
    """2.1 demo data: 'Tjek disse' candidates, a mailbox search, an undo job,
    a threshold suggestion, Inge's own spam."""
    conn = sqlite3.connect(state / "spamfilter.db")
    now = int(time.time())
    known = [("Lars Nielsen", "lars@nielsen-vvs.dk", "Tilbud på nyt fyr – revideret"),
             ("Søren Kristensen", "soren@kristensen.dk", "Billeder fra sommerhuset")]
    for i, (acc, disp, addr, subj, score, ago) in enumerate([
            ("bynet", "Lars Nielsen", "lars.nielsen@nielsen-vvs.dk", "Faktura 2291 – service på fyr", 10.6, 2400),
            ("bynet", "Molt Bogtrykkeri", "ordre@molt-bogtryk.dk", "Korrektur på visitkort", 11.2, 9000),
            ("molt-inge", "Søren Kristensen", "soren@kristensen.dk", "Re: Billeder fra sommerhuset", 10.4, 5200),
            ("molt-inge", "GLS Danmark", "noreply@gls-pakke.example", "Din pakke venter – bekræft adresse", 17.9, 1800),
            ("molt-inge", "Vinder-service", "claims@lotto-winners.example", "Du er udtrukket! Svar i dag", 21.3, 7300),
            ("molt-inge", "Apotek Online", "sales@cheap-pharma.example", "Sidste chance: 80 % rabat", 16.2, 86400 + 400),
            ("molt-inge", "MitID", "security@mitid-verify.example", "Bekræft din identitet nu", 19.4, 3 * 86400)]):
        t = now - ago
        syms = dev_server.SPAM_SYMBOLS[i % 3] if score > 13 else [
            {"n": "R_SPF_SOFTFAIL", "s": 0.6, "o": []}, {"n": "HFILTER_HOSTNAME_UNKNOWN", "s": 2.5, "o": []},
            {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}, {"n": "BAYES_SPAM", "s": 3.1, "o": ["91%"]}]
        dev_server.insert_message(conn, acc, f"<v21-{i}@{addr.split('@')[1]}>", our_action="moved_to_junk",
                                  our_score=score, current_folder="Spamfilter", sender=f"{disp} <{addr}>",
                                  subject=subj, symbols=syms, received_at=t, scanned_at=t + 2, first_seen=t,
                                  last_seen=t, envelope_from=addr, moved_to_junk_at=t + 3)
    for j, (disp, addr, subj) in enumerate(known):
        for k in range(3):
            t = now - (k + 2) * 86400 - j * 3000
            dev_server.insert_message(conn, "molt-inge" if j else "bynet", f"<known{j}{k}@{addr.split('@')[1]}>",
                                      our_action="none", our_score=-2.0, sender=f"{disp} <{addr}>", subject=subj,
                                      received_at=t, scanned_at=t, first_seen=t, last_seen=t, envelope_from=addr)
    conn.commit()
    conn.close()
    svc.live_folders = [
        {"name": "Spamfilter", "label": "Spamfilter", "kind": "filter_junk", "can_move": True, "truncated": False,
         "explanation": "Filterets egen mappe. Det, som spamfilteret har flyttet fra indbakken.",
         "hits": [{"uid": 411, "message_id": "<pn1@postnord.example>", "subject": "Din pakke er klar til afhentning",
                   "sender": "noreply@postnord.dk", "sender_name": "PostNord", "received_at": now - 3 * 3600,
                   "seen": False, "deleted": False, "known": True, "our_score": 10.4, "can_move": True}]},
        {"name": "Junk", "label": "Junk", "kind": "provider_junk", "can_move": True, "truncated": False,
         "explanation": "Udbyderens egen spam-mappe. Her lægger Gigahost eller Scannet post, de selv mener er spam.",
         "hits": [{"uid": 88, "message_id": "<pn2@postnord.example>", "subject": "PostNord: Ændret leveringstid",
                   "sender": "info@postnord.dk", "sender_name": "PostNord", "received_at": now - 26 * 3600,
                   "seen": True, "deleted": False, "known": False, "our_score": None, "can_move": True}]},
        {"name": "INBOX", "label": "Indbakken", "kind": "inbox", "can_move": False, "truncated": False,
         "explanation": "Mailen ligger allerede i indbakken – søg efter den i dit mailprogram.",
         "hits": [{"uid": 9921, "message_id": "<pn3@postnord.example>", "subject": "Kvittering for din forsendelse",
                   "sender": "noreply@postnord.dk", "sender_name": "PostNord", "received_at": now - 4 * 86400,
                   "seen": True, "deleted": False, "known": True, "our_score": -1.2, "can_move": False}]},
        {"name": "Trash", "label": "Papirkurv", "kind": "trash", "can_move": True, "truncated": False,
         "explanation": "Slettet post. Den bliver liggende, til papirkurven tømmes.", "hits": []},
    ]
    svc.suggestions = {"bynet": {
        "ok": True, "account": "bynet", "days": 14, "mode": "move", "current": 10.0, "recommended": 8.5,
        "change": "lower", "confidence": "medium",
        "text": "To spam-mails med score 8,7 og 9,1 slap igennem, og du har ikke frigivet noget over 7,9. "
                "Grænsen kan sænkes til 8,5.",
        "reasons": ["missed_below_current", "no_release_above"], "max_released_score": 7.9,
        "counts": {"scored": 412, "released": 1, "missed": 2, "would_move_current": 58, "would_move_recommended": 61},
        "histogram": [], "grid": []}}
    svc.undo_jobs = {1: {"id": 1, "account": "molt", "since_ts": now - 86400 * 2, "until_ts": now - 86400,
                         "learn": 0, "status": "done", "total": 14, "processed": 14, "moved": 13, "not_found": 1,
                         "skipped": 0, "failed": 0, "learned": 0, "error": "", "created_by": "admin",
                         "created_at": now - 86400, "started_at": now - 86400, "finished_at": now - 86390,
                         "percent": 100, "remaining": 0, "text": "13 mails er lagt tilbage i indbakken."}}


SPOOF = [{"n": "TH_BRAND_SPOOF", "s": 5.0, "o": []}, {"n": "TH_FROM_BRAND_NAME", "s": 0.0, "o": ["PostNord"]},
         {"n": "TH_LURE_SUBJECT", "s": 1.5, "o": ["Din pakke kunne ikke leveres"]},
         {"n": "TH_LURE_COMBO", "s": 4.0, "o": []}, {"n": "BAYES_HAM", "s": -2.97, "o": ["99.2%"]},
         {"n": "R_SPF_ALLOW", "s": -0.2, "o": []}, {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}]
HOMOGLYPH = [{"n": "TH_FROM_NAME_HOMOGLYPH", "s": 5.0, "o": ["ΕasyΡark"]},
             {"n": "TH_LURE_SUBJECT", "s": 1.5, "o": ["Dit betalingskort er udløbet"]},
             {"n": "TH_LURE_COMBO", "s": 4.0, "o": []}, {"n": "HFILTER_HOSTNAME_UNKNOWN", "s": 2.5, "o": []}]
ABUSED_TLD = [{"n": "TH_FROM_ABUSED_TLD", "s": 5.0, "o": ["lastchance.guru"]},
              {"n": "SUBJECT_HAS_EXCLAIM", "s": 0.1, "o": []}, {"n": "BAYES_SPAM", "s": 4.1, "o": ["97%"]},
              {"n": "URIBL_GREY", "s": 0.5, "o": ["lastchance.guru"]}]
AGED_SHOP = [{"n": "TH_AGED_SCAN", "s": 0.0, "o": ["alder=31t"]},
             {"n": "TH_PROVIDER_AUTH_PASS", "s": -1.0, "o": ["spamexperts", "dkim=pass", "dmarc=pass"]},
             {"n": "RSPAMD_URIBL", "s": 4.5, "o": ["vexar.example:url"]},
             {"n": "TH_OWN_PLATFORM_URIBL", "s": -4.5, "o": ["vexar.example"]},
             {"n": "PHISHED_EXCLUDED", "s": 0.0, "o": ["vexar.example"]},
             {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["vexar.example:s=k1"]}, {"n": "BAYES_HAM", "s": -3.0, "o": ["99%"]}]


def seed_v22(state: Path, svc) -> None:
    """2.2 demo data: phishing caught by the new rules, an aged scan, Reparér
    Bayes candidates, learn lists and a realistic weekly report preview."""
    import services as real_services

    conn = sqlite3.connect(state / "spamfilter.db")
    now = int(time.time())
    for acc, mid, sender, subj, score, syms, extra in (
            ("molt-inge", "<pn-fake@goteamup.com>", "PostNord <noreply@goteamup.com>",
             "Din pakke kunne ikke leveres – bekræft adresse", 13.8, SPOOF, {}),
            ("bynet", "<pn-fake2@goteamup.com>", "PostNord <noreply@goteamup.com>",
             "Din pakke kunne ikke leveres – bekræft adresse", 13.8, SPOOF, {}),
            ("molt-inge", "<ep@parkering-dk.top>", "ΕasyΡark <service@parkering-dk.top>",
             "Dit betalingskort er udløbet", 15.2, HOMOGLYPH, {}),
            ("bynet", "<lc@lastchance.guru>", "Mærk lindring <tilbud@lastchance.guru>",
             "Mærk lindring på sekunder – kun i dag!", 13.69, ABUSED_TLD, {})):
        t = now - 5400
        dev_server.insert_message(conn, acc, mid, our_action="moved_to_junk", our_score=score,
                                  rspamd_score=score, current_folder="Spamfilter", sender=sender, subject=subj,
                                  symbols=syms, received_at=t, scanned_at=t + 2, first_seen=t, last_seen=t,
                                  envelope_from=sender.split("<")[1].rstrip(">"), moved_to_junk_at=t + 60)
    t = now - 31 * 3600
    dev_server.insert_message(conn, "bynet", "<faktura-10-2026@vexar.example>", our_action="none", our_score=-4.2,
                              rspamd_score=1.3, current_folder="INBOX",
                              sender="Pinsikbing.example <ordre@vexar.example>", subject="Månedsfaktura oktober 2026",
                              symbols=AGED_SHOP, received_at=t, scanned_at=now - 600, first_seen=now - 600,
                              last_seen=now - 600, envelope_from="bounce@vexar.example", aged=1)
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, "
                 "'<faktura-10-2026@vexar.example>', 'own_domain_uribl', 'vexar.example udlignet 4.5')", (now - 600,))
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, "
                 "'<faktura-10-2026@vexar.example>', 'scan', 'score=-4.20 aged')", (now - 600,))
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('molt-inge', ?, NULL, "
                 "'ham_guard', 'autolearn phishing: TH_BRAND_SPOOF')", (now - 900,))
    conn.commit()
    conn.close()

    def cand(acc, mid, sender, subject, score, reasons, symbols=(), learned_as="ham"):
        return {"account": acc, "message_id": mid, "sender": sender, "subject": subject,
                "received_at": now - 40 * 86400, "folder": "INBOX", "score": score, "learned_as": learned_as,
                "learned_at": now - 30 * 86400, "reasons": list(reasons), "symbols": list(symbols),
                "text": "; ".join(reasons), "suggested_kind": "spam"}

    svc.repair_items = [
        cand("molt-inge", "<hn1@gave-nyborg.top>", "Harald Nyborg <gave@gave-nyborg.top>",
             "Din gratis gave fra Harald Nyborg venter", 6.1, ["phishing_rule", "user_marked_spam"],
             ["TH_BRAND_SPOOF", "TH_LURE_COMBO"]),
        cand("molt-sofie", "<ep1@parkering-dk.top>", "ΕasyΡark <service@parkering-dk.top>",
             "Dit betalingskort er udløbet", 7.4, ["phishing_rule"], ["TH_FROM_NAME_HOMOGLYPH", "TH_LURE_COMBO"]),
        cand("bynet", "<ig1@meta-hjaelp.xyz>", "Instagram <security@meta-hjaelp.xyz>",
             "Nogen forsøgte at logge ind på din konto", 9.4, ["phishing_rule", "provider_spam"],
             ["TH_BRAND_SPOOF", "TH_FROM_ABUSED_TLD"]),
        cand("molt", "<mp1@mobilepay-kunde.help>", "MobilePay <kunde@mobilepay-kunde.help>",
             "Din betaling er sat på pause", 8.8, ["phishing_rule"], ["TH_BRAND_SPOOF", "TH_FROM_ABUSED_TLD"]),
        cand("molt-handel", "<sk1@skat-retur.icu>", "Skattestyrelsen <retur@skat-retur.icu>",
             "Du har penge til gode – bekræft inden fredag", 11.2, ["phishing_rule"], ["TH_BRAND_SPOOF"]),
        cand("bynet", "<lotto@winners.example>", "Vinder-service <claims@winners.example>",
             "Du er udtrukket! Svar i dag", 5.3, ["user_marked_spam"]),
        cand("molt-inge", "<nl1@nyhed.plantorama.dk>", "Plantorama <nyhed@plantorama.dk>",
             "Ugens tilbud: 3 for 2 på stauder", 2.0, ["provider_spam"]),
        cand("molt", "<nl2@klaviyo.example>", "Webshop-nyt <news@klaviyo.example>",
             "Black week starter nu", 3.4, ["provider_spam"]),
    ]
    svc.learn_lists = {
        1: {"id": 1, "status": "done", "total": 33, "processed": 33, "learned": 29, "already": 1, "not_found": 2,
            "skipped": 0, "failed": 1, "note": "Reparér Bayes", "error": None, "created_by": "admin",
            "created_at": now - 2 * 86400, "percent": 100, "remaining": 0, "text": "Færdig."},
        2: {"id": 2, "status": "running", "total": 49, "processed": 18, "learned": 17, "already": 1, "not_found": 0,
            "skipped": 0, "failed": 0, "note": "Reparér Bayes", "error": None, "created_by": "admin",
            "created_at": now - 300, "percent": 36, "remaining": 31, "text": "Lærer mails …"}}
    items = []
    for i, c in enumerate(svc.repair_items[:5]):
        st = ("learned", "learned", "not_found", "learned", "failed")[i]
        items.append({"job_id": 1, "account": c["account"], "message_id": c["message_id"], "kind": "spam",
                      "status": st, "folder": "INBOX" if st != "not_found" else None, "previous": "ham",
                      "reason": "Phishing-regel ramte (" + ", ".join(c["symbols"]) + ")", "sender": c["sender"],
                      "subject": c["subject"],
                      "status_text": {"learned": "Lært", "not_found": "Mailen findes ikke længere",
                                      "failed": "Fejlede"}[st]})
    svc.learn_items = {1: items}

    def weekly_preview(account=None, week=None, *, full=None, engine=None):
        wk = week or "2026-W42"
        full = account in (None, "bynet") if full is None else full
        accs = [{"account": n, "name": DISPLAY_NAMES.get(n, n), "scanned": sc, "moved": mv, "released": rl,
                 "missed": ms, "zapped": 0, "prev": {"moved": pm}}
                for n, sc, mv, rl, ms, pm in (("bynet", 412, 58, 1, 2, 61), ("molt", 233, 19, 0, 1, 22),
                                              ("molt-handel", 518, 31, 0, 0, 29),
                                              ("molt-inge", 96, 14, 1, 0, 9))]
        if not full:
            accs = [a for a in accs if a["account"] == account] or accs[:1]
        data = {"week": wk, "prev_week": f"{wk[:6]}{int(wk[6:]) - 1:02d}", "span": "12.–18. oktober 2026",
                "accounts": accs, "top_blocked": [{"domain": "lastchance.guru", "n": 14}, {"domain": "goteamup.com", "n": 6}],
                "threats": None, "thresholds": [{"name": "Ole · BYnet", "text": "Grænsen 10 passer – ingen ændring."}],
                "drift": {"bayes": {"ok": True, "spam": 256, "ham": 1448}, "backup": {"available": True, "ok": True,
                                                                                      "age_s": 5 * 3600},
                          "login_problems": [], "circuit_stops": [], "own_domain_uribl": 3},
                "webshop": {"line": "Webshop-post: 37 mails fra pinsikbing.example/gravisk.example/vexar.example – 0 flyttet",
                            "moved_items": []}}
        r = real_services.render_weekly(data, full=full, preview=True)
        return {"ok": True, "code": "ok", "text": "", "week": wk, "full": full, "subject": r["subject"],
                "body_text": r["text"], "body_html": r["html"], "data": data}

    svc.weekly_preview = weekly_preview


def write_config(state: Path) -> Path:
    secrets = state / "imap-secrets"
    secrets.mkdir(mode=0o700, exist_ok=True)
    accounts = []
    for a in dev_server.ACCOUNTS:
        (secrets / a.name).write_text(SECRET)
        (secrets / a.name).chmod(0o600)
        entry = {"name": a.name, "enabled": a.enabled, "user": a.user, "imap_host": a.imap_host, "imap_port": 993,
                 "password_file": str(secrets / a.name), "mode": a.mode, "threshold": a.threshold, "junk": "Spamfilter"}
        if a.name in DISPLAY_NAMES:
            entry["display_name"] = DISPLAY_NAMES[a.name]
        accounts.append(entry)
    cfg = state / "accounts.yml"
    cfg.write_text(yaml.safe_dump({"defaults": {"bayes_user": "hjemmeserver", "junk_retention_days": 0,
                                                "trained_retention_days": 0, "poll_interval": 600},
                                   "accounts": accounts}, sort_keys=False, allow_unicode=True))
    return cfg


def seed_admin(state: Path) -> None:
    conn = sqlite3.connect(state / "spamfilter.db")
    conn.executescript(CALIBRATION_SCHEMA)
    now = int(time.time())
    rnd = random.Random(7)
    for a in dev_server.ACCOUNTS:
        kind = "gigahost" if "gigahost" in a.imap_host else "scannet"
        mm = "UIDPLUS" if kind == "gigahost" else "MOVE"
        conn.execute("UPDATE account_status SET folders=?, capabilities=?, move_method=?, idle_supported=1, "
                     "connected_since=COALESCE(connected_since, ?) WHERE account=?",
                     (json.dumps(FOLDERS[kind]), json.dumps(CAPS[kind]), mm, now - 86400 * 2 - rnd.randint(0, 9000), a.name))
    # Jobs: a running spam job, a queued ham job, finished calibrations, history.
    jobs = [
        ("bynet", "INBOX", "calibrate", 300, "done", 300, 300, 300, 0, 0, None, now - 86400),
        ("bynet", "Junk", "calibrate", 300, "done", 23, 23, 23, 0, 0, None, now - 86390),
        ("molt", "Junk", "spam", 300, "done", 3, 3, 2, 1, 0, None, now - 7200),
        ("molt-handel", "INBOX", "ham", 300, "failed", 0, 0, 0, 0, 0, "Login fejlede – opdater adgangskoden.", now - 5400),
        ("molt-inge", "Arkiv", "ham", 500, "cancelled", 500, 120, 118, 2, 0, None, now - 3000),
        ("bynet", "Junk", "spam", 300, "running", 23, 14, 12, 2, 0, None, now - 120),
        ("bynet", "Archive", "ham", 300, "queued", 0, 0, 0, 0, 0, None, now - 60),
    ]
    for (acc, folder, kind, mx, status, total, processed, learned, skipped, failed, err, created) in jobs:
        conn.execute("INSERT INTO train_jobs(account, folder, kind, max_messages, status, total, processed, learned, "
                     "skipped, failed, error, created_by, created_at, started_at, finished_at, seen_only, provider_filter) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (acc, folder, kind, mx, status, total, processed, learned, skipped, failed, err, "admin", created,
                      created + 5 if status != "queued" else None,
                      created + 600 if status in ("done", "failed", "cancelled") else None,
                      int(kind == "ham"), "provider_clean" if kind == "ham" else "any"))
    ham_subjects = [h[2] for h in dev_server.HAM]
    for i in range(300):
        s = round(rnd.gauss(-1.2, 2.6), 2)
        if i < 4:
            s = round(rnd.uniform(8.2, 11), 2)  # a few would-be false positives
        disp, addr, subj = dev_server.HAM[i % len(dev_server.HAM)]
        conn.execute("INSERT INTO calibration_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (1, "bynet", "INBOX", f"<cal{i}@x>", s, s - 0.5, json.dumps(dev_server.HAM_SYMBOLS[:3]),
                      f"{disp} <{addr}>", ham_subjects[i % len(ham_subjects)] if i else subj, now - i * 3000,
                      int(rnd.random() > .1), 0, None))
    for i in range(23):
        disp, addr, subj, sc = dev_server.SPAM[i % len(dev_server.SPAM)]
        s = round(sc + rnd.uniform(-6.5, 2), 2)
        conn.execute("INSERT INTO calibration_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (2, "bynet", "Junk", f"<calj{i}@x>", s, s - 4, json.dumps(dev_server.SPAM_SYMBOLS[i % 3]),
                      f"{disp} <{addr}>", subj, now - i * 9000, 1, int(rnd.random() > .4), 6.1))
    events = [("bynet", "conn_ok", "metode=UIDPLUS idle=ja"), ("molt-handel", "login_failed", "LOGIN afvist (3. forsøg)"),
              ("molt", "folder_created", "Spamfilter"), ("bynet", "learn_spam", "job=6"), ("*", "reload_requested", "Genstart fra Drift actor=admin"),
              ("molt", "user_rescued", "Flyttet tilbage til INBOX"), ("bynet", "scan_failed", "rspamd timeout (1. forsøg)"),
              ("bynet", "scan_recovered", "efter 1 forsøg"), ("molt-inge", "safe_mode", "for mange ulæste ved start")]
    for i, (acc, ev, detail) in enumerate(events):
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (acc, now - i * 1700, None, ev, detail))
    conn.commit()
    conn.close()
    audit = [("admin", "login", "", "ok", ""), ("admin", "account_mode", "molt", "ok", "flag->move"),
             ("admin", "account_threshold", "molt", "ok", "8.0->7.5"), ("admin", "rule_add", "", "ok", "allow @familie.dk"),
             ("sofie", "login", "", "failed", ""), ("admin", "train_queue", "bynet", "ok", "job=6 spam Junk n=300"),
             ("system", "config_changed_externally", "", "detected", "sha256=4f1c09a2b77e1d0c")]
    with (state / "admin-audit.jsonl").open("a") as fh:
        for i, (actor, action, acc, res, detail) in enumerate(reversed(audit)):
            fh.write(json.dumps({"ts": now - (len(audit) - i) * 3600, "actor": actor, "ip": "192.168.1.42",
                                 "action": action, "account": acc, "result": res, "detail": detail},
                                ensure_ascii=False) + "\n")
    (state / "heartbeat").write_text(f"{now - 7} dev-boot")


class DevSMTP:
    """The dev server never sends real mail: every 'sent' mail is printed
    (so you can log in as a 'Kode på mail' user with the printed code)."""

    def __init__(self, host, port, timeout=None, context=None, **kw):
        self.host = host

    def ehlo(self, *a):
        return 250, b"ok"

    def has_extn(self, opt):
        return opt.lower() == "starttls"

    def starttls(self, context=None):
        return 220, b"ok"

    def login(self, user, password):
        return 235, b"ok"

    def send_message(self, msg, from_addr=None, to_addrs=None):
        body = msg.get_body(preferencelist=("plain",)).get_content().strip().splitlines()
        print(f"[dev-smtp] til {', '.join(to_addrs or [])}: {msg['Subject']} | {body[0] if body else ''}", flush=True)
        return {}

    def quit(self):
        return None

    def close(self):
        return None


def seed_v23(state: Path) -> None:
    """2.3 mail (B29): a configured mail server (DevSMTP - nothing leaves
    the machine), notification routes, a tested state, one Bruger with
    'Kode på mail' (inge) and one with both methods (sofie)."""
    import dashboard
    import mailer

    mailer.SMTP_CLASS = mailer.SMTP_SSL_CLASS = DevSMTP
    m = dashboard.mail()
    res = m.save_settings({"enabled": True, "host": "smtp.gigahost.dk", "port": "587", "security": "starttls",
                           "auth": "password", "username": "ole@bynet.example", "from_addr": "",
                           "from_name": "Spamfilter Hjemmeserver"}, password="dev-smtp-kode")
    assert res["ok"], res
    m.save_routes({"alert": {"on": True, "to": "ole@bynet.example"}, "digest": {"on": True, "to": "ole@bynet.example"},
                   "weekly": {"on": False, "to": ""}, "security": {"on": True, "to": "ole@bynet.example"}})
    m.send_test("ole@bynet.example", actor="dev")
    dashboard.twofa_mail_enable("inge", "inge@molt.example", actor="dev")
    dashboard.twofa_mail_enable("sofie", "sofie@molt.example", actor="dev")
    m.ensure_worker()


CONTACTS = {
    "bynet": [("lars@nielsen-vvs.dk", 7, 210), ("sofie@holm.dk", 23, 12), ("soren@kristensen.dk", 4, 40),
              ("ordre@molt-bogtryk.dk", 11, 30), ("support@pinsikbing.example", 41, 2), ("info@gravisk.example", 38, 3),
              ("bogholderi@revisor-aarhus.dk", 16, 25), ("kim@revisor-aarhus.dk", 3, 90),
              ("anna.berg@gmail.com", 9, 60), ("peter@hansen-el.dk", 2, 400), ("kontakt@kommune.dk", 1, 700),
              ("jens@fiskerforeningen.dk", 5, 120), ("salg@grossisten.dk", 27, 8), ("hanne@familie.dk", 61, 1)],
    "molt-inge": [("soren@kristensen.dk", 12, 5), ("mor@familie.dk", 88, 1), ("formand@golfklub.dk", 6, 33),
                   ("tandlaege@smil.dk", 2, 150)],
}
TRUST_HAM = [
    ("bynet", "kc1@nielsen-vvs.dk", "Lars Nielsen <lars@nielsen-vvs.dk>", "Re: Tilbud på nyt fyr – revideret", -3.4,
     [{"n": "TH_KNOWN_CONTACT", "s": -4.0, "o": ["l…@nielsen-vvs.dk", "sendt=7", "senest=2026-03"]},
      {"n": "TH_REPLY", "s": 0.0, "o": ["l…@nielsen-vvs.dk", "sendt=2026-10-12", "loft -6"]},
      {"n": "DMARC_POLICY_ALLOW", "s": -0.5, "o": ["nielsen-vvs.dk", "none"]},
      {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["nielsen-vvs.dk:s=k1"]}, {"n": "BAYES_HAM", "s": -1.9, "o": ["91%"]},
      {"n": "HTML_SHORT_LINK_IMG_1", "s": 1.1, "o": []}]),
    ("bynet", "est1@datamail.example", "Datamail <faktura@datamail.example>", "Faktura 88213 – oktober", 1.2,
     [{"n": "TH_ESTABLISHED", "s": -2.0, "o": ["n=14", "siden=2021"]}, {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["datamail.example"]},
      {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}, {"n": "HFILTER_HOSTNAME_UNKNOWN", "s": 2.5, "o": []}]),
    ("bynet", "fc1@nyt-firma.dk", "Nyt Firma ApS <hej@nyt-firma.dk>", "Samarbejde om webshop?", 4.1,
     [{"n": "TH_FIRST_CONTACT", "s": 1.0, "o": ["nyt-firma.dk"]}, {"n": "R_SPF_ALLOW", "s": -0.2, "o": []},
      {"n": "BAYES_SPAM", "s": 2.6, "o": ["71%"]}, {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}]),
    ("bynet", "ru1@kunde.example", "Kunde <kunde@kunde.example>", "Re: Din ordre 1042", 6.3,
     [{"n": "TH_REPLY_UNVERIFIED", "s": 0.0, "o": ["k…@kunde.example", "sendt=2026-10-02"]},
      {"n": "R_SPF_SOFTFAIL", "s": 0.6, "o": []}, {"n": "BAYES_SPAM", "s": 3.9, "o": ["88%"]},
      {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}]),
]
THREATS = [
    ("bynet", "virus1@billing.example", "Billing <billing@acc-billing.example>", "Faktura vedhæftet – betal i dag",
     19.6, "virus", "Win.Trojan.Agent-12345",
     [{"n": "CLAM_VIRUS", "s": 20.0, "o": ["Win.Trojan.Agent-12345"]}, {"n": "MIME_BAD_ATTACHMENT", "s": 1.0, "o": []}]),
    ("bynet", "phish1@mitid-login.example", "MitID <noreply@mitid-login.example>", "Din MitID er spærret",
     15.1, "phish", None,
     [{"n": "DBL_PHISH", "s": 7.5, "o": ["mitid-login.example"]}, {"n": "TH_LURE_SUBJECT", "s": 1.5, "o": []},
      {"n": "TH_BRAND_SPOOF", "s": 5.0, "o": []}]),
    ("molt-inge", "att1@pakke-dk.example", "GLS <info@pakke-dk.example>", "Pakkelabel og kvittering",
     22.4, "attachment", "Kvittering_GLS_2026_10_21_nr_884213.pdf.exe",
     [{"n": "TH_ATTACH_BLOCK", "s": 20.0, "o": ["Kvittering_GLS_2026_10_21_nr_884213.pdf.exe", "archive"]},
      {"n": "MIME_DOUBLE_BAD_EXTENSION", "s": 1.0, "o": []}, {"n": "R_SPF_SOFTFAIL", "s": 0.6, "o": []}]),
]


def seed_v23_ui(state: Path) -> None:
    """2.3 UI demo data (B13/B16/B17/B19): known contacts learned from Sent
    (hashed with a throw-away key in the dev state dir), one contact just
    removed after a spam verdict, trust labels on mails, threats in
    Spamfilter, a rescan catch, today's protection counters and an
    attachment exception. Never touches /state."""
    import contacts as c

    key = c.load_key(state, None, create=True)
    conn = sqlite3.connect(state / "spamfilter.db")
    c.ensure_schema(conn)
    now = int(time.time())
    for acc, people in CONTACTS.items():
        for addr, n, days in people:
            norm = c.normalize_address(addr)
            conn.execute("INSERT OR REPLACE INTO known_contacts(account, h, domain, mask, sent_count, first_sent_at, "
                         "last_sent_at, source, status) VALUES(?,?,?,?,?,?,?,'sent','active')",
                         (acc, c.hash_address(key, norm), norm.split("@")[1], c.mask(norm), n,
                          now - (days + 900) * 86400, now - days * 86400))
    # Removed by hand + removed after a spam verdict (attention item).
    demo = c.normalize_address("kim@revisor-aarhus.dk")
    conn.execute("UPDATE known_contacts SET status='demoted', status_at=?, status_by='bynet' WHERE account='bynet' "
                 "AND h=?", (now - 3 * 3600, c.hash_address(key, demo)))
    conn.execute("UPDATE known_contacts SET status='removed', status_at=?, status_by='admin' WHERE account='bynet' "
                 "AND h=?", (now - 9 * 86400, c.hash_address(key, c.normalize_address("kontakt@kommune.dk"))))
    for acc, done, total, msgs, complete in (("bynet", 1666, 1666, 1666, 1), ("molt-inge", 412, 412, 412, 1),
                                             ("molt", 1210, 1210, 1210, 1),
                                             ("molt-handel", 980, 2400, 980, 0)):
        conn.execute("INSERT OR REPLACE INTO contacts_sync(account, folder, kind, max_uid, total, messages, synced_at, "
                     "complete, grp) VALUES(?,?,?,?,?,?,?,?,?)",
                     (acc, "*", "account", 0, None, msgs, now - 1800 if complete else None, complete,
                      "molt.example" if acc.startswith("molt") else "bynet.example"))
        conn.execute("INSERT OR REPLACE INTO contacts_sync(account, folder, kind, max_uid, total, messages, synced_at, "
                     "complete) VALUES(?,?,?,?,?,?,?,?)", (acc, "Sent", "sent", done, total, done, now - 1800, complete))
    for acc, mid, sender, subj, score, syms in TRUST_HAM:
        t = now - 2 * 3600
        dev_server.insert_message(conn, acc, mid, our_action="none", our_score=score, rspamd_score=score + 4.0,
                                  current_folder="INBOX", sender=sender, subject=subj, symbols=syms, received_at=t,
                                  scanned_at=t + 2, first_seen=t, last_seen=t,
                                  envelope_from=sender.split("<")[1].rstrip(">"))
    for i, (acc, mid, sender, subj, score, threat, detail, syms) in enumerate(THREATS):
        t = now - (i + 1) * 2700
        dev_server.insert_message(conn, acc, mid, our_action="moved_to_junk", our_score=score, rspamd_score=score,
                                  current_folder="Spamfilter", sender=sender, subject=subj, symbols=syms,
                                  received_at=t, scanned_at=t + 2, first_seen=t, last_seen=t, moved_to_junk_at=t + 20,
                                  envelope_from=sender.split("<")[1].rstrip(">"), threat=threat, threat_detail=detail)
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     (acc, t + 2, mid, "threat_detected", f"{threat}: {detail or '-'}"))
    # A rescan catch (B19): delivered clean, DBL listed 3 hours later.
    t = now - 4 * 3600
    zsyms = [{"n": "DBL_SPAM", "s": 6.5, "o": ["kampagne-tilbud.example"]}, {"n": "BAYES_SPAM", "s": 3.4, "o": ["94%"]},
             {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []}]
    dev_server.insert_message(conn, "bynet", "zap1@kampagne.example", our_action="moved_to_junk", our_score=12.1,
                              rspamd_score=12.1, current_folder="Spamfilter",
                              sender="Kampagne <nyhed@kampagne-tilbud.example>", subject="Kun i dag: 70 % på alt",
                              symbols=zsyms, received_at=t, scanned_at=t + 2, first_seen=t, last_seen=t,
                              moved_to_junk_at=t + 3 * 3600 + 20, zapped_at=t + 3 * 3600 + 20,
                              envelope_from="nyhed@kampagne-tilbud.example")
    for ts, ev, det in ((t + 2, "scan", "score=6.80"), (t + 2700, "zap_rescore", "ny=- efter=45 min score=6.80->6.90"),
                        (t + 3 * 3600, "zap_move", "ny=DBL_SPAM efter=3 t score=6.80->12.10"),
                        (t + 3 * 3600 + 20, "moved_to_junk", "metode=UIDPLUS")):
        conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                     ("bynet", ts, "zap1@kampagne.example", ev, det))
    day = dev_server._day(0)
    for acc, metric, n in (("bynet", "known_contact", 9), ("bynet", "reply_detected", 3), ("bynet", "established", 6),
                           ("molt-inge", "known_contact", 2), ("bynet", "zapped", 1), ("bynet", "threat_detected", 2),
                           ("molt-inge", "threat_detected", 1), ("bynet", "first_contact", 14)):
        dev_server.bump(conn, acc, day, metric, n)
    conn.execute("INSERT OR IGNORE INTO attach_rules(account, pattern, note, created_by, created_at, hits, last_hit_at) "
                 "VALUES('bynet', '@revisor-aarhus.dk', 'Revisoren sender installationsfiler', 'admin', ?, 2, ?)",
                 (now - 20 * 86400, now - 5 * 86400))
    conn.commit()
    conn.close()


def seed_v23_followup(state: Path, svc, rebuild: str) -> None:
    """2.3 follow-up demo: a Straks-advarsel sent today (Oversigt card) and
    the 'Byg Bayes op på ny' state (--rebuild none|running|done|restored|warn)."""
    conn = sqlite3.connect(state / "spamfilter.db")
    dev_server.bump(conn, "bynet", dev_server._day(0), "threat_notice_sent", 1)
    now = int(time.time())
    conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES('bynet', ?, NULL, "
                 "'threat_notice_sent', 'items=2')", (now - 1500,))
    conn.commit()
    conn.close()
    st = svc._rebuild_state()
    if rebuild in ("running", "restored"):
        st["status"] = rebuild
    elif rebuild in ("done", "warn"):
        st["status"] = "running"
        warn = rebuild == "warn"
        st["status_override"] = {
            "ok": True, "code": "done", "rebuild_id": 1, "pool": "hjemmeserver-r1", "pool_old": "hjemmeserver",
            "pool_new": "hjemmeserver-r1", "created_at": now - 5 * 3600, "created_by": "admin",
            "finished_at": now - 1800, "expected_spam": 661, "expected_ham": 1322,
            "learned_spam": 3 if warn else 648, "learned_ham": 0 if warn else 1296, "percent": 100,
            "jobs": {"done": 6}, "bayes": {"ok": True, "spam": 3 if warn else 648, "ham": 0 if warn else 1296,
                                           "active": not warn, "counts_source": "pool"},
            "min_learns": 200, "missing_spam": 197 if warn else 0, "missing_ham": 200 if warn else 0,
            "can_restore": True,
            "warnings": (["Genopbygningen lærte ingen legitime, fordi rspamd svarede »allerede lært« (1.296 gange). "
                          "Filteret kører nu uden Bayes. Tryk »Gendan tidligere Bayes« for at gå tilbage til den "
                          "gamle."] if warn else []),
            "text": ("Genopbygningen er færdig: 3 spam og 0 legitime er lært i puljen hjemmeserver-r1." if warn else
                     "Genopbygningen er færdig: 648 spam og 1.296 legitime er lært i puljen hjemmeserver-r1. "
                     "Bayes er aktiv i puljen hjemmeserver-r1.")}
    if rebuild != "none":
        svc.bayes = dict(svc.bayes, pool="hjemmeserver-r1" if rebuild != "restored" else "hjemmeserver",
                         counts_source="pool")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--state", default="/tmp/sf-dev-admin")
    ap.add_argument("--trusted-proxies", default="", help="e.g. 127.0.0.1 to preview the tunnel status card")
    ap.add_argument("--external-url", default="", help="e.g. https://spam.example.dk")
    ap.add_argument("--no-smtp", action="store_true", help="2.3: preview without a mail server")
    ap.add_argument("--rebuild", default="none", choices=("none", "running", "done", "restored", "warn"),
                    help="2.3 follow-up: state of 'Byg Bayes op på ny'")
    args = ap.parse_args()
    state = Path(args.state)
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    cfg = write_config(state)
    import dashboard

    dashboard.configure_paths(state, cfg)
    dev_server.seed(state)
    seed_admin(state)
    dashboard.init_ui_db()
    for name in ("bynet", "molt"):
        dashboard.settings_set(f"golive:{name}", str(int(time.time()) - 86400))
    dashboard.settings_set("config_sha256", "dev")
    write_users(state, [("admin", TEST_PASSWORD, "admin"), ("sofie", TEST_PASSWORD, "molt-sofie"),
                        ("kontor", TEST_PASSWORD, "molt-handel|molt-inge"),
                        ("inge", TEST_PASSWORD, "molt-inge"), ("gaest", TEST_PASSWORD, "~none"),
                        # 2.3 screenshots: limited Brugere without two-step login
                        ("lone", TEST_PASSWORD, "molt-inge"), ("bent", TEST_PASSWORD, "molt-inge")])
    # 2.1 permissions: sofie/kontor keep the 2.0 defaults (all), inge may only
    # release, gaest sees nothing until a mailbox is assigned.
    dashboard.set_user_perms("inge", ["release"], "dev")
    dashboard.set_user_perms("gaest", [], "dev")
    dashboard.set_user_perms("lone", ["release", "rules", "see_messages"], "dev")
    dashboard.set_user_perms("bent", [], "dev")
    # 2.3 (owner request): bent may only log in from the home network.
    dashboard.set_login_scope("bent", "local", "dev")
    dashboard.record_login("sofie", "127.0.0.1")
    # 2.1 two-step login: sofie has it on, kontor must set it up (admin requirement).
    dashboard.twofa_confirm("sofie", dashboard.totp(dashboard.twofa_pending_secret("sofie") or ""), "dev")
    dashboard.twofa_set_required("kontor", True, "dev")
    dashboard.configure_proxies(args.trusted_proxies)
    if args.external_url:
        dashboard.settings_set("external_url", dashboard.normalize_external_url(args.external_url))
    dashboard.engine = FakeAdminEngine()
    host = dict(HOST_STATUS, ts=int(time.time()) - 140)
    svc = FakeAdminServices(state / "spamfilter.db", good_password=SECRET, host_status=host,
                            backup=dict(BACKUP, ts=int(time.time()) - 5 * 3600 - 600),
                            bayes={"ok": True, "spam_learned": 256, "ham_learned": 1448, "min_learns": 200, "users": 1})
    dashboard.services = svc
    seed_v21(state, svc)
    seed_v22(state, svc)
    seed_v23_ui(state)
    seed_v23_followup(state, svc, args.rebuild)
    dashboard.set_user_perms("inge", ["release", "rules"], "dev")
    if not args.no_smtp:
        seed_v23(state)
    dashboard.app.secret_key = "dev-only"
    dashboard.register_pages()
    print(f"http://127.0.0.1:{args.port}/accounts  (admin / {TEST_PASSWORD}; IMAP test password: {SECRET})")
    from waitress import serve

    serve(dashboard.app, host="127.0.0.1", port=args.port, threads=4, clear_untrusted_proxy_headers=False)


if __name__ == "__main__":
    main()

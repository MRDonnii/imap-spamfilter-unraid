"""Local preview of the web UI with realistic Danish demo data.

    .venv/bin/python tests/dev_server.py [--port 8099] [--state /tmp/sf-dev]

Seeds a throw-away STATE_DIR (5 accounts: one paused, one with failing
login), a users file (admin / sofie, password below) and serves the
dashboard on 127.0.0.1 with fake engine/services - no IMAP, no rspamd.
Never point this at a real state directory.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes_ui import (FakeAccount, FakeEngine, FakeServices, TEST_PASSWORD, bump, create_db,  # noqa: E402
                      insert_message, set_status, write_users)

ACCOUNTS = [
    FakeAccount("bynet", "ole@bynet.example", mode="move", threshold=10.0, imap_host="imap.gigahost.dk"),
    FakeAccount("molt", "ole@molt.example", mode="move", threshold=10.0, imap_host="mail.scannet.dk"),
    FakeAccount("molt-handel", "kontor@molt.example", mode="move", threshold=10.0, imap_host="mail.scannet.dk"),
    FakeAccount("molt-inge", "inge@molt.example", mode="move", threshold=10.0, imap_host="mail.scannet.dk"),
    FakeAccount("molt-sofie", "sofie@molt.example", mode="shadow", enabled=False, imap_host="mail.scannet.dk"),
]

HAM = [
    ("Mor", "mor@familie.dk", "Søndagsmiddag kl. 18?"),
    ("Danske Bank", "noreply@danskebank.dk", "Dit kontoudtog for oktober er klar"),
    ("SKAT", "noreply@skat.dk", "Din årsopgørelse er klar i TastSelv"),
    ("Lars Nielsen", "lars@nielsen-vvs.dk", "Tilbud på nyt fyr – revideret"),
    ("PostNord", "noreply@postnord.dk", "Din pakke er klar til afhentning"),
    ("Booking.com", "noreply@booking.com", "Ny reservation: 2 nætter, 14.–16. nov."),
    ("Sofie Holm", "sofie@holm.dk", "Re: Generalforsamling i grundejerforeningen"),
    ("e-Boks", "info@e-boks.dk", "Du har ny post fra Aarhus Kommune"),
    ("Netflix", "info@mailer.netflix.com", "Nyt på Netflix i denne uge"),
    ("Søren Kristensen", "soren@kristensen.dk", "Billeder fra sommerhuset"),
    ("Coop", "nyhedsbrev@coop.dk", "Ugens tilbud: 3 for 2 på kaffe"),
    ("GitHub", "noreply@github.com", "[anna/projekt] Pull request merged"),
]
SPAM = [
    ("Lotteri Vinder", "claims@lotto-winners.example", "TILLYKKE! Du har vundet 1.000.000 kr", 15.8),
    ("Apotek Online", "sales@cheap-pharma.example", "Billig medicin uden recept – 80 % rabat", 13.2),
    ("MitID Support", "security@mitid-verify.example", "Din MitID udløber i dag – bekræft nu", 17.4),
    ("PostNord", "track@postnord-dk.example", "Pakken kunne ikke leveres – betal 19 kr.", 12.9),
    ("Crypto Profit", "invest@btc-profit.example", "Tjen 25.000 kr om ugen hjemmefra", 14.1),
    ("Nordea", "no-reply@nordea-sikkerhed.example", "Usædvanlig aktivitet på din konto", 16.3),
    ("Ray-Ban Outlet", "shop@rb-outlet.example", "Solbriller fra 199 kr – kun i dag", 10.7),
    ("Dating", "hello@singles-near-you.example", "Anna (29) har sendt dig en besked", 11.9),
    ("Microsoft 365", "admin@m365-renew.example", "Din postkasse er fuld – opgrader nu", 9.6),
]
SPAM_SYMBOLS = [
    [{"n": "BAYES_SPAM", "s": 5.1, "o": ["99.97%"]}, {"n": "RBL_SPAMHAUS_ZEN", "s": 3.5, "o": ["127.0.0.4"]},
     {"n": "DMARC_POLICY_REJECT", "s": 2.0, "o": []}, {"n": "R_SPF_FAIL", "s": 1.0, "o": ["-all"]},
     {"n": "TH_PROVIDER_SPAM", "s": 4.0, "o": ["X-Spam: Yes"]}, {"n": "MIME_HTML_ONLY", "s": 0.2, "o": []},
     {"n": "ARC_NA", "s": 0.0, "o": []}, {"n": "RCVD_COUNT_ONE", "s": 0.0, "o": ["1"]}],
    [{"n": "URIBL_BLACK", "s": 7.5, "o": ["cheap-pharma.example"]}, {"n": "PHISHING", "s": 3.2, "o": []},
     {"n": "FROM_NEQ_ENVFROM", "s": 0.1, "o": []}, {"n": "R_DKIM_NA", "s": 0.0, "o": []},
     {"n": "HFILTER_HOSTNAME_UNKNOWN", "s": 2.5, "o": []}],
    [{"n": "FUZZY_DENIED", "s": 6.0, "o": ["1:f00d:0.98"]}, {"n": "SUBJ_ALL_CAPS", "s": 3.0, "o": []},
     {"n": "FREEMAIL_FROM", "s": 0.0, "o": ["gmail.com"]}, {"n": "R_SPF_SOFTFAIL", "s": 0.6, "o": []},
     {"n": "MID_RHS_NOT_FQDN", "s": 0.5, "o": []}],
]
HAM_SYMBOLS = [{"n": "DMARC_POLICY_ALLOW", "s": -0.5, "o": ["danskebank.dk", "reject"]},
               {"n": "R_DKIM_ALLOW", "s": -0.2, "o": ["danskebank.dk:s=sel1"]},
               {"n": "R_SPF_ALLOW", "s": -0.2, "o": ["+ip4:91.208.1.0/24"]},
               {"n": "BAYES_HAM", "s": -3.0, "o": ["98.20%"]}, {"n": "MIME_GOOD", "s": -0.1, "o": ["text/plain"]},
               {"n": "RCVD_TLS_ALL", "s": 0.0, "o": []}]


def seed(state: Path) -> None:
    db = state / "spamfilter.db"
    create_db(db)
    conn = sqlite3.connect(db)
    rnd = random.Random(42)
    now = int(time.time())
    folders = json.dumps([{"name": "INBOX", "flags": [], "messages": 1832},
                          {"name": "Spamfilter", "flags": [], "messages": 41},
                          {"name": "Junk", "flags": ["\\Junk"], "messages": 3}])
    set_status(conn, "bynet", "idle", junk_exists=1, move_method="UIDPLUS", connected_since=now - 86400 * 3,
               last_scan_at=now - 140, folders=folders, capabilities=json.dumps(["IMAP4rev1", "IDLE", "UIDPLUS"]))
    set_status(conn, "molt", "working", junk_exists=1, move_method="MOVE", last_scan_at=now - 20)
    set_status(conn, "molt-handel", "auth_failed", junk_exists=1,
               detail="Mailserveren afviser adgangskoden (3 forsøg). Næste forsøg om 24 min.",
               last_error="auth: LOGIN failed", last_error_at=now - 400, error_count=3)
    set_status(conn, "molt-inge", "idle", junk_exists=0, move_method="MOVE", last_scan_at=now - 3600)
    set_status(conn, "molt-sofie", "paused")
    names = [a.name for a in ACCOUNTS if a.enabled]
    n = 0
    for i in range(260):
        acc = rnd.choice(names)
        t = now - rnd.randint(60, 14 * 86400)
        n += 1
        if rnd.random() < 0.27:
            disp, addr, subj, score = rnd.choice(SPAM)
            score = round(score + rnd.uniform(-1.5, 1.5), 1)
            mode = next(a.mode for a in ACCOUNTS if a.name == acc)
            action = {"move": "moved_to_junk", "flag": "flagged", "shadow": "shadow_spam"}[mode]
            folder = "Spamfilter" if action == "moved_to_junk" else "INBOX"
            if rnd.random() < 0.18:
                action, folder, score = "provider_junk", "Spamfilter", None
            syms = rnd.choice(SPAM_SYMBOLS)
            insert_message(conn, acc, f"<{n}.spam@{addr.split('@')[1]}>", our_action=action, our_score=score,
                           rspamd_score=(score - 4.0) if score else None, current_folder=folder,
                           sender=f"{disp} <{addr}>", subject=subj, symbols=syms, received_at=t,
                           scanned_at=t + 2, first_seen=t, last_seen=t, sender_ip=f"185.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}",
                           envelope_from=addr, provider_flag=1 if action == "provider_junk" else rnd.choice([0, 1]),
                           provider_score=round(rnd.uniform(3, 9), 2), rspamd_action="add header",
                           origin="junk_poll" if action == "provider_junk" else "inbox_scan", size=rnd.randint(4000, 90000))
            if action == "moved_to_junk":
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                             (acc, t + 62, f"<{n}.spam@{addr.split('@')[1]}>", "moved_to_junk", "metode=UIDPLUS"))
                conn.execute("INSERT INTO events(account, ts, message_id, event, detail) VALUES(?,?,?,?,?)",
                             (acc, t + 2, f"<{n}.spam@{addr.split('@')[1]}>", "pending_move", f"score={score}"))
        else:
            disp, addr, subj = rnd.choice(HAM)
            score = round(rnd.uniform(-6, 6.5), 1)
            action = "none"
            if rnd.random() < 0.04:
                action, score = "manual_release", round(rnd.uniform(8, 10), 1)
            insert_message(conn, acc, f"<{n}.msg@{addr.split('@')[1]}>", our_action=action, our_score=score,
                           rspamd_score=score, sender=f"{disp} <{addr}>", subject=subj, symbols=HAM_SYMBOLS,
                           received_at=t, scanned_at=t + 2, first_seen=t, last_seen=t, envelope_from=addr,
                           sender_ip=f"91.208.{rnd.randint(1, 250)}.{rnd.randint(1, 250)}", provider_flag=0,
                           user_verdict="ham" if action == "manual_release" else None,
                           verdict_at=t + 3600 if action == "manual_release" else None, verdict_by="admin",
                           score_version=2 if rnd.random() > 0.08 else None, size=rnd.randint(4000, 200000))
    for acc in names:
        for d in range(14):
            day_scan = rnd.randint(25, 70) if acc != "molt-inge" else rnd.randint(5, 20)
            bump(conn, acc, _day(d), "scanned", day_scan)
            bump(conn, acc, _day(d), "spam_detected", rnd.randint(2, max(3, day_scan // 4)))
            bump(conn, acc, _day(d), "released", rnd.choice([0, 0, 0, 1]))
    bump(conn, "bynet", _day(0), "skipped_seen", 3)
    bump(conn, "bynet", _day(0), "skipped_no_msgid", 1)
    for acc, pat, kind, note, hits, force in [("*", "@familie.dk", "allow", "Familien", 41, 0),
                                              ("*", "@lotto-winners.example", "block", "", 12, 0),
                                              ("bynet", "lars@nielsen-vvs.dk", "allow", "VVS-firma – blev fanget", 3, 0),
                                              ("molt", "@btc-profit.example", "block", "Krypto-spam", 7, 0),
                                              ("*", "@danskebank.dk", "allow", "", 9, 0),
                                              ("*", "@webshop-platform.example", "allow",
                                               "Webshop-platform – ordrer og kontaktformularer", 23, 1)]:
        conn.execute("INSERT INTO sender_rules(account, pattern, kind, note, created_by, created_at, hits, last_hit_at, "
                     "force) VALUES(?,?,?,?,?,?,?,?,?)",
                     (acc, pat, kind, note or None, "admin", now - 86400 * 9, hits,
                      now - rnd.randint(300, 86400 * 3), force))
    conn.commit()
    conn.close()


def _day(offset: int) -> str:
    import ui_kit

    return ui_kit.today_str(offset)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--state", default="/tmp/sf-dev")
    args = ap.parse_args()
    state = Path(args.state)
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    cfg = state / "accounts.yml"
    cfg.write_text("defaults: {bayes_user: hjemmeserver}\naccounts: []\n")
    import dashboard

    dashboard.configure_paths(state, cfg)
    seed(state)
    dashboard.init_ui_db()
    write_users(state, [("admin", TEST_PASSWORD, "admin"), ("sofie", TEST_PASSWORD, "molt-sofie")])
    dashboard.engine = FakeEngine(ACCOUNTS)
    dashboard.services = FakeServices(state / "spamfilter.db",
                                      bayes={"ok": True, "spam_learned": 143, "ham_learned": 268,
                                             "min_learns": 200, "users": 1})
    dashboard.app.secret_key = "dev-only"
    try:
        dashboard.register_pages()
    except Exception as ex:  # noqa: BLE001 - ui_admin may be mid-development
        print("ui_admin not loaded:", type(ex).__name__, ex)
        import ui_mail  # noqa: F401
    print(f"http://127.0.0.1:{args.port}/  (admin / {TEST_PASSWORD})")
    from waitress import serve

    serve(dashboard.app, host="127.0.0.1", port=args.port, threads=4)


if __name__ == "__main__":
    main()

"""Drift -> "Krypteret backup" card (2.6, B3) - spamfilter.

Shows the nightly encrypted backup (backup.summary(): last run, last
success, archives on /backup, warnings), whether the backup key was ever
shown, and the host's off-site copy (offsite-status.json from
deploy/backup-offsite.sh). Read-only: backups are made by the filter every
night and by `sfctl backup-now`; the key is only ever shown by sfctl.
Rendered by ui_admin's /system page (admin only); never shows a secret.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import dashboard as ui
import ui_kit as kit
from ui_kit import h

log = logging.getLogger("dashboard.backup")


def _summary() -> dict[str, Any] | None:
    try:
        import backup  # noqa: PLC0415

        backup.configure(ui.STATE_DIR, ui.CONFIG_PATH)
        return backup.summary()
    except Exception as ex:  # noqa: BLE001 - the Drift page must render
        log.warning("backup summary failed: %s", type(ex).__name__)
        return None


def alert_html() -> str:
    """A Drift-page alert when the 48 h alarm is on (else '')."""
    s = _summary()
    if not s or not s.get("alert"):
        return ""
    return kit.alert("Der er ikke lavet en vellykket krypteret backup i over 48 timer. "
                     + str(s.get("error") or s.get("text") or ""), "bad", title="Backup mangler")


def card() -> str:
    import ui_admin as adm  # noqa: PLC0415 - registered by ui_admin; helpers live there

    s = _summary()
    title, sub = "Krypteret backup", "Hver nat fra kl. 02:30 til /backup (Unraid-arrayet)."
    if s is None:
        return kit.card('<p class="muted">Backup-status kan ikke læses lige nu.</p>', title=title, subtitle=sub)
    tone = str(s.get("tone") or "warn")
    pairs = [("Status", f'{kit.status_dot(tone)} {h(s.get("text") or "")}')]
    if s.get("ts"):
        pairs.append(("Seneste forsøg", h(f"{kit.fmt_ts(s['ts'])} ({adm._age_text(max(0, int(time.time() - s['ts'])))} siden)")))
    if s.get("last_ok_ts"):
        pairs.append(("Seneste vellykkede", h(f"{kit.fmt_ts(s['last_ok_ts'])} ({adm._age_text(s.get('age_s'))} siden)")))
    if s.get("archive"):
        pairs.append(("Arkiv", f'<span class="mono small">{h(s["archive"])}</span> · {h(adm._bytes(s.get("size")))}'))
    if s.get("mounted"):
        pairs.append(("Gemte backups", h(f"{kit.fmt_int(s.get('archives') or 0)} i {s.get('dest')} "
                                         "(14 dage + 8 uger)")))
    if s.get("error"):
        pairs.append(("Fejl", f'<span class="tone-bad">{h(str(s["error"])[:240])}</span>'))
    key = s.get("key") or {}
    if key.get("exists"):
        pairs.append(("Nøgle", h(f"id {key.get('key_id')} · "
                                 + ("vist " + kit.fmt_ts(key["shown_at"]) if key.get("shown_at") else "aldrig vist"))))
    off = s.get("offsite")
    if off:
        if off.get("skipped"):
            otxt, otone = f"slået fra ({off.get('skipped')})", "warn"
        elif off.get("ok") and off.get("stale"):
            otxt, otone = (f"{off.get('remote') or ''} · {adm._age_text(off.get('age_s'))} siden – "
                           "ældre end 48 timer (kører User Script Spamfilter-offsite?)"), "warn"
        elif off.get("ok"):
            otxt, otone = f"{off.get('remote') or ''} · {adm._age_text(off.get('age_s'))} siden", "ok"
        else:
            otxt, otone = f"fejlede: {str(off.get('error') or '')[:160]}", "bad"
        pairs.append(("Ud af huset", f'{kit.status_dot(otone)} {h(otxt)}'))
    else:
        pairs.append(("Ud af huset", '<span class="muted">ingen status (User Script Spamfilter-offsite)</span>'))
    dr = s.get("drill")
    if dr:
        if not dr.get("ok"):
            dtxt, dtone = f"fejlede {adm._age_text(dr.get('age_s'))} siden: {str(dr.get('error') or '')[:160]}", "bad"
        elif dr.get("overdue"):
            dtxt, dtone = f"seneste lykkedes {adm._age_text(dr.get('age_s'))} siden – over {dr.get('every_days')} dage", "warn"
        else:
            dtxt, dtone = (f"lykkedes {adm._age_text(dr.get('age_s'))} siden ({str(dr.get('archive') or '')[:80]}"
                           " hentet ud af huset og kontrolleret; se resultatets omfang)"), "ok"
        pairs.append(("Gendannelseskontrol efter download", f'{kit.status_dot(dtone)} {h(dtxt)}'))
        if dr.get('detail'):
            pairs.append(("Kontrollens omfang", h(str(dr['detail'])[:300])))
    elif off and not off.get("skipped"):
        pairs.append(("Gendannelseskontrol efter download", '<span class="muted">ikke kørt endnu (hver 30. dag efter kopien ud af huset)</span>'))
    extra = kit.alert("Gamle øvelser kontrollerede kun arkivet. Fra 2.15 starter den månedlige øvelse også "
                      "webapplikationen og Redis/Bayes i en midlertidig kopi uden mailarbejdere (sfctl backup-drill).", "info")
    for w in (s.get("warnings") or [])[:3]:
        extra += kit.alert(str(w)[:240], "warn")
    if not s.get("mounted"):
        extra += kit.alert("Containeren har ingen /backup-sti. Kør deploy/aio/update.sh (tilføjer "
                           "/mnt/user/backup/spamfilter) eller tilføj “Backup-placering” i Unraid-skabelonen. "
                           "Der skrives aldrig backup i app-mappen.", "warn", title="Ingen backup-placering")
    elif key.get("exists") and not key.get("shown_at"):
        extra += kit.alert("Backupnøglen er aldrig vist. Kør docker exec -it spamfilter sfctl backup-key show, og gem "
                           "den i din kode-manager – uden den kan en backup ikke gendannes på en ny maskine.", "warn")
    return kit.card(kit.kv_list(pairs) + extra, title=title, subtitle=sub)

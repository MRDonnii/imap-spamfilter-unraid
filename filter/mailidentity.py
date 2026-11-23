"""Local mail identities. Header IDs are routing hints, never proof of content.

An ordinary first Message-ID keeps its existing database key. Missing IDs,
reserved keys and conflicting deliveries receive a content-derived LOCAL key.
No header is added to mail. Transport headers and line endings may change in
transit; every original non-transport header and the MIME body remain bound.
"""
import hashlib
import re
import sqlite3

PREFIX = 'sf-local:'
SCHEMA = '''CREATE TABLE IF NOT EXISTS mail_identity (
 account TEXT NOT NULL, message_key TEXT NOT NULL, wire_id TEXT,
 fingerprint TEXT NOT NULL, PRIMARY KEY(account, message_key),
 UNIQUE(account, wire_id, fingerprint));
 CREATE INDEX IF NOT EXISTS idx_mail_identity_wire ON mail_identity(account, wire_id);'''
# These fields are inserted/rewritten by delivery infrastructure. Do not ignore
# arbitrary X-* fields: application markers must also be bound to the payload.
TRANSPORT = frozenset({'received', 'return-path', 'authentication-results', 'arc-seal',
 'arc-message-signature', 'arc-authentication-results', 'dkim-signature',
 'delivered-to', 'x-original-to', 'x-spam-status', 'x-spam-flag', 'x-spam-level',
 'x-spam-score', 'x-virus-scanned'})


def fingerprint(raw: bytes) -> str:
    data = raw.replace(b'\r\n', b'\n')
    head, sep, body = data.partition(b'\n\n')
    fields = re.split(rb'\n(?![ \t])', head)
    stable = []
    for field in fields:
        name, colon, value = field.partition(b':')
        if not colon or not re.fullmatch(rb'[!-9;-~]+', name):
            # A malformed header block may already contain body text.
            # Hash all bytes conservatively: never lowercase that text or
            # discard a body line merely because it resembles Received.
            return hashlib.sha256(data).hexdigest()
        if name.decode('ascii', 'replace').lower() not in TRANSPORT:
            stable.append(name.lower() + colon + value)
    return hashlib.sha256(b'\n'.join(stable) + b'\n\n' + body).hexdigest()


def bind(conn, account: str, wire_id: str | None, raw: bytes, *, legacy_exists=False) -> str:
    digest = fingerprint(raw)
    row = conn.execute('SELECT message_key FROM mail_identity WHERE account=? AND fingerprint=? '
                       'AND wire_id IS ?', (account, digest, wire_id)).fetchone()
    if row:
        return str(row[0])
    conflict = bool(wire_id and conn.execute('SELECT 1 FROM mail_identity WHERE account=? '
                                            'AND message_key=?', (account, wire_id)).fetchone())
    safe_wire = bool(wire_id and len(wire_id) <= 500 and wire_id.isascii()
                     and not re.search(r'[\x00-\x20\x7f"\\]', wire_id))
    key = (wire_id if safe_wire and not wire_id.startswith(PREFIX) and not conflict and not legacy_exists
           else PREFIX + digest)
    for candidate in (key, PREFIX + digest):
        conn.execute('INSERT OR IGNORE INTO mail_identity VALUES(?,?,?,?)',
                     (account, candidate, wire_id, digest))
        # Another connection may have bound the header ID after our SELECT.
        # Return only a key that actually belongs to this payload, including
        # when the competing writer chose a different key for the same mail.
        stored = conn.execute('SELECT message_key FROM mail_identity WHERE account=? AND fingerprint=? '
                              'AND wire_id IS ?', (account, digest, wire_id)).fetchone()
        if stored:
            return str(stored[0])
    raise sqlite3.IntegrityError('mail identity could not be bound safely')


def binding(conn, account: str | None, key: str):
    if account is not None:
        return conn.execute('SELECT wire_id, fingerprint FROM mail_identity WHERE account=? AND message_key=?',
                            (account, key)).fetchone()
    rows = conn.execute('SELECT DISTINCT wire_id, fingerprint FROM mail_identity WHERE message_key=?',
                        (key,)).fetchall()
    return rows[0] if len(rows) == 1 else None

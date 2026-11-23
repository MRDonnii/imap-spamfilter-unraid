"""Read-only, mailbox-scoped follow-up of explicit spam judgements.

A bounded convenience sample, not accuracy or proof of a common campaign.
Uses the FIRST scan trace; later AI/campaign decisions are not relabelled as
missed spam. No message bodies, subjects, identifiers or new rules in output.
"""
import json
from collections import Counter, defaultdict
from email.utils import parseaddr

LIMIT = 500
NOTICE = ('Kun gemte, seneste spamrettelser; ikke samlet træfsikkerhed. Første scanning kan være '
          'fulgt af AI eller en senere flytning. Samme domæne beviser ikke samme spamkampagne. '
          'Ingen regler eller grænser ændres.')
LABELS = {
    'allow': 'En tilladelsesregel gjaldt ved første scanning; tjek reglen under Tjek disse.',
    'sticky_ham': 'En tidligere frigivelse gjaldt ved første scanning; tjek om afsenderens indhold har ændret sig.',
    'below_threshold': 'Scoren var under grænsen ved første scanning; behold grænsen og følg gentagelserne.',
    'first_scan_spam': 'Første scanning fandt allerede spam; rettelsen beviser ikke en overset mail.',
    'unknown': 'Der mangler et brugbart første scanningsspor; årsagen kan ikke fastslås.',
}


def summarize(conn, accounts, since, until, *, limit=LIMIT, authenticated=None):
    """Explicit allowlist; latest human verdict wins, each content key once.

    Period refers to latest correction, not delivery. Omitted/deleted history
    cannot be reconstructed. Limit+1 makes truncation visible per mailbox.
    """
    if not 1 <= limit <= LIMIT:
        raise ValueError('Ugyldig prøvegrænse.')
    result = []
    for account in sorted(set(accounts)):
        rows = conn.execute('''SELECT m.sender,m.symbols,m.verdict_at,
            (SELECT snapshot FROM decision_traces d WHERE d.account=m.account
             AND d.message_key=m.message_id AND d.stage='scan' ORDER BY d.id LIMIT 1) AS snapshot
            FROM messages m
            WHERE m.account=? AND m.user_verdict='spam' AND m.verdict_at>=? AND m.verdict_at<?
              AND m.verdict_by IS NOT NULL
            ORDER BY m.verdict_at DESC,m.message_id LIMIT ?''', (account, since, until, limit+1)).fetchall()
        reasons = Counter()
        domains = defaultdict(set)
        unverified = 0
        for r in rows[:limit]:
            reason = 'unknown'
            try:
                data = json.loads(r['snapshot'])
                decision = data['result']
                # Only a well-formed initial policy trace, never a current rule.
                if data['schema_version'] == 1 and type(decision['spam']) is bool:
                    if decision['spam']:
                        reason = 'first_scan_spam'
                    elif decision['reason'] in ('sender_allow', 'verified_force_allow', 'verified_threat_exception'):
                        reason = 'allow'
                    elif decision['reason'] == 'sticky_ham':
                        reason = 'sticky_ham'
                    elif decision['reason'] in ('score', 'allow_distrusted'):
                        reason = 'below_threshold'
            except (ValueError, TypeError, KeyError, IndexError):
                pass
            reasons[reason] += 1
            sender = parseaddr(r['sender'] or '')[1].lower()
            if sender.count('@') == 1:
                domains[sender.rpartition('@')[2]].add(sender)
            if authenticated is not None and not authenticated(r['symbols'], r['sender']):
                unverified += 1
        result.append(dict(account=account, sample_size=min(len(rows), limit), truncated=len(rows)>limit,
                           reasons=[dict(code=code, n=n, text=LABELS[code]) for code,n in sorted(reasons.items())],
                           unverified=unverified if authenticated is not None else None,
                           rotating_domains=sum(len(senders)>=3 for senders in domains.values()),
                           since=since, until=until, notice=NOTICE))
    return result


def lines(item):
    """Shared plain wording; callers escape for HTML and supply account labels."""
    out = [f"{item['sample_size']} seneste eksplicitte spamrettelser i perioden" +
           (' (prøven er begrænset).' if item['truncated'] else '.')]
    out += [f"{r['n']}: {r['text']}" for r in item['reasons']]
    if item['unverified']:
        out.append(f"{item['unverified']}: Afsenderbevis mangler eller er modstridende i de gemte symboler; "
                   'automatisk adresseblokering kræver en verificeret afsender.')
    if item['rotating_domains']:
        out.append(f"{item['rotating_domains']} domæner optræder med mindst tre forskellige adresser i prøven. "
                   'En adresseblokering dækker ikke de andre adresser; domænet blokeres ikke automatisk.')
    return out + [NOTICE]

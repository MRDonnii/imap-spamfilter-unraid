"""Neutral local-fuzzy canary, exclusively for isolated restore trials.

No external storage and no real messages. Seeding is explicit and only used
by the accountless CI fixture; ordinary backup/restore never trains a canary.
"""
import time

MAIL = (b'From: restore@sample.invalid\r\nTo: neutral@sample.invalid\r\n'
        b'Subject: Local fuzzy restoration canary\r\nMIME-Version: 1.0\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n\r\n' +
        (' '.join(f'Neutral restoration paragraph {i} contains distinct offline words '
                  'orchard railway lantern meadow telescope hillside paper calendar'
                  for i in range(50))).encode())


def check(*, attempts=20):
    import requests
    for _ in range(attempts):
        response = requests.post('http://127.0.0.1:11333/checkv2', data=MAIL, timeout=20)
        response.raise_for_status()
        if 'FUZZY_LOCAL_SPAM' in response.json().get('symbols', {}):
            return True
        time.sleep(1)
    raise ValueError('Det gendannede lokale fuzzy-mønster blev ikke genkendt.')


def seed(password):
    import requests
    # Negative control proves this pattern was not already present.
    response = requests.post('http://127.0.0.1:11333/checkv2', data=MAIL, timeout=20)
    response.raise_for_status()
    if 'FUZZY_LOCAL_SPAM' in response.json().get('symbols', {}):
        raise ValueError('Fuzzy-prøven kræver et frisk lokalt datalager.')
    response = requests.post('http://127.0.0.1:11334/fuzzyadd', data=MAIL,
        headers={'Password': password, 'Flag': '100', 'Weight': '10'}, timeout=20)
    response.raise_for_status()
    if response.json().get('success') is False:
        raise ValueError('Det lokale fuzzy-mønster kunne ikke indlæres.')
    check()

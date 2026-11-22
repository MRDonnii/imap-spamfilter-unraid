# Third-party notices

The spamfilter's own work in this repository is licensed under the PolyForm
Noncommercial License 1.0.0 (see [LICENSE](LICENSE)). The parts below come
from other projects and keep their own copyright and licence; the PolyForm
licence does not replace those terms.

## imap-spamfilter (upstream)

This project started as a fork of
[marcelverdult/imap-spamfilter](https://github.com/marcelverdult/imap-spamfilter).
Code and configuration that remain from it (among others parts of
`filter/filter.py`, `filter/dashboard.py`, `filter/bootstrap_train.py`, the
rspamd base files in `rspamd/local.d/`, `redis/redis.conf.template` and
everything under `upstream-unused/` and `UPSTREAM-README.md`), and the upstream
container image the filter image is built on (`FILTER_BASE_IMAGE` in
`deploy/versions.env`), are licensed under the MIT License:

```
MIT License

Copyright (c) 2026 Marcel Verdult

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Bundled files

| File(s) | Project | Licence |
| --- | --- | --- |
| `filter/static/inter-*.woff2` | Inter typeface (Rasmus Andersson) | SIL Open Font License 1.1 |
| `filter/static/icons.svg` | Icons drawn after Lucide / Tabler | ISC (Lucide), MIT (Tabler) |
| `deploy/aio/clamav/sanesecurity.gpg` | Sanesecurity public signing key | public key, used to verify downloads |

## Not in this repository, but in the all-in-one image

The container image built by `deploy/aio/build.sh` also contains programs
that are installed or copied in at build time and keep their own licences,
among others: rspamd (Apache-2.0), Redis 8 (RSALv2 / SSPLv1 / AGPLv3, used
unmodified), Unbound (BSD-3-Clause), ClamAV (GPL-2.0, run as a separate
program), Python and the packages in `filter/requirements.txt` (Flask,
Werkzeug, waitress, IMAPClient, PyYAML, requests, urllib3, certifi,
cryptography, cffi, pycparser, dnspython, Pillow - each under its own
permissive licence). Signature and block lists (Sanesecurity, Phishing Army,
ClamAV) are downloaded at run time under their providers' terms.

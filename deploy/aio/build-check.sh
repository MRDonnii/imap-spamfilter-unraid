#!/bin/bash
# Build-time sanity check of the all-in-one image (last RUN of
# deploy/aio/Dockerfile; also `docker run --rm --entrypoint
# /usr/local/lib/spamfilter-aio/build-check.sh IMAGE` on a built image).
#
#   - versions: rspamd, Redis, Unbound, Python as pinned in versions.env
#   - rspamd untouched: the sha256 manifest of rspamd's own files taken
#     BEFORE Python and Redis were copied in still matches (rspamd installs
#     /usr/bin/rspamd* /usr/bin/rspamadm /usr/bin/rspamc, its private libs
#     under /usr/lib/<triplet>/rspamd/ and its rules under /usr/share/rspamd;
#     nothing under /usr/local, which the Python copy replaces)
#   - every binary we copied finds its shared libraries (ldd)
#   - the filter's Python modules import (2.5.0: also push, webpush, ui_push;
#     2.6: webauthn, passkeys, login_alerts, campaigns, backup, dmarc, newsletters + their ui_ modules;
#     2.7: mailcheck, ui_mailcheck + dnspython; 2.9: ui_kontrolrum)
#     and a cryptography round trip for the push notifications
#   - users/uids: 10099:10099 filter, 11333:11333 rspamd, 999:1000 redis,
#     unbound - the uids of the 4-container layout; 2.7 clamav 3310:3310
#   - the symlinks that map the old container paths into /appdata
#   - a sample config (repo rspamd/local.d with dummy passwords) renders,
#     passes rspamadm configtest and leaves every rspamd worker on loopback
#     with no password-free controller client (secure_ip 192.0.2.1 only);
#     the rendered unbound.conf passes unbound-checkconf
#   - 2.7 ClamAV: clamd, freshclam, clamconf present; clamconf parses
#     /etc/spamfilter/clamav (clamd.conf, freshclam.conf); clamd has no TCP
#     socket; and an OFFLINE self-test: clamd (as uid 3310, our clamd.conf
#     with a temp signature dir and socket) loads a one-line test signature,
#     answers PING and finds that sample over INSTREAM (sf-health's own
#     client code) - no download, no EICAR file in the image
# Env (from the Dockerfile ARGs): EXPECT_RSPAMD, EXPECT_REDIS,
# EXPECT_UNBOUND, EXPECT_PYTHON, EXPECT_CLAMAV_MIN (2.12).
set -euo pipefail

fail() { printf 'BUILD CHECK FAILED: %s\n' "$*" >&2; exit 1; }
ok() { printf 'build check: %s\n' "$*"; }

LIB=/usr/local/lib/spamfilter-aio
SHARE=/usr/local/share/spamfilter-aio
PY=/usr/local/bin/python3

# ---------------------------------------------------------------- versions
v="$(rspamd --version 2>&1 | head -n 3 | tr '\n' ' ')"
[[ "$v" == *"${EXPECT_RSPAMD:?}"* ]] || fail "rspamd version '$v' is not ${EXPECT_RSPAMD}"
ok "rspamd ${EXPECT_RSPAMD}"
v="$(redis-server --version)"
[[ "$v" == *"v=${EXPECT_REDIS:?} "* ]] || fail "redis-server '$v' is not ${EXPECT_REDIS}"
v="$(redis-cli --version)"
[[ "$v" == *" ${EXPECT_REDIS} "* || "$v" == *" ${EXPECT_REDIS}" ]] || fail "redis-cli '$v' is not ${EXPECT_REDIS}"
ok "redis ${EXPECT_REDIS}"
v="$(unbound -V 2>&1 | head -n 1)"
[[ "$v" == "Version ${EXPECT_UNBOUND:?}."* ]] || fail "unbound '$v' is not ${EXPECT_UNBOUND}.x"
ok "$v (unbound)"
v="$("$PY" --version 2>&1)"
[[ "$v" == "Python ${EXPECT_PYTHON:?}."* ]] || fail "python '$v' is not ${EXPECT_PYTHON}.x"
ok "$v"
# 2.12 (#7): no pip in the image (its vendored urllib3/certifi are outdated).
if "$PY" -c 'import pip' 2>/dev/null || compgen -G '/usr/local/lib/python3.*/ensurepip/_bundled/*.whl' >/dev/null; then
  fail "pip is still installed (it is removed in the filter stage)"
fi
[[ -x /usr/local/bin/python ]] || fail "/usr/local/bin/python missing (supervisord, sfctl and the backup use it)"
tini --version >/dev/null || fail "tini missing"
supervisord --version >/dev/null || fail "supervisord missing"
command -v setpriv >/dev/null || fail "setpriv missing"
command -v drill >/dev/null || fail "drill missing (host-monitor DNS test)"

# ---------------------------------------------------------------- rspamd untouched
[[ -s /usr/local/share/spamfilter-aio/rspamd.sha256 ]] || fail "rspamd manifest missing"
(cd / && sha256sum --quiet -c /usr/local/share/spamfilter-aio/rspamd.sha256) ||
  fail "rspamd's own files changed after the Python/Redis copy"
ok "rspamd files unchanged ($(wc -l </usr/local/share/spamfilter-aio/rspamd.sha256) files)"
if dpkg-query -W rspamd >/dev/null 2>&1; then
  # Docker base images drop /usr/share/{doc,man,info,locale} (dpkg path-exclude):
  # a MISSING file there is expected. Anything else - a changed or missing
  # program/config/library file - still fails the build.
  out="$(dpkg --verify rspamd 2>&1 | grep -vE '^missing +(c +)?/usr/share/(doc|man|info|locale|lintian)/' || true)"
  [[ -z "$out" ]] || fail "dpkg --verify rspamd: $out"
  ok "dpkg --verify rspamd: clean (docs stripped by the base image ignored)"
fi

# ---------------------------------------------------------------- shared libraries
missing="$(for f in /usr/local/bin/python3 /usr/local/bin/redis-server /usr/local/bin/redis-cli \
                    /usr/sbin/unbound /usr/bin/rspamd /usr/sbin/clamd /usr/bin/freshclam \
                    $(find /usr/local/lib -name '*.so*' -type f 2>/dev/null); do
             # grep finding nothing is the GOOD case: never let it end the script
             { ldd "$f" 2>/dev/null || true; } | { grep 'not found' || true; } | sed "s|^|$f: |"
           done | sort -u)"
[[ -z "$missing" ]] || fail "missing shared libraries:
$missing"
ok "all shared libraries resolve"
(cd /app && "$PY" -s -c 'import filter, dashboard, services, trainer, mailer, sfctl, lookalike, aio_health, healthcheck, push, webpush, ui_push, webauthn, passkeys, login_alerts, campaigns, ui_campaigns, backup, ui_backup, dmarc, ui_dmarc, newsletters, ui_newsletters, ai_verdict, ui_ai, namespoof, ui_namespoof, mailcheck, ui_mailcheck, ui_kontrolrum, flask, waitress, imapclient, yaml, requests') >/dev/null ||
  fail "the filter modules do not import"
ok "filter modules import"
# 2.5.0 push notifications: the pinned cryptography works (P-256 + AES-GCM,
# the RFC 8291 round trip) - a wheel that imports but cannot sign fails here.
(cd /app && "$PY" -s -c '
import cryptography, webpush
from cryptography.hazmat.primitives.asymmetric import ec
ua = ec.generate_private_key(ec.SECP256R1())
body = webpush.encrypt(b"build-check", webpush.public_key_bytes(ua), b"0123456789abcdef")
assert webpush.decrypt(body, ua, b"0123456789abcdef") == b"build-check"
print(cryptography.__version__)') >/dev/null || fail "cryptography / webpush does not work (push notifications)"
ok "push crypto works (cryptography, RFC 8291 round trip)"
# 2.7 Mailsikkerhed: the pinned dnspython builds a DNSSEC-aware query and
# reads the AD flag back (no network).
(cd /app && "$PY" -s -c '
import dns.flags, dns.message, dns.version, mailcheck
q = dns.message.make_query("example.dk.", "TXT", want_dnssec=True)
q.flags |= dns.flags.AD
r = dns.message.make_response(q)
r.flags |= dns.flags.AD
assert mailcheck.answer_from_message(r, q.question[0].rdtype).ad
print(dns.version.version)') >/dev/null || fail "dnspython / mailcheck does not work (Mailsikkerhed)"
ok "dnspython works (Mailsikkerhed)"
# 2.8 (A3): QR codes - Pillow, libzbar (ctypes) and pdftoppm all present, and
# a synthetic QR code ("TH") decodes. 2.8 (A1): gpgv + clamscan for sf-sigs.
(cd /app && "$PY" -s -c '
import qrscan
a = qrscan.available()
assert all(a.values()), a
print(a)') >/dev/null || fail "QR-code reading (Pillow / libzbar / pdftoppm) does not work"
ok "QR-code reading works (Pillow, libzbar, pdftoppm)"
# 2.13: the phishing signals load and recognise mixed scripts (no network).
(cd /app && SF_RDAP=0 "$PY" -s -c '
import phishsignals
assert phishsignals.mixed_words("D\u043em\u00e6nenavnet") and not phishsignals.mixed_words("Domænenavnet")
assert phishsignals.pay_lure("Opdater dine betalingsoplysninger", set())') >/dev/null || fail "phishsignals does not load"
ok "phishing signals load (snydetegn, betalingsphishing, domænealder)"
if ! command -v gpgv >/dev/null || ! command -v clamscan >/dev/null; then
  fail "gpgv / clamscan missing (Sanesecurity signatures)"
fi
test -s /etc/spamfilter/clamav/sanesecurity.gpg || fail "the Sanesecurity key is missing"
ok "gpgv, clamscan and the Sanesecurity key present"

# ---------------------------------------------------------------- users
uidgid() { getent passwd "$1" | cut -d: -f3,4; }
[[ "$(uidgid 10099)" == 10099:10099 ]] || fail "uid 10099 must have gid 10099"
[[ "$(uidgid 11333)" == 11333:11333 ]] || fail "uid 11333 (rspamd) must have gid 11333"
[[ "$(uidgid 999)" == 999:1000 ]] || fail "uid 999 (redis) must have gid 1000"
getent passwd unbound >/dev/null || fail "user unbound missing"
[[ "$(uidgid 3310)" == 3310:3310 && "$(getent passwd 3310 | cut -d: -f1)" == clamav ]] ||
  fail "uid 3310 must be the user clamav with gid 3310 (created before the clamav packages)"
ok "users 10099 filter, 11333 rspamd, 999:1000 redis, unbound, 3310 clamav"

# ---------------------------------------------------------------- path links
link() { [[ -L "$1" && "$(readlink "$1")" == "$2" ]] || fail "$1 must link to $2"; }
link /state /appdata/state
link /config /appdata/config
link /data /appdata/redis
link /usr/local/etc/redis /appdata/redis-config
link /etc/rspamd/local.d /run/spamfilter/rspamd/local.d
[[ -d /var/lib/rspamd && ! -L /var/lib/rspamd ]] || fail "/var/lib/rspamd must stay a directory (VOLUME of the base)"
ok "path links"

# ---------------------------------------------------------------- sample config
work="$(mktemp -d)"
clam="" clam_pid=""
cleanup() {
  if [[ -n "$clam_pid" ]]; then kill "$clam_pid" 2>/dev/null || true; wait "$clam_pid" 2>/dev/null || true; fi
  rm -rf "$work" ${clam:+"$clam"} /run/spamfilter/rspamd /run/spamfilter/unbound
}
trap cleanup EXIT
mkdir -p "$work/local.d/maps.d" /run/spamfilter
cp "$SHARE/rspamd/"*.conf "$SHARE/rspamd/"*.inc "$work/local.d/" 2>/dev/null || true
cp "$SHARE/rspamd/maps.d/"* "$work/local.d/maps.d/"
# shellcheck disable=SC2016 # literal ${...} placeholders
sed 's/${REDIS_PASSWORD}/build-check-only/' "$SHARE/rspamd/redis.conf.template" >"$work/local.d/redis.conf"
# shellcheck disable=SC2016
sed 's/${RSPAMD_PASSWORD}/build-check-only/' "$SHARE/rspamd/worker-controller.inc.template" >"$work/local.d/worker-controller.inc"
"$PY" -s -E "$LIB/aio_render.py" rspamd --src "$work/local.d" --dst /run/spamfilter/rspamd/local.d >/dev/null
out="$(rspamadm configtest 2>&1)" || true
grep -q 'syntax OK' <<<"$out" || fail "rspamadm configtest of the sample config: $(tail -n 5 <<<"$out")"
rspamadm configdump -j >"$work/dump.json" 2>/dev/null || fail "rspamadm configdump -j failed"
"$PY" -s -E "$LIB/aio_render.py" check-binds "$work/dump.json" || fail "an rspamd worker binds outside loopback, or the controller has a password-free client"
ok "rspamd sample config: syntax OK, workers on loopback only, controller secure_ip pinned"
mkdir -p /run/spamfilter/unbound
"$PY" -s -E "$LIB/aio_render.py" unbound --src /nonexistent --fallback "$SHARE/unbound.conf" \
  --dir /run/spamfilter/unbound --dst /run/spamfilter/unbound/unbound.conf \
  --root-key /usr/share/dns/root.key >/dev/null
unbound-checkconf /run/spamfilter/unbound/unbound.conf >/dev/null || fail "unbound-checkconf of the rendered config"
ok "unbound sample config: checkconf OK"

# ---------------------------------------------------------------- ClamAV (2.7)
CLAMAV_CONF=/etc/spamfilter/clamav
for b in /usr/sbin/clamd /usr/bin/freshclam /usr/bin/clamconf /usr/local/bin/sf-clamav; do
  [[ -x "$b" ]] || fail "$b missing"
done
v="$(clamd --version 2>&1 | head -n 1)"
[[ "$v" == "ClamAV "* ]] || fail "clamd --version: $v"
# 2.12 (#7): an outdated ClamAV is refused (freshclam warns "OUTDATED").
cv="${v#ClamAV }"; cv="${cv%%/*}"
[[ "$(printf '%s\n%s\n' "${EXPECT_CLAMAV_MIN:?}" "$cv" | sort -V | head -n 1)" == "$EXPECT_CLAMAV_MIN" ]] ||
  fail "ClamAV $cv is older than ${EXPECT_CLAMAV_MIN}"
ok "$v (clamd); $(freshclam --version 2>&1 | head -n 1 | cut -d/ -f1) (freshclam)"
[[ -f "$CLAMAV_CONF/clamd.conf" && -f "$CLAMAV_CONF/freshclam.conf" ]] || fail "$CLAMAV_CONF/{clamd,freshclam}.conf missing"
if grep -qE '^[[:space:]]*TCP(Socket|Addr)' "$CLAMAV_CONF/clamd.conf"; then
  fail "clamd.conf must not open a TCP socket (unix socket only)"
fi
# clamconf reports a bad file as "Can't parse" / "Parse error" (its exit code
# alone does not tell; the missing signature dir is expected here).
out="$(clamconf -c "$CLAMAV_CONF" 2>&1 || true)"
if grep -qiE "can't parse|parse error|unknown option|incorrect argument" <<<"$out"; then
  fail "clamconf: $(grep -iE "can't parse|parse error|unknown option|incorrect argument" <<<"$out" | head -n 3)"
fi
grep -q 'clamd.sock' <<<"$out" || fail "clamconf did not read clamd.conf"
grep -q 'database.clamav.net' <<<"$out" || fail "clamconf did not read freshclam.conf"
ok "clamconf: clamd.conf and freshclam.conf parse, unix socket only"
# Offline self-test with a test-only signature (md5 of a harmless sample).
clam="$(mktemp -d)"
mkdir "$clam/db"
printf 'spamfilter build check: clamd INSTREAM self-test\n' >"$clam/sample"
printf '%s:%s:SF.BuildCheck.SelfTest\n' "$(md5sum <"$clam/sample" | cut -d' ' -f1)" \
  "$(stat -c %s "$clam/sample")" >"$clam/db/sf-build-check.hdb"
sed -e "s|^DatabaseDirectory .*|DatabaseDirectory $clam/db|" \
    -e "s|^LocalSocket .*|LocalSocket $clam/clamd.sock|" \
    -e "s|^TemporaryDirectory .*|TemporaryDirectory $clam|" "$CLAMAV_CONF/clamd.conf" >"$clam/clamd.conf"
chown -R 3310:3310 "$clam"
setpriv --reuid=3310 --regid=3310 --clear-groups -- clamd --config-file="$clam/clamd.conf" --foreground \
  >"$clam/clamd.log" 2>&1 &
clam_pid=$!
# shellcheck disable=SC2016 # python source
selftest='
import sys, time
import aio_health as h
sock, sample = sys.argv[1], open(sys.argv[2], "rb").read()
for _ in range(120):
    try:
        if h.clamd_request(b"PING", sock, 2.0) == "PONG":
            break
    except OSError:
        pass
    time.sleep(0.5)
else:
    sys.exit("clamd did not answer PING within 60 s")
hit = h.clamd_request(b"INSTREAM", sock, 10.0, stream=sample)
clean = h.clamd_request(b"INSTREAM", sock, 10.0, stream=b"nothing to see here\n")
if "SF.BuildCheck.SelfTest" not in hit or not hit.endswith("FOUND"):
    sys.exit(f"the test signature was not found: {hit!r}")
if not clean.endswith("OK"):
    sys.exit(f"a clean sample was not OK: {clean!r}")
print(hit)
'
out="$(cd /app && setpriv --reuid=3310 --regid=3310 --clear-groups -- "$PY" -s -c "$selftest" \
  "$clam/clamd.sock" "$clam/sample" 2>&1)" ||
  fail "clamd self-test: $(tail -n 3 <<<"$out"); clamd log: $(tail -n 8 "$clam/clamd.log" 2>/dev/null | tr '\n' ' ')"
ok "clamd self-test: PING, test signature found over INSTREAM ($out), clean sample OK"
ok "all checks passed"

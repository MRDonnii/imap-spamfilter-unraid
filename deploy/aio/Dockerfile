# spamfilter 2.4 - ALL-IN-ONE image: filter + WebUI, rspamd,
# Redis and Unbound in ONE container ('spamfilter'), supervised by
# supervisord under tini. Replaces the four containers of 2.0-2.3.
#
# Build ONLY through deploy/aio/build.sh (it stages a minimal build context
# - no secrets, no tests - and passes the pinned ARGs from versions.env):
#   deploy/aio/build.sh                 # -> imap-spamfilter-unraid:2.17.0
# The Dockerfile uses no BuildKit-only syntax, so Unraid's classic builder
# and CI's buildx both work.
#
# Stages:
#   filter  the pinned upstream filter base (Python 3.14 + Flask/waitress/
#           IMAPClient/PyYAML/requests in /usr/local) + the pinned
#           'cryptography' wheels from filter/requirements.txt (2.5.0 push
#           notifications; installed BEFORE the runtime-library scan below,
#           so its shared objects are covered) + our app in /app,
#           exactly like filter/Dockerfile.unraid; it also lists the Debian
#           packages the Python runtime links against.
#   redis   official Debian-based Redis image, pinned by digest
#           (versions.env REDIS_AIO_DIGEST): only redis-server and redis-cli
#           are copied out (glibc build, OpenSSL 3). Its bundled modules
#           (RediSearch, JSON, ...) are NOT loaded - the Bayes data are plain
#           hashes; the smoke test loads a real dump.rdb to prove it.
#   final   FROM the SAME pinned rspamd image digest as the 4-container
#           layout, so rspamd is byte-identical (asserted below). Debian
#           packages: tini, supervisor, unbound, dns-root-data, ldnsutils
#           (drill), ca-certificates, tzdata, the Python runtime libs, and
#           2.7 clamav-daemon + clamav-freshclam (virus scanning; the user
#           clamav is created FIRST with the fixed uid/gid 3310, which
#           Debian's postinst then keeps - it only adds a missing user). They
#           come from the live Debian mirror; the exact versions of a build
#           are recorded in /usr/local/share/spamfilter-aio/packages.txt
#           (compare two builds: docker run --rm --entrypoint cat IMAGE
#           /usr/local/share/spamfilter-aio/packages.txt).
#
# Runtime contract (deploy/aio/lib-aio.sh / unraid-template.xml):
#   -v <app dir>:/appdata  -v <app dir>/rspamd/data:/var/lib/rspamd
#   --tmpfs /run/spamfilter  -p 192.168.1.10:18080:8080
#   --cap-drop ALL --cap-add CHOWN,SETUID,SETGID,KILL  no-new-privileges
#   --memory 4g (2.7: ClamAV needs ~1-1.5 GB; SF_CLAMAV=0 runs in 3g)
# The old container paths are symlinks into /appdata (/state, /config,
# /data, /usr/local/etc/redis), so accounts.yml (password_file:
# /state/imap-secrets/...), the backup and monitor scripts and
# `docker exec -it spamfilter sfctl ...` work unchanged.

ARG FILTER_BASE_IMAGE=ghcr.io/marcelverdult/imap-spamfilter@sha256:11b10295f03a7eb503c7cf40a370334f33a902ca3470b28ce1a344a2bed85f7c
ARG RSPAMD_IMAGE=rspamd/rspamd@sha256:33526f94cfbb5ab5485805ad9d6eddb6a52aca6529aad0ce99b67b01c2e756de
ARG REDIS_IMAGE=redis:8.10.3-trixie@sha256:1f88291b4c57bdf249f02eb085a8669889b2d2954e91d4de5118a5da6b78dd53

# ------------------------------------------------------------------ filter
FROM ${FILTER_BASE_IMAGE} AS filter
USER root
COPY filter/requirements.txt /tmp/requirements.txt
# 2.5.0 push notifications: 'cryptography' (+ cffi, pycparser) at the exact
# versions pinned in requirements.txt - wheels only, no build tools, no
# dependency resolution (the base image already provides everything else).
# 2.7 Mailsikkerhed: 'dnspython' the same way (pure-Python, no dependencies).
# 2.8 (A3) QR codes: 'Pillow' the same way (manylinux wheel with its own libraries).
# 2.11.1 security: 'certifi', 'urllib3', 'Werkzeug' and 'Flask' the same way - the
# pinned base ships older versions with known vulnerabilities; the installed
# versions are checked against requirements.txt.
# 2.12 (#7): pip itself is removed afterwards (and ensurepip's bundled wheel):
# nothing installs packages at runtime, and pip's own vendored copies of
# urllib3/certifi lag behind the pinned ones and are flagged by Trivy.
RUN set -eu; \
    grep -E '^(cryptography|cffi|pycparser)==' /tmp/requirements.txt > /tmp/requirements-push.txt; \
    test "$(wc -l < /tmp/requirements-push.txt)" -eq 3; \
    python -m pip install --no-cache-dir --disable-pip-version-check --no-deps --only-binary=:all: \
        -r /tmp/requirements-push.txt; \
    python -c 'import cryptography.hazmat.primitives.asymmetric.ec, cryptography.hazmat.primitives.ciphers.aead'; \
    grep -E '^dnspython==' /tmp/requirements.txt > /tmp/requirements-dns.txt; \
    test "$(wc -l < /tmp/requirements-dns.txt)" -eq 1; \
    python -m pip install --no-cache-dir --disable-pip-version-check --no-deps --only-binary=:all: \
        -r /tmp/requirements-dns.txt; \
    python -c 'import dns.message, dns.query, dns.flags, dns.rcode, dns.rdatatype'; \
    grep -E '^Pillow==' /tmp/requirements.txt > /tmp/requirements-qr.txt; \
    test "$(wc -l < /tmp/requirements-qr.txt)" -eq 1; \
    python -m pip install --no-cache-dir --disable-pip-version-check --no-deps --only-binary=:all: \
        -r /tmp/requirements-qr.txt; \
    python -c 'import PIL.Image, PIL.PngImagePlugin, PIL.JpegImagePlugin'; \
    grep -E '^(certifi|urllib3|Werkzeug|Flask)==' /tmp/requirements.txt > /tmp/requirements-sec.txt; \
    test "$(wc -l < /tmp/requirements-sec.txt)" -eq 4; \
    python -m pip install --no-cache-dir --disable-pip-version-check --no-deps --only-binary=:all: \
        -r /tmp/requirements-sec.txt; \
    python -c 'import sys, importlib.metadata as m; want = dict(l.strip().split("==") for l in open(sys.argv[1])); got = {k: m.version(k) for k in want}; assert got == want, got; import flask, werkzeug, urllib3, certifi, requests' /tmp/requirements-sec.txt; \
    rm -f /tmp/requirements.txt /tmp/requirements-push.txt /tmp/requirements-dns.txt /tmp/requirements-qr.txt /tmp/requirements-sec.txt; \
    python -m pip uninstall -y --disable-pip-version-check pip; \
    rm -rf /usr/local/lib/python3.*/ensurepip/_bundled /usr/local/bin/pip /usr/local/bin/pip3*; \
    ! python -c 'import pip' 2>/dev/null
COPY filter/*.py /app/
COPY filter/static/ /app/static/
COPY filter/favicon.png /app/favicon.png
COPY filter/familieguide.pdf /app/familieguide.pdf
RUN set -eu; \
    rm -f /app/test_*.py /app/*_test.py /app/admin.py; \
    rm -rf /app/__pycache__; \
    chown -R root:root /app; \
    find /app -type d -exec chmod 0755 {} +; \
    find /app -type f -exec chmod 0644 {} +; \
    rm -f /usr/local/bin/sfctl; \
    find /usr/local -type f \( -name '*.so' -o -name '*.so.*' -o -perm -u+x \) -exec ldd {} + 2>/dev/null \
      | awk '/=>/ && !/not found/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) next; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
      | sort -u | xargs -r dpkg-query --search 2>/dev/null | grep -v '^diversion by ' \
      | cut -d: -f1 | tr -d ',' | tr ' ' '\n' \
      | grep -E '^[a-z0-9][a-z0-9+.-]+$' | sort -u > /python-runtime-packages; \
    test -s /python-runtime-packages

# ------------------------------------------------------------------ redis
FROM ${REDIS_IMAGE} AS redis

# ------------------------------------------------------------------ final
FROM ${RSPAMD_IMAGE}
USER root
ARG AIO_VERSION=2.17.0
ARG EXPECT_RSPAMD=4.2.2
ARG EXPECT_REDIS=8.10.3
ARG EXPECT_UNBOUND=1.26
ARG EXPECT_PYTHON=3.14
ARG EXPECT_CLAMAV_MIN=1.4.6

# 1. What rspamd installs must survive the Python/Redis copy: nothing of
#    the base lives under /usr/local (fail otherwise), and a sha256
#    manifest of rspamd's own files is checked again at the end.
RUN set -eu; \
    found="$(find /usr/local -mindepth 1 -type f | head -n 20)"; \
    if [ -n "$found" ]; then echo "the rspamd base ships files under /usr/local (the Python copy would replace them):"; echo "$found"; exit 1; fi; \
    { ls -1 /usr/bin/rspamd* /usr/bin/rspamadm /usr/bin/rspamc 2>/dev/null; \
      find /usr/lib -path '*/rspamd/*' -type f; find /usr/share/rspamd -type f; } \
      | sort -u | xargs -r sha256sum > /tmp/rspamd.sha256; \
    test -s /tmp/rspamd.sha256

# 2. Debian packages (Debian sources only; rspamd is held and never upgraded).
COPY --from=filter /python-runtime-packages /tmp/python-runtime-packages
RUN set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    mkdir -p /tmp/apt-off; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do \
      if [ -f "$f" ] && grep -qi rspamd "$f"; then mv "$f" /tmp/apt-off/; fi; \
    done; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d; \
    if dpkg-query -W rspamd >/dev/null 2>&1; then apt-mark hold rspamd >/dev/null; fi; \
    getent group clamav >/dev/null || groupadd --system --gid 3310 clamav; \
    getent passwd clamav >/dev/null || useradd --system --uid 3310 --gid 3310 \
        --no-create-home --home-dir /var/lib/clamav --shell /usr/sbin/nologin clamav; \
    apt-get update; \
    # 2.12.3: take Debian's security fixes for the base packages (rspamd stays\
    # held above), so the Trivy gate in CI does not fail on fixed CVEs.\
    apt-get -y -o Dpkg::Options::=--force-confold upgrade; \
    apt-get install -y --no-install-recommends \
      tini supervisor unbound dns-root-data ldnsutils ca-certificates tzdata util-linux \
      clamav-daemon clamav-freshclam clamav gpgv \
      libzbar0 poppler-utils \
      $(cat /tmp/python-runtime-packages); \
    rm -f /usr/sbin/policy-rc.d; \
    for f in /tmp/apt-off/*; do [ -e "$f" ] && mv "$f" /etc/apt/sources.list.d/; done; \
    rm -rf /var/lib/apt/lists/* /tmp/apt-off /tmp/python-runtime-packages

# 3. Python 3.14 + the filter app, Redis binaries.
COPY --from=filter /usr/local/ /usr/local/
COPY --from=filter /app/ /app/
COPY --from=redis /usr/local/bin/redis-server /usr/local/bin/redis-cli /usr/local/bin/
# The copied Python is a shared build: refresh the linker cache so
# libpython3.14.so.1.0 in /usr/local/lib is found, and drop the GUI module
# (_tkinter needs Tcl/Tk, which a mail filter never uses).
RUN set -eu; \
    rm -f /usr/local/lib/python3.*/lib-dynload/_tkinter*.so; \
    ldconfig

# 4. Our runtime: entrypoint, supervisor config, wrappers, bundle.
COPY aio/supervisord.conf /etc/spamfilter/supervisord.conf
COPY aio/clamav/ /etc/spamfilter/clamav/
COPY aio/sf-entrypoint aio/sf-run aio/sf-fatal-listener aio/sf-health aio/sf-clamav /usr/local/bin/
# 2.8 (A1): Sanesecurity's signatures (GPG-verified, load-tested before use).
COPY aio/sf-sigs /usr/local/bin/sf-sigs
COPY aio/sfctl-aio /usr/local/bin/sfctl
COPY aio/aio_render.py aio/build-check.sh /usr/local/lib/spamfilter-aio/
COPY aio/share/ /usr/local/share/spamfilter-aio/

# 5. Users (the uids of the 4-container layout; 2.7 clamav 3310:3310 above),
#    path links into /appdata, rspamd workers on loopback, permissions.
RUN set -eu; \
    getent group 10099 >/dev/null || groupadd --system --gid 10099 spamfilter; \
    getent passwd 10099 >/dev/null || useradd --system --uid 10099 --gid 10099 \
        --no-create-home --home-dir /tmp --shell /usr/sbin/nologin spamfilter; \
    getent group 11333 >/dev/null || groupadd --system --gid 11333 rspamd-aio; \
    getent passwd 11333 >/dev/null || useradd --system --uid 11333 --gid 11333 \
        --no-create-home --home-dir /var/lib/rspamd --shell /usr/sbin/nologin rspamd-aio; \
    getent group 1000 >/dev/null || groupadd --system --gid 1000 redis; \
    if getent passwd 999 >/dev/null; then usermod -g 1000 "$(getent passwd 999 | cut -d: -f1)"; \
    else useradd --system --uid 999 --gid 1000 --no-create-home --home-dir /data --shell /usr/sbin/nologin redis; fi; \
    mkdir -p /appdata /run/spamfilter /usr/local/etc /etc/rspamd/override.d; \
    rm -rf /state /config /data /usr/local/etc/redis /etc/rspamd/local.d; \
    ln -s /appdata/state /state; \
    ln -s /appdata/config /config; \
    ln -s /appdata/redis /data; \
    ln -s /appdata/redis-config /usr/local/etc/redis; \
    ln -s /run/spamfilter/rspamd/local.d /etc/rspamd/local.d; \
    ln -sf redis-server /usr/local/bin/redis-check-rdb; \
    ln -sf redis-server /usr/local/bin/redis-check-aof; \
    /usr/local/bin/python3 -s -E /usr/local/lib/spamfilter-aio/aio_render.py override --dir /etc/rspamd/override.d; \
    mv /tmp/rspamd.sha256 /usr/local/share/spamfilter-aio/rspamd.sha256; \
    printf '%s\n' "$AIO_VERSION" > /usr/local/share/spamfilter-aio/VERSION; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort > /usr/local/share/spamfilter-aio/packages.txt; \
    chown -R root:root /usr/local/lib/spamfilter-aio /usr/local/share/spamfilter-aio /etc/spamfilter; \
    find /usr/local/share/spamfilter-aio /etc/spamfilter -type d -exec chmod 0755 {} +; \
    find /usr/local/share/spamfilter-aio /etc/spamfilter /usr/local/lib/spamfilter-aio -type f -exec chmod 0644 {} +; \
    chmod 0755 /usr/local/lib/spamfilter-aio/build-check.sh /usr/local/bin/sf-entrypoint /usr/local/bin/sf-run \
        /usr/local/bin/sf-fatal-listener /usr/local/bin/sf-health /usr/local/bin/sf-clamav /usr/local/bin/sf-sigs /usr/local/bin/sfctl

ENV SPAMFILTER_AIO=1 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp \
    TZ=Europe/Copenhagen \
    STATE_DIR=/state \
    CONFIG_PATH=/config/accounts.yml \
    RSPAMD_SCAN_URL=http://127.0.0.1:11333/checkv2 \
    RSPAMD_LEARN_URL=http://127.0.0.1:11334 \
    LOOKALIKE_DNS_SERVER=127.0.0.1 \
    LOOKALIKE_DNS_PORT=5353 \
    AUTOMATIC_RETENTION_ENABLED=0 \
    SF_CLAMAV=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 6. Build-time sanity check (versions, rspamd untouched, libraries, uids,
#    links, sample configs). A failure stops the build.
RUN EXPECT_RSPAMD="$EXPECT_RSPAMD" EXPECT_REDIS="$EXPECT_REDIS" EXPECT_UNBOUND="$EXPECT_UNBOUND" \
    EXPECT_PYTHON="$EXPECT_PYTHON" EXPECT_CLAMAV_MIN="$EXPECT_CLAMAV_MIN" /usr/local/lib/spamfilter-aio/build-check.sh

USER root
WORKDIR /
EXPOSE 8080
# All four parts: filter heartbeat + /healthz, rspamd pong, Redis PONG with
# the password from redis.conf, Unbound answers (filter/aio_health.py).
# 2.7: ClamAV is reported too, but only as a warning - a missing clamd
# (first signature download, SF_CLAMAV=0) never makes the container unhealthy.
HEALTHCHECK --interval=30s --timeout=25s --start-period=180s --retries=3 \
    CMD ["/usr/local/bin/sf-health", "check"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sf-entrypoint"]
CMD []

LABEL org.opencontainers.image.title="imap-spamfilter-unraid" \
      org.opencontainers.image.description="spamfilter all-in-one (filter + WebUI, rspamd, Redis, Unbound, ClamAV)" \
      org.opencontainers.image.version="${AIO_VERSION}" \
      org.opencontainers.image.vendor="imap-spamfilter-unraid" \
      spamfilter.layout="aio" \
      spamfilter.version="${AIO_VERSION}"

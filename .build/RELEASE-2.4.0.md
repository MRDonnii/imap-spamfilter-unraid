# Release 2.4.0 – operator runbook (four containers → one)

Target: an Unraid 7.4 server (here `192.168.1.10`), app dir `/mnt/user/appdata/spamfilter`.
Upgrade from 2.3.6 (four containers: `spamfilter`, `spamfilter-rspamd`, `spamfilter-redis`, `spamfilter-unbound` on `spamnet`) to **one** container `spamfilter` from `imap-spamfilter-unraid:2.4.0`.
**Nothing in this release deletes mail**, and the engine code is the 2.3.6 engine (only the version, the configurable lookalike resolver and the AIO health/doctor additions changed). `SCORE_VERSION` is unchanged; there is no schema change.

The AIO reuses the app dir **as is**: the same files, the same uids (10099 filter, 11333 rspamd, 999:1000 Redis), and nothing is chowned. Files that name the old hosts (`rspamd/local.d/redis.conf`, `options.inc`, `worker-*.inc`, `unbound.conf`) are never edited; a 127.0.0.1 copy is rendered into the tmpfs `/run/spamfilter` at every start. The four old containers can therefore be started again at any time until `cleanup.sh` removes them.

## What changes

| Area | Change |
| --- | --- |
| Image | `deploy/aio/Dockerfile`: FROM the same pinned `rspamd/rspamd@sha256:8cf57587…` (rspamd byte-identical, checked by a sha256 manifest + `dpkg --verify`), Python 3.14 + `/app` copied from the pinned filter base, `redis-server`/`redis-cli` 8.10.2 from `redis:8.10.2-trixie@sha256:97ec8815…` (pinned in `versions.env`; its bundled modules are not loaded – the smoke test loads a real `dump.rdb` to prove the data need none), Unbound 1.22 / tini / supervisor / ldnsutils from Debian 13. A build-time check (`build-check.sh`) asserts versions, uids, libraries, path links and that a sample config passes `rspamadm configtest` / `unbound-checkconf` with every rspamd worker on loopback and no password-free controller client. The Debian package versions of the build are recorded in `/usr/local/share/spamfilter-aio/packages.txt`. |
| Processes | tini → `sf-entrypoint` → supervisord. redis (uid 999) → unbound (`unbound`) → rspamd (11333) → filter (10099). `sf-run` prefixes each log line (`[redis]` …), waits for dependencies and backs off (2–60 s) on crash loops; a FATAL program stops the container so Docker restarts it. Stop: filter first (40 s), Redis last. |
| Network | Only 8080 is published (`192.168.1.10:18080`). rspamd 11333/11334, Redis 6379 and Unbound **5353** listen on 127.0.0.1 only (checked by `sf-health listeners`). Unbound uses an unprivileged port, so no sysctl is needed and no other uid can grab a privileged DNS port. The rspamd controller exempts **no** client from its password in the AIO (`secure_ip` → `192.0.2.1`, in the tmpfs copy and the image's `override.d`): every program shares one loopback here. Container network: `bridge`; `spamnet` goes away with the cleanup. |
| Health | One HEALTHCHECK, `sf-health check`: filter (heartbeat of this run + `/healthz`), rspamd (`/ping` on 11333 and 11334), Redis (`PING` with the password read inside from `redis.conf`, as uid 999), Unbound (answers `localhost.`). Result per part in `/run/spamfilter/health.json`; `sfctl doctor` shows every part when `SPAMFILTER_AIO=1`. |
| Unraid | Template `my-spamfilter.xml` (name `spamfilter`, icon, WebUI link, Danish overview). The run scripts set the dockerMan labels, so the Docker tab shows the icon/WebUI instead of "3rd Party". |
| Scripts | `deploy/aio/`: `build.sh`, `smoke-test.sh`, `migrate.sh`, `rollback.sh`, `cleanup.sh`, `update.sh` (all `--dry-run`, logs in `operations/aio-*-<stamp>.log`). The 4-container scripts (`recreate-*.sh`, `run-containers.sh`, `migrate-2.0.sh`) refuse to run while the AIO is live. `host-monitor.sh` and `backup-and-verify.sh` detect the layout by the image label `spamfilter.layout=aio`. |
| Code | `lookalike.DnsResolver` default server/port from `$LOOKALIKE_DNS_SERVER` / `$LOOKALIKE_DNS_PORT` (defaults unchanged `spamfilter-unbound:53`; the AIO image sets `127.0.0.1:5353`); `filter/aio_health.py` (incl. `sf-health bayes`: learned counts from `/stat` with the controller password); `sfctl doctor` AIO section; version 2.4.0. |
| CI | `ci.yml` builds the AIO image (no push) and smoke-tests it (fresh app dir: four parts healthy, scan + learn, restart, learned count survives). `release.yml` refuses to run without a pinned `REDIS_AIO_DIGEST`, builds the AIO image once, smoke-tests it and pushes **exactly that image** (no second build) as `ghcr.io/mrbjarke/imap-spamfilter-unraid:<version>` and `:beta`. The filter-only image is built in CI but no longer published. |

## 0. Before you start

- [ ] Last night's backup is OK: `jq . $APP/state/backup-status.json` → `ok: true`.
- [ ] `curl -fsS http://192.168.1.10:18080/api/health | jq .accounts` → all 5 accounts `idle`/`working`, none `paused_moves`.
- [ ] `cat $APP/operations/site.env` contains `TRUSTED_PROXIES=192.168.1.10` (the tunnel depends on it; the AIO gets it the same way).
- [ ] At least 1 GiB free on the app dir and on Docker (`df -h /mnt/user /var/lib/docker`). The image is ~0.8 GiB.
- [ ] Pick a quiet time. The switch itself takes 2–5 minutes; mail waits at the providers meanwhile, and for 30 minutes after the start only clear spam (threshold + 5) is moved.
- [ ] Work inside `tmux` (or `screen`) on the host for steps 2–9. Ctrl-C and a dropped SSH session are handled (the log tee ignores the signals and the automatic rollback runs to the end), but tmux keeps the session and its output.

```sh
APP=/mnt/user/appdata/spamfilter
STAMP=$(date +%Y%m%d-%H%M%S)
```

## 1. Copy the tree to `$APP/source`

On the workstation:

```sh
cd ~/.codex/imap-spamfilter-unraid
tar --exclude=.git --exclude=.venv --exclude=.build --exclude=.pytest_cache \
    --exclude='__pycache__' --exclude=upstream-unused \
    -czf /tmp/spamfilter-2.4.0.tar.gz .
scp /tmp/spamfilter-2.4.0.tar.gz root@192.168.1.10:/tmp/
```

On the host, as root:

```sh
APP=/mnt/user/appdata/spamfilter; STAMP=$(date +%Y%m%d-%H%M%S)
cp -a "$APP/source" "$APP/operations/source-2.3.6-$STAMP"      # the 2.3.6 tree, for a rollback
tar -xzf /tmp/spamfilter-2.4.0.tar.gz -C "$APP/source" --no-same-owner
chown -R root:root "$APP/source" && chmod -R go-w "$APP/source"
grep -x 'VERSION=2.4.0' "$APP/source/deploy/versions.env"
cd "$APP/source"
```

## 2. Build the image (the live containers are not touched)

```sh
./deploy/aio/build.sh --dry-run
./deploy/aio/build.sh
```

- Takes a few minutes; it pulls the pinned rspamd and filter bases and `redis:8.10.2-trixie@sha256:97ec8815…` (pinned in `versions.env`, nothing to pin by hand).
- The last build step is the build check; any `BUILD CHECK FAILED` line stops the build.
- If the build stops in the build check with `unbound '…' is not 1.22` (Debian may ship a newer Unbound in a trixie point release), report it – do not edit the pins on the host.

Check:

```sh
docker image inspect imap-spamfilter-unraid:2.4.0 \
  --format '{{index .Config.Labels "spamfilter.layout"}} {{index .Config.Labels "spamfilter.version"}} {{json .Config.Volumes}}'
# -> aio 2.4.0 {"/var/lib/rspamd":{}}   (or null)
docker run --rm --entrypoint cat imap-spamfilter-unraid:2.4.0 /usr/local/share/spamfilter-aio/packages.txt | grep -E '^(unbound|supervisor|tini) '
```

## 2b. Install the 2.4 host jobs first (they handle both layouts)

The User Scripts are inline copies. The 2.3.6 monitor would raise "spamfilter-redis kører ikke" alerts and the 2.3.6 backup would fail once the four containers are stopped, so install the 2.4 versions **before** the migration. They detect the layout themselves, so they also keep working after a rollback:

```sh
./deploy/install-user-scripts.sh
./deploy/host-monitor.sh --dry-run | sed '/^\[dry-run\]/,$d' | jq -c '.layout, (.containers | keys)'
#  "legacy" ["spamfilter","spamfilter-redis","spamfilter-rspamd","spamfilter-unbound"]
```

## 3. Isolated smoke test (accounts disabled, no mailbox is touched)

```sh
./deploy/aio/smoke-test.sh --dry-run
./deploy/aio/smoke-test.sh
```

What it does, all in the copy:

- restores the newest `operations/backups/spamfilter-*.tar.gz` into `operations/aio-test/<stamp>/appdata`; the copy's `redis.conf` gets `appendonly no`, because the archive holds only `dump.rdb` and Redis with AOF on would ignore it and start empty;
- makes **every account unable to log in**, wherever its secret lives: `enabled: false`, mode shadow, no inline `password`, `password_file: /nonexistent/smoke-test`, `imap_host: 127.0.0.1`, `imap_port: 1` (also in `defaults`); it fails if any account could still log in;
- cancels the undo / training / learn-list jobs that were queued or running when the backup was taken (the trainer would otherwise resume them for disabled accounts too);
- deletes the IMAP passwords, `smtp.password`, `removed-secrets/` and the mail outbox and switches the mail server settings off;
- starts `spamfilter-aio-test` on `127.0.0.1:18090` with the copy, with every original IMAP host mapped to `127.0.0.1` (`--add-host`).

It waits until all four parts are healthy and checks:

- the Bayes learned counts and Redis keys of the copy (compared with the live rspamd – the backup is from 03:00, so live may be slightly higher)
- the WebUI login page answers 200
- only 8080 listens outside loopback
- `sfctl doctor` runs (it will warn about accounts/2FA in the copy – expected)

The container and the copy are removed at the end. Expect `Smoke test passed`.

- To look at the test WebUI first: `./deploy/aio/smoke-test.sh --keep`, then from the workstation `ssh -L 18090:127.0.0.1:18090 root@192.168.1.10` and open `http://127.0.0.1:18090/`; afterwards `docker rm -f spamfilter-aio-test && rm -rf $APP/operations/aio-test/<stamp>`.
- Optional extra: `--learn-test` scans and learns one test mail **in the copy**, restarts the test container and checks the learned count survived.

## 4. Migrate

```sh
./deploy/aio/migrate.sh --dry-run
```

Read the plan: backup, snapshot, stop `spamfilter`, `spamfilter-rspamd`, `spamfilter-unbound`, `spamfilter-redis` (in that order), rename `spamfilter` → `spamfilter-legacy`, template, `docker run … imap-spamfilter-unraid:2.4.0`, gate.

Optional – let the gate also check the Home Assistant endpoint **with** the token (otherwise it checks the 404 without a token). The token is read silently and only ever handed to curl on stdin:

```sh
read -rs SF_HA_TOKEN && export SF_HA_TOKEN      # paste the sfha_… token, Enter
```

Then:

```sh
./deploy/aio/migrate.sh
unset SF_HA_TOKEN
```

- The gate waits up to 420 s for:
  - Docker `healthy`; filter/rspamd/redis/unbound `ok`
  - a fresh heartbeat, `/healthz` 200 and `loaded 5 account(s)` in the log
  - `/api/health` version `2.4.0`; every account that was idle/working is idle/working again; paused accounts are still paused
  - Bayes learned counts (BAYES_SPAM/BAYES_HAM): the total is not lower, and no statfile lost more than 5 (a user re-learning a mail during the gate); Redis keys at most 1 % (min. 10) fewer
  - the Home Assistant endpoint answers
- On **any** failure (or Ctrl-C, or a dropped SSH session) the script rolls back by itself:
  - the AIO is removed; its log goes to `operations/failed-aio-<stamp>.log`
  - `spamfilter-legacy` becomes `spamfilter` again; restart policies, Unraid autostart and template are restored
  - Redis → Unbound → rspamd → filter start again, each gated
- The whole run is logged in `operations/aio-migrate-<stamp>.log`; the numbers are in `aio-migrate-<stamp>.before.json` / `.after.json`.

## 5. Verify

```sh
docker ps -a --filter name=spamfilter --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
#  spamfilter          Up … (healthy)   imap-spamfilter-unraid:2.4.0
#  spamfilter-legacy / -rspamd / -redis / -unbound   Exited   (kept for rollback)
docker exec spamfilter sf-health check            # ok: filter ok, rspamd ok, redis ok, unbound ok
docker exec spamfilter supervisorctl status       # redis, unbound, rspamd, filter RUNNING
docker exec spamfilter sf-health listeners        # only the WebUI (8080) outside loopback
docker exec -it spamfilter sfctl doctor           # incl. "Redis svarer", "Unbound svarer"
curl -fsS http://192.168.1.10:18080/api/health | jq '.version, .accounts'
jq -c '.bayes, .dbsize' "$APP"/operations/aio-migrate-*.before.json "$APP"/operations/aio-migrate-*.after.json
docker logs --since 10m spamfilter 2>&1 | grep -E '^\[(init|filter)\]' | tail -n 20
cat /var/lib/docker/unraid-autostart              # spamfilter yes; spamfilter-redis/-rspamd/-unbound no
docker exec -u 10099:10099 spamfilter sf-health bayes   # BAYES_SPAM / BAYES_HAM learned counts (controller password)
```

> **Never start the stopped old containers by hand** (`spamfilter-redis`, `-rspamd`, `-unbound`, `spamfilter-legacy` – Docker tab "Start", "Start all", or their autostart toggle) while the AIO runs: the old Redis would open the same `redis/` data dir as the AIO's Redis and corrupt the Bayes store. The 2.4 monitor alerts at once and kills an old Redis it finds running next to the AIO (not while a deploy script holds the lock). The way back is `rollback.sh`.

By hand:

- [ ] Unraid → Docker: ONE container `spamfilter` with the spamfilter icon and a working WebUI link.
- [ ] LAN login (with 2FA) at `http://192.168.1.10:18080/`; Oversigt and Fanget spam look as before.
- [ ] Tunnel: `https://spamfilter.example.org` → login works; Indstillinger → "Adgang udefra" shows the request as proxied (TRUSTED_PROXIES still matches).
- [ ] Home Assistant: the `sensor.spamfilter_*` entities update within their poll interval.
- [ ] Træning → Bayes shows the same pool (e.g. `spamfilter-r2`) and the same learned counts.

## 6. Host jobs on the new layout

The 2.4 User Scripts were installed in step 2b. Check them against the AIO:

```sh
./deploy/host-monitor.sh --dry-run | sed '/^\[dry-run\]/,$d' | jq -c '.layout, .parts, (.containers | keys)'
#  "aio" {"filter":{"ok":true,...},...} ["spamfilter"]
./deploy/backup-and-verify.sh && jq . "$APP/state/backup-status.json"     # "layout: aio" in the output, ok: true
```

## 7. Rollback (any time until step 8)

```sh
./deploy/aio/rollback.sh --dry-run
./deploy/aio/rollback.sh --yes          # add --no-backup if the AIO is too broken for a backup
```

- It takes a backup first.
- It stops the AIO (90 s, Redis saves) and keeps it as `spamfilter-aio-rolledback`.
- `spamfilter-legacy` becomes `spamfilter` again; policies, autostart and template are restored.
- Redis → Unbound → rspamd → filter start again, each gated.
- Everything the AIO learned is kept (same files).
- Unraid's autostart list gets the four back in their old order (redis, unbound, rspamd, spamfilter) with their delay fields.
- It also repairs what an interrupted `migrate.sh` can leave behind before anything was renamed (the four stopped, restart policy `no`, off autostart).
- Verify with `docker ps --filter name=spamfilter` (four healthy containers) and `curl -fsS http://192.168.1.10:18080/api/health`.
- Remove the stopped AIO later with `docker rm spamfilter-aio-rolledback`.

To go back to the 2.3.6 **source tree** as well:

```sh
rm -rf "$APP/source" && cp -a "$APP/operations/source-2.3.6-$STAMP" "$APP/source"
./deploy/install-user-scripts.sh
```

## 8. Cleanup (after a few good days – no rollback afterwards)

```sh
./deploy/aio/cleanup.sh --dry-run
./deploy/aio/cleanup.sh --yes
```

- It only runs while `spamfilter` is the AIO and `healthy`.
- It removes the **stopped** `spamfilter-legacy`, `spamfilter-rspamd`, `spamfilter-redis`, `spamfilter-unbound` (and `spamfilter-aio-rolledback` / `spamfilter-rollback` / `spamfilter-aio-test` if present).
- It removes the network `spamnet` if no container uses it, and their Unraid autostart entries.
- Images it removes:
  - the old Redis/Unbound images
  - the filter-only `imap-spamfilter-unraid` images (2.3.x, `*-filter`)
  - AIO images older than the previous version
- Images it keeps:
  - the running AIO image and the rspamd base (needed for the next build)
  - the filter base and the pinned `redis:8.10.2-trixie` build image
- Never forced; never touches another container, image, network, volume or the app dir.

Check: `docker ps -a --filter name=spamfilter` → only `spamfilter`; `docker network ls | grep spamnet` → nothing; `docker images | grep -E 'imap-spamfilter|redis|unbound|rspamd'`.

## 9. Later updates

Copy the new tree as in step 1, then:

```sh
./deploy/aio/update.sh --dry-run --build
./deploy/aio/update.sh --build
```

- It builds, takes a backup, stops `spamfilter` (90 s) and keeps it as `spamfilter-rollback`.
- It starts the new image with identical parameters and gates it (all four parts).
- On failure the previous container starts again.
- On success the template gets the new tag, the rollback container is removed (`--keep-rollback` keeps it) and AIO images older than the previous version are pruned.

## Decisions / deviations from PLAN.md section 2

- **supervisor instead of s6:**
  - Debian's supervisor gives ordered start and stop (priorities); the filter stops first with a 40 s grace and Redis last.
  - It has per-program uids and a FATAL event hook.
  - It is a stock Debian package, so there are no unpinned downloads.
  - Readiness ordering is done by `sf-run --wait` and back-off by `sf-run`.
- **Container and template name `spamfilter` (lowercase):** dockerMan matches the template to the container by `<Name>`. "Spamfilter" would make Unraid treat the running `spamfilter` as unmanaged, and an "Edit → Apply" would create a SECOND container on the same data (two Redis servers on one AOF). Every script, the docs and `docker exec -it spamfilter sfctl` use `spamfilter`.
- **A second mapping `<app>/rspamd/data:/var/lib/rspamd`:** the rspamd base image declares `VOLUME /var/lib/rspamd`. Without the mapping Docker would mount an anonymous volume there: rspamd's data would leave the app dir, and the volumes would pile up on every recreate. The template shows it as an advanced path. `build.sh` fails if the image declares any other VOLUME, and the entrypoint refuses to start if `/var/lib/rspamd` is not `<app>/rspamd/data`.
- **Port binding in ExtraParams:** a dockerMan `Port` field cannot bind to one host IP. `-p 192.168.1.10:18080:8080/tcp` lives in ExtraParams, and the WebUI label `http://[IP]:[PORT:8080]/` resolves from the container's real port mapping.
- **Bayes gate "same data" instead of "equal numbers":** the filter runs during the gate and may legitimately learn or re-learn (a user drags a mail; spam -1 / ham +1). The gate fails when the total learned count drops, a statfile loses more than 5, or Redis has more than 1 % (min. 10) fewer keys, which is what an empty or wrong Bayes store looks like.
- **Only the AIO image is published:** the filter-only image (`:2.4.0-filter`) is built in CI to keep the 4-container rollback path buildable, but it is not pushed (one image per version in GHCR).
- **Review fixes (2.4.0):** smoke-test copy loads `dump.rdb` (`appendonly no` in the copy) and cannot log in by construction; the log tee survives Ctrl-C/SIGHUP so the automatic rollback finishes; the monitor guards against an old Redis started next to the AIO; the rollback restores Unraid's autostart order; the controller exempts no client from its password; Unbound on 5353 without the sysctl; Redis build image pinned by digest and the release pushes the tested image. Details: `.build/DEVIATIONS.md` section 2.4.0.
- **Capabilities:** `CHOWN`, `SETUID`, `SETGID`, `KILL` (supervisord as root switches to four uids and signals them; the entrypoint creates the tmpfs subdirs). There is no `DAC_OVERRIDE`, so root in the container cannot read the parts' files; probes and `docker exec` use `setpriv` / `-u <uid>`. No sysctl: Unbound listens on the unprivileged `127.0.0.1:5353`.

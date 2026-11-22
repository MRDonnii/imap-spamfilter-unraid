# deploy/ — operating the spamfilter on Unraid

All scripts run as root on the Unraid host from the source tree
(`/mnt/user/appdata/spamfilter/source/deploy/`). Every script that
changes something accepts `--dry-run` (prints the plan, changes nothing)
and honours `SPAMFILTER_APP` (default `/mnt/user/appdata/spamfilter`).
Image tags/digests and a few knobs live in `versions.env`; all `docker run`
flags, health gates and the rollback logic live in `lib.sh`. Scripts never
print secrets.

## 2.4: one container (deploy/aio/)

From 2.4 production is ONE container `spamfilter` (image
`imap-spamfilter-unraid:2.4.0`, `deploy/aio/Dockerfile`): the filter + WebUI,
rspamd, Redis and Unbound under supervisord, each as its old uid, only 8080
published. It reuses this app dir unchanged (no file is rewritten or
chowned; host-specific copies are rendered into the tmpfs `/run/spamfilter`),
so the four containers below can be started again until `cleanup.sh` runs.
The operator runbook is `.build/RELEASE-2.4.0.md`.

2.7 adds ClamAV to the same container: clamd + freshclam as uid/gid 3310,
clamd on a unix socket only (`/run/spamfilter/clamav`, 3310:11333 0750),
signatures in `<app dir>/clamav` (the one dir the entrypoint creates in an
existing app dir). Memory limit 4g (`SF_AIO_MEMORY`); `SF_CLAMAV=0` (site.env
or the template) switches it off. ClamAV is optional for every gate: a
missing clamd is a warning (`sf-health clamav`), never unhealthy. CI smoke
tests run with `SF_CLAMAV=0`; `smoke-test.sh --clamav-scan` is the optional
end-to-end EICAR check through rspamd (needs the signature download).

| When | Command |
|---|---|
| Build the image (pinned bases, build-time checks) | `aio/build.sh` |
| Throwaway test on a sanitised backup copy (127.0.0.1:18090; no account can log in, pending IMAP jobs cancelled, the copy's Redis loads the backup's dump.rdb) | `aio/smoke-test.sh` |
| Once: four containers -> one (backup, snapshot, gate, automatic rollback) | `aio/migrate.sh --dry-run`, then `aio/migrate.sh` |
| Back to the four containers (any time before cleanup) | `aio/rollback.sh --yes` |
| Remove the stopped 4-container setup, `spamnet`, old images | `aio/cleanup.sh --dry-run`, then `aio/cleanup.sh --yes` |
| Later updates (backup, gate, rollback to the previous image, prune) | `aio/update.sh --build` |

- `lib.sh` sources `aio/lib-aio.sh`: AIO run args (= the ExtraParams of the
  Unraid template `aio/unraid-template.xml`, installed as
  `/boot/config/plugins/dockerMan/templates-user/my-spamfilter.xml`), the
  layout detection (image label `spamfilter.layout=aio`), gates, rollback.
- The 4-container scripts below (`recreate-*.sh`, `run-containers.sh`,
  `migrate-2.0.sh`) refuse to run while the AIO is live: a second Redis on the
  same data dir would corrupt it.
- `host-monitor.sh` and `backup-and-verify.sh` work with both layouts (AIO:
  `docker exec -u <uid> spamfilter ...`, parts from the container's own
  HEALTHCHECK, `[rspamd]`/`[unbound]` log prefixes). Re-install them with
  `install-user-scripts.sh` BEFORE the migration.
- In the AIO, root has no CAP_DAC_OVERRIDE: use `docker exec -u 10099:10099`
  (filter), `-u 11333:11333` (rspamd) or `-u 999:1000` (Redis) for file
  access; `sfctl` switches to 10099 by itself.
- In the AIO the rspamd controller exempts NO client from its password
  (`secure_ip` -> 192.0.2.1 in the tmpfs copy and the image's override.d;
  every program shares one loopback). Learned counts:
  `docker exec -u 10099:10099 spamfilter sf-health bayes` (not `rspamc stat`).
- The AIO's Unbound listens on `127.0.0.1:5353` (no sysctl);
  `drill -p 5353 @127.0.0.1 ...` inside the container.
- Run `migrate.sh`, `update.sh` and `rollback.sh` inside tmux/screen. Ctrl-C
  and a dropped SSH session still finish the automatic rollback (the log tee
  ignores INT/TERM/HUP), and `rollback.sh` also repairs a migration that was
  killed before it renamed anything.
- NEVER start the stopped `spamfilter-redis`/`-rspamd`/`-unbound`/`-legacy`
  by hand while the AIO runs: the old Redis would share the `redis/` data
  dir. `host-monitor.sh` alerts at once and kills an old Redis it finds next
  to a running AIO (not while a deploy script holds the deploy lock).

## Script order (four containers, 2.0-2.3 and rollback)

| When | Command |
|---|---|
| Once, 1.x → 2.0 | `./migrate-2.0.sh --dry-run`, then `./migrate-2.0.sh` |
| Filter code update | copy the new source tree, then `./recreate-filter.sh --build` |
| rspamd / unbound config or image change | `./recreate-infra.sh rspamd` (or `unbound`, `redis`, `all`) |
| Re-install cron jobs after editing backup/monitor/update-runner scripts (2.11.2: `aio/update.sh` does it after every successful update) | `./install-user-scripts.sh` |
| 2.10: install the version an admin chose under Opdateringer (User Script, every minute; 2.11.2: uses the WebUI's GitHub token when the host has no `operations/github-token`) | `update-runner.sh` (`--dry-run` checks a waiting request) |
| 2.12: sign a published release by hand (owner machine; uploads `.sha256.sig`, checked by `update-runner.sh` against `release-signers`) | `sign-release.sh vX.Y.Z [--key FILE] [--dry-run]` |
| Manual backup | `./backup-and-verify.sh` |
| Manual status refresh | `./host-monitor.sh` (`--dry-run` prints the JSON) |
| Fresh install only | `init-host.sh` → `run-containers.sh` → `init-dashboard-user.sh` → `install-user-scripts.sh` |

### migrate-2.0.sh (first time)
Builds `imap-spamfilter-unraid:2.0.0`, validates `unbound.conf`
(unbound-checkconf) and `rspamd/local.d` (`rspamadm configtest`) in
throwaway containers, runs a verified backup, locks down `source/`,
installs `unbound.conf` and the non-secret rspamd files (the rendered
`redis.conf` / `worker-controller.inc` are never touched), recreates
redis → unbound → rspamd → filter with health gates, chowns `state/` and
`config/` to uid 10099 (dirs 0700, files 0600, `heartbeat`,
`host-status.json`, `backup-status.json` 0644), installs the User Scripts
`Spamfilter-backup` (03:00) and `Spamfilter-monitor` (*/5) with the script
bodies inline, and runs the monitor once. Re-running is safe: containers
whose definition is unchanged are skipped.

### recreate-filter.sh (updates)
Backup → stop → rename to `spamfilter-rollback` → delete heartbeat → run
the new image → gate: running ≥ 40 s with RestartCount 0, heartbeat newer
than the container start, `curl -fsS http://192.168.1.10:18080/healthz` = 200
and the log line `loaded N account(s)`. A failed gate rolls back
automatically (failed logs: `operations/failed-spamfilter-<stamp>.log`).

### recreate-infra.sh redis|rspamd|unbound|all
Same pattern for the infra containers (Docker health gate). Config files
replaced in the run are restored on rollback. After a redis/unbound
recreate rspamd is restarted so it resolves the new addresses. With
`ENABLE_FUZZY=1` the rspamd step checks `rspamadm fuzzy_ping` and falls back
to the disabled `fuzzy_check.conf` if UDP 11335 egress is blocked.

### backup-and-verify.sh (cron 03:00)
SQLite online backup + Redis BGSAVE + config/secrets/audit log/
`removed-secrets`/`unbound.conf` into
`operations/backups/spamfilter-<UTC>.tar.gz` (0600), restore-tested in
`--network none` containers built from the running containers' image ids.
Prunes archives older than 14 days, writes `state/backup-status.json`,
sends an Unraid alert on failure.

### host-monitor.sh (cron */5)
Writes `state/host-status.json` (containers, disk, rspamd, Spamhaus DNS
test via Unbound, RBL failure rate, heartbeat age, account states from
`/api/health`, backup age, active alerts) for the WebUI's Drift page and
sends de-duplicated Unraid notifications (state in
`operations/monitor-state.json`). Works while the filter is down.

## Rollback

During a recreate the previous container is kept stopped as
`<name>-rollback`; a failed gate restores it automatically. Since 2.3,
`recreate-filter.sh` and `recreate-infra.sh` remove that stopped
`<name>-rollback` once the new container has passed its health gate, and
delete local `imap-spamfilter-unraid` images older than the previous
version (the running image and one previous version are always kept, as
are newer tags, non-version tags such as `latest` and any image a
container still uses). Add `--keep-rollback` to keep the stopped container
for a manual rollback; `migrate-2.0.sh` always keeps it. With a kept
rollback container you go back manually like this, e.g. for the filter:

```bash
docker stop spamfilter && docker rename spamfilter spamfilter-failed
docker rename spamfilter-rollback spamfilter
# 1.x ran as 99:100 - give state/config back to it before starting:
chown -R 99:100 /mnt/user/appdata/spamfilter/{state,config}
docker update --restart unless-stopped spamfilter && docker start spamfilter
docker rm spamfilter-failed
```

Without a kept rollback container, start the previous image (it is never
pruned) with the normal gated deploy:
`deploy/recreate-filter.sh --image imap-spamfilter-unraid:<previous version>`.

The 2.0 schema changes are additive only, so 1.x keeps working on the
migrated database. For data, unpack the newest
`operations/backups/spamfilter-*.tar.gz` (see `BACKUP.md`). Replaced
config files are kept under `operations/config-backups/<stamp>/`; files
that did not exist before that run are listed in
`operations/config-backups/<stamp>/NEW_FILES` (paths relative to the app
dir). The User Scripts schedule files are under
`operations/user-scripts-backup-<stamp>/`.

### Going back from 2.2 to 2.1 (rspamd rules)

Only the automatic rollback inside a failing deploy run removes the rspamd
files that 2.2 added. Renaming `spamfilter-rspamd-rollback` back, or
redeploying the 2.1.0 tree, leaves them active: `local.d` is bind-mounted,
2.1's file list does not know them, and its config digest ignores them.
2.1 would then run with the 2.2 phishing rules and OpenPhish, but without
the 2.2 filter's webshop offset. After going back, delete what 2.2 created
and put back the files it replaced (2.1's `groups.conf`), then restart
rspamd:

```bash
APP=/mnt/user/appdata/spamfilter
STAMP=<stamp of the 2.2 deploy>   # ls $APP/operations/config-backups/
cat $APP/operations/config-backups/$STAMP/NEW_FILES   # what 2.2 created
rm -f $APP/rspamd/local.d/{composites,multimap,phishing}.conf
rm -rf $APP/rspamd/local.d/maps.d
cp -p $APP/operations/config-backups/$STAMP/rspamd/local.d/*.conf $APP/rspamd/local.d/
docker restart spamfilter-rspamd
```

The 2.2 schema changes are additive too, so 2.1 runs on the 2.2 database.

## Validation that only works on the host
`rspamadm configtest`, `unbound-checkconf`, the container capability sets
(`--cap-drop ALL` on all four; unbound gets NET_BIND_SERVICE, SETUID,
SETGID, SYS_CHROOT, CHOWN, DAC_OVERRIDE, MKNOD; redis runs directly as
999:1000) and fuzzy egress are exercised by the scripts themselves on the
host: `--dry-run` only prints the plan; the real run validates the configs
in throwaway containers before it changes anything.

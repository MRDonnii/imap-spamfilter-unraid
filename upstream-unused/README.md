# upstream-unused — DO NOT USE ON HJEMMESERVER

These files come from the upstream project (marcelverdult/imap-spamfilter)
and are kept only for reference when merging upstream changes:

- `unraid/` — Community Applications templates + `bootstrap.sh`
- `docker-compose.yml` — Compose Manager stack
- `ca_profile.xml` — Community Applications profile

**Using any of them would damage this install.** They create containers
with different names/paths (`/mnt/user/appdata/spamfilter`), unpinned
images (`redis:8-alpine`, `latest` tags), the upstream runtime user
(99:100 instead of 10099), no health gates and no rollback, and
`bootstrap.sh` re-renders `redis.conf` / `worker-controller.inc`
(rotating or breaking the rspamd/Redis passwords). An Unraid template
would also put an "update" button on containers that are meant to be
pinned by digest.

This install is managed only with the scripts in `deploy/` (see
`deploy/README.md`): `migrate-2.0.sh`, `recreate-filter.sh`,
`recreate-infra.sh`, `backup-and-verify.sh`, `host-monitor.sh`.

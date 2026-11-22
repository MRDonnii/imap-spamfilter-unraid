"""CLI to bulk-train Bayes (or calibrate) from an existing IMAP folder.

Thin wrapper over trainer.py, so it shares the trainer's guarantees:
read-only IMAP (EXAMINE + BODY.PEEK - nothing is moved, flagged or
deleted), newest messages first, chunked fetches, 5 MiB size cap, at most
5 learns/s, learns through the engine's learn_message bookkeeping.

Usage (inside the container):
    python bootstrap_train.py <account> <folder> <spam|ham|calibrate>
        [--limit N] [--seen-only] [--min-age-days N]
        [--provider-filter any|provider_spam|provider_clean]
        [--queue] [--dry-run]

  --dry-run  list what would be learned (header pass only; no rspamd,
             no database writes)
  --queue    only queue the job for the running filter's trainer thread
             (visible on the Træning page) and exit

The old --move-to option is gone on purpose: training never writes to IMAP.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import trainer

DEFAULT_LIMIT = 300


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("account", help="account name from accounts.yml")
    p.add_argument("folder", help="IMAP folder, e.g. INBOX or Junk")
    p.add_argument("kind", choices=["spam", "ham", "calibrate"])
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                   help=f"max messages, newest first (default {DEFAULT_LIMIT})")
    p.add_argument("--seen-only", action="store_true", help="only messages marked read")
    p.add_argument("--min-age-days", type=int, default=0,
                   help="only messages older than N days")
    p.add_argument("--provider-filter", default="any",
                   choices=["any", "provider_spam", "provider_clean"])
    p.add_argument("--queue", action="store_true",
                   help="queue for the running filter's trainer and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be learned; change nothing")
    p.add_argument("--config", help="accounts.yml path (default: engine CONFIG_PATH)")
    # 1.x option, kept only to fail with a clear message instead of a usage error.
    p.add_argument("--move-to", help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None, *, engine: Any = None) -> int:
    args = _parser().parse_args(argv)
    if args.move_to:
        print("--move-to is no longer supported: training never writes to IMAP",
              file=sys.stderr)
        return 2
    if engine is None:
        import filter as engine
    if args.config:
        engine.CONFIG_PATH = Path(args.config)
    if not 1 <= args.limit <= 5000:
        print("--limit must be between 1 and 5000", file=sys.stderr)
        return 2

    if args.dry_run:
        try:
            cands, oversize = trainer.plan_job(
                args.account, args.folder, max_messages=args.limit,
                seen_only=args.seen_only, min_age_days=args.min_age_days,
                provider_filter=args.provider_filter, engine=engine)
        except trainer.JobAborted as ex:
            print(f"error: {ex.text}", file=sys.stderr)
            return 2
        verb = "scan" if args.kind == "calibrate" else f"learn-{args.kind}"
        for c in cands:
            subj = (c.subject or "")[:60].replace("\n", " ")
            print(f"[dry-run] would {verb}: uid={c.uid} size={c.size} subj={subj!r}")
        print(f"[dry-run] {len(cands)} message(s) selected, {oversize} skipped as too large")
        return 0

    import services

    engine.init_db()
    try:
        if args.kind == "calibrate":
            job_id = services.queue_calibration(args.account, args.folder,
                                                max_messages=args.limit,
                                                min_age_days=args.min_age_days,
                                                actor="cli", engine=engine)
        else:
            job_id = services.queue_train_job(args.account, args.folder, args.kind, args.limit,
                                              min_age_days=args.min_age_days,
                                              seen_only=args.seen_only,
                                              provider_filter=args.provider_filter,
                                              # explicit CLI kind + folder
                                              allow_inbox_spam=True,
                                              actor="cli", engine=engine)
    except ValueError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    if args.queue:
        print(f"queued job {job_id}; the filter's trainer picks it up within seconds")
        return 0

    # Run here; the atomic queued->running claim keeps the trainer thread
    # of a running filter off this job (and vice versa).
    status = trainer.run_job(job_id, engine=engine)
    if status == "skipped":
        print(f"job {job_id} was taken by the running trainer; follow it in the UI")
        return 0
    job = next((j for j in services.list_train_jobs(50, engine=engine) if j["id"] == job_id), None)
    if job:
        print(f"job {job_id}: {status} total={job['total']} learned={job['learned']} "
              f"skipped={job['skipped']} failed={job['failed']}"
              + (f" error={job['error']}" if job.get("error") else ""))
    if args.kind == "calibrate" and status == "done":
        _print_calibration(services, job_id, engine)
    return 0 if status == "done" else 3


CLI_THRESHOLDS = (6.0, 8.0, 10.0, 12.0, 15.0)


def _print_calibration(services: Any, job_id: int, engine: Any) -> None:
    """Final AND blind catch counts (S4): the blind score leaves out the
    provider's verdict (SPAM_FLAG, TH_PROVIDER_*) and Bayes (BAYES_*), which
    already 'know' a provider-sorted folder that Bayes was trained on."""
    s = services.calibration_summary(job_id, CLI_THRESHOLDS, engine=engine)

    def caught(d: dict) -> str:
        return " ".join(f">={c['threshold']:g}:{c['n']}" for c in d.get("caught_at") or [])

    print(f"calibration: {s.get('count', 0)} scored, median final={s.get('median')}")
    print(f"  final score caught {caught(s)}")
    print(f"  blind score caught {caught(s.get('blind') or {})}")
    print("  blind = without SPAM_FLAG, TH_PROVIDER_* and BAYES_* - what the other rules catch "
          "on new spam; a big gap means the final numbers are flattered")


if __name__ == "__main__":
    sys.exit(main())

# Validation — 2.15.0 beta

Scope: only public MRDonnii/imap-spamfilter-unraid, based on 249fca756a11ba24fc301f4cbe73314711091534. No live server or mailbox actions.

The six original regression cases (missing ID on UIDPLUS/MOVE, body/sender ID collision, ordinary allow during grace on UIDPLUS/MOVE) failed against the original engine and pass with these changes. Further regression coverage includes distinct no-ID messages across restart, exact-content lookup, actual release/search through services, virus/spoof priority, reserved-ID impersonation, notification impersonation, complete evidence beyond truncated UI symbols, raised score threshold, coverage isolation and deterministic evaluation.

Completed during implementation: 269 focused engine/services tests; 195 focused services/restore/quality/deploy tests. Real encrypted backup restored to a temporary directory, actual Redis loaded with a neutral key, HTTP app started, original database unchanged; wrong key, broken SQLite and broken Redis rejected. Python compilation, shell parsing, whitespace checks and build-context staging passed.

Pending when this initial report was committed: final full suite and GitHub container build/smoke/security checks. Publishing requires their results and checksum/signature download verification. These results will be recorded separately before handover.

Limitations: no live IMAP/SMTP/server acceptance; no human-labelled family dataset; no AI correctness claim. Restore drill loads SQLite/application/Redis without account workers, Rspamd or ClamAV. Container CI is required because local Docker access is unavailable. The existing CI disables ClamAV signature downloads and checks it offline during image build.

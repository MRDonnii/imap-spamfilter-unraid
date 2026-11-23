# Validation — 2.15.0 beta

Scope: only public MRDonnii/imap-spamfilter-unraid, based on 249fca756a11ba24fc301f4cbe73314711091534. No live server or mailbox actions.

The six original regression cases (missing ID on UIDPLUS/MOVE, body/sender ID collision, ordinary allow during grace on UIDPLUS/MOVE) failed against the original engine and pass with these changes. Further regression coverage includes distinct no-ID messages across restart, exact-content lookup, actual release/search through services, virus/spoof priority, reserved-ID impersonation, notification impersonation, complete evidence beyond truncated UI symbols, raised score threshold, coverage isolation and deterministic evaluation.

Completed during implementation: 269 focused engine/services tests; 195 focused services/restore/quality/deploy tests. Real encrypted backup restored to a temporary directory, actual Redis loaded with a neutral key, HTTP app started, original database unchanged; wrong key, broken SQLite and broken Redis rejected. Python compilation, shell parsing, whitespace checks and build-context staging passed.

Container evidence: [CI run 45089101084](https://github.com/MRDonnii/imap-spamfilter-unraid/actions/runs/45089101084), aio-image job, passed actual encrypted snapshot/restore, HTTP application and Redis loading, Rspamd scanning/learning, restart persistence, listener checks, frozen-image pip-audit and Trivy. The first smoke attempt exposed a missing working directory in the new test command; it was corrected to /app.

The first full local implementation run completed with 4003 passing tests and two legacy-queue compatibility failures. Cancellation after a threshold change now requires a recorded previous threshold and an actual increase. All 69 affected safety/identity/rule/UI tests then passed. The whole suite is repeated after this correction; the final count and exact release-commit CI are recorded in the [2.15.0 release notes](https://github.com/MRDonnii/imap-spamfilter-unraid/releases/tag/v2.15.0) and [PR checks](https://github.com/MRDonnii/imap-spamfilter-unraid/pull/4/checks).

Publication gate: all checks on the release commit must pass; source tarball, GitHub asset digest, SHA-256 and SSH release signature must match after download. The signature key was preflight-tested successfully without exposing its contents. No release is considered installable until these checks complete.

Limitations: no live IMAP/SMTP/server acceptance; no human-labelled family dataset; no AI correctness claim. Restore drill loads SQLite/application/Redis without account workers, Rspamd or ClamAV. Container CI is required because local Docker access is unavailable. The existing CI disables ClamAV signature downloads and checks it offline during image build.


A subsequent full local run passed 4005 tests with 7 skips. A final adversarial regression then demonstrated that an oversized junk-folder arrival reusing an existing released ID could still overwrite its verdict when no body was fetched. Junk observation now requires content before recording a verdict or learning; unavailable bodies are counted separately. Oversize and missing-body collisions are covered on both UIDPLUS and MOVE. Final whole-suite results for this additional guard are in the release notes and exact-commit CI linked above.

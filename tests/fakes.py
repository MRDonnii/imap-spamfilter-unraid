"""Index of the shared test fakes (SPEC section 1 names tests/fakes.py).

The fakes were built concurrently per role and are kept in separate,
non-conflicting modules; import from the one that fits the layer under test:

  fakes_engine    RFC-accurate FakeIMAP (UID n:* semantics, MOVE vs UIDPLUS,
                  COPYUID, \\Deleted + UID EXPUNGE, EXAMINE read-only),
                  FakeRspamd, stub_mailctx, setup_engine. Used by the engine
                  tests and the end-to-end smoke test.
  fakes_services  FakeIMAP variant that records writes and rejects any write
                  on a read-only select, plus FakeEngine exposing the E14/A2
                  primitive names over a real SQLite file.
  fakes_ui        make_env/login/post helpers; the DB is created with the REAL
                  filter.init_db() schema. FakeEngine/FakeServices for the UI.
  fakes_ui_admin  YAML-backed engine fake + admin services fake.
  fakes_deploy    fake docker/curl/notify binaries for the deploy scripts.

The canonical IMAP/rspamd fakes are re-exported here.
"""

from fakes_engine import (  # noqa: F401
    BARE_CAPS,
    GIGAHOST_CAPS,
    SCANNET_CAPS,
    FakeIMAP,
    FakeRspamd,
    make_account,
    make_message,
    setup_engine,
    stub_mailctx,
)

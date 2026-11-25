"""ENGINE: accounts.yml loading (SPEC 2)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fakes_engine import setup_engine  # noqa: E402


@pytest.fixture
def eng(tmp_path, monkeypatch):
    return setup_engine(tmp_path, monkeypatch)


def write_cfg(path: Path, accounts: list[dict], defaults: dict | None = None) -> Path:
    data: dict = {"accounts": accounts}
    if defaults is not None:
        data["defaults"] = defaults
    path.write_text(yaml.safe_dump(data))
    return path


def secret(tmp_path: Path, name: str, value: str = "s3cret") -> str:
    p = tmp_path / f"{name}.pw"
    p.write_text(value + "\n")
    return str(p)


def test_load_account_configs_returns_all_without_reading_secrets(eng, tmp_path):
    cfg = write_cfg(tmp_path / "accounts.yml", [
        {"name": "a", "user": "a@x.dk", "imap_host": "h", "password_file": str(tmp_path / "missing.pw")},
        {"name": "b", "user": "b@x.dk", "imap_host": "h", "enabled": False, "junk": "Spamfilter",
         "password_file": str(tmp_path / "missing2.pw")},
    ], defaults={"bayes_user": "hjemmeserver"})
    accs = eng.load_account_configs(cfg)
    assert [a.name for a in accs] == ["a", "b"]
    a, b = accs
    assert a.password == "" and b.password == ""  # secrets never read
    assert a.enabled is True and b.enabled is False
    assert b.junk == "Spamfilter" and b.junk_explicit is True and a.junk_explicit is False
    assert a.trash_explicit is False
    assert a.bayes_user == "hjemmeserver" and eng.bayes_identity(a) == "hjemmeserver"
    # 2.0 defaults
    assert a.mode == "shadow" and a.threshold == 8.0
    assert a.max_moves_per_hour == 60 and a.junk_poll_interval == 300
    assert a.auto_block_repeated_spam is True
    assert a.training_folders is False and a.provider_bonus is True
    assert a.trusted_relays == [] and a.trusted_relay_domains == []


def test_default_junk_does_not_count_as_explicit(eng, tmp_path):
    cfg = write_cfg(tmp_path / "accounts.yml", [
        {"name": "a", "user": "a@x.dk", "imap_host": "h", "password": "x"},
    ], defaults={"junk": "Spam"})
    (a,) = eng.load_account_configs(cfg)
    assert a.junk == "Spam" and a.junk_explicit is False


def test_read_secret_and_load_accounts(eng, tmp_path):
    cfg = write_cfg(tmp_path / "accounts.yml", [
        {"name": "a", "user": "a@x.dk", "imap_host": "h", "password_file": secret(tmp_path, "a")},
        {"name": "p", "user": "p@x.dk", "imap_host": "h", "enabled": False},  # paused, no secret
        {"name": "i", "user": "i@x.dk", "imap_host": "h", "password": "inline"},
    ])
    accs = {a.name: a for a in eng.load_account_configs(cfg)}
    assert eng.read_secret(accs["a"]) == "s3cret"
    assert eng.read_secret(accs["i"]) == "inline"
    with pytest.raises(ValueError):
        eng.read_secret(accs["p"])
    loaded = eng.load_accounts(cfg)
    assert [a.name for a in loaded] == ["a", "i"]  # enabled only
    assert loaded[0].password == "s3cret"


def test_load_accounts_exits_on_unreadable_secret(eng, tmp_path):
    cfg = write_cfg(tmp_path / "accounts.yml", [
        {"name": "a", "user": "a@x.dk", "imap_host": "h", "password_file": str(tmp_path / "nope")},
    ])
    with pytest.raises(SystemExit):
        eng.load_accounts(cfg)
    assert len(eng.load_account_configs(cfg)) == 1  # configs still load


@pytest.mark.parametrize("override, fragment", [
    ({"mode": "filter"}, "mode"),
    ({"auto_block_repeated_spam": "maybe"}, "auto_block_repeated_spam"),
    ({"training_folders": "maybe"}, "training_folders"),
    ({"provider_bonus": "nope"}, "provider_bonus"),
    ({"enabled": "perhaps"}, "enabled"),
    ({"trusted_relays": ["192.168.1.0/33"]}, "trusted_relays"),
    ({"trusted_relays": "not-an-ip"}, "trusted_relays"),
    ({"trusted_relay_domains": ["bad domain"]}, "trusted_relay_domains"),
    ({"trusted_relay_domains": [{"x": 1}]}, "trusted_relay_domains"),
    ({"threshold": 3.0}, "threshold"),
    ({"bayes_user": "a\nb"}, "bayes_user"),
    ({"junk": "INBOX"}, "distinct"),
    ({"max_moves_per_hour": 0}, "max_moves_per_hour"),
])
def test_validation_rejects_bad_values(eng, tmp_path, override, fragment):
    entry = {"name": "a", "user": "a@x.dk", "imap_host": "h", "password": "x", **override}
    cfg = write_cfg(tmp_path / "accounts.yml", [entry])
    with pytest.raises(ValueError) as ei:
        eng.load_account_configs(cfg)
    assert not isinstance(ei.value, SystemExit)
    msg = str(ei.value)
    assert fragment in msg or "junk" in msg


def test_valid_new_keys_are_parsed(eng, tmp_path):
    cfg = write_cfg(tmp_path / "accounts.yml", [{
        "name": "a", "user": "a@x.dk", "imap_host": "h", "password": "x",
        "training_folders": "yes", "provider_bonus": False, "auto_block_repeated_spam": False,
        "trusted_relays": ["46.183.139.0/24", "2001:db8::/32"],
        "trusted_relay_domains": ["relay.example.net", ".example.org"],
    }])
    (a,) = eng.load_account_configs(cfg)
    assert a.auto_block_repeated_spam is False
    assert a.training_folders is True and a.provider_bonus is False
    assert a.trusted_relays == ["46.183.139.0/24", "2001:db8::/32"]
    assert a.trusted_relay_domains == ["relay.example.net", ".example.org"]


@pytest.mark.parametrize("text", ["accounts: [", "just a string", "accounts: 5", "defaults: []\naccounts: []"])
def test_broken_yaml_raises_valueerror(eng, tmp_path, text):
    p = tmp_path / "accounts.yml"
    p.write_text(text)
    with pytest.raises(ValueError):
        eng.load_account_configs(p)


def test_missing_config_file_is_valueerror(eng, tmp_path):
    with pytest.raises(ValueError):
        eng.load_account_configs(tmp_path / "absent.yml")


def test_duplicate_names_rejected(eng, tmp_path):
    e = {"name": "a", "user": "a@x.dk", "imap_host": "h", "password": "x"}
    cfg = write_cfg(tmp_path / "accounts.yml", [e, dict(e)])
    with pytest.raises(ValueError, match="duplicate"):
        eng.load_account_configs(cfg)


def test_request_reload_touches_flag(eng, tmp_path):
    eng.request_reload()
    assert (tmp_path / "reload_requested").exists()


def test_primitives_exist():
    import filter as engine

    for name in ("init_db", "Db", "load_accounts", "load_account_configs", "read_secret",
                 "bayes_identity", "connect", "imap_move", "move_method_for",
                 "find_uids_by_message_id", "rspamd_scan", "rspamd_learn", "parse_envelope",
                 "bump_stat", "match_sender_rule", "add_sender_rule", "delete_sender_rule",
                 "normalize_rule_pattern", "request_reload", "learn_message", "MoveUnsupported",
                 "ScanResult", "MAX_FETCH_BYTES", "STATE_DIR", "DB_PATH", "CONFIG_PATH"):
        assert hasattr(engine, name), name
    assert engine.VERSION == "2.19.4"
    assert engine.SCORE_VERSION == 2


def test_double_import_guard():
    """A1: running filter.py as __main__ registers it as `filter`."""
    src = (Path(__file__).resolve().parents[1] / "filter" / "filter.py").read_text()
    assert 'if __name__ == "__main__":\n    sys.modules.setdefault("filter", sys.modules[__name__])' in src
    # The guard sits before any other module-level code that could import
    # services/trainer (they `import filter`).
    assert src.index("sys.modules.setdefault") < src.index("VERSION = ")

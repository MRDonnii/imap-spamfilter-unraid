"""CI only: real local fuzzy learning -> consistent encrypted Redis snapshot."""
from pathlib import Path
import shutil
import sys
import time


def main(root=Path('/fixture')):
    sys.path.insert(0, '/app')
    import backup
    import filter as engine
    import fuzzyrestoreproof
    import yaml
    app = Path('/appdata')
    assert yaml.safe_load((app / 'config/accounts.yml').read_text()).get('accounts') == []
    fuzzyrestoreproof.seed((app / 'state/controller.password').read_text().strip())
    # The fixture uses sync=1s; allow the queued fuzzy write to reach Redis.
    time.sleep(3)
    # This assertion belongs to the encrypted archive, never to live state.
    (app / 'state/restore-fuzzy-canary.json').write_text('{"schema_version":1}\n')
    dest = root / 'backups'
    dest.mkdir()
    backup.configure(app / 'state', app / 'config/accounts.yml', appdata=app, backup_dir=dest, version=engine.VERSION)
    backup.REQUIRE_MOUNT = False
    status = backup.run_backup(reason='neutral-fuzzy-ci-fixture', now=time.time())
    assert status['ok'], 'Could not make neutral encrypted fuzzy fixture'
    verified = backup.verify(dest / status['archive'])
    assert verified['learning_stores']['local_fuzzy']['snapshot'] == 'redis/dump.rdb'
    with backup.Archive(dest / status['archive'], backup.load_key()) as archive:
        assert 'state/restore-fuzzy-canary.json' in {f['name'] for f in archive.manifest['files']}
    shutil.copyfile(dest / status['archive'], root / 'fixture.sfbak')
    shutil.copyfile(app / 'state/backup.key', root / 'fixture.key')
    (root / 'fixture.key').chmod(0o600)
    print('Neutral encrypted restore fixture ready; local fuzzy learned and verified before backup')


if __name__ == '__main__':
    main()

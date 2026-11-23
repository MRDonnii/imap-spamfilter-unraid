"""CI only: make a neutral encrypted snapshot, using the built AIO image.

No real accounts/network/secrets. Executed only by the explicit image CI step.
"""
import os
from pathlib import Path
import shutil
import sys


def main(root=Path('/fixture')):
    app = root / 'appdata'
    app.mkdir()
    os.environ['STATE_DIR'] = str(app / 'state')
    os.environ['CONFIG_PATH'] = str(app / 'config/accounts.yml')
    sys.path[:0] = ['/app', '/usr/local/lib/spamfilter-aio']
    import aio_render
    import backup
    import filter as engine
    import stackrestore
    assert aio_render.init_appdata(app, Path('/usr/local/share/spamfilter-aio'), chown=False)
    (app / 'config/accounts.yml').write_text('accounts: []\n')
    engine.init_db()
    stackrestore.seed_canary(app / 'redis')
    dest = root / 'backups'
    dest.mkdir()
    backup.configure(app / 'state', app / 'config/accounts.yml', appdata=app, backup_dir=dest)
    backup.REQUIRE_MOUNT = False
    def local_dump(path):
        shutil.copyfile(app / 'redis/dump.rdb', path)
        return True, ''
    backup.redis_dump = local_dump
    status = backup.run_backup(reason='neutral-ci-fixture')
    assert status['ok'], 'Could not make neutral encrypted fixture'
    shutil.copyfile(dest / status['archive'], root / 'fixture.sfbak')
    shutil.copyfile(app / 'state/backup.key', root / 'fixture.key')
    (root / 'fixture.key').chmod(0o600)
    print('Neutral encrypted restore fixture ready')


if __name__ == '__main__':
    main()

"""Exercise the real updater with local packages and no network or service access."""
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('TEST_BASH', 'bash')


def bash_path(path):
    value = path.as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value


class UpdateTest(unittest.TestCase):
    def test_live_old_process_is_not_success_and_binaries_are_restored(self):
        with tempfile.TemporaryDirectory(prefix='pronet-update-test-') as directory:
            root = Path(directory)
            app, backup, mock = (root / n for n in ('app', 'backup', 'mock'))
            for p in (app / 'bin', backup, mock):
                p.mkdir(parents=True, exist_ok=True)
            old_panel = b'original-panel\n'
            (app / 'x-ui').write_bytes(old_panel)
            (app / 'bin/xray-linux-amd64').write_bytes(b'original-core\n')
            (app / 'x-ui.sh').write_bytes(b'original-menu\n')
            archive = root / 'package.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for name, body in {
                    'x-ui/x-ui': '#!/usr/bin/env bash\necho 3.10.2-pronet.10\n',
                    'x-ui/bin/xray-linux-amd64': '#!/usr/bin/env bash\necho custom-core\n',
                    'x-ui/x-ui.sh': '#!/usr/bin/env bash\necho new-menu\n',
                }.items():
                    data = body.encode()
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), 0o755
                    tar.addfile(info, io.BytesIO(data))
            checksum = root / 'checksums.txt'
            checksum.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  x-ui-linux-amd64.tar.gz\n')
            paths = {p.name: shlex.quote(bash_path(p)) for p in (root, app, backup, mock, archive, checksum)}
            (mock / 'curl').write_text(
                '#!/usr/bin/env bash\nset -e\nfor arg in "$@"; do '
                'case "$arg" in *checksums.txt) src="$FIXTURE_CHECKSUM";; '
                '*tar.gz) src="$FIXTURE_ARCHIVE";; esac; done\n'
                'while [[ "$1" != -o ]]; do shift; done\ncp "$src" "$2"\n', newline='\n'
            )
            (mock / 'uname').write_text('#!/usr/bin/env bash\necho x86_64\n', newline='\n')
            (mock / 'flock').write_text('#!/usr/bin/env bash\nexit 0\n', newline='\n')
            for p in mock.iterdir():
                p.chmod(0o755)
            startup = root / 'startup.sh'
            startup.write_text('kill(){ return 0; }\nsleep(){ :; }\n', newline='\n')
            script = (ROOT / 'pronet-update.sh').read_text().replace('/usr/bin/x-ui', bash_path(root / 'menu'))
            script = script.replace('/run/lock/pronet-update.lock', bash_path(root / 'update.lock'))
            script_path = root / 'update.sh'
            script_path.write_text(script, newline='\n')
            env = dict(os.environ, XUI_UPDATE_TAG='v3.10.2-pronet.10', XUI_MAIN_FOLDER=bash_path(app),
                       XUI_BACKUP_FOLDER=bash_path(backup), XUI_UPDATE_PID='999999999',
                       XUI_UPDATE_STATUS_FILE=bash_path(root / 'status.json'), XUI_UPDATE_RUN_ID='1',
                       FIXTURE_ARCHIVE=bash_path(archive), FIXTURE_CHECKSUM=bash_path(checksum),
                       BASH_ENV=bash_path(startup))
            command = 'export PATH=' + paths['mock'] + ':"$PATH"; bash ' + shlex.quote(bash_path(script_path))
            result = subprocess.run([BASH, '-c', command], env=env, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0, 'An unchanged process was incorrectly reported as updated')
            self.assertEqual((app / 'x-ui').read_bytes(), old_panel)
            self.assertEqual((app / 'bin/xray-linux-amd64').read_bytes(), b'original-core\n')
            self.assertEqual((app / 'x-ui.sh').read_bytes(), b'original-menu\n')
            self.assertTrue((root / 'status.json').exists(), result.stderr.decode(errors='replace'))
            self.assertIn('"state":"failed"', (root / 'status.json').read_text())


if __name__ == '__main__':
    unittest.main()

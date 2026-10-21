"""A recreated image restores only a newer, complete persisted runtime."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DockerRuntimeTest(unittest.TestCase):
    def test_recreation_restores_verified_update_but_never_downgrades_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);app=root/'app';runtime=root/'db/pronet-runtime';slot=runtime/'releases/v3.10.2-pronet.13-test'
            (app/'bin').mkdir(parents=True);slot.mkdir(parents=True)
            def panel(version): return '#!/bin/sh\necho '+version+'\n'
            (app/'x-ui').write_text(panel('3.10.2-pronet.12'));(app/'x-ui').chmod(0o755)
            for name,body in {'x-ui':panel('3.10.2-pronet.13'),'xray':'new-core','menu':'new-menu'}.items():
                (slot/name).write_text(body);(slot/name).chmod(0o755)
            (slot/'version').write_text('3.10.2-pronet.13\n')
            (slot/'checksums.txt').write_text(''.join(hashlib.sha256((slot/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in ('x-ui','xray','menu')))
            (runtime/'current').symlink_to(slot, target_is_directory=True)
            env=dict(os.environ,XUI_MAIN_FOLDER=str(app),XUI_DB_FOLDER=str(root/'db'),XUI_DOCKER_MENU=str(root/'menu'))
            def restore():
                r=subprocess.run(['bash',str(ROOT/'pronet-docker-runtime.sh')],env=env,capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                return r.stdout+r.stderr
            report=restore()
            self.assertEqual((app/'x-ui').read_text(),panel('3.10.2-pronet.13'),report)
            self.assertEqual((app/'bin/xray-linux-amd64').read_text(),'new-core')
            (app/'x-ui').write_text(panel('3.10.2-pronet.14'));restore()
            self.assertEqual((app/'x-ui').read_text(),panel('3.10.2-pronet.14'))
            (app/'x-ui').write_text(panel('3.10.2-pronet.12'));(slot/'xray').write_text('corrupt');restore()
            self.assertEqual((app/'x-ui').read_text(),panel('3.10.2-pronet.12'))

if __name__=='__main__':unittest.main()

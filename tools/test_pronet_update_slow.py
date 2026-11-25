"""The real updater must survive a slow graceful shutdown before exec."""
import hashlib
import os
import platform
from pathlib import Path
import shlex
import signal
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class SlowRestartTest(unittest.TestCase):
    def test_slow_live_exec_is_not_rolled_back_at_thirty_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);app=root/'app';backup=root/'backup';mock=root/'mock'
            arch='amd64' if platform.machine()=='x86_64' else 'arm64'
            for folder in (app/'bin',backup,mock,root/'package/x-ui/bin'):folder.mkdir(parents=True)
            source=root/'panel.c';source.write_text('''#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
volatile sig_atomic_t update=0;
void notify(int sig){update=1;}
int main(int argc,char **argv){if(argc>1){puts(VERSION);return 0;} signal(SIGUSR2,notify);while(!update)pause();sleep(35);execl(argv[0],argv[0],NULL);return 1;}
''')
            for version,path in [('3.10.2-pronet.12',app/'x-ui'),('3.10.2-pronet.13',root/'package/x-ui/x-ui')]:
                subprocess.run(['gcc','-DVERSION="'+version+'"',str(source),'-o',str(path)],check=True)
            (app/f'bin/xray-linux-{arch}').write_text('old-core');(app/'x-ui.sh').write_text('old-menu')
            for name in [f'bin/xray-linux-{arch}','x-ui.sh']:
                p=root/'package/x-ui'/name;p.write_text('#!/bin/sh\necho fixture\n');p.chmod(0o755)
            package=root/'package.tar.gz'
            with tarfile.open(package,'w:gz') as tar:tar.add(root/'package/x-ui',arcname='x-ui')
            (root/'checksums.txt').write_text(hashlib.sha256(package.read_bytes()).hexdigest()+f'  x-ui-linux-{arch}.tar.gz\n')
            (mock/'curl').write_text('#!/bin/bash\nsrc="$FIXTURE/package.tar.gz"\nfor arg in "$@"; do case "$arg" in *checksums.txt) src="$FIXTURE/checksums.txt";; esac; done\nwhile [[ "$1" != -o ]]; do shift; done\ncp "$src" "$2"\n');(mock/'curl').chmod(0o755)
            text=(ROOT/'pronet-update.sh').read_text().replace('/usr/bin/x-ui',str(root/'menu')).replace('/run/lock/pronet-update.lock',str(root/'lock'))
            script=root/'update.sh';script.write_text(text)
            proc=subprocess.Popen([str(app/'x-ui')])
            try:
                env=dict(os.environ,PATH=str(mock)+':'+os.environ['PATH'],FIXTURE=str(root),XUI_UPDATE_TAG='v3.10.2-pronet.13',XUI_MAIN_FOLDER=str(app),XUI_BACKUP_FOLDER=str(backup),XUI_UPDATE_PID=str(proc.pid),XUI_UPDATE_STATUS_FILE=str(root/'status.json'),XUI_UPDATE_RUN_ID='1')
                result=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True,timeout=100)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn('"state":"success"',(root/'status.json').read_text())
                self.assertEqual(os.stat('/proc/'+str(proc.pid)+'/exe').st_ino,(app/'x-ui').stat().st_ino)
            finally:
                proc.send_signal(signal.SIGTERM);proc.wait(timeout=5)

if __name__=='__main__':unittest.main()

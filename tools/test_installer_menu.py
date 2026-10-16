"""Read-only shell fixture tests; never runs installation or changes host services."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('TEST_BASH', 'bash')
INSTALL = (ROOT / 'pronet-install.sh').read_text(encoding='utf-8')
MENU = (ROOT / 'x-ui.sh').read_text(encoding='utf-8')

def function(name):
    start = MENU.index('\n' + name + '() {') + 1
    return MENU[start:MENU.index('\n}\n', start) + 3]

class InstallerTest(unittest.TestCase):
    def run_shell(self, text, input=''):
        result = subprocess.run([BASH, '-c', text], input=input.encode('utf-8'), capture_output=True)
        out, err = result.stdout.decode('utf-8'), result.stderr.decode('utf-8')
        self.assertEqual(result.returncode, 0, err + out)
        return out

    def test_menu_and_update_guards(self):
        output = self.run_shell(function('show_menu') + '\nshow_status(){ :; }; show_menu', '0\n')
        for label in ('SSL Certificate Management', 'Reset Username', 'PostgreSQL Management', 'Logs Management'):
            self.assertIn(label, output)
        self.assertNotIn('raw.githubusercontent.com/MHSanaei', MENU)
        self.assertNotIn('raw.githubusercontent.com/mhsanaei', MENU)
        self.assertIn('MaMMaD1999/pronet-3x-ui', function('installed_script_url'))
        self.assertIn('Only ProNet custom', function('legacy_version'))

    def test_shared_postgres_cannot_be_purged(self):
        body = function('purge_postgresql')
        for forbidden in ('apt-get', 'rm -', 'systemctl', 'dropdb', 'dnf', 'apk del'):
            self.assertNotIn(forbidden, body)
        output = self.run_shell('LOGI(){ echo "$*"; };\n' + body + '\npurge_postgresql')
        self.assertIn('all databases are preserved', output)

    def summary(self, fresh, host='', ssh='', cert=False):
        # Replace only the CLI calls and certificate file check with deterministic fixtures.
        summary = INSTALL[INSTALL.index('info=$(cd /usr/local/x-ui;'):]
        summary = summary.replace('cd /usr/local/x-ui; ./x-ui', 'panel')
        summary = summary.replace('[[ -n "$cert" && -f "$cert" ]]', '[[ -n "$cert" ]]')
        script = '''set -euo pipefail
panel(){
  if [[ "$*" == *-getCert* ]]; then printf 'cert: %s\\n' "$TEST_CERT";
  else printf 'username: existing-user\\nport: 2053\\nwebBasePath: /secret/\\n'; fi
}
curl(){ return 1; }
openssl(){ printf 'DNS:panel.example.com\\n'; }
hostname(){ printf '192.0.2.10\\n'; }
VERSION=test; backup=/backup; username=new-user; password=random-test-password
'''
        script += f"fresh={fresh}; PRONET_PANEL_HOST='{host}'; SSH_CONNECTION='{ssh}'; TEST_CERT={'/cert.pem' if cert else ''}\n"
        return self.run_shell(script + summary)

    def test_fresh_ipv4_summary(self):
        out = self.summary(1, ssh='198.51.100.2 123 203.0.113.10 22')
        self.assertIn('http://203.0.113.10:2053/secret/', out)
        self.assertIn('Username: new-user', out)
        self.assertIn('Password: random-test-password', out)
        self.assertIn('Management menu: x-ui', out)

    def test_upgrade_preserves_password(self):
        out = self.summary(0, host='panel.example.com')
        self.assertIn('Username: existing-user', out)
        self.assertIn('Password: unchanged', out)
        self.assertNotIn('random-test-password', out)

    def test_ipv6_and_https(self):
        self.assertIn('http://[2001:db8::1]:2053/secret/', self.summary(1, host='2001:db8::1'))
        self.assertIn('https://panel.example.com:2053/secret/', self.summary(0, cert=True))

if __name__ == '__main__':
    unittest.main()

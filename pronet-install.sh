#!/usr/bin/env bash
set -euo pipefail
# No configuration is erased. Staging files and backups are retained for review.
VERSION="${1:-v3.10.2-pronet.6}"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-pronet\.[0-9]+$ ]] || exit 1
[[ $(id -u) == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
for command in systemctl curl tar sha256sum openssl; do
  command -v "$command" >/dev/null || { echo "Install $command first." >&2; exit 1; }
done
case "$(uname -m)" in
  x86_64) arch=amd64;;
  aarch64|arm64) arch=arm64;;
  *) echo 'Only amd64 and arm64 are supported.' >&2; exit 1;;
esac
stage=$(mktemp -d /tmp/pronet-install.XXXXXXXX)
base="https://github.com/MaMMaD1999/pronet-3x-ui/releases/download/$VERSION"
archive="x-ui-linux-$arch.tar.gz"
curl --fail --location --retry 3 --proto '=https' "$base/$archive" -o "$stage/$archive"
curl --fail --location --retry 3 --proto '=https' "$base/checksums.txt" -o "$stage/checksums.txt"
(cd "$stage"; grep -E "  $archive$" checksums.txt > selected.sha256; test -s selected.sha256; sha256sum -c selected.sha256)
tar -tzf "$stage/$archive" | awk '/^\// || /(^|\/)\.\.(\/|$)/ {exit 1}'
tar -xzf "$stage/$archive" -C "$stage"
test -x "$stage/x-ui/x-ui"
test -x "$stage/x-ui/bin/xray-linux-$arch"
"$stage/x-ui/bin/xray-linux-$arch" version >/dev/null
fresh=1
[[ -f /etc/x-ui/x-ui.db || -x /usr/local/x-ui/x-ui ]] && fresh=0
backup="/var/backups/pronet/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup"
chmod 700 "$backup"
# The CLI also reads systemd's database environment. Preserve PostgreSQL and
# never mistake a PostgreSQL installation for a fresh SQLite installation.
for env_file in /etc/default/x-ui /etc/conf.d/x-ui /etc/sysconfig/x-ui; do
  [[ -f "$env_file" ]] || continue
  cp -a "$env_file" "$backup/service.env"
  fresh=0
  command -v python3 >/dev/null || { echo 'python3 is required to back up the existing database configuration.' >&2; exit 1; }
  python3 - "$env_file" "$backup" <<'PY'
import os, pathlib, shlex, subprocess, sys, urllib.parse
values = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    tokens = shlex.split(line, comments=True)
    if tokens and tokens[0] == 'export': tokens = tokens[1:]
    if len(tokens) == 1 and '=' in tokens[0]:
        key, value = tokens[0].split('=', 1)
        values[key] = value
if values.get('XUI_DB_TYPE', '').lower() in ('postgres', 'postgresql', 'pg'):
    dsn = values.get('XUI_DB_DSN')
    if not dsn: raise SystemExit('PostgreSQL DSN is missing; no files changed.')
    env = dict(os.environ)
    if dsn.startswith(('postgres://', 'postgresql://')):
        uri = urllib.parse.urlsplit(dsn)
        fields = dict(host=uri.hostname or '', port=str(uri.port or 5432),
            user=urllib.parse.unquote(uri.username or ''), password=urllib.parse.unquote(uri.password or ''),
            dbname=urllib.parse.unquote(uri.path.lstrip('/')),
            **dict(urllib.parse.parse_qsl(uri.query)))
    else:
        fields = dict(token.split('=', 1) for token in shlex.split(dsn) if '=' in token)
    names = dict(host='PGHOST', port='PGPORT', user='PGUSER', password='PGPASSWORD', dbname='PGDATABASE',
        sslmode='PGSSLMODE', sslcert='PGSSLCERT', sslkey='PGSSLKEY', sslrootcert='PGSSLROOTCERT')
    for key, name in names.items():
        if key in fields: env[name] = fields[key]
    result = subprocess.run(['pg_dump', '--format=custom', '--file=' + str(pathlib.Path(sys.argv[2])/'database.dump')], env=env, capture_output=True)
    if result.returncode: raise SystemExit('PostgreSQL backup failed; no program files were changed. Check pg_dump access.')
    print('PostgreSQL backup complete.')
PY
  break
done
systemctl stop x-ui 2>/dev/null || true
[[ ! -d /etc/x-ui ]] || cp -a /etc/x-ui "$backup/config"
[[ ! -d /usr/local/x-ui ]] || cp -a /usr/local/x-ui "$backup/program"
printf 'Backup: %s\nStaging: %s\n' "$backup" "$stage"
mkdir -p /usr/local/x-ui /etc/x-ui /var/log/x-ui
cp -a "$stage/x-ui/." /usr/local/x-ui/
install -m 755 /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
install -m 644 /usr/local/x-ui/x-ui.service.debian /etc/systemd/system/x-ui.service
systemctl daemon-reload
if [[ "$fresh" == 1 ]]; then
  username="pronet_$(openssl rand -hex 3)"
  password=$(openssl rand -hex 16)
  panel_path="/$(openssl rand -hex 12)/"
  (cd /usr/local/x-ui; ./x-ui setting -username "$username" -password "$password" -port 2053 -webBasePath "$panel_path")
fi
systemctl enable --now x-ui
sleep 3
systemctl is-active --quiet x-ui
info=$(cd /usr/local/x-ui; ./x-ui setting -show true)
panel_port=$(printf '%s\n' "$info" | sed -n 's/^port: //p')
panel_path=$(printf '%s\n' "$info" | sed -n 's/^webBasePath: //p')
panel_user=$(printf '%s\n' "$info" | sed -n 's/^username: //p')
cert=$(cd /usr/local/x-ui; ./x-ui setting -getCert true | sed -n 's/^cert: //p')
scheme=http
panel_host="${PRONET_PANEL_HOST:-}"
if [[ -n "$cert" && -f "$cert" ]]; then
  scheme=https
  if [[ -z "$panel_host" ]]; then
    panel_host=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -Eo 'DNS:[^,[:space:]]+' | cut -d: -f2 | grep -v '\*' | head -n1 || true)
  fi
fi
if [[ -z "$panel_host" ]]; then
  panel_host=$(curl -4fsS --connect-timeout 2 --max-time 4 https://api4.ipify.org 2>/dev/null || true)
  [[ "$panel_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || panel_host=''
fi
if [[ -z "$panel_host" ]]; then
  read -r _ _ panel_host _ <<< "${SSH_CONNECTION:-}"
  panel_host="${panel_host:-$(hostname -I | awk '{print $1}')}"
fi
[[ "$panel_host" != *:* ]] || panel_host="[$panel_host]"
printf '\n========== ProNet installation complete ==========\nVersion: %s\n' "$VERSION"
if [[ -n "$panel_host" ]]; then
  printf 'Login URL: %s://%s:%s%s\n' "$scheme" "$panel_host" "$panel_port" "$panel_path"
else
  printf 'Login URL: %s://<SERVER-IP>:%s%s (public IP could not be detected)\n' "$scheme" "$panel_port" "$panel_path"
fi
if [[ "$fresh" == 1 ]]; then
  printf 'Username: %s\nPassword: %s\n' "$username" "$password"
else
  printf 'Username: %s\nPassword: unchanged (stored as a hash; use x-ui menu option 7 to reset if needed).\n' "${panel_user:-unchanged}"
fi
printf 'Management menu: x-ui\nBackup: %s\n' "$backup"
[[ "$scheme" == https ]] || printf 'HTTPS setup: x-ui -> 20 (SSL Certificate Management)\n'
printf '==================================================\n'

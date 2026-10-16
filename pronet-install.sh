#!/usr/bin/env bash
set -euo pipefail
# No configuration is erased. Staging files and backups are retained for review.
VERSION="${1:-v3.10.2-pronet.2}"
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
import os, pathlib, shlex, subprocess, sys
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
    env = dict(os.environ, PGDATABASE=dsn)
    subprocess.run(['pg_dump', '--format=custom', '--file=' + str(pathlib.Path(sys.argv[2])/'database.dump')], env=env, check=True)
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
  printf 'Username: %s\nPassword: %s\nPanel path: :2053%s\n' "$username" "$password" "$panel_path"
fi
systemctl enable --now x-ui
sleep 3
systemctl is-active --quiet x-ui
printf 'Installed ProNet %s. Configure HTTPS before remote use.\n' "$VERSION"

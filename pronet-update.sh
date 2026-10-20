#!/bin/bash
# Called by the authenticated panel after a consistent database backup.
set -euo pipefail
umask 077
tag=${XUI_UPDATE_TAG:?}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+-pronet\.[0-9]+$ ]] || exit 2
folder=${XUI_MAIN_FOLDER:?}
backup=${XUI_BACKUP_FOLDER:?}
pid=${XUI_UPDATE_PID:?}
status=${XUI_UPDATE_STATUS_FILE:?}
run=${XUI_UPDATE_RUN_ID:?}
[[ $pid =~ ^[0-9]+$ && $run =~ ^[0-9]+$ && $folder = /* && -d $backup ]] || exit 2
stage=$(mktemp -d "$folder/.pronet-update.XXXXXX")
write_status() {
 printf '{"runId":"%s","state":"%s","exitCode":%s,"finishedAt":%s}\n' "$run" "$1" "$2" "$(date +%s)" > "$status.tmp"
 mv -f "$status.tmp" "$status"
}
swapped=0
finish() {
 code=$?
 if ((code != 0)); then
  if ((swapped)); then
   cp "$backup/x-ui" "$folder/x-ui.rollback"; mv -f "$folder/x-ui.rollback" "$folder/x-ui"
   cp "$backup/xray" "$folder/bin/$core.rollback"; mv -f "$folder/bin/$core.rollback" "$folder/bin/$core"
   if [[ -f $backup/x-ui.sh ]]; then cp "$backup/x-ui.sh" "$folder/x-ui.sh.rollback"; mv -f "$folder/x-ui.sh.rollback" "$folder/x-ui.sh"; fi
   if [[ -f $backup/menu ]]; then cp "$backup/menu" /usr/bin/x-ui.rollback; mv -f /usr/bin/x-ui.rollback /usr/bin/x-ui; fi
  fi
  write_status failed "$code"
 fi
 rm -rf -- "$stage"
}
trap finish EXIT
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 2;; esac
core=xray-linux-$arch
base=https://github.com/MaMMaD1999/pronet-3x-ui/releases/download/$tag
curl -fsSL --retry 3 "$base/x-ui-linux-$arch.tar.gz" -o "$stage/package.tar.gz"
curl -fsSL --retry 3 "$base/checksums.txt" -o "$stage/checksums.txt"
hash=$(awk -v file="x-ui-linux-$arch.tar.gz" '$2==file {print $1}' "$stage/checksums.txt")
[[ $hash =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$hash" "$stage/package.tar.gz" | sha256sum -c -
tar -tzf "$stage/package.tar.gz" > "$stage/contents"
! grep -Eq '(^/|(^|/)\.\.(/|$))' "$stage/contents"
tar -xzf "$stage/package.tar.gz" -C "$stage" --no-same-owner
[[ -x $stage/x-ui/x-ui && -x $stage/x-ui/bin/$core ]]
[[ -x $stage/x-ui/x-ui.sh ]]
"$stage/x-ui/x-ui" -v | grep -F -- "${tag#v}"
"$stage/x-ui/bin/$core" version >/dev/null
cp -p "$folder/x-ui" "$backup/x-ui"
cp -p "$folder/bin/$core" "$backup/xray"
[[ ! -f $folder/x-ui.sh ]] || cp -p "$folder/x-ui.sh" "$backup/x-ui.sh"
[[ ! -f /usr/bin/x-ui ]] || cp -p /usr/bin/x-ui "$backup/menu"
kill -0 "$pid"
swapped=1
mv -f "$stage/x-ui/bin/$core" "$folder/bin/$core"
mv -f "$stage/x-ui/x-ui" "$folder/x-ui"
install -m 755 "$stage/x-ui/x-ui.sh" "$folder/x-ui.sh.new"
mv -f "$folder/x-ui.sh.new" "$folder/x-ui.sh"
install -m 755 "$stage/x-ui/x-ui.sh" /usr/bin/x-ui.new
mv -f /usr/bin/x-ui.new /usr/bin/x-ui
# Other runtime assets/configuration/certificates remain unchanged. The package
# contains the custom core and embedded UI; both were validated before swapping.
write_status pending 0
kill -USR2 "$pid"
sleep 4
kill -0 "$pid"
write_status success 0

#!/bin/bash
# Called by the authenticated panel after a consistent database backup.
set -euo pipefail
umask 077
tag=${XUI_UPDATE_TAG:?}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(pronet|ghandshekan)\.[0-9]+$ ]] || exit 2
folder=${XUI_MAIN_FOLDER:?}
backup=${XUI_BACKUP_FOLDER:?}
pid=${XUI_UPDATE_PID:?}
status=${XUI_UPDATE_STATUS_FILE:?}
run=${XUI_UPDATE_RUN_ID:?}
[[ $pid =~ ^[0-9]+$ && $run =~ ^[0-9]+$ && $folder = /* && -d $backup ]] || exit 2
stage=''
write_status() {
 printf '{"runId":"%s","state":"%s","exitCode":%s,"finishedAt":%s}\n' "$run" "$1" "$2" "$(date +%s)" > "$status.tmp"
 mv -f "$status.tmp" "$status"
}
swapped=0
service_unit=''
if command -v systemctl >/dev/null && [[ $(systemctl show x-ui.service -p MainPID --value 2>/dev/null || true) == "$pid" ]]; then
 service_unit=x-ui.service
fi
finish() {
 code=$?
 set +e
 if ((code != 0)); then
  if ((swapped)); then
   cp "$backup/x-ui" "$folder/x-ui.rollback"; mv -f "$folder/x-ui.rollback" "$folder/x-ui"
   cp "$backup/xray" "$folder/bin/$core.rollback"; mv -f "$folder/bin/$core.rollback" "$folder/bin/$core"
   if [[ -f $backup/x-ui.sh ]]; then cp "$backup/x-ui.sh" "$folder/x-ui.sh.rollback"; mv -f "$folder/x-ui.sh.rollback" "$folder/x-ui.sh"; fi
   if [[ -f $backup/menu ]]; then cp "$backup/menu" /usr/bin/x-ui.rollback; mv -f /usr/bin/x-ui.rollback /usr/bin/x-ui; fi
   if [[ -f $backup/docker-runtime ]]; then cp "$backup/docker-runtime" "$folder/pronet-docker-runtime.sh.rollback"; mv -f "$folder/pronet-docker-runtime.sh.rollback" "$folder/pronet-docker-runtime.sh"; fi
   if [[ -n $service_unit ]]; then
    systemctl restart "$service_unit"
   elif kill -0 "$pid" 2>/dev/null; then
    kill -USR2 "$pid"
   fi
  fi
  write_status failed "$code"
 fi
 [[ -z $stage ]] || rm -rf -- "$stage"
}
trap finish EXIT
[[ -w $folder && -w $folder/bin ]] || { echo 'Application filesystem is read-only; recreate the container with the newer custom image and existing database volume.' >&2; exit 2; }
stage=$(mktemp -d "$folder/.pronet-update.XXXXXX")
lock=/run/lock/pronet-update.lock
if [[ -f /.dockerenv || ${XUI_IN_DOCKER:-false} == true ]]; then
 lock=${XUI_DB_FOLDER:-$(dirname "$(dirname "$backup")")}/pronet-update.lock
fi
mkdir -p "$(dirname "$lock")"
exec 9>"$lock"
flock -n 9 || { echo 'Another GhandShekan installation or update is running.' >&2; exit 1; }
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 2;; esac
core=xray-linux-$arch
base=https://github.com/MaMMaD1999/ghandshekan-3x-ui/releases/download/$tag
curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 --proto '=https' --proto-redir '=https' "$base/x-ui-linux-$arch.tar.gz" -o "$stage/package.tar.gz"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 --proto '=https' --proto-redir '=https' "$base/checksums.txt" -o "$stage/checksums.txt"
hash=$(awk -v file="x-ui-linux-$arch.tar.gz" '$2==file {print $1}' "$stage/checksums.txt")
[[ $hash =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$hash" "$stage/package.tar.gz" | sha256sum -c -
tar -tzf "$stage/package.tar.gz" > "$stage/contents"
! grep -Eq '(^/|(^|/)\.\.(/|$))' "$stage/contents"
tar -xzf "$stage/package.tar.gz" -C "$stage" --no-same-owner
[[ -x $stage/x-ui/x-ui && -x $stage/x-ui/bin/$core ]]
[[ -x $stage/x-ui/x-ui.sh ]]
"$stage/x-ui/x-ui" -v | grep -Fx -- "${tag#v}"
"$stage/x-ui/bin/$core" version >/dev/null
cp -p "$folder/x-ui" "$backup/x-ui"
cp -p "$folder/bin/$core" "$backup/xray"
[[ ! -f $folder/x-ui.sh ]] || cp -p "$folder/x-ui.sh" "$backup/x-ui.sh"
[[ ! -f /usr/bin/x-ui ]] || cp -p /usr/bin/x-ui "$backup/menu"
[[ ! -f $folder/pronet-docker-runtime.sh ]] || cp -p "$folder/pronet-docker-runtime.sh" "$backup/docker-runtime"
kill -0 "$pid"
swapped=1
mv -f "$stage/x-ui/bin/$core" "$folder/bin/$core"
mv -f "$stage/x-ui/x-ui" "$folder/x-ui"
install -m 755 "$stage/x-ui/x-ui.sh" "$folder/x-ui.sh.new"
mv -f "$folder/x-ui.sh.new" "$folder/x-ui.sh"
if [[ -w /usr/bin ]]; then
 install -m 755 "$stage/x-ui/x-ui.sh" /usr/bin/x-ui.new
 mv -f /usr/bin/x-ui.new /usr/bin/x-ui
fi
if [[ -f /.dockerenv || ${XUI_IN_DOCKER:-false} == true ]]; then
 if [[ -f $stage/x-ui/pronet-docker-runtime.sh ]]; then
  install -m 755 "$stage/x-ui/pronet-docker-runtime.sh" "$folder/pronet-docker-runtime.sh.new"
  mv -f "$folder/pronet-docker-runtime.sh.new" "$folder/pronet-docker-runtime.sh"
  install -m 755 "$stage/x-ui/DockerEntrypoint.sh" "$folder/DockerEntrypoint.sh"
 fi
fi
# Other runtime assets/configuration/certificates remain unchanged. The package
# contains the custom core and embedded UI; both were validated before swapping.
write_status pending 0
kill -USR2 "$pid"
timeout=${XUI_UPDATE_RESTART_TIMEOUT:-120}
[[ $timeout =~ ^[0-9]+$ && $timeout -ge 30 && $timeout -le 300 ]] || exit 2
for ((attempt=0; attempt<timeout; attempt++)); do
 if [[ /proc/$pid/exe -ef $folder/x-ui ]]; then
  sleep 3
  if kill -0 "$pid" && [[ /proc/$pid/exe -ef $folder/x-ui ]]; then
   if [[ -f /.dockerenv || ${XUI_IN_DOCKER:-false} == true ]]; then
    runtime=${XUI_DB_FOLDER:-$(dirname "$(dirname "$backup")")}/pronet-runtime
    mkdir -p "$runtime/releases"
    slot=$(mktemp -d "$runtime/releases/${tag#v}-$run.XXXXXX")
    cp "$folder/x-ui" "$slot/x-ui"; cp "$folder/bin/$core" "$slot/xray"; cp "$folder/x-ui.sh" "$slot/menu"
    cp "$folder/pronet-docker-runtime.sh" "$slot/bootstrap"
    printf '%s\n' "${tag#v}" > "$slot/version"
    (cd "$slot" && sha256sum x-ui xray menu bootstrap > checksums.txt)
    ln -s "releases/$(basename "$slot")" "$runtime/current.$run"; mv -Tf "$runtime/current.$run" "$runtime/current"
   fi
   write_status success 0
   exit 0
  fi
 fi
 sleep 1
done
echo 'Updated panel did not replace the running executable; restoring the previous binaries.' >&2
exit 1

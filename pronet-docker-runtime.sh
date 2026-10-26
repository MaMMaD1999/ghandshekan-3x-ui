#!/bin/bash
# Restore a verified web update from the existing database volume on image boot.
set -euo pipefail
folder=${XUI_MAIN_FOLDER:-/app}
runtime=${XUI_DB_FOLDER:-/etc/x-ui}/pronet-runtime
menu=${XUI_DOCKER_MENU:-/usr/bin/x-ui}
[[ -L $runtime/current ]] || exit 0
skip() { echo "GhandShekan runtime: $*; starting the image version." >&2; exit 0; }
slot=$(readlink -f "$runtime/current") || skip 'invalid runtime pointer'
root=$(readlink -f "$runtime/releases") || skip 'missing runtime directory'
[[ $slot == "$root/"* && -f $slot/version && -f $slot/checksums.txt ]] || skip 'runtime outside its release directory'
target=$(cat "$slot/version")
[[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+-(pronet|ghandshekan)\.[0-9]+$ ]] || skip 'invalid runtime version'
manifest=$(awk '{print $2}' "$slot/checksums.txt" | LC_ALL=C sort | tr '\n' ':')
[[ $manifest == 'menu:x-ui:xray:' || $manifest == 'bootstrap:menu:x-ui:xray:' ]] || skip 'invalid runtime manifest'
(cd "$slot" && sha256sum -c checksums.txt >/dev/null 2>&1) || skip 'runtime checksum mismatch'
if [[ -f $slot/bootstrap && ${GHAND_RUNTIME_BOOTSTRAP:-0} != 1 ]]; then
 export GHAND_RUNTIME_BOOTSTRAP=1
 exec bash "$slot/bootstrap"
fi
current=$("$folder/x-ui" -v)
parts() { local v=${1//-pronet./.}; v=${v//-ghandshekan./.}; echo "${v//./ }"; }
read -r -a image_parts <<< "$(parts "$current")"
read -r -a saved_parts <<< "$(parts "$target")"
[[ ${#image_parts[@]} == 4 ]] || skip 'unrecognized image version'
newer=0
for i in 0 1 2 3; do
 [[ ${#saved_parts[i]} -lt 10 && ${#image_parts[i]} -lt 10 && ${image_parts[i]} =~ ^[0-9]+$ ]] || skip 'invalid numeric version'
 if ((10#${saved_parts[i]} > 10#${image_parts[i]})); then newer=1; break; fi
 if ((10#${saved_parts[i]} < 10#${image_parts[i]})); then exit 0; fi
done
((newer)) || exit 0
[[ $("$slot/x-ui" -v) == "$target" ]] || skip 'runtime executable version mismatch'
[[ -w $folder && -w $folder/bin ]] || skip 'application filesystem is read-only'
install -m 755 "$slot/x-ui" "$folder/x-ui.restore" || skip 'cannot stage panel executable'
install -m 755 "$slot/xray" "$folder/bin/xray.restore" || skip 'cannot stage core executable'
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) skip 'unsupported architecture';; esac
mv -f "$folder/bin/xray.restore" "$folder/bin/xray-linux-$arch"
mv -f "$folder/x-ui.restore" "$folder/x-ui"
if [[ -w $(dirname "$menu") ]]; then install -m 755 "$slot/menu" "$menu.new"; mv -f "$menu.new" "$menu"; fi
echo "GhandShekan runtime: restored verified $target from the database volume."

#!/usr/bin/env bash
set -euo pipefail
case "${1:-status}" in
  start|stop|restart|status) exec systemctl "$1" x-ui;;
  log) exec journalctl -u x-ui -f;;
  setting) shift; cd /usr/local/x-ui; exec ./x-ui setting "$@";;
  update) echo 'Use the versioned ProNet installer; stock updates would remove custom accounting.';;
  *) echo 'Commands: start, stop, restart, status, log, setting'; exit 1;;
esac

#!/bin/sh
cd "$(dirname "$0")/firmware" || exit 1
[ -f device.conf ] || python3 -m smartlock_fw init
exec python3 -m smartlock_fw run

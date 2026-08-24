#!/bin/bash
set -u
service_user=@@SERVICE_USER@@
scenario_user=@@SCENARIO_USER@@
audit_user=@@AUDIT_USER@@
credential=@@CREDENTIAL@@
artifact=/opt/rangeforge/app/config.ini
exec 2>&1
set -x

if test -f "$artifact"; then echo "RF_CHECK artifact_exists 1"; else echo "RF_CHECK artifact_exists 0"; fi
if test "$(stat -c '%a' "$artifact" 2>/dev/null)" = "640" && \
   test "$(stat -c '%U:%G' "$artifact" 2>/dev/null)" = "root:$service_user"; then
  echo "RF_CHECK artifact_mode 1"
else
  echo "RF_CHECK artifact_mode 0"
fi
if runuser -u "$service_user" -- test -r "$artifact"; then
  echo "RF_CHECK service_can_read 1"
else
  echo "RF_CHECK service_can_read 0"
fi
if runuser -u "$audit_user" -- test ! -r "$artifact"; then
  echo "RF_CHECK audit_cannot_read 1"
else
  echo "RF_CHECK audit_cannot_read 0"
fi
if test "$(id -u "$scenario_user" 2>/dev/null)" != "0"; then
  echo "RF_CHECK scenario_user_nonroot 1"
else
  echo "RF_CHECK scenario_user_nonroot 0"
fi
set +x
RF_AUTH_PASSWORD="$credential" python3 - "$service_user" "$scenario_user" <<'PY'
import errno
import os
import pwd
import pty
import select
import signal
import sys
import time

service_user, scenario_user = sys.argv[1:]
password = os.environ.pop("RF_AUTH_PASSWORD")
service = pwd.getpwnam(service_user)
pid, fd = pty.fork()
if pid == 0:
    os.setgroups([])
    os.setgid(service.pw_gid)
    os.setuid(service.pw_uid)
    os.execv("/usr/bin/su", ("su", "-", scenario_user, "-c", "/usr/bin/id -un"))

output = bytearray()
sent = False
status = None
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    ready, _, _ = select.select((fd,), (), (), 0.2)
    if ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            chunk = b""
        output.extend(chunk)
        if b"password:" in output.lower() and not sent:
            os.write(fd, password.encode() + b"\n")
            sent = True
    ended, child_status = os.waitpid(pid, os.WNOHANG)
    if ended:
        status = child_status
        break
if status is None:
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
os.close(fd)
success = os.waitstatus_to_exitcode(status) == 0 and scenario_user.encode() in output
raise SystemExit(0 if success else 1)
PY
authentication_result=$?
set -x
if test "$authentication_result" -eq 0; then
  echo "RF_CHECK credential_authenticates 1"
else
  echo "RF_CHECK credential_authenticates 0"
fi

#!/bin/bash
set -euo pipefail
test "$(id -u)" -eq 0
service_user=@@SERVICE_USER@@
scenario_user=@@SCENARIO_USER@@
audit_user=@@AUDIT_USER@@
credential=@@CREDENTIAL@@

if ! id "$scenario_user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$scenario_user"
fi
if ! id "$audit_user" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$audit_user"
fi
printf '%s:%s\n' "$scenario_user" "$credential" | chpasswd
install -d -o root -g "$service_user" -m 0750 /opt/rangeforge/app
cat > /opt/rangeforge/app/config.ini <<EOF
[database]
username=$scenario_user
password=$credential
EOF
chown root:"$service_user" /opt/rangeforge/app/config.ini
chmod 0640 /opt/rangeforge/app/config.ini

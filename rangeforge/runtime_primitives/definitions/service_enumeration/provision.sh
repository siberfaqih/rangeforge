#!/bin/bash
set -euo pipefail
test "$(id -u)" -eq 0
scenario_id=@@SCENARIO_ID@@
service_name=@@PRIMARY_SERVICE_NAME@@
port=@@PRIMARY_SERVICE_PORT@@

install -d -o root -g root -m 0755 /etc/rangeforge /opt/rangeforge /var/lib/rangeforge
printf '{"scenario_id":"%s","service":"%s","port":%s}\n' \
  "$scenario_id" "$service_name" "$port" > /etc/rangeforge/service.json
chown root:root /etc/rangeforge/service.json
chmod 0600 /etc/rangeforge/service.json

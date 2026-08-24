#!/bin/bash
set -u
service_name=@@PRIMARY_SERVICE_NAME@@
port=@@PRIMARY_SERVICE_PORT@@
scenario_id=@@SCENARIO_ID@@
exec 2>&1
set -x

if grep -Fq "\"scenario_id\":\"$scenario_id\"" /etc/rangeforge/service.json 2>/dev/null; then
  echo "RF_CHECK service_metadata 1"
else
  echo "RF_CHECK service_metadata 0"
fi
if systemctl is-active --quiet "$service_name.service"; then
  echo "RF_CHECK service_running 1"
else
  echo "RF_CHECK service_running 0"
fi
if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"; then
  echo "RF_CHECK port_listening 1"
else
  echo "RF_CHECK port_listening 0"
fi

#!/bin/bash
set -u
service_user=@@SERVICE_USER@@
exec 2>&1
set -x

if grep -Fq 'shell=True' /opt/rangeforge/web_foothold.py 2>/dev/null; then
  echo "RF_CHECK vulnerable_condition 1"
else
  echo "RF_CHECK vulnerable_condition 0"
fi
if test "$(systemctl show -p User --value rf-web-foothold.service 2>/dev/null)" = "$service_user"; then
  echo "RF_CHECK service_identity 1"
else
  echo "RF_CHECK service_identity 0"
fi
if test "$(id -u "$service_user" 2>/dev/null)" != "0"; then
  echo "RF_CHECK service_nonroot 1"
else
  echo "RF_CHECK service_nonroot 0"
fi
if test -f /var/lib/rangeforge/local.txt; then echo "RF_CHECK local_exists 1"; else echo "RF_CHECK local_exists 0"; fi
if test "$(stat -c '%U:%G' /var/lib/rangeforge/local.txt 2>/dev/null)" = "root:$service_user"; then
  echo "RF_CHECK local_owner 1"
else
  echo "RF_CHECK local_owner 0"
fi
if test "$(stat -c '%a' /var/lib/rangeforge/local.txt 2>/dev/null)" = "640"; then
  echo "RF_CHECK local_mode 1"
else
  echo "RF_CHECK local_mode 0"
fi
if runuser -u "$service_user" -- test -r /var/lib/rangeforge/local.txt; then
  echo "RF_CHECK local_readable_service 1"
else
  echo "RF_CHECK local_readable_service 0"
fi

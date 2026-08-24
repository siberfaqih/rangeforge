#!/bin/bash
set -u
service_user=@@SERVICE_USER@@
scenario_user=@@SCENARIO_USER@@
audit_user=@@AUDIT_USER@@
sudo_path=/etc/sudoers.d/rangeforge-scenario
exec 2>&1
set -x

if id "$scenario_user" >/dev/null 2>&1; then echo "RF_CHECK target_exists 1"; else echo "RF_CHECK target_exists 0"; fi
if grep -Fxq "$scenario_user ALL=(root) NOPASSWD: /usr/bin/find" "$sudo_path" 2>/dev/null && visudo -cf "$sudo_path" >/dev/null 2>&1; then
  echo "RF_CHECK sudo_rule 1"
else
  echo "RF_CHECK sudo_rule 0"
fi
if runuser -u "$scenario_user" -- sudo -n /usr/bin/find /root -maxdepth 1 -name proof.txt -exec /usr/bin/id -u \; -quit 2>/dev/null | grep -qx 0; then
  echo "RF_CHECK root_reachable 1"
else
  echo "RF_CHECK root_reachable 0"
fi
if ! runuser -u "$service_user" -- sudo -n -l >/dev/null 2>&1; then
  echo "RF_CHECK service_no_rule 1"
else
  echo "RF_CHECK service_no_rule 0"
fi
if ! runuser -u "$audit_user" -- sudo -n -l >/dev/null 2>&1; then
  echo "RF_CHECK audit_no_rule 1"
else
  echo "RF_CHECK audit_no_rule 0"
fi
if ! sudo -n -l -U "$scenario_user" 2>/dev/null | grep -Eq 'NOPASSWD:[[:space:]]+ALL([[:space:]]|$)'; then
  echo "RF_CHECK not_sudo_all 1"
else
  echo "RF_CHECK not_sudo_all 0"
fi
if test -f /root/proof.txt; then echo "RF_CHECK proof_exists 1"; else echo "RF_CHECK proof_exists 0"; fi
if test "$(stat -c '%U:%G' /root/proof.txt 2>/dev/null)" = "root:root"; then
  echo "RF_CHECK proof_owner 1"
else
  echo "RF_CHECK proof_owner 0"
fi
if test "$(stat -c '%a' /root/proof.txt 2>/dev/null)" = "600"; then
  echo "RF_CHECK proof_mode 1"
else
  echo "RF_CHECK proof_mode 0"
fi
if runuser -u "$scenario_user" -- test ! -r /root/proof.txt; then
  echo "RF_CHECK scenario_cannot_read_proof 1"
else
  echo "RF_CHECK scenario_cannot_read_proof 0"
fi
if runuser -u "$service_user" -- test ! -r /root/proof.txt; then
  echo "RF_CHECK service_cannot_read_proof 1"
else
  echo "RF_CHECK service_cannot_read_proof 0"
fi

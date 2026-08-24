#!/bin/bash
set -euo pipefail
test "$(id -u)" -eq 0
scenario_user=@@SCENARIO_USER@@
proof_flag=@@PROOF_FLAG@@
sudo_path=/etc/sudoers.d/rangeforge-scenario

id "$scenario_user" >/dev/null
printf '%s ALL=(root) NOPASSWD: /usr/bin/find\n' "$scenario_user" > "$sudo_path"
chown root:root "$sudo_path"
chmod 0440 "$sudo_path"
visudo -cf "$sudo_path" >/dev/null
printf '%s\n' "$proof_flag" > /root/proof.txt
chown root:root /root/proof.txt
chmod 0600 /root/proof.txt

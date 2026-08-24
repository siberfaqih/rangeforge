#!/bin/bash
set -euo pipefail
test "$(id -u)" -eq 0
service_user=@@SERVICE_USER@@
port=@@PORT@@
local_flag=@@LOCAL_FLAG@@

install -d -o root -g root -m 0755 /opt/rangeforge
cat > /opt/rangeforge/web_foothold.py <<'PY'
#!/usr/bin/python3
import argparse
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlparse(self.path)
        if request.path == "/diagnostic":
            command = parse_qs(request.query).get("check", ["id"])[0]
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                body = (result.stdout + result.stderr).encode()
                self.send_response(200)
            except subprocess.TimeoutExpired:
                body = b"diagnostic timed out\n"
                self.send_response(408)
        else:
            body = b"RangeForge diagnostics service\n"
            self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, required=True)
args = parser.parse_args()
ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()
PY
chown root:root /opt/rangeforge/web_foothold.py
chmod 0755 /opt/rangeforge/web_foothold.py

printf '%s\n' "$local_flag" > /var/lib/rangeforge/local.txt
chown root:"$service_user" /var/lib/rangeforge/local.txt
chmod 0640 /var/lib/rangeforge/local.txt

cat > /etc/systemd/system/rf-web-foothold.service <<EOF
[Unit]
Description=RangeForge isolated training diagnostics service
After=network.target

[Service]
Type=simple
User=$service_user
Group=$service_user
ExecStart=/usr/bin/python3 /opt/rangeforge/web_foothold.py --port $port
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable rf-web-foothold.service >/dev/null
systemctl restart rf-web-foothold.service

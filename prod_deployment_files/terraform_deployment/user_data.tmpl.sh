#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# === Fill these in ===
WG_SERVER_ENDPOINT_ENV="${WG_SERVER_ENDPOINT}"
WG_SERVER_PUBLIC_KEY_ENV="${WG_SERVER_PUBLIC_KEY}"
WG_PRESHARED_KEY_ENV="${WG_PRESHARED_KEY}"
CLIENT_PRIVATE_KEY_ENV="${CLIENT_PRIVATE_KEY}"

# --- Packages ---
apt-get update
apt-get install -y wireguard nginx-full

# --- WireGuard configuration (client) ---
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY_ENV}
Address = 10.0.2.100/24

[Peer]
PublicKey = ${WG_SERVER_PUBLIC_KEY_ENV}
PresharedKey = ${WG_PRESHARED_KEY_ENV}
Endpoint = ${WG_SERVER_ENDPOINT_ENV}
AllowedIPs = 10.0.0.1/32, 10.0.0.175/32
EOF

chmod 600 /etc/wireguard/wg0.conf

# --- Bring up wg0 at boot + now ---
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Optional: wait briefly for tunnel
sleep 15

echo "" > /etc/nginx/nginx.conf

# # Write stream block 
cat >> /etc/nginx/nginx.conf <<'EOL'
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

events {
}

stream {

    server {
        listen 0.0.0.0:443;
        proxy_pass 10.0.0.175:443;  # Reached via wg0 due to AllowedIPs route
#        proxy_protocol on;          # Keep only if backend expects PROXY protocol
    }
    server {
        listen 0.0.0.0:80;
        proxy_pass 10.0.0.175:80;  # Reached via wg0 due to AllowedIPs route
#        proxy_protocol on;          # Keep only if backend expects PROXY protocol
    }
}
EOL


nginx -t
systemctl restart nginx
systemctl enable nginx

# --- Restart WireGuard to ensure it's working ---
systemctl restart wg-quick@wg0

# --- Add DNS record to /etc/hosts ---
IP=10.0.0.175
HOST=bulkintel.home.lab

if ! grep -qE "^[[:space:]]*${IP}[[:space:]]+${HOST}([[:space:]]|$)" /etc/hosts; then
  echo "${IP} ${HOST}" >> /etc/hosts
fi

# --- Cron job to monitor and restart WireGuard if needed ---
cat >/etc/cron.d/wg-watch <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
* * * * * root /usr/bin/curl -sS -k --max-time 10 -o /dev/null https://bulkintel.home.lab/; rc=$?; [ $rc -eq 28 ] && /usr/bin/logger -t wg-watch "Timeout (rc=$rc), restarting wg-quick@wg0" && /usr/bin/systemctl restart wg-quick@wg0
EOF

chmod 0644 /etc/cron.d/wg-watch
chown root:root /etc/cron.d/wg-watch
systemctl enable --now cron
systemctl restart cron

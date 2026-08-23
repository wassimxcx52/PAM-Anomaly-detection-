#!/bin/sh
# setup-env.sh -- one-time env setup for the PAM stack (Linux/macOS).
#   cd deploy && ./setup-env.sh
set -eu
cd "$(dirname "$0")"

# host LAN IP (the address WALLIX must forward logs to)
HOST_IP=$(ip -4 addr 2>/dev/null | grep -oE '192\.168\.[0-9]+\.[0-9]+' | head -1 || true)
[ -z "${HOST_IP:-}" ] && HOST_IP="<your-LAN-IP>"

echo ""
echo "This machine's LAN IP : $HOST_IP"
echo "  -> In the WALLIX GUI, set SIEM Integration destination + syslog to THIS IP."
echo ""

printf "Enter the WALLIX Bastion VM IP (from the VM console): "
read WALLIX_IP
[ -z "$WALLIX_IP" ] && { echo "No IP entered, aborting."; exit 1; }

cp .env.example .env
sed -i.bak "s|^WALLIX_HOST=.*|WALLIX_HOST=$WALLIX_IP|" .env && rm -f .env.bak

echo ""
echo ".env written: WALLIX_HOST=$WALLIX_IP"
echo "Then run:  docker compose -f docker-compose.yml up -d --build"

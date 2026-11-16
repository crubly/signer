#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/sign}"
TUNNEL_NAME="${TUNNEL_NAME:-signer-tunnel}"

echo "=== Cloudflare Tunnel Setup for Signer ==="
echo ""
echo "1) Authenticating with Cloudflare..."
echo "   A browser link will appear below — open it and authorize your domain."
cloudflared tunnel login

echo ""
read -rp "Enter your domain/subdomain for Signer (e.g. sign.example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
  echo "Domain cannot be empty."
  exit 1
fi

echo ""
echo "2) Creating/checking tunnel '$TUNNEL_NAME'..."
if ! cloudflared tunnel info "$TUNNEL_NAME" >/dev/null 2>&1; then
  cloudflared tunnel create "$TUNNEL_NAME"
fi

echo "3) Routing DNS $DOMAIN -> $TUNNEL_NAME..."
cloudflared tunnel route dns -f "$TUNNEL_NAME" "$DOMAIN"

echo "4) Fetching tunnel token..."
TOKEN="$(cloudflared tunnel token "$TUNNEL_NAME")"

cd "$APP_DIR"
if [[ ! -f .env ]]; then
  cp .env.example .env
fi

# Update PUBLIC_URL and CF_TUNNEL_TOKEN in .env
grep -v '^PUBLIC_URL=' .env | grep -v '^CF_TUNNEL_TOKEN=' > .env.tmp || true
{
  cat .env.tmp
  echo "PUBLIC_URL=https://${DOMAIN}"
  echo "CF_TUNNEL_TOKEN=${TOKEN}"
} > .env
rm -f .env.tmp

echo "5) Configuring ingress rule (http://backend:8095) via cloudflared..."
mkdir -p "$HOME/.cloudflared"
TUNNEL_ID="$(cloudflared tunnel list -o json | python3 -c "import sys,json; ts=json.load(sys.stdin); print(next(t['id'] for t in ts if t['name']=='$TUNNEL_NAME'))")"
cat > "$HOME/.cloudflared/config.yml" <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${DOMAIN}
    service: http://backend:8095
  - service: http_status:404
EOF

echo "6) Starting Docker stack (postgres + backend + cloudflared)..."
docker compose --profile tunnel up -d --build

echo ""
echo "Done! Signer backend is live at: https://${DOMAIN}"

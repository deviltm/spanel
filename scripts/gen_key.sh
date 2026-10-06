#!/usr/bin/env bash
# Генерация мастер-ключа шифрования секретов (AES-256-GCM, 32 байта, base64).
# Использование:
#   ./scripts/gen_key.sh                 — просто напечатать ключ
#   ./scripts/gen_key.sh --write-env     — записать в .env (параметр SECRETS_ENCRYPTION_KEY)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

if command -v openssl >/dev/null 2>&1; then
    KEY="$(openssl rand -base64 32)"
else
    KEY="$(python3 -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
fi

if [ "${1:-}" = "--write-env" ]; then
    if [ ! -f "$ROOT/.env" ]; then
        cp "$ROOT/.env.example" "$ROOT/.env"
    fi
    ESCAPED="$(printf '%s' "$KEY" | sed 's/[&|\/]/\\&/g')"
    sed -i "s|^SECRETS_ENCRYPTION_KEY=.*|SECRETS_ENCRYPTION_KEY=${ESCAPED}|" "$ROOT/.env"
    chmod 600 "$ROOT/.env"
    echo "Ключ записан в .env (SECRETS_ENCRYPTION_KEY)."
else
    echo "$KEY"
fi

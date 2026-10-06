#!/usr/bin/env bash
# Установка компонентов панели spanel.
# - создаёт виртуальное окружение .venv
# - ставит зависимости из requirements.txt
# - готовит каталог данных ./data и .env (если отсутствует)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ОШИБКА: $PYTHON не найден. Установите Python 3.10+." >&2
    exit 1
fi

echo "==> Проверка Python..."
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
    echo "ОШИБКА: требуется Python 3.10+, найдено: $("$PYTHON" --version)" >&2; exit 1; }

echo "==> Создание виртуального окружения .venv ..."
if [ ! -d "$ROOT/.venv" ]; then
    "$PYTHON" -m venv "$ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

echo "==> Обновление pip ..."
pip install --quiet --upgrade pip

echo "==> Установка зависимостей (fastapi, uvicorn, paramiko, httpx, cryptography) ..."
pip install --quiet -r requirements.txt

echo "==> Каталог данных ..."
mkdir -p "$ROOT/data"
chmod 700 "$ROOT/data" || true

echo "==> Конфигурация ..."
if [ ! -f "$ROOT/.env" ]; then
    cp "$ROOT/.env.example" "$ROOT/.env"
    # генерируем мастер-ключ сразу, чтобы панель работала без ручных действий
    KEY="$("$PYTHON" -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
    sed -i "s|^SECRETS_ENCRYPTION_KEY=.*|SECRETS_ENCRYPTION_KEY=${KEY}|" "$ROOT/.env"
    chmod 600 "$ROOT/.env"
    echo "   создан .env с сгенерированным SECRETS_ENCRYPTION_KEY (не потеряйте этот файл!)"
fi

echo
echo "Готово. Запуск:  ./scripts/run.sh"
echo "Остановка: Ctrl+C (или kill для фонового режима)"

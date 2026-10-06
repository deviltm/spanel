#!/usr/bin/env bash
# Запуск панели spanel.
#   ./scripts/run.sh            — запуск на переднем плане (Ctrl+C для остановки)
#   ./scripts/run.sh --bg       — запуск в фоне, лог: data/spanel.log, pid: data/spanel.pid
#   ./scripts/stop.sh           — остановка фонового процесса
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

VENV="$ROOT/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    echo "Виртуальное окружение не найдено. Сначала выполните: ./scripts/install.sh" >&2
    exit 1
fi

# загрузка .env (если существует)
if [ -f "$ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$ROOT/.env"
    set +a
fi

export SPANEL_DATA_DIR="${SPANEL_DATA_DIR:-$ROOT/data}"
mkdir -p "$SPANEL_DATA_DIR"

HOST="${PANEL_HOST:-0.0.0.0}"
PORT="${PANEL_PORT:-8080}"

cd "$ROOT"

if [ "${1:-}" = "--bg" ]; then
    PIDFILE="$SPANEL_DATA_DIR/spanel.pid"
    LOGFILE="$SPANEL_DATA_DIR/spanel.log"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "Панель уже запущена (pid $(cat "$PIDFILE")). Сначала: ./scripts/stop.sh" >&2
        exit 1
    fi
    nohup "$VENV/bin/python" -m uvicorn app.main:app --host "$HOST" --port "$PORT" \
        >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "Панель запущена в фоне: pid $(cat "$PIDFILE"), http://$HOST:$PORT, лог: $LOGFILE"
else
    echo "Панель: http://$HOST:$PORT  (остановка: Ctrl+C)"
    exec "$VENV/bin/python" -m uvicorn app.main:app --host "$HOST" --port "$PORT"
fi

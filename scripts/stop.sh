#!/usr/bin/env bash
# Остановка панели spanel, запущенной через ./scripts/run.sh --bg
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

DATA_DIR="${SPANEL_DATA_DIR:-$ROOT/data}"
PIDFILE="$DATA_DIR/spanel.pid"

if [ ! -f "$PIDFILE" ]; then
    echo "PID-файл не найден ($PIDFILE). Панель, похоже, не запущена в фоне." >&2
    exit 1
fi

PID="$(cat "$PIDFILE")"
if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    for i in $(seq 1 10); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$PID" 2>/dev/null; then
        echo "Процесс $PID не завершился, отправляю SIGKILL..."
        kill -9 "$PID" 2>/dev/null || true
    fi
    echo "Панель остановлена (pid $PID)."
else
    echo "Процесс $PID уже не существует."
fi
rm -f "$PIDFILE"

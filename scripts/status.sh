#!/usr/bin/env bash
# Статус панели spanel и последние строки лога.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DATA_DIR="${SPANEL_DATA_DIR:-$ROOT/data}"
PIDFILE="$DATA_DIR/spanel.pid"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Панель запущена (pid $(cat "$PIDFILE"))"
else
    echo "Панель не запущена в фоне."
fi

if [ -f "$DATA_DIR/spanel.log" ]; then
    echo "--- последние 15 строк лога ($DATA_DIR/spanel.log) ---"
    tail -n 15 "$DATA_DIR/spanel.log"
fi

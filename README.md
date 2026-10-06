# spanel — панель проксирования веб-интерфейсов через SSH (без агента)

Добавляете SSH-сервер (хост, порт, пользователь, ключ или пароль), указываете
порт удалённой веб-панели (например `127.0.0.1:8006`) — панель поднимает
SSH-туннель (`direct-tcpip`) и публикует защищённый URL сервиса.

## Быстрый старт (Linux/macOS)

```bash
git clone <repo> && cd spanel

# 1. Установка компонентов (venv + зависимости + .env с мастер-ключом)
./scripts/install.sh

# 2. Запуск панели (передний план, Ctrl+C — остановка)
./scripts/run.sh

#    или в фоне:
./scripts/run.sh --bg
./scripts/status.sh      # статус + последние строки лога
./scripts/stop.sh        # остановка
```

Панель доступна на `http://localhost:8080` (настраивается в `.env`).

## Скрипты

| Скрипт | Назначение |
|---|---|
| `scripts/install.sh` | Создание `.venv`, установка зависимостей из `requirements.txt`, подготовка `./data` и `.env` (с генерацией `SECRETS_ENCRYPTION_KEY`) |
| `scripts/run.sh` | Запуск панели; `--bg` — в фоне (лог `data/spanel.log`, pid `data/spanel.pid`) |
| `scripts/stop.sh` | Остановка фонового процесса (SIGTERM → SIGKILL) |
| `scripts/status.sh` | Проверка запущена ли панель + хвост лога |
| `scripts/gen_key.sh` | Генерация мастер-ключа; `--write-env` — записать в `.env` |
| `scripts/spanel.service` | Unit-файл systemd для продакшена |

## Конфигурация (`.env`)

См. `.env.example`:

- `SECRETS_ENCRYPTION_KEY` — base64(32 байта), AES-256-GCM шифрование приватных
  ключей/паролей. **Не теряйте**: без него расшифровать сохранённые секреты нельзя.
- `PANEL_HOST` / `PANEL_PORT` — адрес панели (по умолчанию `0.0.0.0:8080`).
- `BASE_DOMAIN` — базовый домен публичных URL сервисов (`https://<slug>.<domain>`).
- `SPANEL_DATA_DIR` — каталог данных (SQLite БД).

## Docker

```bash
export SECRETS_ENCRYPTION_KEY=$(./scripts/gen_key.sh)
docker compose up -d --build
```

Данные БД — в volume `spanel_data`.

## systemd (продакшен)

```bash
sudo cp -r . /opt/spanel && cd /opt/spanel && ./scripts/install.sh
sudo cp scripts/spanel.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now spanel
```

## Test-скенарий (e2e)

`tests/fake_remote.py` эмулирует «удалённый сервер» (paramiko sshd на :2222 +
веб-панель на :8006) для проверки туннелирования без реального сервера.

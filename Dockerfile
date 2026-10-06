# Dockerfile для панели spanel
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# данные (БД, dev-мастер-ключ) — в отдельном volume
ENV SPANEL_DATA_DIR=/data \
    PANEL_HOST=0.0.0.0 \
    PANEL_PORT=8080
VOLUME ["/data"]

EXPOSE 8080

CMD ["sh", "-c", "python -m uvicorn app.main:app --host ${PANEL_HOST} --port ${PANEL_PORT}"]

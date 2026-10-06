"""Шифрование секретов (приватные ключи, пароли) по AES-256-GCM.

Мастер-ключ берётся из переменной окружения SECRETS_ENCRYPTION_KEY
(base64, 32 байта). Если переменная не задана — ключ генерируется
и сохраняется в ./data/master.key (для dev-режима).
В проде используйте Vault / Docker secrets / env.
"""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ENV_VAR = "SECRETS_ENCRYPTION_KEY"
_DATA_DIR = Path(os.environ.get("SPANEL_DATA_DIR", "./data"))
_KEY_FILE = _DATA_DIR / "master.key"

_cache: dict[str, bytes] = {}


def _load_key() -> bytes:
    if "k" in _cache:
        return _cache["k"]
    raw = os.environ.get(_ENV_VAR, "").strip()
    if raw:
        key = base64.b64decode(raw)
        if len(key) != 32:
            raise ValueError(f"{_ENV_VAR} must decode to 32 bytes")
    else:  # dev fallback
        _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _KEY_FILE.exists():
            key = _KEY_FILE.read_bytes()
        else:
            key = secrets.token_bytes(32)
            _KEY_FILE.write_bytes(key)
            os.chmod(_KEY_FILE, 0o600)
    _cache["k"] = key
    return key


def encrypt(plaintext: str) -> str:
    """Возвращает строку 'gcm$<b64 nonce>$<b64 ciphertext>'."""
    if plaintext is None or plaintext == "":
        return ""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_load_key()).encrypt(nonce, plaintext.encode(), None)
    return "gcm$" + base64.b64encode(nonce).decode() + "$" + base64.b64encode(ct).decode()


def decrypt(token: str) -> str:
    """Расшифровывает токен encrypt(). Пустая строка — без ошибок."""
    if not token:
        return ""
    if not token.startswith("gcm$"):
        # значение сохранено до включения шифрования — возвращаем как есть
        return token
    try:
        _, n_b64, c_b64 = token.split("$", 2)
        nonce = base64.b64decode(n_b64)
        pt = AESGCM(_load_key()).decrypt(nonce, base64.b64decode(c_b64), None)
        return pt.decode()
    except Exception as e:  # noqa: BLE001
        raise ValueError("key_decrypt_error: не удалось расшифровать секрет") from e

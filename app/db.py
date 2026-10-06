"""Модель данных панели (SQLite).

Таблицы соответствуют ТЗ: servers, ssh_credentials, services.
Секреты (private_key / passphrase / password) хранятся только
в зашифрованном виде (app.crypto.encrypt).
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("SPANEL_DB", "./data/spanel.db"))
_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _lock, get_conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                tags TEXT DEFAULT '[]',
                connection_mode TEXT NOT NULL DEFAULT 'ssh',   -- ssh | agent | reverse_ssh
                status TEXT NOT NULL DEFAULT 'pending_test',
                last_error TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS ssh_credentials (
                server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
                ssh_host TEXT NOT NULL,
                ssh_port INTEGER NOT NULL DEFAULT 22,
                username TEXT NOT NULL,
                auth_type TEXT NOT NULL DEFAULT 'private_key', -- private_key | password
                enc_private_key TEXT DEFAULT '',               -- AES-GCM
                enc_passphrase TEXT DEFAULT '',                -- AES-GCM
                enc_password TEXT DEFAULT '',                  -- AES-GCM
                host_key_fingerprint TEXT DEFAULT '',
                host_key_algorithm TEXT DEFAULT '',
                host_key_verified INTEGER NOT NULL DEFAULT 0,
                known_hosts_policy TEXT NOT NULL DEFAULT 'tofu', -- strict|tofu|disabled
                last_success_at TEXT,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS services (
                id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                target_host TEXT NOT NULL DEFAULT '127.0.0.1',
                target_port INTEGER NOT NULL,
                target_protocol TEXT NOT NULL DEFAULT 'http',  -- http | https
                tls_verify INTEGER NOT NULL DEFAULT 0,
                public_slug TEXT NOT NULL UNIQUE,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                is_iframe_allowed INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'enabled',
                last_error TEXT DEFAULT '',
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                actor TEXT,
                action TEXT,
                object TEXT,
                details TEXT
            );
            """
        )


def audit(actor: str, action: str, obj: str, details: str = "") -> None:
    # в details никогда не пишутся секреты
    with _lock, get_conn() as c:
        c.execute(
            "INSERT INTO audit_log (ts, actor, action, object, details) VALUES (?,?,?,?,?)",
            (now_iso(), actor, action, obj, details[:500]),
        )


# ---------- servers ----------

ALLOWED_TARGET_HOSTS = {"127.0.0.1", "::1", "localhost"}


def create_server(name, description, tags, mode, ssh: dict) -> str:
    sid = str(uuid.uuid4())
    ts = now_iso()
    with _lock, get_conn() as c:
        c.execute(
            "INSERT INTO servers (id,name,description,tags,connection_mode,status,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sid, name, description or "", json.dumps(tags or []), mode, "pending_test", ts, ts),
        )
        c.execute(
            "INSERT INTO ssh_credentials (server_id,ssh_host,ssh_port,username,auth_type,"
            " enc_private_key,enc_passphrase,enc_password,known_hosts_policy)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                sid, ssh["host"], int(ssh.get("port", 22)), ssh["username"],
                ssh.get("auth_type", "private_key"),
                ssh.get("enc_private_key", ""), ssh.get("enc_passphrase", ""),
                ssh.get("enc_password", ""), ssh.get("known_hosts_policy", "tofu"),
            ),
        )
    return sid


def update_server(sid: str, name=None, description=None, tags=None) -> None:
    fields, vals = [], []
    if name is not None:
        fields.append("name=?"); vals.append(name)
    if description is not None:
        fields.append("description=?"); vals.append(description)
    if tags is not None:
        fields.append("tags=?"); vals.append(json.dumps(tags))
    if fields:
        fields.append("updated_at=?"); vals.append(now_iso()); vals.append(sid)
        with _lock, get_conn() as c:
            c.execute(f"UPDATE servers SET {','.join(fields)} WHERE id=?", vals)


def update_ssh_creds(sid: str, ssh: dict) -> None:
    """Обновление SSH-данных. Если ключ/пароль переданы пустыми — старые сохраняются."""
    sets = ["ssh_host=?", "ssh_port=?", "username=?", "auth_type=?", "known_hosts_policy=?"]
    vals = [ssh["host"], int(ssh.get("port", 22)), ssh["username"],
            ssh.get("auth_type", "private_key"), ssh.get("known_hosts_policy", "tofu")]
    if ssh.get("enc_private_key"):
        sets.append("enc_private_key=?"); vals.append(ssh["enc_private_key"])
        # новый ключ -> сбрасываем passphrase, если передан новый или очищаем
        sets.append("enc_passphrase=?"); vals.append(ssh.get("enc_passphrase", ""))
    elif "enc_private_key" in ssh and ssh["enc_private_key"] == "":
        pass  # не трогаем
    if ssh.get("clear_key"):
        sets.append("enc_private_key=''"); sets.append("enc_passphrase=''")
    if ssh.get("enc_passphrase"):
        sets.append("enc_passphrase=?"); vals.append(ssh["enc_passphrase"])
    if ssh.get("enc_password"):
        sets.append("enc_password=?"); vals.append(ssh["enc_password"])
    if ssh.get("clear_password"):
        sets.append("enc_password=''")
    vals.append(sid)
    with _lock, get_conn() as c:
        c.execute(f"UPDATE ssh_credentials SET {','.join(sets)} WHERE server_id=?", vals)


def set_server_status(sid: str, status: str, error: str = "") -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE servers SET status=?, last_error=?, updated_at=? WHERE id=?",
                  (status, error, now_iso(), sid))


def mark_cred_success(sid: str, fp: str = "", algo: str = "") -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE ssh_credentials SET last_success_at=?, last_error=NULL WHERE server_id=?",
                  (now_iso(), sid))
        if fp:
            c.execute("UPDATE ssh_credentials SET host_key_fingerprint=?, host_key_algorithm=?"
                      " WHERE server_id=? AND host_key_fingerprint=''", (fp, algo, sid))


def set_cred_error(sid: str, err: str) -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE ssh_credentials SET last_error=? WHERE server_id=?", (err, sid))


def verify_host_key(sid: str, fp: str, algo: str) -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE ssh_credentials SET host_key_fingerprint=?, host_key_algorithm=?,"
                  " host_key_verified=1 WHERE server_id=?", (fp, algo, sid))


def delete_server(sid: str) -> None:
    with _lock, get_conn() as c:
        c.execute("DELETE FROM servers WHERE id=?", (sid,))  # каскадно удаляет creds+services


def list_servers() -> list[dict]:
    with _lock, get_conn() as c:
        rows = c.execute(
            "SELECT s.*, k.ssh_host, k.ssh_port, k.username, k.auth_type, k.known_hosts_policy,"
            " k.host_key_fingerprint, k.host_key_algorithm, k.host_key_verified,"
            " k.last_success_at AS ssh_last_success_at, k.last_error AS ssh_last_error,"
            " (k.enc_private_key != '') AS has_key, (k.enc_password != '') AS has_password"
            " FROM servers s LEFT JOIN ssh_credentials k ON k.server_id = s.id ORDER BY s.created_at"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = json.loads(d.get("tags") or "[]")
        out.append(d)
    return out


def get_server(sid: str) -> dict | None:
    with _lock, get_conn() as c:
        r = c.execute(
            "SELECT s.*, k.ssh_host, k.ssh_port, k.username, k.auth_type, k.known_hosts_policy,"
            " k.host_key_fingerprint, k.host_key_algorithm, k.host_key_verified,"
            " (k.enc_private_key != '') AS has_key, (k.enc_password != '') AS has_password"
            " FROM servers s LEFT JOIN ssh_credentials k ON k.server_id=s.id WHERE s.id=?",
            (sid,),
        ).fetchone()
    if not r:
        return None
    d = dict(r)
    d["tags"] = json.loads(d.get("tags") or "[]")
    return d


def get_ssh_secrets(sid: str) -> dict | None:
    """Внутренний метод! Возвращает расшифрованные секреты. НИКОГДА не отдавать в API."""
    from . import crypto
    with _lock, get_conn() as c:
        r = c.execute("SELECT * FROM ssh_credentials WHERE server_id=?", (sid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    try:
        d["private_key"] = crypto.decrypt(d.pop("enc_private_key"))
        d["passphrase"] = crypto.decrypt(d.pop("enc_passphrase"))
        d["password"] = crypto.decrypt(d.pop("enc_password"))
    except ValueError:
        raise
    return d


# ---------- services ----------

def create_service(sid, name, target_host, target_port, target_protocol,
                   public_slug, is_enabled=True, is_iframe_allowed=True, tls_verify=False) -> str:
    if target_host not in ALLOWED_TARGET_HOSTS:
        raise ValueError(
            f"Целевой хост '{target_host}' запрещён. Разрешены только локальные адреса "
            f"удалённого сервера: {', '.join(sorted(ALLOWED_TARGET_HOSTS))}"
        )
    if not (1 <= int(target_port) <= 65535):
        raise ValueError("Порт должен быть в диапазоне 1..65535")
    id_ = str(uuid.uuid4())
    ts = now_iso()
    with _lock, get_conn() as c:
        c.execute(
            "INSERT INTO services (id,server_id,name,target_host,target_port,target_protocol,"
            " tls_verify,public_slug,is_enabled,is_iframe_allowed,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (id_, sid, name, target_host, int(target_port), target_protocol,
             1 if tls_verify else 0, public_slug, 1 if is_enabled else 0,
             1 if is_iframe_allowed else 0, ts, ts),
        )
    return id_


def update_service(id_, **kw) -> None:
    allowed = {"name", "target_host", "target_port", "target_protocol",
               "public_slug", "is_enabled", "is_iframe_allowed", "tls_verify"}
    fields, vals = [], []
    for k, v in kw.items():
        if k in allowed and v is not None:
            if isinstance(v, bool):
                v = 1 if v else 0
            fields.append(f"{k}=?"); vals.append(v)
    if fields:
        fields.append("updated_at=?"); vals.append(now_iso()); vals.append(id_)
        with _lock, get_conn() as c:
            c.execute(f"UPDATE services SET {','.join(fields)} WHERE id=?", vals)


def set_service_status(id_, status, error="") -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE services SET status=?, last_error=? WHERE id=?", (status, error, id_))


def delete_service(id_) -> None:
    with _lock, get_conn() as c:
        c.execute("DELETE FROM services WHERE id=?", (id_,))


def list_services(sid: str | None = None) -> list[dict]:
    with _lock, get_conn() as c:
        if sid:
            rows = c.execute("SELECT * FROM services WHERE server_id=? ORDER BY created_at", (sid,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM services ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


def get_service_by_slug(slug: str) -> dict | None:
    with _lock, get_conn() as c:
        r = c.execute("SELECT * FROM services WHERE public_slug=?", (slug,)).fetchone()
    return dict(r) if r else None


def touch_service(id_) -> None:
    with _lock, get_conn() as c:
        c.execute("UPDATE services SET last_used_at=? WHERE id=?", (now_iso(), id_)) \
            if "last_used_at" in [x[1] for x in c.execute("PRAGMA table_info(services)")] else None


def recent_audit(limit: int = 50) -> list[dict]:
    with _lock, get_conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

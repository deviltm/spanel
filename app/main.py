"""spanel — панель проксирования удалённых веб-панелей без агента, через SSH.

Запуск:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import db
from .crypto import encrypt
from .ssh_manager import manager

# в логах не должно быть секретов — стандартный уровень INFO, секреты никогда не логируем
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("spanel")

STATIC_DIR = Path(__file__).parent / "static"
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "tunnel.local")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    # восстановление туннелей после перезапуска панели (для серверов со статусом online)
    for s in db.list_servers():
        if s["connection_mode"] == "ssh" and s["status"] in ("online", "connecting"):
            manager.ensure_connected(s["id"])
    yield
    manager.shutdown()


app = FastAPI(title="spanel", lifespan=lifespan)

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


# ---------- schemas ----------

class SSHIn(BaseModel):
    host: str
    port: int = 22
    username: str
    auth_type: str = Field("private_key", pattern="^(private_key|password)$")
    private_key: str | None = None       # текст ключа; при редактировании пустой = не менять
    passphrase: str | None = None
    password: str | None = None
    clear_key: bool = False
    clear_password: bool = False
    known_hosts_policy: str = Field("tofu", pattern="^(strict|tofu|disabled)$")


class ServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = ""
    tags: list[str] = []
    connection_mode: str = Field("ssh", pattern="^(ssh|agent|reverse_ssh)$")
    ssh: SSHIn


class ServerPatch(BaseModel):
    name: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    ssh: SSHIn | None = None


class ServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    target_host: str = "127.0.0.1"
    target_port: int = Field(ge=1, le=65535)
    target_protocol: str = Field("http", pattern="^(http|https)$")
    tls_verify: bool = False
    public_slug: str | None = None
    is_enabled: bool = True
    is_iframe_allowed: bool = True


class ServicePatch(BaseModel):
    name: str | None = None
    target_port: int | None = Field(None, ge=1, le=65535)
    target_protocol: str | None = Field(None, pattern="^(http|https)$")
    tls_verify: bool | None = None
    public_slug: str | None = None
    is_enabled: bool | None = None
    is_iframe_allowed: bool | None = None


def _ssh_block_for_update(cur: dict, new) -> dict:
    """Собирает UPDATE-набор: новые секреты шифруются, пустые поля сохраняют старые."""
    out: dict = {
        "host": new.host, "port": new.port, "username": new.username,
        "auth_type": new.auth_type, "known_hosts_policy": new.known_hosts_policy,
    }
    if new.private_key:
        out["enc_private_key"] = encrypt(new.private_key)
        out["enc_passphrase"] = encrypt(new.passphrase) if new.passphrase else ""
    elif new.clear_key:
        out["clear_key"] = True
    if new.password:
        out["enc_password"] = encrypt(new.password)
    elif new.clear_password:
        out["clear_password"] = True
    return out


# ---------- servers API ----------

@app.post("/api/v1/servers", status_code=201)
def create_server(body: ServerIn):
    if body.connection_mode != "ssh":
        raise HTTPException(400, f"Режим '{body.connection_mode}' пока не реализован (MVP: только ssh)")
    ssh = body.ssh
    if ssh.auth_type == "private_key" and not ssh.private_key:
        raise HTTPException(422, "Не задан приватный ключ")
    if ssh.auth_type == "password" and not ssh.password:
        raise HTTPException(422, "Не задан SSH пароль")
    try:
        sid = db.create_server(
            body.name, body.description, body.tags, body.connection_mode,
            {
                "host": ssh.host, "port": ssh.port, "username": ssh.username,
                "auth_type": ssh.auth_type,
                "enc_private_key": encrypt(ssh.private_key) if ssh.private_key else "",
                "enc_passphrase": encrypt(ssh.passphrase) if ssh.passphrase else "",
                "enc_password": encrypt(ssh.password) if ssh.password else "",
                "known_hosts_policy": ssh.known_hosts_policy,
            },
        )
    except sqlite_integrity_error() as e:
        raise HTTPException(409, f"Сервер с таким именем уже существует: {e}")
    db.audit("admin", "server.create", body.name, f"mode=ssh host={ssh.host}:{ssh.port} user={ssh.username}")
    log.info("server created id=%s name=%s", sid[:8], body.name)
    return {"id": sid, "name": body.name, "connection_mode": "ssh", "status": "pending_test"}


def sqlite_integrity_error():
    import sqlite3
    return sqlite3.IntegrityError


@app.get("/api/v1/servers")
def servers_list():
    all_services = db.list_services()
    out = []
    for s in db.list_servers():
        live = manager.status(s["id"])
        out.append({
            **{k: s[k] for k in ("id", "name", "description", "tags", "connection_mode",
                                 "status", "last_error", "created_at", "updated_at")},
            "ssh": {
                "host": s.get("ssh_host"), "port": s.get("ssh_port"),
                "username": s.get("username"), "auth_type": s.get("auth_type"),
                "private_key": "[ключ сохранен]" if s.get("has_key") else "",
                "password": "••••••••" if s.get("has_password") else "",
                "known_hosts_policy": s.get("known_hosts_policy"),
                "host_key_fingerprint": s.get("host_key_fingerprint"),
                "host_key_verified": bool(s.get("host_key_verified")),
                "last_success_at": s.get("ssh_last_success_at"),
            },
            "live": live,
            "services": [v for v in all_services if v["server_id"] == s["id"]],
        })
    return out


@app.get("/api/v1/servers/{sid}")
def server_get(sid: str):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    s["live"] = manager.status(sid)
    s["services"] = db.list_services(sid)
    return s


@app.patch("/api/v1/servers/{sid}")
def server_patch(sid: str, body: ServerPatch):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    db.update_server(sid, body.name, body.description, body.tags)
    if body.ssh:
        db.update_ssh_creds(sid, _ssh_block_for_update(s, body.ssh))
        # после смены данных — переподключение
        manager.disconnect(sid)
        db.set_server_status(sid, "pending_test", "Изменены параметры подключения")
    db.audit("admin", "server.update", s["name"])
    return {"ok": True}


@app.delete("/api/v1/servers/{sid}")
def server_delete(sid: str):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    manager.disconnect(sid)
    db.delete_server(sid)
    db.audit("admin", "server.delete", s["name"], "SSH-ключи удалены из хранилища")
    return {"ok": True}


@app.post("/api/v1/servers/{sid}/ssh/test")
def ssh_test(sid: str):
    if not db.get_server(sid):
        raise HTTPException(404, "Сервер не найден")
    res = manager.test_connection(sid)
    db.audit("admin", "ssh.test", db.get_server(sid)["name"],
             f"tcp={res['tcp_reachable']} auth={res['authentication']} err={res['error'][:120]}")
    return res


@app.post("/api/v1/servers/{sid}/hostkey/confirm")
def confirm_hostkey(sid: str):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    fp = s.get("host_key_fingerprint") or ""
    if not fp:
        raise HTTPException(400, "Отпечаток ещё не получен — сначала выполните проверку подключения")
    db.verify_host_key(sid, fp, s.get("host_key_algorithm") or "")
    db.set_server_status(sid, "pending_test", "")
    db.audit("admin", "hostkey.confirm", s["name"], fp)
    return {"ok": True, "fingerprint": fp}


@app.post("/api/v1/servers/{sid}/hostkey/reset")
def reset_hostkey(sid: str):
    """Сброс сохранённого отпечатка (например, сервер переустановили)."""
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    with db._lock, db.get_conn() as c:
        c.execute("UPDATE ssh_credentials SET host_key_fingerprint='', host_key_algorithm='', "
                  "host_key_verified=0 WHERE server_id=?", (sid,))
    manager.disconnect(sid)
    db.set_server_status(sid, "pending_test", "Отпечаток хоста сброшен — выполните проверку подключения")
    db.audit("admin", "hostkey.reset", s["name"])
    return {"ok": True}


@app.post("/api/v1/servers/{sid}/connect")
def connect_now(sid: str):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    st = manager.ensure_connected(sid)
    return {"status": st.status, "last_error": st.last_error}


@app.post("/api/v1/servers/{sid}/disconnect")
def disconnect_now(sid: str):
    manager.disconnect(sid)
    db.set_server_status(sid, "disabled", "Отключено вручную")
    db.audit("admin", "server.disconnect", sid[:8])
    return {"ok": True}


# ---------- services API ----------

@app.post("/api/v1/servers/{sid}/services", status_code=201)
def create_service(sid: str, body: ServiceIn):
    s = db.get_server(sid)
    if not s:
        raise HTTPException(404, "Сервер не найден")
    slug = body.public_slug or f"{s['name'].lower().replace(' ', '-')}-{body.target_port}"
    if not SLUG_RE.match(slug):
        raise HTTPException(422, "slug: только строчные латинские буквы, цифры и дефис, 2..41 симв.")
    try:
        svc_id = db.create_service(
            sid, body.name, body.target_host, body.target_port, body.target_protocol,
            slug, body.is_enabled, body.is_iframe_allowed, body.tls_verify)
    except ValueError as e:
        raise HTTPException(422, str(e))
    except Exception as e:  # noqa: BLE001
        import sqlite3
        if isinstance(e, sqlite3.IntegrityError):
            raise HTTPException(409, f"slug '{slug}' уже занят") from e
        raise
    ok, err = manager.check_target(sid, body.target_host, body.target_port) \
        if body.is_enabled else (False, "сервис отключён")
    db.set_service_status(svc_id, "enabled" if ok else "target_unreachable", "" if ok else err)
    db.audit("admin", "service.create", f"{s['name']}/{body.name}",
             f"{body.target_host}:{body.target_port} slug={slug} reachable={ok}")
    return {"id": svc_id, "public_url": f"https://{slug}.{BASE_DOMAIN}",
            "status": "enabled" if ok else "target_unreachable",
            "last_error": err}


@app.get("/api/v1/services")
def services_list():
    out = []
    for v in db.list_services():
        v["public_url"] = f"https://{v['public_slug']}.{BASE_DOMAIN}"
        out.append(v)
    return out


@app.patch("/api/v1/services/{vid}")
def service_patch(vid: str, body: ServicePatch):
    svcs = [v for v in db.list_services() if v["id"] == vid]
    if not svcs:
        raise HTTPException(404, "Сервис не найден")
    kw = body.model_dump(exclude_none=True)
    if "public_slug" in kw and not SLUG_RE.match(kw["public_slug"]):
        raise HTTPException(422, "Некорректный slug")
    if "target_host" in kw:
        kw.pop("target_host")  # whitelist — менять нельзя
    db.update_service(vid, **kw)
    db.audit("admin", "service.update", svcs[0]["name"], str(list(kw)))
    return {"ok": True}


@app.delete("/api/v1/services/{vid}")
def service_delete(vid: str):
    found = [v for v in db.list_services() if v["id"] == vid]
    if not found:
        raise HTTPException(404, "Сервис не найден")
    db.delete_service(vid)
    db.audit("admin", "service.delete", found[0]["name"])
    return {"ok": True}


@app.post("/api/v1/services/{vid}/check")
def service_check(vid: str):
    v = next((x for x in db.list_services() if x["id"] == vid), None)
    if not v:
        raise HTTPException(404, "Сервис не найден")
    ok, err = manager.check_target(v["server_id"], v["target_host"], v["target_port"])
    db.set_service_status(vid, "enabled" if ok else "target_unreachable", "" if ok else err)
    return {"reachable": ok, "error": err}


@app.get("/api/v1/audit")
def audit(limit: int = 50):
    return db.recent_audit(limit)


# ---------- proxy: browser <-> panel <-> SSH channel <-> remote web ----------

_STRIP_REQ = {"host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "transfer-encoding", "upgrade-insecure-requests"}
_STRIP_RESP = {"content-security-policy", "x-frame-options", "content-length",
               "content-encoding", "transfer-encoding", "connection", "keep-alive"}


def _error_page(code: int, title: str, detail: str) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html><meta charset=utf-8><title>{code} {title}</title>
        <style>body{{font-family:system-ui;background:#0b1220;color:#dbe4f3;display:grid;
        place-items:center;height:100vh;margin:0}}div{{max-width:640px;padding:32px;
        background:#111a2e;border:1px solid #223052;border-radius:12px}}
        h1{{margin-top:0;color:#ff7b7b}}code{{background:#0b1220;padding:2px 6px;border-radius:4px}}</style>
        <div><h1>{code} — {title}</h1><p>{detail}</p>
        <p><a href="/" style="color:#5aa9ff">← Вернуться в панель</a></div>""",
        status_code=code)


@app.get("/")
def index():
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


@app.api_route("/proxy/{slug}/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
@app.api_route("/proxy/{slug}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
async def proxy(request: Request, slug: str, path: str = ""):
    svc = db.get_service_by_slug(slug)
    if not svc:
        return _error_page(404, "Сервис не найден",
                           f"Публичный адрес <code>{slug}</code> не зарегистрирован в панели.")
    if not svc["is_enabled"]:
        return _error_page(403, "Сервис отключён", "Доступ к сервису отключён администратором панели.")
    server = db.get_server(svc["server_id"])
    if not server:
        return _error_page(404, "Сервер удалён", "Родительский SSH-сервер был удалён.")

    target_path = "/" + path.lstrip("/")
    if request.url.query:
        target_path += "?" + request.url.query
    base = f"{svc['target_protocol']}://{svc['target_host']}:{svc['target_port']}"
    url = base + quote(target_path)

    headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_REQ}
    headers["host"] = f"{svc['target_host']}:{svc['target_port']}"
    headers["x-forwarded-for"] = request.client.host if request.client else ""
    headers["x-forwarded-proto"] = "https"
    headers["x-forwarded-host"] = f"{slug}.{BASE_DOMAIN}"
    body = await request.body()

    # SSH-канал в пуле потоков (paramiko блокирующий)
    def dial():
        return manager.open_channel(svc["server_id"], svc["target_host"], svc["target_port"])

    try:
        chan = await asyncio.get_running_loop().run_in_executor(None, dial)
    except TimeoutError as e:
        db.set_service_status(svc["id"], "target_timeout", str(e))
        return _error_page(504, "Таймаут SSH", f"{e}<br>Панель не дождалась активного SSH-соединения к «{server['name']}».")
    except PermissionError as e:
        return _error_page(403, "Запрещено политикой", str(e))
    except Exception as e:  # noqa: BLE001
        code = 502
        db.set_service_status(svc["id"], "no_active_ssh" if "SSH" in str(e) else "target_unreachable", str(e)[:300])
        hint = ""
        if "AllowTcpForwarding" in str(e):
            hint = "<br><br>Совет: включите <code>AllowTcpForwarding yes</code> в /etc/ssh/sshd_config на сервере."
        return _error_page(code, "Нет доступа к целевому сервису",
                            f"SSH-подключение к «{server['name']}»: {e}{hint}")

    transport = httpx.AsyncHTTPTransport(socket=chan)
    client = httpx.AsyncClient(transport=transport, verify=bool(svc["tls_verify"]),
                               follow_redirects=False, timeout=httpx.Timeout(
                                   connect=10, read=120, write=120, pool=10))

    try:
        req = client.build_request(request.method, url, headers=headers, content=body)
        resp = await client.send(req, stream=True)
    except httpx.ConnectError as e:
        chan.close(); manager._release(svc["server_id"]); await client.aclose()
        db.set_service_status(svc["id"], "target_unreachable",
                              f"SSH установлен, но {svc['target_host']}:{svc['target_port']} недоступен")
        return _error_page(502, "Целевой порт недоступен",
                           f"SSH-подключение к «{server['name']}» установлено, но порт "
                           f"<code>{svc['target_port']}</code> недоступен. Проверьте, что веб-сервис запущен.")
    except httpx.RemoteProtocolError as e:
        chan.close(); manager._release(svc["server_id"]); await client.aclose()
        db.set_service_status(svc["id"], "http_error", str(e)[:300])
        return _error_page(502, "Ошибка протокола бэкенда", str(e))
    except Exception as e:  # noqa: BLE001
        chan.close(); manager._release(svc["server_id"]); await client.aclose()
        msg = str(e)
        code = 502
        if "SSL" in msg or "certificate" in msg.lower():
            db.set_service_status(svc["id"], "tls_error", msg[:300])
            return _error_page(502, "TLS ошибка бэкенда",
                               f"Веб-сервис использует HTTPS с самоподписанным сертификатом. "
                               f"Разрешите пропуск проверки сертификата в настройках сервиса.<br>{msg}")
        if "timeout" in msg.lower():
            code = 504
            db.set_service_status(svc["id"], "target_timeout", msg[:300])
        else:
            db.set_service_status(svc["id"], "http_error", msg[:300])
        return _error_page(code, "Ошибка проксирования", msg)

    db.set_service_status(svc["id"], "enabled", "")

    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _STRIP_RESP}
    if not svc["is_iframe_allowed"]:
        resp_headers["x-frame-options"] = "DENY"

    async def stream():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose(); await client.aclose()
            chan.close(); manager._release(svc["server_id"])

    media = resp.headers.get("content-type", "")
    if "websocket" in request.headers.get("upgrade", "").lower():
        # WebSocket через direct-tcpip требует отдельного bidirectional pump
        chan.close(); await client.aclose(); manager._release(svc["server_id"])
        return _error_page(501, "WebSocket over proxy URL не поддерживается в MVP HTTP-роутера",
                           "Используйте встроенный ws-pump (см. README).")
    return StreamingResponse(stream(), status_code=resp.status_code, headers=resp_headers,
                             media_type=media or None)


# loop ref для run_in_executor — не нужен, берём asyncio.get_running_loop() на месте


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8080)

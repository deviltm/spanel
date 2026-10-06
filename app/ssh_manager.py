"""SSH-менеджер панели (режим «без агента»).

Панель выступает SSH-клиентом: одно постоянное соединение на сервер,
проксирование веб-запросов через direct-tcpip каналы к целевым хостам.

Разрешено ТОЛЬКО: TCP-каналы к whitelisted адресам + проверка доступности порта.
Запрещено: shell, exec, interactive, sftp, X11/agent forwarding (ТЗ п.11).
"""
from __future__ import annotations

import base64
import hashlib
import socket
import threading
import time
from dataclasses import dataclass, field

import paramiko

from . import db

CONN_TIMEOUT = 10          # сек, tcp+ssh handshake
CHANNEL_DIAL_TIMEOUT = 5   # сек, открытие direct-tcpip
KEEPALIVE_INTERVAL = 15
KEEPALIVE_COUNT_MAX = 3
RECONNECT_MIN_DELAY = 1
RECONNECT_MAX_DELAY = 60


def fingerprint_of(key: paramiko.RSAKey | paramiko.Ed25519Key | paramiko.Key) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class HostKeyChanged(Exception):
    pass


@dataclass
class TunnelState:
    server_id: str
    status: str = "connecting"      # connecting|online|auth_error|host_key_error|timeout|offline|key_decrypt_error|disabled
    last_error: str = ""
    client: paramiko.SSHClient | None = None
    active_channels: int = 0
    bytes_rx: int = 0
    bytes_tx: int = 0
    started_at: float = field(default_factory=time.time)
    stop_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)


class SSHTunnelManager:
    def __init__(self) -> None:
        self._states: dict[str, TunnelState] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._global_lock = threading.Lock()

    # ---------- public API ----------

    def test_connection(self, server_id: str) -> dict:
        """Однократная проверка: TCP -> handshake -> auth -> host key. Не сохраняет соединение."""
        result = {"tcp_reachable": False, "ssh_handshake": False, "authentication": False,
                  "host_key": "", "host_key_changed": False, "latency_ms": None, "error": ""}
        creds = db.get_server(server_id)
        if not creds:
            result["error"] = "Сервер не найден"
            return result
        t0 = time.monotonic()
        try:
            secrets = db.get_ssh_secrets(server_id)
        except ValueError as e:
            db.set_server_status(server_id, "key_decrypt_error", str(e))
            result["error"] = str(e)
            return result

        host, port = secrets["ssh_host"], int(secrets["ssh_port"])
        # 1. TCP reachability
        try:
            with socket.create_connection((host, port), timeout=CONN_TIMEOUT):
                result["tcp_reachable"] = True
        except socket.timeout:
            err = f"Не удалось подключиться к SSH-серверу {host}:{port}: таймаут соединения."
            db.set_server_status(server_id, "timeout", err); db.set_cred_error(server_id, err)
            result["error"] = err
            return result
        except OSError as e:
            err = f"Хост {host}:{port} недоступен: {e.strerror or e}"
            db.set_server_status(server_id, "offline", err); db.set_cred_error(server_id, err)
            result["error"] = err
            return result

        client = paramiko.SSHClient()
        policy = secrets.get("known_hosts_policy", "tofu")
        saved_fp = secrets.get("host_key_fingerprint") or ""
        seen: dict[str, str] = {}

        def _policy(key_) -> None:
            fp = fingerprint_of(key_)
            seen["fp"] = fp
            seen["algo"] = key_.get_name()
            if policy == "disabled":
                client.get_host_keys().add(host, key_.get_name(), key_)
                return
            if saved_fp:
                if fp != saved_fp:
                    raise HostKeyChanged(
                        "Host key сервера изменился. Подключение заблокировано. "
                        "Возможна атака или сервер был переустановлен.")
                client.get_host_keys().add(host, key_.get_name(), key_)
            elif policy == "strict":
                raise HostKeyChanged(f"Host key неизвестен ({fp}). Требуется подтверждение (strict).")
            else:  # tofu — запоминаем, но просим подтверждения
                client.get_host_keys().add(host, key_.get_name(), key_)

        try:
            sock = socket.create_connection((host, port), timeout=CONN_TIMEOUT)
            transport = paramiko.Transport(sock)
            client._transport = transport  # SSHClient использует готовый transport без known_hosts-проверки
            transport.start_client(timeout=CONN_TIMEOUT)
            _policy(transport.get_remote_server_key())
            result["ssh_handshake"] = True
            self._authenticate(client, secrets)
            result["authentication"] = True
        except HostKeyChanged as e:
            db.set_server_status(server_id, "host_key_error", str(e)); db.set_cred_error(server_id, str(e))
            result["error"] = str(e); result["host_key_changed"] = True
            result["host_key"] = seen.get("fp", "")
            return result
        except paramiko.AuthenticationException as e:
            err = ("Ошибка аутентификации: неверный ключ, пароль ключа или пользователь. "
                   f"({e})" if "password" not in str(e).lower() else
                   "Ключ зашифрован. Укажите пароль приватного ключа.")
            db.set_server_status(server_id, "auth_error", err); db.set_cred_error(server_id, err)
            result["error"] = err
            return result
        except Exception as e:  # noqa: BLE001
            err = f"Ошибка SSH-подключения: {e}"
            db.set_server_status(server_id, "offline", err); db.set_cred_error(server_id, err)
            result["error"] = err
            return result
        finally:
            result["latency_ms"] = round((time.monotonic() - t0) * 1000)
            client.close()

        result["host_key"] = seen.get("fp", "")
        algo = seen.get("algo", "")
        verified = bool(int(creds.get("host_key_verified") or 0))
        if not verified and saved_fp and saved_fp == result["host_key"]:
            verified = True
        if not verified and policy != "disabled":
            # TOFU: сохраняем отпечаток, ждём подтверждения администратором
            db.mark_cred_success(server_id, result["host_key"], algo)
            db.set_server_status(server_id, "pending_host_key",
                                 f"Подтвердите отпечаток хоста: {result['host_key']}")
            result["needs_host_key_confirm"] = True
        else:
            db.mark_cred_success(server_id, result["host_key"], algo)
            db.set_server_status(server_id, "online", "")
        return result

    @staticmethod
    def _authenticate(client: paramiko.SSHClient, secrets: dict) -> None:
        if secrets["auth_type"] == "password":
            if not secrets.get("password"):
                raise paramiko.AuthenticationException("SSH password не задан")
            client.connect(hostname=secrets["ssh_host"], port=int(secrets["ssh_port"]),
                           username=secrets["username"], password=secrets["password"],
                           timeout=CONN_TIMEOUT, banner_timeout=CONN_TIMEOUT,
                           auth_timeout=CONN_TIMEOUT, allow_agent=False, look_for_keys=False)
            return
        pkey_str = secrets.get("private_key") or ""
        if not pkey_str:
            raise paramiko.AuthenticationException("Приватный ключ не задан")
        passphrase = secrets.get("passphrase") or None
        pkey = None
        last_err: Exception | None = None
        key_classes = [c for c in (getattr(paramiko, n, None) for n in
                                   ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey")) if c is not None]
        for cls in key_classes:
            try:
                pkey = cls.from_private_key(_io(pkey_str), password=passphrase)
                break
            except paramiko.PasswordRequiredException:
                raise paramiko.AuthenticationException(
                    "Ключ зашифрован. Укажите пароль приватного ключа.") from None
            except Exception as e:  # noqa: BLE001
                last_err = e
        if pkey is None:
            raise paramiko.AuthenticationException(f"Ошибка загрузки/расшифровки ключа: {last_err}") from last_err
        client.connect(hostname=secrets["ssh_host"], port=int(secrets["ssh_port"]),
                       username=secrets["username"], pkey=pkey,
                       timeout=CONN_TIMEOUT, banner_timeout=CONN_TIMEOUT,
                       auth_timeout=CONN_TIMEOUT, allow_agent=False, look_for_keys=False)

    # ---------- persistent connections ----------

    def ensure_connected(self, server_id: str) -> TunnelState:
        with self._global_lock:
            st = self._states.get(server_id)
            if st is None:
                st = TunnelState(server_id=server_id)
                self._states[server_id] = st
                th = threading.Thread(target=self._supervisor, args=(st,), daemon=True,
                                      name=f"ssh-sup-{server_id[:8]}")
                self._threads[server_id] = th
                th.start()
            return st

    def disconnect(self, server_id: str) -> None:
        with self._global_lock:
            st = self._states.pop(server_id, None)
            self._threads.pop(server_id, None)
        if st:
            st.stop_event.set()
            with st.lock:
                if st.client:
                    try:
                        st.client.close()
                    except Exception:  # noqa: BLE001
                        pass

    def shutdown(self) -> None:
        for sid in list(self._states):
            self.disconnect(sid)

    def status(self, server_id: str) -> dict:
        st = self._states.get(server_id)
        if not st:
            return {"status": "disconnected", "active_channels": 0}
        return {"status": st.status, "last_error": st.last_error,
                "active_channels": st.active_channels,
                "bytes_rx": st.bytes_rx, "bytes_tx": st.bytes_tx}

    def _supervisor(self, st: TunnelState) -> None:
        delay = RECONNECT_MIN_DELAY
        while not st.stop_event.is_set():
            try:
                self._connect_once(st)
                delay = RECONNECT_MIN_DELAY
                # ждём обрыва соединения
                while not st.stop_event.is_set():
                    with st.lock:
                        tr = st.client.get_transport() if st.client else None
                    if not tr or not tr.is_active():
                        break
                    time.sleep(2)
                raise ConnectionError("SSH-соединение потеряно")
            except HostKeyChanged as e:
                self._set_status(st, "host_key_error", str(e))
                return  # без авто-реконнекта до подтверждения администратором
            except paramiko.AuthenticationException as e:
                self._set_status(st, "auth_error", f"Ошибка аутентификации: {e}")
                return  # не долбим сервер бесконечно (ТЗ: критерий отказоустойчивости)
            except ValueError as e:  # key_decrypt_error
                self._set_status(st, "key_decrypt_error", str(e))
                return
            except Exception as e:  # noqa: BLE001
                msg = str(e) or e.__class__.__name__
                if "timed out" in msg.lower():
                    self._set_status(st, "timeout", f"Таймаут подключения: {msg}")
                else:
                    self._set_status(st, "offline", f"Нет соединения: {msg}")
            if st.stop_event.wait(delay):
                return
            delay = min(delay * 2, RECONNECT_MAX_DELAY)

    def _connect_once(self, st: TunnelState) -> None:
        secrets = db.get_ssh_secrets(st.server_id)
        if not secrets:
            raise RuntimeError("Сервер удалён")
        host, port = secrets["ssh_host"], int(secrets["ssh_port"])
        policy = secrets.get("known_hosts_policy", "tofu")
        saved_fp = secrets.get("host_key_fingerprint") or ""
        sock = socket.create_connection((host, port), timeout=CONN_TIMEOUT)
        tr = paramiko.Transport(sock)
        try:
            tr.start_client(timeout=CONN_TIMEOUT)
            key_ = tr.get_remote_server_key()
            fp = fingerprint_of(key_)
            # сверка отпечатка по политике (без known_hosts-файлов)
            if policy != "disabled":
                if saved_fp:
                    if fp != saved_fp:
                        raise HostKeyChanged(
                            "Host key сервера изменился. Подключение заблокировано. "
                            "Возможна атака или сервер был переустановлен.")
                elif policy == "strict":
                    raise HostKeyChanged(f"Host key неизвестен ({fp}). Требуется подтверждение (strict).")
            self._authenticate_transport(tr, secrets)
        except Exception:
            tr.close()
            raise
        tr.set_keepalive(KEEPALIVE_INTERVAL)
        with st.lock:
            st.client = _ClientWrap(tr)
            st.started_at = time.time()
        db.mark_cred_success(st.server_id, fp, key_.get_name())
        self._set_status(st, "online", "")

    def _set_status(self, st: TunnelState, status: str, error: str = "") -> None:
        st.status, st.last_error = status, error
        try:
            db.set_server_status(st.server_id, status, error)
        except Exception:  # noqa: BLE001
            pass

    # ---------- proxy channels ----------

    def open_channel(self, server_id: str, target_host: str, target_port: int):
        if target_host not in db.ALLOWED_TARGET_HOSTS:
            raise PermissionError(
                f"Целевой адрес '{target_host}' запрещён политикой панели "
                f"(разрешены: {', '.join(sorted(db.ALLOWED_TARGET_HOSTS))})")
        st = self.ensure_connected(server_id)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with st.lock:
                tr = st.client.get_transport() if st.client else None
            if tr and tr.is_active():
                try:
                    ch = tr.open_channel("direct-tcpip", dest_addr=(target_host, target_port),
                                         src_addr=("127.0.0.1", 0), timeout=CHANNEL_DIAL_TIMEOUT)
                    st.active_channels += 1
                    return ch
                except paramiko.ChannelException as e:
                    txt = str(e)
                    if "open failed" in txt or "Administratively prohibited" in txt:
                        raise RuntimeError(
                            "Удалённый сервер разрешил SSH-соединение, но запретил проброс каналов. "
                            "Проверьте AllowTcpForwarding в /etc/ssh/sshd_config") from e
                    raise RuntimeError(f"Целевой порт {target_host}:{target_port} недоступен: {txt}") from e
                except OSError as e:
                    raise RuntimeError(f"Целевой порт {target_host}:{target_port} недоступен: {e}") from e
            if st.status in ("auth_error", "host_key_error", "key_decrypt_error"):
                raise RuntimeError(st.last_error or f"SSH: {st.status}")
            if st.stop_event.is_set():
                raise RuntimeError("SSH-подключение отключено")
            time.sleep(0.3)
        raise TimeoutError(f"Таймаут ожидания SSH-соединения (статус: {st.status})")

    def check_target(self, server_id: str, target_host: str, target_port: int) -> tuple[bool, str]:
        try:
            ch = self.open_channel(server_id, target_host, target_port)
            ch.close()
            self._release(server_id)
            return True, ""
        except Exception as e:  # noqa: BLE001
            return False, str(e)

    def _release(self, server_id: str) -> None:
        st = self._states.get(server_id)
        if st:
            st.active_channels = max(0, st.active_channels - 1)


    @staticmethod
    def _authenticate_transport(tr: paramiko.Transport, secrets: dict) -> None:
        """Аутентификация на уже запущенном transport (persistent-режим)."""
        user = secrets["username"]
        if secrets["auth_type"] == "password":
            if not secrets.get("password"):
                raise paramiko.AuthenticationException("SSH password не задан")
            tr.auth_password(user, secrets["password"])
            return
        pkey_str = secrets.get("private_key") or ""
        if not pkey_str:
            raise paramiko.AuthenticationException("Приватный ключ не задан")
        passphrase = secrets.get("passphrase") or None
        pkey = None
        last_err: Exception | None = None
        for cls in [c for c in (getattr(paramiko, n, None) for n in
                                ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey")) if c is not None]:
            try:
                pkey = cls.from_private_key(_io(pkey_str), password=passphrase)
                break
            except paramiko.PasswordRequiredException:
                raise paramiko.AuthenticationException(
                    "Ключ зашифрован. Укажите пароль приватного ключа.") from None
            except Exception as e:  # noqa: BLE001
                last_err = e
        if pkey is None:
            raise paramiko.AuthenticationException(f"Ошибка загрузки/расшифровки ключа: {last_err}")
        tr.auth_publickey(user, pkey)


class _ClientWrap:
    """Лёгкая обёртка над Transport — интерфейс .get_transport() для совместимости."""
    def __init__(self, tr: paramiko.Transport):
        self._tr = tr

    def get_transport(self):
        return self._tr

    def close(self):
        self._tr.close()
def _io(s: str):
    """paramiko принимает file-like для from_private_key."""
    import io
    return io.StringIO(s)


manager = SSHTunnelManager()

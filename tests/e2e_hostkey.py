"""E2E: host key TOFU на нестандартном SSH-порту + повторные проверки после 'Изменить'.

Воспроизводит баг: "Server '[host]:port' not found in known_hosts" при auth=False
и проверяет, что теперь:
 1) первый тест возвращает needs_host_key_confirm (а не ошибку);
 2) confirm -> connect -> online;
 3) повторный ssh/test проходит без ошибки known_hosts;
 4) PATCH ('Изменить') сбрасывает fingerprint -> снова чистый TOFU, без ошибки;
 5) /proxy/<slug>/ работает через туннель.
"""
import os
import socket
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def wait_port(port, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def write_pub(priv_path: str):
    """paramiko не умеет писать .pub — делаем это сами (как ssh-keygen -y)."""
    import base64
    key = paramiko.RSAKey(filename=priv_path)
    with open(priv_path + ".pub", "w") as f:
        f.write(f"ssh-rsa {base64.b64encode(key.asbytes()).decode()}\n")


def main():
    import paramiko
    import requests

    os.makedirs("/tmp/testssh", exist_ok=True)
    if not os.path.exists("/tmp/testssh/host_rsa"):
        paramiko.RSAKey.generate(2048).write_private_key_file("/tmp/testssh/host_rsa")
    write_pub("/tmp/testssh/host_rsa")
    if not os.path.exists("/tmp/testssh/client_rsa"):
        paramiko.RSAKey.generate(2048).write_private_key_file("/tmp/testssh/client_rsa")
    write_pub("/tmp/testssh/client_rsa")

    # fake remote (ssh :2222, web :8006)
    fr = subprocess.Popen([sys.executable, os.path.join(BASE, "tests/fake_remote.py")],
                          cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(2222) and wait_port(8006), "fake remote не поднялся"

    # panel
    panel_port = free_port()
    env = dict(os.environ, SECRETS_ENCRYPTION_KEY="aGlnaC1zZWNyZXQta2V5LWZvci10ZXN0aW5nLTEyMzQ1Ng==",
               PANEL_HOST="127.0.0.1", PANEL_PORT=str(panel_port),
               SPANEL_DB=os.environ.get("SPANEL_DB", str(free_port())), DATA_DIR="/tmp/spanel-e2e")
    os.makedirs("/tmp/spanel-e2e", exist_ok=True)
    pn = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                           "--host", "127.0.0.1", "--port", str(panel_port)],
                          cwd=BASE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(panel_port), "панель не поднялась"
    API = f"http://127.0.0.1:{panel_port}/api/v1"

    priv = open("/tmp/testssh/client_rsa").read()
    ok = True
    try:
        r = requests.post(API + "/servers", json={
            "name": "nix1", "connection_mode": "ssh",
            "ssh": {"host": "127.0.0.1", "port": 2222, "username": "testuser",
                    "auth_type": "private_key", "private_key": priv,
                    "known_hosts_policy": "tofu"}}, timeout=10)
        sid = r.json()["id"]

        # 1. первый тест — TOFU, НЕ ошибка known_hosts
        res = requests.post(f"{API}/servers/{sid}/ssh/test", timeout=30).json()
        print("test#1:", {k: res[k] for k in ("tcp_reachable", "authentication", "needs_host_key_confirm", "error")})
        assert res["authentication"] and res.get("needs_host_key_confirm"), "нет TOFU-подтверждения"
        assert "known_hosts" not in res["error"], "баг: ошибка known_hosts на первом тесте"

        # 2. confirm + connect -> online
        requests.post(f"{API}/servers/{sid}/hostkey/confirm", timeout=10)
        for _ in range(40):
            st = requests.post(f"{API}/servers/{sid}/connect", timeout=10).json()
            if st["status"] == "online":
                break
            time.sleep(0.5)
        print("connect status:", st["status"])
        assert st["status"] == "online", st

        # 3. повторный тест (как после «Изменить» в UI) — без ошибки known_hosts
        res2 = requests.post(f"{API}/servers/{sid}/ssh/test", timeout=30).json()
        print("test#2:", {k: res2[k] for k in ("authentication", "host_key_changed", "error")})
        assert res2["authentication"], f"баг повторяется: {res2['error']}"
        assert "known_hosts" not in res2["error"]

        # 4. PATCH как кнопка «Изменить» -> перепроверка тоже чистая
        requests.patch(f"{API}/servers/{sid}", json={"name": "nix1", "ssh": {
            "host": "127.0.0.1", "port": 2222, "username": "testuser",
            "auth_type": "private_key", "known_hosts_policy": "tofu"}}, timeout=10)
        res3 = requests.post(f"{API}/servers/{sid}/ssh/test", timeout=30).json()
        print("test#3 (после PATCH):", {k: res3[k] for k in ("authentication", "needs_host_key_confirm", "error")})
        assert res3["authentication"] and res3.get("needs_host_key_confirm"), \
            f"после изменения — не TOFU: {res3['error']}"
        assert "not found in known_hosts" not in res3["error"]
        requests.post(f"{API}/servers/{sid}/hostkey/confirm", timeout=10)

        # 5. проброс порта через туннель
        rv = requests.post(f"{API}/servers/{sid}/services", json={
            "name": "WebPanel", "target_host": "127.0.0.1", "target_port": 8006,
            "target_protocol": "http", "public_slug": "nix1-8006"}, timeout=10)
        slug = rv.json()["public_slug"]
        page = None
        for _ in range(30):
            page = requests.get(f"http://127.0.0.1:{panel_port}/proxy/{slug}/", timeout=15)
            if page.status_code == 200:
                break
            time.sleep(0.5)
        print("proxy:", page.status_code, "содержит панель:", "Удалённая веб-панель" in page.text)
        assert page.status_code == 200 and "Удалённая веб-панель" in page.text
    except AssertionError as e:
        ok = False
        print("FAIL:", e)
    finally:
        pn.terminate(); fr.terminate()
    print("E2E HOSTKEY:", "PASS ✅" if ok else "FAIL ❌")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

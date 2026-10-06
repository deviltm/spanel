"""Эмуляция 'удалённого сервера' для end-to-end теста панели:
- paramiko SSH-сервер (key auth, direct-tcpip forwarding) на :2222
- фейковый веб-интерфейс (эмулирует Proxmox-like) на :8006
"""
import select
import socket
import threading

import paramiko

HOST_KEY = paramiko.RSAKey(filename="/tmp/testssh/host_rsa")
CLIENT_PUB = open("/tmp/testssh/client_rsa.pub").read().split()[:2]


class Server(paramiko.ServerInterface):
    def check_auth_publickey(self, username, key):
        pub = key.get_name() + " " + key.get_base64()
        if username == "testuser" and pub == " ".join(CLIENT_PUB):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_direct_tcpip_request(self, chanid, origin, dest):
        return paramiko.OPEN_SUCCEEDED  # AllowTcpForwarding yes

    def check_channel_request(self, kind, chanid):
        if kind == "direct-tcpip":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def pump(a, b):
    try:
        while True:
            r, _, _ = select.select([a], [], [], 30)
            if not r:
                break
            data = a.recv(8192)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def handle_channel(chan):
    dest = chan.get_dest_addr()
    try:
        up = socket.create_connection(dest, timeout=5)
    except OSError:
        chan.close()
        return
    threading.Thread(target=pump, args=(chan, up), daemon=True).start()
    threading.Thread(target=pump, args=(up, chan), daemon=True).start()


def ssh_loop():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 2222))
    ls.listen(10)
    print("fake sshd on 127.0.0.1:2222", flush=True)
    while True:
        sock, _ = ls.accept()

        def serve(sock=sock):
            try:
                tr = paramiko.Transport(sock)
                tr.add_server_key(HOST_KEY)
                tr.start_server(server=Server())
                while tr.is_active():
                    ch = tr.accept(timeout=30)
                    if ch is None:
                        continue
                    handle_channel(ch)
            except Exception as e:  # noqa: BLE001
                print("sshd err:", e, flush=True)

        threading.Thread(target=serve, daemon=True).start()


def web_loop():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = (f"<html><head><title>Remote Web Panel</title></head>"
                    f"<body><h1>Удалённая веб-панель :8006</h1>"
                    f"<p>Запрошен путь: {self.path}</p>"
                    f"<p>Host: {self.headers.get('host')}</p></body></html>").encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(("127.0.0.1", 8006), H).serve_forever()


if __name__ == "__main__":
    threading.Thread(target=web_loop, daemon=True).start()
    print("fake web panel on 127.0.0.1:8006", flush=True)
    ssh_loop()

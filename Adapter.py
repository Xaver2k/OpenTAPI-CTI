"""Lokaler Telefonadapter. Python 3.10+ mit Standardbibliothek."""
import argparse
import hmac
import sys
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FrapuriCTI"
EVENTS = {"incoming_call": "in", "outgoing_call": "out",
          "call_established": "up", "call_terminated": "end", "missed_call": "end"}
NETWORKS = tuple(map(ipaddress.ip_network, ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))
NUMBER = re.compile(r"\+?[0-9]{1,32}")
CALL_ID = re.compile(r"[A-Za-z0-9._:@-]{1,160}")

def private_ip(text):
    ip = ipaddress.ip_address(text)
    if not any(ip in network for network in NETWORKS):
        raise ValueError("Bitte eine private IPv4-Adresse angeben.")
    return str(ip)

def dial_number(text):
    return re.sub(r"[ ()/-]", "", text)

class Calls:
    def __init__(self, after_answer=False):
        self.after_answer = after_answer
        self.active = {}
        self.ended = {}
        self.lock = threading.Lock()

    def update(self, ident, event, number):
        with self.lock:
            now = time.monotonic()
            self.ended = {key: ts for key, ts in self.ended.items() if now - ts < 60}
            if event == "end":
                self.active.pop(ident, None)
                self.ended[ident] = now
            elif ident in self.ended:
                return
            elif event in ("in", "out"):
                self.active.setdefault(ident, ("ring", event, number))
            elif event == "up" and ident in self.active:
                _, direction, original = self.active[ident]
                self.active[ident] = ("up", direction, original or number)

    def snapshot(self):
        with self.lock:
            return "".join(f"{i} {state} {direction} {n or '-'}\n"
                           for i,(state,direction,n) in self.active.items()
                           if not (self.after_answer and direction == "in" and state == "ring")).encode("ascii")

class Yealink:
    def __init__(self, cfg):
        private_ip(cfg["telefon"])
        if cfg["schema"] not in ("http", "https"):
            raise ValueError("Ungültiges Protokoll.")
        self.cfg = cfg

    def dial(self, number):
        if not NUMBER.fullmatch(number):
            raise ValueError("Ungültige Rufnummer.")
        host = self.cfg["telefon"]
        cls = http.client.HTTPSConnection if self.cfg["schema"] == "https" else http.client.HTTPConnection
        connection = cls(host, timeout=3)
        try:
            connection.request("GET", "/servlet?key=number=" + quote(number, safe=""))
            response = connection.getresponse()
            body = response.read(2048).lower()
            if not 200 <= response.status < 300 or b"error" in body or b"<html" in body:
                raise OSError(f"Telefon antwortet mit HTTP {response.status}; Action-URI-Freigabe prüfen.")
        finally:
            connection.close()

def event_url(cfg,event):
    scheme = "https" if cfg.get("cert") else "http"
    ident = "$csta_id" if cfg.get("profil") == "snom" else "$call_id"
    return f"{scheme}://{cfg['pc']}:18762/event/{cfg['token']}?ev={event}&id={ident}&n=$remote"

def event_tls(server, cfg):
    if cfg.get("cert") or cfg.get("key"):
        if not cfg.get("cert") or not cfg.get("key"):
            raise ValueError("Für HTTPS werden Zertifikat und privater Schlüssel benötigt.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cfg["cert"], cfg["key"], password=lambda: "")
        server.tls = context

def handler(cfg, calls, adapter, local=False, on_event=None):
    used = {}
    nonce_lock = threading.Lock()
    secret = cfg["lokal"].encode("ascii")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # URLs enthalten ein Token und ggf. eine Rufnummer.

        def reply(self, code, data=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            if getattr(self, "nonce", None):
                signature = hmac.digest(secret, b"reply|" + self.nonce.encode() + b"|" + data, "sha256")
                self.send_header("X-CTI-Proof", signature.hex())
            self.end_headers()
            if data:
                self.wfile.write(data)

        def auth(self, body=b""):
            nonce = self.headers.get("X-CTI-Nonce", "")
            signature = self.headers.get("X-CTI-Mac", "")
            if not re.fullmatch(r"[0-9]{10,11}-[0-9a-f]{32}", nonce) or not re.fullmatch(r"[0-9a-f]{64}", signature):
                return False
            stamp = int(nonce.split("-")[0])
            now = int(time.time())
            if abs(now - stamp) > 30:
                return False
            message = (self.command + "|" + self.path + "|" + nonce + "|").encode("ascii") + body
            if not hmac.compare_digest(hmac.digest(secret, message, "sha256").hex(), signature):
                return False
            with nonce_lock:
                for key in list(used):
                    if used[key] < now:
                        del used[key]
                if nonce in used or len(used) >= 2048:
                    return False
                used[nonce] = stamp + 30
            self.nonce = nonce
            return True

        def do_GET(self):
            u = urlsplit(self.path)
            if local:
                if u.path == "/calls" and self.auth():
                    self.reply(200, calls.snapshot())
                else:
                    self.reply(403)
                return
            if (self.client_address[0] != cfg["telefon"]
                    or not hmac.compare_digest(u.path.encode(), ("/event/"+cfg["token"]).encode())):
                self.reply(403)
                return
            try:
                query = parse_qs(u.query, max_num_fields=6)
                event, ident = query["ev"][0], query["id"][0]
                if event not in EVENTS.values() or not CALL_ID.fullmatch(ident):
                    raise ValueError()
                # Yealink may send '+' unescaped.
                raw = next((v[2:] for v in u.query.split("&") if v.startswith("n=")), "")
                from urllib.parse import unquote
                remote = unquote(raw).strip()
                uri = re.fullmatch(r"<?sips?:([^@;<>]+)@[^<>]+>?", remote, re.I)
                n = dial_number(uri.group(1) if uri else remote)
                calls.update(ident, event, n if NUMBER.fullmatch(n) else "")
            except (KeyError, ValueError):
                self.reply(400)
                return
            if on_event:
                on_event(event, bool(NUMBER.fullmatch(n)))
            elif sys.stdout is not None:
                print(time.strftime("%H:%M:%S"), cfg["nebenstelle"], event, flush=True)
            self.reply(204)

        def do_POST(self):
            if not local or self.path != "/dial":
                self.reply(403)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 80:
                    raise ValueError()
                body = self.rfile.read(size)
                if len(body) != size or not self.auth(body):
                    self.reply(403)
                    return
                n = dial_number(body.decode("ascii"))
                if not NUMBER.fullmatch(n):
                    raise ValueError()
            except (ValueError, UnicodeError):
                self.reply(400)
                return
            try:
                adapter.dial(n)
            except (OSError, http.client.HTTPException) as exc:
                if on_event:
                    on_event("wahlfehler", False)
                self.reply(502)
                return
            self.reply(204)
    return Handler

class Server(ThreadingHTTPServer):
    allow_reuse_address = False

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            if getattr(self, "tls", None):
                with self.tls.wrap_socket(request, server_side=True) as secure:
                    self.finish_request(secure, client_address)
            else:
                super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.slots.release()

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def verify_request(self, request, addr):
        return addr[0] == getattr(self, "allowed_ip", addr[0])

    def handle_error(self, request, client_address):
        # Keine URL oder Rufnummer in Tracebacks protokollieren.
        pass
    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(5)
        return conn, addr

def main():
    p = argparse.ArgumentParser()
    p.add_argument("modus", choices=["einrichten", "urls", "start", "wahltest"])
    p.add_argument("--pc", type=private_ip)
    p.add_argument("--telefon", type=private_ip)
    p.add_argument("--nebenstelle")
    p.add_argument("--nummer")
    p.add_argument("--schema", choices=["http","https"], default="https")
    args = p.parse_args()
    conf = ROOT / "adapter.json"
    if args.modus == "einrichten":
        if not args.pc or not args.telefon or args.pc == args.telefon or not re.fullmatch(r"[0-9]+", args.nebenstelle or ""):
            p.error("--pc, --telefon und --nebenstelle erforderlich")
        ROOT.mkdir(exist_ok=True)
        cfg = dict(pc=args.pc, telefon=args.telefon, nebenstelle=args.nebenstelle,
                   schema=args.schema, token=secrets.token_hex(24), lokal=secrets.token_hex(24))
        with conf.open("x", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    else:
        cfg = json.loads(conf.read_text(encoding="utf-8"))
    if args.modus in ("urls","einrichten"):
        for key,event in EVENTS.items():
            print(f"action_url.{key} = {event_url(cfg,event)}")
        return
    if cfg.get("zentral"):
        p.error("Für zentrale Placetel-Wahl CTI-Start.cmd öffnen.")
    a = Yealink(cfg)
    if args.modus == "wahltest":
        if not NUMBER.fullmatch(args.nummer or ""): p.error("Testziel als Ziffern oder +Ländervorwahl angeben")
        a.dial(args.nummer)
        print("Wählbefehl übermittelt. Zieltelefon prüfen.")
        return
    calls = Calls(cfg.get("nach_annahme", True))
    with Server((private_ip(cfg["pc"]),18762), handler(cfg,calls,a)) as lan, Server(("127.0.0.1",18763),handler(cfg,calls,a,True)) as ipc:
        lan.allowed_ip = cfg["telefon"]
        event_tls(lan,cfg)
        threading.Thread(target=ipc.serve_forever, daemon=True).start()
        print("CTI bereit für Nebenstelle",cfg["nebenstelle"],"– Ende mit Strg+C.",flush=True)
        try: lan.serve_forever()
        except KeyboardInterrupt: pass
        finally: ipc.shutdown()

if __name__ == "__main__":
    main()

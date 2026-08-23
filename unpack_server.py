import json
import mimetypes
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import unpack_feature

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))
SERVERSTATUS_URL = "https://serverstatus-tp1j.onrender.com"


class Handler(BaseHTTPRequestHandler):
    server_version = "Unpack"

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/unpack":
            return unpack_feature.handle_unpack(self)
        self.send_json(404, {"error": "Not found"})

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)
        if path == "/":
            candidate = PUBLIC / "unpack.html"
        elif path.startswith("/unpack/"):
            candidate = PUBLIC / path.lstrip("/")
        elif path == "/favicon.ico":
            candidate = PUBLIC / "favicon.svg"
        else:
            self.send_json(404, {"error": "Not found"})
            return
        candidate = candidate.resolve()
        if PUBLIC.resolve() not in candidate.parents and candidate != PUBLIC.resolve():
            self.send_json(404, {"error": "Not found"})
            return
        if not candidate.is_file():
            self.send_json(404, {"error": "Not found"})
            return
        mime = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        body = candidate.read_bytes()
        if candidate.name == "unpack.html":
            text = body.decode("utf-8", "replace")
            text = text.replace('href="/unpack.html"', 'href="/"')
            text = text.replace('href="/">ServerStatus', f'href="{SERVERSTATUS_URL}">ServerStatus')
            text = text.replace('class="rail-link" href="/"', f'class="rail-link" href="{SERVERSTATUS_URL}"')
            body = text.encode("utf-8")
        elif candidate.name == "app.js" and candidate.parent.name == "unpack":
            text = body.decode("utf-8", "replace")
            text = text.replace('href="/">Open ServerStatus', f'href="{SERVERSTATUS_URL}">Open ServerStatus')
            body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or mime == "application/javascript" else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Unpack listening on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

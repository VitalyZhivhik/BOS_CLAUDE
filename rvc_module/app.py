"""Веб-сервер RVC: отдаёт дашборд и отчёт о реализуемых уязвимостях."""

from __future__ import annotations

import os
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    from flask import Flask, jsonify, request, send_from_directory
except Exception:
    Flask = None
    jsonify = None
    request = None
    send_from_directory = None

from rvc.knowledge import Knowledge
from rvc.pipeline import build_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
REPORT_BASE_DIR = os.environ.get("RVC_BASE_DIR", "").strip() or os.path.join(BASE_DIR, "tools")
try:
    os.makedirs(os.path.join(REPORT_BASE_DIR, "data", "scan_history"), exist_ok=True)
    os.makedirs(os.path.join(REPORT_BASE_DIR, "history"), exist_ok=True)
except Exception:
    pass

_kb = Knowledge()
_cache: dict = {}

def _build_cached_report(refresh: bool) -> dict:
    if "report" not in _cache or refresh:
        _cache["report"] = build_report(REPORT_BASE_DIR, _kb)
    return _cache["report"]

def _run_simple_server(host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            u = urlparse(self.path)
            path = u.path
            qs = parse_qs(u.query or "")
            if path == "/" or path == "/index.html":
                p = os.path.join(WEB_DIR, "index.html")
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(data)
                except Exception:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write("index.html not found".encode("utf-8"))
                return

            if path == "/api/report":
                refresh = bool(qs.get("refresh"))
                report = _build_cached_report(refresh)
                payload = json.dumps(report, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload)
                return

            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("Not found".encode("utf-8"))

        def log_message(self, *args):
            return

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.serve_forever()

if Flask is not None:
    app = Flask(__name__, static_folder=None)

    @app.route("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.route("/api/report")
    def api_report():
        refresh = bool(request.args.get("refresh"))
        return jsonify(_build_cached_report(refresh))


if __name__ == "__main__":
    host = os.environ.get("RVC_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(os.environ.get("RVC_PORT", "5000"))
    except Exception:
        port = 5000
    if Flask is None:
        _run_simple_server(host, port)
    else:
        app.run(host=host, port=port, debug=False)

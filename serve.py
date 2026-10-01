"""Local dev/verification server.

Serves web/index.html statically and handles /health + /api/* by calling the
Lambda handler in-process. Lets the full demo be exercised before any AWS
deployment, with no AWS credentials.
"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agentfence.api import lambda_handler  # noqa: E402

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/api") or path == "/health":
            ev = {"httpMethod": "GET", "path": path, "body": None}
            r = lambda_handler(ev, None)
            return self._send(r["statusCode"], r["body"])
        if path in ("/", "/index.html", "/demo", "/home"):
            return self._send(200, open(os.path.join(WEB, "index.html"), encoding="utf-8").read(),
                              "text/html; charset=utf-8")
        self._send(404, json.dumps({"error": "NOT_FOUND"}))

    def do_POST(self):
        path = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        ev = {"httpMethod": "POST", "path": path, "body": body}
        r = lambda_handler(ev, None)
        self._send(r["statusCode"], r["body"])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8099"))
    print(f"AgentFence local: http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()

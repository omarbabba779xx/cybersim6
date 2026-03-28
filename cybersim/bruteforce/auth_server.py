"""
CyberSim6 - Fictitious Authentication Server
Local HTTP server with a login form for brute force testing.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from cybersim.core.logging_engine import CyberSimLogger


# Default credentials (fictitious - for testing only)
DEFAULT_CREDENTIALS = {
    "admin": "cybersim2026",
}

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head><title>CyberSim6 - Login (Fictitious)</title></head>
<body>
<h1>CyberSim6 Auth Server</h1>
<p style="color:red;">This is a FICTITIOUS server for educational testing only.</p>
<form method="POST" action="/login">
    <label>Username: <input name="username" type="text"></label><br><br>
    <label>Password: <input name="password" type="password"></label><br><br>
    <button type="submit">Login</button>
</form>
</body>
</html>
"""


class AuthHandler(BaseHTTPRequestHandler):
    """Handler for the fictitious authentication server."""

    credentials: dict = DEFAULT_CREDENTIALS
    logger: CyberSimLogger = None
    attempt_log: list = []
    lock = threading.Lock()
    lockout_tracker: dict = {}
    LOCKOUT_THRESHOLD = 10
    LOCKOUT_DURATION = 60

    def do_GET(self):
        if self.path == "/login" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LOGIN_HTML.encode())
        elif self.path == "/stats":
            self._send_stats()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = parse_qs(body)

        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        source_ip = self.client_address[0]

        # Check lockout
        with self.lock:
            lockout_info = self.lockout_tracker.get(source_ip, {})
            if lockout_info.get("locked_until", 0) > time.time():
                self._send_locked(username, source_ip)
                return

        # Validate credentials
        expected_pw = self.credentials.get(username)
        success = expected_pw is not None and expected_pw == password

        with self.lock:
            attempt = {
                "time": time.time(),
                "source": source_ip,
                "username": username,
                "success": success,
            }
            self.attempt_log.append(attempt)

            if not success:
                tracker = self.lockout_tracker.setdefault(source_ip, {"failures": 0})
                tracker["failures"] = tracker.get("failures", 0) + 1
                if tracker["failures"] >= self.LOCKOUT_THRESHOLD:
                    tracker["locked_until"] = time.time() + self.LOCKOUT_DURATION
                    tracker["failures"] = 0
            else:
                self.lockout_tracker.pop(source_ip, None)

        if self.logger:
            self.logger.log_event(
                module="bruteforce_auth_server",
                module_type="target",
                event_type="login_attempt",
                details={
                    "source": source_ip,
                    "username": username,
                    "success": success,
                    "message": f"Login {'SUCCESS' if success else 'FAILED'} for '{username}' from {source_ip}",
                    "status": "warning" if success else "info",
                },
            )

        if success:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "Login successful"}).encode())
        else:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "failure", "message": "Invalid credentials"}).encode())

    def _send_locked(self, username, source_ip):
        if self.logger:
            self.logger.log_event(
                module="bruteforce_auth_server",
                module_type="target",
                event_type="account_locked",
                details={
                    "source": source_ip,
                    "username": username,
                    "message": f"Account locked for {source_ip} (too many failures)",
                    "status": "warning",
                },
            )
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "locked", "message": "Too many failed attempts"}).encode())

    def _send_stats(self):
        with self.lock:
            total = len(self.attempt_log)
            successes = sum(1 for a in self.attempt_log if a["success"])
            failures = total - successes
        stats = {"total_attempts": total, "successes": successes, "failures": failures}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(stats).encode())

    def log_message(self, format, *args):
        pass


class AuthServer:
    """Wrapper to run the auth server in a thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9090,
                 logger: CyberSimLogger = None, credentials: dict = None):
        self.host = host
        self.port = port
        self.logger = logger
        self.credentials = credentials or DEFAULT_CREDENTIALS
        self.server = None
        self._thread = None

    def start(self):
        AuthHandler.logger = self.logger
        AuthHandler.credentials = self.credentials
        AuthHandler.attempt_log = []
        AuthHandler.lockout_tracker = {}
        self.server = HTTPServer((self.host, self.port), AuthHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] Auth server started on http://{self.host}:{self.port}/login")

    def stop(self):
        if self.server:
            self.server.shutdown()
            total = len(AuthHandler.attempt_log)
            print(f"[-] Auth server stopped. Total login attempts: {total}")

    def get_attempt_log(self):
        return AuthHandler.attempt_log

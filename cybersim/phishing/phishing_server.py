"""
CyberSim6 - Phishing Simulation Server
Serves fake login pages and captures credentials for analysis.
Simulates a GoPhish-like campaign in local-only mode.
EDUCATIONAL PURPOSE ONLY.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs

from cybersim.core.logging_engine import CyberSimLogger


PHISHING_TEMPLATES = {
    "corporate_login": {
        "name": "Corporate Portal Login",
        "html": """<!DOCTYPE html>
<html>
<head>
    <title>Corporate Portal - Secure Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f0f2f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .login-box {{ background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }}
        h2 {{ color: #1a73e8; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #1a73e8; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        .logo {{ text-align: center; font-size: 24px; margin-bottom: 20px; }}
        .warning {{ display: none; }}
    </style>
</head>
<body>
<div class="login-box">
    <div class="logo">&#128274; Corporate Portal</div>
    <h2>Sign In</h2>
    <p>Please verify your identity to continue.</p>
    <form method="POST" action="/capture">
        <input name="email" type="email" placeholder="Email address" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Sign In</button>
    </form>
    <p style="font-size:11px;color:#999;text-align:center;">Protected by CyberSec &copy; 2026</p>
    <p class="warning" style="color:red;font-size:10px;">
        [SIMULATION] This is a CyberSim6 phishing simulation page.
    </p>
</div>
</body>
</html>""",
    },
    "password_reset": {
        "name": "Password Reset",
        "html": """<!DOCTYPE html>
<html>
<head>
    <title>Security Alert - Password Reset Required</title>
    <style>
        body {{ font-family: Arial; background: #fff3cd; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .alert-box {{ background: white; padding: 40px; border-radius: 8px;
                     border-left: 5px solid #dc3545; width: 400px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        input {{ width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; background: #dc3545; color: white;
                 border: none; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
<div class="alert-box">
    <h2>&#9888; Security Alert</h2>
    <p>Unusual activity detected on your account. Please verify your identity immediately.</p>
    <form method="POST" action="/capture">
        <input name="email" type="email" placeholder="Your email" required>
        <input name="password" type="password" placeholder="Current password" required>
        <input name="new_password" type="password" placeholder="New password" required>
        <button type="submit">Reset Password</button>
    </form>
    <p style="font-size:10px;color:#999;">If you did not request this, contact IT support.</p>
</div>
</body>
</html>""",
    },
    "office365": {
        "name": "Office 365 Login",
        "html": """<!DOCTYPE html>
<html>
<head>
    <title>Sign in to your account</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial; background: #f2f2f2; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .ms-box {{ background: white; padding: 44px; width: 440px;
                  box-shadow: 0 2px 6px rgba(0,0,0,0.2); }}
        h2 {{ font-weight: 600; font-size: 24px; }}
        input {{ width: 100%; padding: 8px; margin: 12px 0; border: none;
                border-bottom: 1px solid #666; font-size: 15px; box-sizing: border-box; }}
        button {{ background: #0067b8; color: white; border: none; padding: 10px 20px;
                 cursor: pointer; font-size: 15px; margin-top: 15px; }}
    </style>
</head>
<body>
<div class="ms-box">
    <img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>" alt="" width="108">
    <h2>Sign in</h2>
    <form method="POST" action="/capture">
        <input name="email" type="email" placeholder="Email, phone, or Skype" required>
        <input name="password" type="password" placeholder="Password" required>
        <br>
        <button type="submit">Sign in</button>
    </form>
    <p style="font-size:12px;margin-top:20px;">
        <a href="#">Can't access your account?</a>
    </p>
</div>
</body>
</html>""",
    },
}

CAPTURE_RESPONSE = """<!DOCTYPE html>
<html><head><title>CyberSim6 - Phishing Simulation</title></head>
<body style="font-family:Arial;text-align:center;padding:50px;">
<h1 style="color:#dc3545;">&#9888; You Have Been Phished!</h1>
<h2>This was a CyberSim6 Phishing Simulation</h2>
<p>This page was a simulated phishing attack for <b>educational purposes only</b>.</p>
<p>In a real attack, your credentials would now be in the attacker's hands.</p>
<hr>
<h3>What to look for:</h3>
<ul style="text-align:left;max-width:500px;margin:0 auto;">
<li>Check the URL carefully - is it the real domain?</li>
<li>Look for HTTPS and valid certificates</li>
<li>Be suspicious of urgent security alerts</li>
<li>Never enter credentials from email links</li>
<li>Use multi-factor authentication (MFA)</li>
<li>Report suspicious emails to your IT team</li>
</ul>
<hr>
<p style="color:#999;font-size:12px;">CyberSim6 - EMSI Tanger 4IIR - Educational Purpose Only</p>
</body></html>"""


class PhishingHandler(BaseHTTPRequestHandler):
    """Handles phishing page serving and credential capture."""

    logger: CyberSimLogger | None = None
    template: str = "corporate_login"
    captured_credentials: list[dict[str, Any]] = []
    lock = threading.Lock()

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/login"):
            template_data = PHISHING_TEMPLATES.get(self.template, PHISHING_TEMPLATES["corporate_login"])
            self._send_html(200, template_data["html"])
        elif self.path == "/stats":
            self._send_stats()
        elif self.path == "/reveal":
            self._send_html(200, CAPTURE_RESPONSE)
        else:
            self._send_html(404, "<h1>404</h1>")

    def do_POST(self):
        if self.path == "/capture":
            self._handle_capture()
        else:
            self._send_html(404, "<h1>404</h1>")

    def _handle_capture(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = parse_qs(body)

        email = params.get("email", [""])[0]
        password = params.get("password", [""])[0]
        source_ip = self.client_address[0]

        credential = {
            "timestamp": time.time(),
            "source_ip": source_ip,
            "email": email,
            "password_length": len(password),
            "template": self.template,
            "user_agent": self.headers.get("User-Agent", ""),
        }

        with self.lock:
            self.captured_credentials.append(credential)

        if self.logger:
            self.logger.log_event(
                module="phishing_server",
                module_type="attack",
                event_type="credentials_captured",
                details={
                    "source": source_ip,
                    "email": email,
                    "password_length": len(password),
                    "template": self.template,
                    "message": f"Credentials captured: {email} (pw length: {len(password)}) via {self.template}",
                    "status": "warning",
                },
            )

        # Show the awareness page
        self._send_html(200, CAPTURE_RESPONSE)

    def _send_stats(self):
        with self.lock:
            stats = {
                "total_captures": len(self.captured_credentials),
                "credentials": [
                    {"email": c["email"], "password_length": c["password_length"],
                     "source_ip": c["source_ip"], "template": c["template"]}
                    for c in self.captured_credentials
                ],
            }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(stats, indent=2).encode())

    def _send_html(self, code, html_content):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode())

    def log_message(self, format, *args):
        pass


class PhishingServer:
    """Manages the phishing simulation server."""

    def __init__(self, host="127.0.0.1", port=8083, template="corporate_login",
                 logger=None):
        self.host = host
        self.port = port
        self.template = template
        self.logger = logger
        self.server = None
        self._thread = None

    def start(self):
        PhishingHandler.logger = self.logger
        PhishingHandler.template = self.template
        PhishingHandler.captured_credentials = []
        self.server = HTTPServer((self.host, self.port), PhishingHandler)
        self.host, self.port = self.server.server_address[:2]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        template_name = PHISHING_TEMPLATES.get(self.template, {}).get("name", self.template)
        print(f"[+] Phishing server started on http://{self.host}:{self.port}")
        print(f"    Template: {template_name}")
        print(f"    Available templates: {', '.join(PHISHING_TEMPLATES.keys())}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self._thread:
                self._thread.join(timeout=2)
        captured = len(PhishingHandler.captured_credentials)
        print(f"[-] Phishing server stopped. Credentials captured: {captured}")
        self.server = None
        self._thread = None

    def get_captured(self):
        return PhishingHandler.captured_credentials

    @staticmethod
    def list_templates():
        return {k: v["name"] for k, v in PHISHING_TEMPLATES.items()}

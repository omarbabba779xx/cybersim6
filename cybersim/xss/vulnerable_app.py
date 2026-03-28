"""
CyberSim6 - XSS Vulnerable Web Application
Demonstrates Reflected, Stored, and DOM-based XSS vulnerabilities.
EDUCATIONAL PURPOSE ONLY.
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from cybersim.core.logging_engine import CyberSimLogger

# In-memory storage for stored XSS
stored_comments = []

INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>CyberSim6 - XSS Vulnerable App</title></head>
<body>
<h1>CyberSim6 - XSS Testing Platform</h1>
<p style="color:red;"><b>WARNING: Intentionally vulnerable. EDUCATIONAL USE ONLY.</b></p>
<hr>

<h2>1. Reflected XSS - Search</h2>
<form method="GET" action="/search">
    <input name="q" placeholder="Search..." size="40">
    <button type="submit">Search</button>
</form>

<h2>2. Stored XSS - Guestbook</h2>
<form method="POST" action="/comment">
    <input name="name" placeholder="Your name" size="20">
    <input name="message" placeholder="Your message" size="40">
    <button type="submit">Post</button>
</form>
<p><a href="/guestbook">View Guestbook</a></p>

<h2>3. DOM-based XSS</h2>
<p>Try: <a href="/dom#&lt;img src=x onerror=alert('XSS')&gt;">/dom#payload</a></p>

<h2>4. Reflected XSS - Error Page</h2>
<form method="GET" action="/error">
    <input name="msg" placeholder="Error message" size="40">
    <button type="submit">Show Error</button>
</form>

<hr>
<p><small>Endpoints: /search?q=, /comment (POST), /guestbook, /dom, /error?msg=</small></p>
</body>
</html>
"""

DOM_XSS_HTML = """<!DOCTYPE html>
<html>
<head><title>CyberSim6 - DOM XSS</title></head>
<body>
<h1>DOM-based XSS Demo</h1>
<p style="color:red;"><b>WARNING: Intentionally vulnerable. EDUCATIONAL USE ONLY.</b></p>
<div id="output"></div>
<script>
    // VULNERABLE: Directly writing hash fragment to DOM without sanitization
    var hash = decodeURIComponent(window.location.hash.substring(1));
    if (hash) {
        document.getElementById('output').innerHTML = '<h2>Welcome: ' + hash + '</h2>';
    } else {
        document.getElementById('output').innerHTML = '<p>No input. Add #yourname to the URL.</p>';
    }
</script>
<p><a href="/">Back</a></p>
</body>
</html>
"""


class XSSVulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional XSS vulnerabilities."""

    logger: CyberSimLogger = None
    lock = threading.Lock()
    request_log = []

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/" or parsed.path == "/index":
            self._send_html(200, INDEX_HTML)
        elif parsed.path == "/search":
            self._handle_search(params)
        elif parsed.path == "/guestbook":
            self._handle_guestbook()
        elif parsed.path == "/dom":
            self._send_html(200, DOM_XSS_HTML)
        elif parsed.path == "/error":
            self._handle_error(params)
        elif parsed.path == "/api/comments":
            self._handle_api_comments()
        else:
            self._send_html(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = parse_qs(body)

        if parsed.path == "/comment":
            self._handle_add_comment(params)
        else:
            self._send_html(404, "<h1>404</h1>")

    def _handle_search(self, params):
        """VULNERABLE: Reflected XSS - user input reflected without sanitization."""
        query = params.get("q", [""])[0]
        self._log_request("reflected_xss", f"/search?q={query}")

        # INTENTIONALLY VULNERABLE - no escaping
        html = f"""<h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found for "{query}".</p>
        <p><a href="/">Back</a></p>"""
        self._send_html(200, html)

    def _handle_guestbook(self):
        """VULNERABLE: Stored XSS - displays stored comments without sanitization."""
        self._log_request("stored_xss_display", "/guestbook")

        html = "<h1>Guestbook</h1>"
        with self.lock:
            comments_snapshot = list(stored_comments)
        if comments_snapshot:
            for comment in comments_snapshot:
                # INTENTIONALLY VULNERABLE - no escaping
                html += "<div style='border:1px solid #ccc;padding:10px;margin:5px;'>"
                html += f"<b>{comment['name']}</b>: {comment['message']}"
                html += "</div>"
        else:
            html += "<p>No comments yet.</p>"
        html += '<p><a href="/">Back to post a comment</a></p>'
        self._send_html(200, html)

    def _handle_add_comment(self, params):
        """VULNERABLE: Stores user input without sanitization."""
        name = params.get("name", ["Anonymous"])[0]
        message = params.get("message", [""])[0]
        self._log_request("stored_xss_inject", f"/comment name={name} msg={message[:50]}")

        with self.lock:
            stored_comments.append({"name": name, "message": message})

        if self.logger:
            self.logger.log_event(
                module="xss_vulnerable_app",
                module_type="target",
                event_type="comment_stored",
                details={
                    "source": self.client_address[0],
                    "name": name,
                    "comment_text": message[:100],
                    "message": f"Comment stored from {name}: {message[:50]}",
                    "status": "info",
                },
            )

        self.send_response(302)
        self.send_header("Location", "/guestbook")
        self.end_headers()

    def _handle_error(self, params):
        """VULNERABLE: Reflected XSS in error message."""
        msg = params.get("msg", ["Unknown error"])[0]
        self._log_request("reflected_xss_error", f"/error?msg={msg}")

        # INTENTIONALLY VULNERABLE
        html = f"""<h1>Error</h1>
        <div style="color:red;border:1px solid red;padding:10px;">
            <b>Error:</b> {msg}
        </div>
        <p><a href="/">Back</a></p>"""
        self._send_html(200, html)

    def _handle_api_comments(self):
        """JSON API for comments."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"comments": stored_comments}).encode())

    def _log_request(self, xss_type, details):
        with self.lock:
            self.request_log.append({"type": xss_type, "details": details})
        if self.logger:
            self.logger.log_event(
                module="xss_vulnerable_app",
                module_type="target",
                event_type="xss_endpoint_hit",
                details={
                    "source": self.client_address[0],
                    "xss_type": xss_type,
                    "details": details,
                    "message": f"XSS endpoint hit: {xss_type} - {details[:80]}",
                    "status": "info",
                },
            )

    def _send_html(self, code, html):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass


class XSSVulnerableServer:
    """Wrapper to run the XSS vulnerable server."""

    def __init__(self, host="127.0.0.1", port=8082, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
        self.server = None
        self._thread = None

    def start(self):
        global stored_comments
        stored_comments = []
        XSSVulnerableHandler.logger = self.logger
        XSSVulnerableHandler.request_log = []
        self.server = HTTPServer((self.host, self.port), XSSVulnerableHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] XSS vulnerable app started on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
        print(f"[-] XSS vulnerable app stopped. Requests: {len(XSSVulnerableHandler.request_log)}")

    def get_request_log(self):
        return XSSVulnerableHandler.request_log

"""
CyberSim6 - Vulnerable SQL Server
A deliberately vulnerable web application with SQL injection flaws.
Uses SQLite for a self-contained, local-only test environment.
EDUCATIONAL PURPOSE ONLY.
"""

import json
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger

DB_PATH = ":memory:"


def init_database(conn):
    """Create and populate the vulnerable test database."""
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS secret_data (
            id INTEGER PRIMARY KEY,
            flag TEXT NOT NULL
        );

        INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin_s3cr3t_pw', 'admin@cybersim6.local', 'admin');
        INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice123', 'alice@cybersim6.local', 'user');
        INSERT OR IGNORE INTO users VALUES (3, 'bob', 'bob_password', 'bob@cybersim6.local', 'user');
        INSERT OR IGNORE INTO users VALUES (4, 'charlie', 'charli3!', 'charlie@cybersim6.local', 'moderator');

        INSERT OR IGNORE INTO products VALUES (1, 'Firewall Pro', 299.99, 'Enterprise firewall solution');
        INSERT OR IGNORE INTO products VALUES (2, 'AV Shield', 49.99, 'Antivirus protection');
        INSERT OR IGNORE INTO products VALUES (3, 'VPN Tunnel', 9.99, 'Monthly VPN subscription');

        INSERT OR IGNORE INTO secret_data VALUES (1, 'FLAG{cybersim6_sqli_success}');
        INSERT OR IGNORE INTO secret_data VALUES (2, 'FLAG{union_based_injection}');
        INSERT OR IGNORE INTO secret_data VALUES (3, 'FLAG{blind_sqli_master}');
    """)
    conn.commit()


INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>CyberSim6 - Vulnerable Shop (EDUCATIONAL)</title></head>
<body>
<h1>CyberSim6 Vulnerable Web App</h1>
<p style="color:red;"><b>WARNING: This app is intentionally vulnerable. EDUCATIONAL USE ONLY.</b></p>
<hr>
<h2>Product Search</h2>
<form method="GET" action="/search">
    <input name="q" placeholder="Search products..." size="40">
    <button type="submit">Search</button>
</form>
<h2>User Login</h2>
<form method="POST" action="/login">
    <input name="username" placeholder="Username"><br><br>
    <input name="password" type="password" placeholder="Password"><br><br>
    <button type="submit">Login</button>
</form>
<h2>User Profile</h2>
<form method="GET" action="/user">
    <input name="id" placeholder="User ID" size="10">
    <button type="submit">View Profile</button>
</form>
<hr>
<p><small>Endpoints: /search?q=, /login (POST), /user?id=, /api/users?id=</small></p>
</body>
</html>
"""


class VulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional SQL injection vulnerabilities."""

    db_conn: sqlite3.Connection = None
    logger: CyberSimLogger = None
    lock = threading.Lock()
    query_log = []

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/" or parsed.path == "/index":
            self._send_html(200, INDEX_HTML)

        elif parsed.path == "/search":
            self._handle_search(params)

        elif parsed.path == "/user":
            self._handle_user_profile(params)

        elif parsed.path == "/api/users":
            self._handle_api_users(params)

        else:
            self._send_html(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        params = parse_qs(body)

        if parsed.path == "/login":
            self._handle_login(params)
        else:
            self._send_html(404, "<h1>404 Not Found</h1>")

    def _handle_search(self, params):
        """VULNERABLE: Direct string concatenation in SQL query."""
        query = params.get("q", [""])[0]
        # INTENTIONALLY VULNERABLE - string concatenation
        sql = f"SELECT name, price, description FROM products WHERE name LIKE '%{query}%'"
        self._log_query(sql, "search")

        try:
            with self.lock:
                cursor = self.db_conn.cursor()
                cursor.execute(sql)
                rows = cursor.fetchall()

            html = f"<h2>Search Results for: {query}</h2>"
            if rows:
                html += "<table border='1'><tr><th>Name</th><th>Price</th><th>Description</th></tr>"
                for row in rows:
                    html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td></tr>"
                html += "</table>"
            else:
                html += "<p>No results found.</p>"
            html += f"<p><small>SQL: {sql}</small></p>"
            html += '<p><a href="/">Back</a></p>'
            self._send_html(200, html)
        except sqlite3.Error as e:
            error_html = f"<h2>Database Error</h2><pre>{e}</pre><p>Query: {sql}</p>"
            error_html += '<p><a href="/">Back</a></p>'
            self._send_html(500, error_html)

    def _handle_login(self, params):
        """VULNERABLE: SQL injection in authentication."""
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        # INTENTIONALLY VULNERABLE
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        self._log_query(sql, "login")

        try:
            with self.lock:
                cursor = self.db_conn.cursor()
                cursor.execute(sql)
                user = cursor.fetchone()

            if user:
                html = f"<h2>Login Successful!</h2>"
                html += f"<p>Welcome, {user[1]}! Role: {user[4]}</p>"
                html += f"<p>Email: {user[3]}</p>"
            else:
                html = "<h2>Login Failed</h2><p>Invalid credentials.</p>"
            html += f"<p><small>SQL: {sql}</small></p>"
            html += '<p><a href="/">Back</a></p>'
            self._send_html(200, html)
        except sqlite3.Error as e:
            self._send_html(500, f"<h2>Error</h2><pre>{e}</pre>")

    def _handle_user_profile(self, params):
        """VULNERABLE: Numeric injection without quotes."""
        user_id = params.get("id", ["1"])[0]
        # INTENTIONALLY VULNERABLE
        sql = f"SELECT id, username, email, role FROM users WHERE id={user_id}"
        self._log_query(sql, "user_profile")

        try:
            with self.lock:
                cursor = self.db_conn.cursor()
                cursor.execute(sql)
                rows = cursor.fetchall()

            html = "<h2>User Profile</h2>"
            if rows:
                for row in rows:
                    html += f"<p>ID: {row[0]}, Username: {row[1]}, Email: {row[2]}, Role: {row[3]}</p>"
            else:
                html += "<p>User not found.</p>"
            html += f"<p><small>SQL: {sql}</small></p>"
            html += '<p><a href="/">Back</a></p>'
            self._send_html(200, html)
        except sqlite3.Error as e:
            self._send_html(500, f"<h2>Error</h2><pre>{e}</pre>")

    def _handle_api_users(self, params):
        """VULNERABLE: JSON API with SQL injection."""
        user_id = params.get("id", ["1"])[0]
        sql = f"SELECT id, username, email, role FROM users WHERE id={user_id}"
        self._log_query(sql, "api_users")

        try:
            with self.lock:
                cursor = self.db_conn.cursor()
                cursor.execute(sql)
                rows = cursor.fetchall()

            result = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": result, "query": sql}).encode())
        except sqlite3.Error as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e), "query": sql}).encode())

    def _log_query(self, sql, endpoint):
        with self.lock:
            self.query_log.append({"sql": sql, "endpoint": endpoint})
        if self.logger:
            self.logger.log_event(
                module="sqli_vulnerable_server",
                module_type="target",
                event_type="sql_query_executed",
                details={
                    "source": self.client_address[0],
                    "endpoint": endpoint,
                    "sql": sql,
                    "message": f"SQL executed on /{endpoint}: {sql[:100]}",
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


class VulnerableSQLServer:
    """Wrapper to run the vulnerable SQL server in a thread."""

    def __init__(self, host="127.0.0.1", port=8081, logger=None):
        self.host = host
        self.port = port
        self.logger = logger
        self.server = None
        self._thread = None
        self._conn = None

    def start(self):
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        init_database(self._conn)
        VulnerableHandler.db_conn = self._conn
        VulnerableHandler.logger = self.logger
        VulnerableHandler.query_log = []
        self.server = HTTPServer((self.host, self.port), VulnerableHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] Vulnerable SQL server started on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
        if self._conn:
            self._conn.close()
        print(f"[-] Vulnerable SQL server stopped. Queries logged: {len(VulnerableHandler.query_log)}")

    def get_query_log(self):
        return VulnerableHandler.query_log

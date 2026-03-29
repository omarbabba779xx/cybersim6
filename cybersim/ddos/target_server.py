"""
CyberSim6 - DDoS Target Server
Local HTTP server that serves as a target for DDoS simulations.
Logs all incoming requests for analysis.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import cast

from cybersim.core.logging_engine import CyberSimLogger


class TargetHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs every request."""

    logger: CyberSimLogger | None = None
    request_count = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            TargetHandler.request_count += 1
            count = TargetHandler.request_count

        if self.logger:
            server_host, server_port = cast(tuple[str, int], self.server.server_address)
            self.logger.log_event(
                module="ddos_target",
                module_type="target",
                event_type="request_received",
                details={
                    "source": self.client_address[0],
                    "target": f"{server_host}:{server_port}",
                    "method": "GET",
                    "path": self.path,
                    "request_number": count,
                    "message": f"Request #{count} from {self.client_address[0]}",
                    "status": "info",
                },
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>CyberSim6 Target Server</h1>"
            b"<p>This is a local target for DDoS simulation.</p>"
            b"</body></html>"
        )

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        """Suppress default stderr logging."""
        pass


class TargetServer:
    """Wrapper to run the target HTTP server in a thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 logger: CyberSimLogger | None = None):
        self.host = host
        self.port = port
        self.logger = logger
        self.server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self):
        """Start the server in a background thread."""
        TargetHandler.logger = self.logger
        TargetHandler.request_count = 0
        server = HTTPServer((self.host, self.port), TargetHandler)
        self.server = server
        server_host, server_port = cast(tuple[str, int], server.server_address)
        self.host, self.port = server_host, server_port
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] Target server started on http://{self.host}:{self.port}")

    def stop(self):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self._thread:
                self._thread.join(timeout=2)
            print(f"[-] Target server stopped. Total requests: {TargetHandler.request_count}")
            self.server = None
            self._thread = None

    def get_request_count(self):
        return TargetHandler.request_count

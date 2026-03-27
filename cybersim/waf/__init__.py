"""
CyberSim6 - Web Application Firewall (WAF) Module
Reverse-proxy firewall that inspects HTTP traffic for attack patterns.
"""

from cybersim.waf.firewall import (
    WAFAction,
    WAFResult,
    WAFRule,
    WAFSeverity,
    WebApplicationFirewall,
)

__all__ = [
    "WAFAction",
    "WAFResult",
    "WAFRule",
    "WAFSeverity",
    "WebApplicationFirewall",
]

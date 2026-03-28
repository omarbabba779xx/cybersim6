"""
CyberSim6 - Phishing Campaign Module
Simulates sending phishing emails and tracking results.
EDUCATIONAL PURPOSE ONLY - No real emails are sent.
"""

import time
import requests as http_requests

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_url_localhost


# Simulated target list (all fictional)
SIMULATED_TARGETS = [
    {"name": "Alice Dupont", "email": "alice.dupont@cybersim6.local", "department": "Engineering"},
    {"name": "Bob Martin", "email": "bob.martin@cybersim6.local", "department": "Marketing"},
    {"name": "Charlie Nouri", "email": "charlie.nouri@cybersim6.local", "department": "Sales"},
    {"name": "Diana Roux", "email": "diana.roux@cybersim6.local", "department": "HR"},
    {"name": "Eve Tazi", "email": "eve.tazi@cybersim6.local", "department": "Finance"},
]

PHISHING_EMAILS = {
    "corporate_login": {
        "subject": "Action Required: Verify Your Corporate Account",
        "body": """Dear {name},

We have detected unusual activity on your corporate account.
Please verify your identity by clicking the link below:

http://{phishing_url}/login

This is an automated security alert. Please respond within 24 hours.

Best regards,
IT Security Team""",
    },
    "password_reset": {
        "subject": "URGENT: Password Reset Required",
        "body": """Dear {name},

Your account password will expire in 24 hours.
Please reset your password immediately:

http://{phishing_url}/login

Failure to reset may result in account lockout.

IT Support Team""",
    },
    "office365": {
        "subject": "You have 3 unread messages",
        "body": """Dear {name},

You have 3 unread messages in your inbox.
Sign in to view them:

http://{phishing_url}/login

Microsoft Office 365 Team""",
    },
}


class PhishingCampaign(BaseModule):
    """Simulates a phishing email campaign (no real emails sent)."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "phishing_campaign"

    def _validate_safety(self):
        pass  # Campaign simulation - no network targets needed

    def run(self, template: str = "corporate_login", phishing_url: str = None,
            targets: list = None, **kwargs):
        """
        Simulate a phishing campaign.

        Args:
            template: Email template to use
            phishing_url: URL of the phishing server
            targets: List of target dicts (uses defaults if None)
        """
        phishing_url = phishing_url or "127.0.0.1:8083"
        validate_url_localhost(f"http://{phishing_url}")
        targets = targets or SIMULATED_TARGETS
        email_template = PHISHING_EMAILS.get(template, PHISHING_EMAILS["corporate_login"])

        self._running = True
        self.log_event("campaign_started", {
            "message": f"Phishing campaign started: '{email_template['subject']}' to {len(targets)} targets",
            "template": template,
            "target_count": len(targets),
            "status": "warning",
        })

        sent = 0
        for target in targets:
            if not self._running:
                break

            email_body = email_template["body"].format(
                name=target["name"],
                phishing_url=phishing_url,
            )

            # Simulate sending (no real email)
            sent += 1
            self.log_event("email_sent", {
                "message": f"[SIMULATED] Email sent to {target['email']} ({target['department']})",
                "recipient": target["email"],
                "department": target["department"],
                "subject": email_template["subject"],
                "preview": email_body[:120],
                "status": "info",
            })
            time.sleep(0.2)

        self._running = False
        self.log_event("campaign_completed", {
            "message": f"Campaign complete: {sent} simulated emails sent.",
            "emails_sent": sent,
            "status": "info",
        })

        # Check if phishing server has captured anything
        try:
            resp = http_requests.get(f"http://{phishing_url}/stats", timeout=3)
            if resp.status_code == 200:
                stats = resp.json()
                self.log_event("campaign_results", {
                    "message": f"Phishing results: {stats['total_captures']} credentials captured",
                    "captures": stats["total_captures"],
                    "status": "info",
                })
        except http_requests.RequestException as exc:
            self.log_event("campaign_results_unavailable", {
                "message": f"Phishing server stats unavailable: {exc}",
                "status": "info",
            })
        except ValueError as exc:
            self.log_event("campaign_results_unavailable", {
                "message": f"Phishing server returned invalid stats JSON: {exc}",
                "status": "warning",
            })

        return {"emails_sent": sent, "template": template}

    def stop(self):
        self._running = False

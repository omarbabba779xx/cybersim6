"""Tests for Phishing module (detection)."""

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.phishing.detection import PhishingDetector


class TestPhishingDetector:
    def setup_method(self):
        self.logger = CyberSimLogger(session_id="test_phish")
        self.detector = PhishingDetector(config={}, logger=self.logger)

    def test_clean_email(self):
        result = self.detector.analyze_email(
            subject="Weekly team meeting",
            body="Hi team, the meeting is at 3pm today.",
            sender="manager@cybersim6.local",
        )
        assert result["risk_level"] == "LOW"
        assert result["risk_score"] < 30

    def test_urgency_keywords_detected(self):
        result = self.detector.analyze_email(
            subject="URGENT: Action Required",
            body="Your account will be suspended immediately. Verify your identity now.",
            sender="support@suspicious.tk",
        )
        assert result["risk_score"] > 0
        has_urgency = any(f["type"] == "urgency" for f in result["findings"])
        assert has_urgency

    def test_suspicious_url_detected(self):
        result = self.detector.analyze_email(
            subject="Verify your account",
            body="Click http://192.168.1.100/login to verify.",
            sender="it@company.com",
            url="http://192.168.1.100/login",
        )
        has_url = any(f["type"] == "suspicious_url" for f in result["findings"])
        assert has_url

    def test_domain_mismatch_detected(self):
        result = self.detector.analyze_email(
            subject="Login required",
            body="Sign in at the link below.",
            sender="admin@company.com",
            url="http://evil.com/login",
        )
        has_mismatch = any(f["type"] == "domain_mismatch" for f in result["findings"])
        assert has_mismatch

    def test_insecure_login_detected(self):
        result = self.detector.analyze_email(
            subject="Verify",
            body="Click to verify",
            sender="a@b.com",
            url="http://example.com/login",
        )
        has_insecure = any(f["type"] == "insecure_login" for f in result["findings"])
        assert has_insecure

    def test_high_risk_phishing(self):
        result = self.detector.analyze_email(
            subject="URGENT: Your account will expire in 24 hours",
            body="Verify your identity immediately by clicking http://192.168.1.1/login. "
                 "Enter your password to confirm. Failure to respond within 24 hours "
                 "will result in account suspension.",
            sender="security@suspicious-domain.tk",
            url="http://192.168.1.1/login",
        )
        assert result["risk_level"] == "HIGH"
        assert result["risk_score"] >= 60

    def test_credential_request_detected(self):
        result = self.detector.analyze_email(
            subject="Verify account",
            body="Please click the link http://evil.com and enter your password to sign in.",
            sender="a@b.com",
            url="http://evil.com/login",
        )
        has_cred = any(f["type"] == "credential_request" for f in result["findings"])
        assert has_cred

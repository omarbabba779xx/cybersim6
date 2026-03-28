"""Tests for phishing campaign execution."""

from __future__ import annotations

import cybersim.phishing.campaign as campaign_module


def test_campaign_logs_stats_results(logger, monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"total_captures": 3}

    monkeypatch.setattr(campaign_module.time, "sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(campaign_module.http_requests, "get", lambda *_args, **_kwargs: FakeResponse())

    campaign = campaign_module.PhishingCampaign(config={}, logger=logger)
    result = campaign.run(
        template="corporate_login",
        phishing_url="127.0.0.1:8083",
        targets=[{"name": "Alice", "email": "alice@cybersim6.local", "department": "Engineering"}],
    )

    assert result["emails_sent"] == 1
    result_events = logger.get_events(module="phishing_campaign", event_type="campaign_results")
    assert result_events
    assert result_events[-1]["details"]["captures"] == 3


def test_campaign_logs_when_stats_are_unavailable(logger, monkeypatch):
    monkeypatch.setattr(campaign_module.time, "sleep", lambda *_args, **_kwargs: None)

    def raise_request_error(*_args, **_kwargs):
        raise campaign_module.http_requests.RequestException("stats endpoint offline")

    monkeypatch.setattr(campaign_module.http_requests, "get", raise_request_error)

    campaign = campaign_module.PhishingCampaign(config={}, logger=logger)
    result = campaign.run(
        template="corporate_login",
        phishing_url="127.0.0.1:8083",
        targets=[{"name": "Bob", "email": "bob@cybersim6.local", "department": "Finance"}],
    )

    assert result["emails_sent"] == 1
    unavailable_events = logger.get_events(
        module="phishing_campaign",
        event_type="campaign_results_unavailable",
    )
    assert unavailable_events
    assert "stats endpoint offline" in unavailable_events[-1]["details"]["message"]

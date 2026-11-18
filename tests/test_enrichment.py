import pytest
import requests

import enrichment
import function_app
from enrichment import clean_ips, validate_alert


# Test that a valid alert passes validation
def test_validate_alert():
    alert = {
        "alert_id": "a-7f3c91",
        "title": "Suspicious sign-in",
        "severity": "medium",
        "entities": {"ips": ["185.220.101.4"]},
    }

    assert validate_alert(alert) is None


# Test that an invalid alert raises a ValueError
def test_validate_alert_rejects_invalid_alert():
    with pytest.raises(ValueError):
        validate_alert({"alert_id": "a-123"})


# Test that valid IPs are accepted and invalid or duplicate IPs are skipped
def test_clean_ips():
    ips = [
        "185.220.101.4",
        "10.0.0.12",
        "185.220.101.4",
        "not-an-ip",
        "2001:db8::1",
    ]

    valid, skipped = clean_ips(ips)

    assert valid == ["185.220.101.4"]
    assert len(skipped) == 3


# Test that a successful API response returns the IP reputation details
def test_lookup_ip_success(monkeypatch):
    class MockResponse:
        status_code = 200

        def json(self):
            return {
                "score": 85,
                "categories": ["tor"],
                "country": "DE",
            }

    monkeypatch.setattr(enrichment, "rate_limit", lambda: None)
    monkeypatch.setattr(
        enrichment.requests,
        "get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = enrichment.lookup_ip("185.220.101.4", "test-key")

    assert result["status"] == "ok"
    assert result["malicious"] is True
    assert result["country"] == "DE"


# Test that an IP not found by the API returns an unknown status
def test_lookup_ip_404(monkeypatch):
    class MockResponse:
        status_code = 404

    monkeypatch.setattr(enrichment, "rate_limit", lambda: None)
    monkeypatch.setattr(
        enrichment.requests,
        "get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = enrichment.lookup_ip("185.220.101.4", "test-key")

    assert result["status"] == "unknown"


# Test that a request timeout returns an error status
def test_lookup_ip_timeout(monkeypatch):
    monkeypatch.setattr(enrichment, "rate_limit", lambda: None)
    monkeypatch.setattr(
        enrichment.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            requests.Timeout("Request timed out")
        ),
    )
    monkeypatch.setattr(enrichment.time, "sleep", lambda delay: None)

    result = enrichment.lookup_ip("185.220.101.4", "test-key")

    assert result["status"] == "error"


# Test that the API request is retried after a rate limit and eventually succeeds
def test_lookup_ip_429_then_success(monkeypatch):
    class MockResponse:
        def __init__(self, status_code):
            self.status_code = status_code
            self.headers = {}

        def json(self):
            return {
                "score": 20,
                "categories": [],
                "country": "DE",
            }

    responses = iter(
        [
            MockResponse(429),
            MockResponse(200),
        ]
    )

    monkeypatch.setattr(enrichment, "rate_limit", lambda: None)
    monkeypatch.setattr(
        enrichment.requests,
        "get",
        lambda *args, **kwargs: next(responses),
    )
    monkeypatch.setattr(enrichment.time, "sleep", lambda delay: None)

    result = enrichment.lookup_ip("185.220.101.4", "test-key")

    assert result["status"] == "ok"
    assert result["malicious"] is False


# Test that repeated server errors eventually exhaust all retries
def test_lookup_ip_persistent_500(monkeypatch):
    class MockResponse:
        def __init__(self):
            self.status_code = 500
            self.headers = {}

    calls = []

    def mock_get(*args, **kwargs):
        calls.append(1)
        return MockResponse()

    monkeypatch.setattr(enrichment, "rate_limit", lambda: None)
    monkeypatch.setattr(enrichment.requests, "get", mock_get)
    monkeypatch.setattr(enrichment.time, "sleep", lambda delay: None)

    result = enrichment.lookup_ip("185.220.101.4", "test-key")

    assert result["status"] == "error"
    assert len(calls) == enrichment.MAX_RETRIES


# Test that an alert receives a malicious verdict when an IP is malicious
def test_enrich_alert_malicious_verdict(monkeypatch):
    alert = {
        "alert_id": "a-7f3c91",
        "title": "Suspicious sign-in",
        "severity": "medium",
        "entities": {"ips": ["185.220.101.4"]},
    }

    monkeypatch.setenv("REPUTATION_API_KEY", "test-key")
    monkeypatch.setattr(
        enrichment,
        "lookup_ip",
        lambda ip, api_key: {
            "ip": ip,
            "status": "ok",
            "malicious": True,
        },
    )

    result = enrichment.enrich_alert(alert)

    assert result["verdict"] == "malicious"


# Test that an alert receives an unknown verdict when an IP lookup fails
def test_enrich_alert_unknown_verdict(monkeypatch):
    alert = {
        "alert_id": "a-7f3c91",
        "title": "Suspicious sign-in",
        "severity": "medium",
        "entities": {"ips": ["185.220.101.4"]},
    }

    monkeypatch.setenv("REPUTATION_API_KEY", "test-key")
    monkeypatch.setattr(
        enrichment,
        "lookup_ip",
        lambda ip, api_key: {"ip": ip, "status": "error"},
    )

    result = enrichment.enrich_alert(alert)

    assert result["verdict"] == "unknown"


# Test that enrichment continues with other IPs when one lookup fails
def test_enrich_alert_continues_after_lookup_failure(monkeypatch):
    alert = {
        "alert_id": "a-7f3c91",
        "title": "Suspicious sign-in",
        "severity": "medium",
        "entities": {
            "ips": ["185.220.101.4", "8.8.8.8"],
        },
    }

    monkeypatch.setenv("REPUTATION_API_KEY", "test-key")

    def mock_lookup(ip, api_key):
        if ip == "185.220.101.4":
            raise requests.Timeout("Request timed out")

        return {"ip": ip, "status": "ok", "malicious": False}

    monkeypatch.setattr(enrichment, "lookup_ip", mock_lookup)

    result = enrichment.enrich_alert(alert)

    assert len(result["results"]) == 2
    assert result["results"][0]["status"] == "error"
    assert result["results"][1]["status"] == "ok"
    assert result["verdict"] == "unknown"


# Test that the HTTP endpoint returns a 400 response for invalid JSON
def test_enrich_rejects_invalid_json():
    class MockRequest:
        def get_json(self):
            raise ValueError("Invalid JSON")

    response = function_app.enrich(MockRequest())

    assert response.status_code == 400

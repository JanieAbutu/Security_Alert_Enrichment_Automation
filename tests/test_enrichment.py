import pytest
import function_app

from enrichment import validate_alert, clean_ips


def test_validate_alert():
    alert = {
        "alert_id": "a-7f3c91",
        "title": "Suspicious sign-in",
        "severity": "medium",
        "entities": {
            "ips": ["185.220.101.4"]
        },
    }

    assert validate_alert(alert) is None


def test_validate_alert_rejects_invalid_alert():
    with pytest.raises(ValueError):
        validate_alert({"alert_id": "a-123"})


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


import requests
import enrichment


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

    responses = iter([
        MockResponse(429),
        MockResponse(200),
    ])

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


def test_lookup_ip_persistent_500(monkeypatch):
    class MockResponse:
        status_code = 500
        headers = {}

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



def test_enrich_rejects_invalid_json():
    class MockRequest:
        def get_json(self):
            raise ValueError("Invalid JSON")

    response = function_app.enrich(MockRequest())

    assert response.status_code == 400
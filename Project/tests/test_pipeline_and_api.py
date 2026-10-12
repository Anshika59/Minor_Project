"""Integration tests for the complete detection pipeline and Flask Web API."""

import pytest
import json
from src.pipeline import PhishingDetectorPipeline
from src.web.app import create_app


@pytest.fixture
def pipeline():
    return PhishingDetectorPipeline()


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_pipeline_phishing_detection(pipeline):
    phish_email = (
        "From: \"PayPal Security\" <service@paypal-account-verify.xyz>\n"
        "Reply-To: stealer@gmail.com\n"
        "Subject: Urgent: Verify Account\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail\n\n"
        "Dear Customer,\n"
        "Your account is suspended. Enter your password immediately:\n"
        "http://paypal-account-verify.xyz/login"
    )
    res = pipeline.analyze(phish_email)
    verdict = res["final_verdict"]

    assert verdict["final_label"] == "Phishing"
    assert verdict["risk_score"] >= 70.0
    assert len(verdict["plain_language_reasons"]) > 0


def test_pipeline_safe_detection(pipeline):
    safe_email = (
        "From: GitHub <noreply@github.com>\n"
        "Reply-To: noreply@github.com\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
        "Subject: Your repository was updated\n\n"
        "Hi Developer,\n"
        "Pull request #12 has been merged into main.\n"
        "https://github.com/project/pull/12"
    )
    res = pipeline.analyze(safe_email)
    verdict = res["final_verdict"]

    assert verdict["final_label"] == "Safe"
    assert verdict["risk_score"] < 40.0


def test_web_api_analyze_json(client):
    payload = {
        "email_text": "From: test@example.com\nSubject: Hi\n\nTesting plain email"
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert "final_verdict" in data["data"]


def test_web_api_samples(client):
    resp = client.get("/api/samples/paypal_phishing.eml")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert "paypal-account-verify" in data["content"]

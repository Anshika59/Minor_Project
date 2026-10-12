"""Unit tests for Content and Linguistic Analysis (Objective 4)."""

import pytest
from src.content_analyzer import ContentAnalyzer


def test_urgency_and_threat_cues():
    analyzer = ContentAnalyzer()
    subject = "URGENT: Your account has been suspended"
    body = (
        "Dear Customer,\n"
        "We detected unauthorized access on your account. Immediate action is required within 24 hours.\n"
        "Failure to respond will lead to account termination."
    )
    res = analyzer.analyze(body, subject)

    assert res["urgency_score"] >= 20.0
    assert res["threat_score"] >= 20.0
    assert res["generic_greeting_detected"] is True
    assert res["risk_score"] >= 40.0


def test_credential_harvesting_cues():
    analyzer = ContentAnalyzer()
    subject = "Verify your credentials"
    body = (
        "Hello,\n"
        "Please enter your password and verify your account credentials immediately."
    )
    res = analyzer.analyze(body, subject)

    assert res["credential_request_score"] >= 25.0


def test_clean_legitimate_content():
    analyzer = ContentAnalyzer()
    subject = "Weekly project synchronization notes"
    body = (
        "Hi team,\n"
        "Attached are the meeting minutes from this morning's architectural design review.\n"
        "Have a great weekend.\n"
        "Best regards, John"
    )
    res = analyzer.analyze(body, subject)

    assert res["risk_score"] <= 10.0
    assert res["credential_request_score"] == 0.0

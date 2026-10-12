"""Unit tests for Sender and Header Authentication Analysis (Objective 2)."""

import pytest
from src.ingestion import EmailParser
from src.header_analyzer import HeaderAnalyzer, levenshtein_distance


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "goog1e") == 1
    assert levenshtein_distance("apple", "apple") == 0


def test_display_name_spoofing():
    analyzer = HeaderAnalyzer()
    raw = (
        "From: \"PayPal Support\" <scammer123@gmail.com>\n"
        "Subject: Urgent Account Warning\n\n"
        "Your account is restricted."
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    assert result["risk_score"] >= 30.0
    rules = [i["rule"] for i in result["indicators"]]
    assert "display_name_spoofing" in rules


def test_embedded_display_address():
    analyzer = HeaderAnalyzer()
    raw = (
        "From: \"service@paypal.com\" <hacker@compromised-server.org>\n"
        "Subject: Verify your email\n\n"
        "Click to verify."
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    rules = [i["rule"] for i in result["indicators"]]
    assert "embedded_display_address" in rules


def test_typosquatting_detection():
    analyzer = HeaderAnalyzer()
    raw = (
        "From: \"Security\" <notice@paypa1-security-update.com>\n"
        "Subject: Warning\n\n"
        "Please check."
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    rules = [i["rule"] for i in result["indicators"]]
    assert "domain_typosquatting" in rules


def test_authentication_spf_and_dkim_fail():
    analyzer = HeaderAnalyzer()
    raw = (
        "From: User <test@legitdomain.com>\n"
        "Authentication-Results: mx.test.com; spf=fail; dkim=fail; dmarc=fail\n"
        "Subject: Invoice\n\n"
        "Please pay."
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    auth = result["authentication"]
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "fail"
    assert auth["dmarc"] == "fail"
    assert result["risk_score"] >= 50.0

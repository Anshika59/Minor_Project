"""Unit tests for URL and Link Analysis Module (Objective 3)."""

import pytest
from src.ingestion import EmailParser
from src.url_analyzer import URLAnalyzer


def test_masked_link_detection():
    analyzer = URLAnalyzer()
    raw = (
        "From: admin@test.com\n"
        "Content-Type: text/html\n\n"
        "<a href=\"http://evil-tracker.com/login\">https://paypal.com/signin</a>"
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    assert result["masked_count"] == 1
    assert result["risk_score"] >= 45.0
    rules = [i["rule"] for i in result["indicators"]]
    assert "masked_hyperlink" in rules


def test_blacklisted_domain_lookup():
    analyzer = URLAnalyzer()
    raw = (
        "From: admin@test.com\n\n"
        "Visit: http://credential-harvester.buzz/verify"
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    assert result["blacklisted_count"] == 1
    rules = [i["rule"] for i in result["indicators"]]
    assert "blacklisted_domain" in rules


def test_ip_address_host_detection():
    analyzer = URLAnalyzer()
    raw = (
        "From: admin@test.com\n\n"
        "Click here: http://192.168.1.100/admin"
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    assert result["ip_url_count"] == 1
    rules = [i["rule"] for i in result["indicators"]]
    assert "ip_address_url" in rules


def test_shortened_url_detection():
    analyzer = URLAnalyzer()
    raw = (
        "From: admin@test.com\n\n"
        "Special offer: https://bit.ly/claim-free-gift"
    )
    email_obj = EmailParser.parse(raw)
    result = analyzer.analyze(email_obj)

    assert result["shortener_count"] == 1
    rules = [i["rule"] for i in result["indicators"]]
    assert "url_shortener" in rules

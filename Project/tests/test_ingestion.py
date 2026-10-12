"""Unit tests for Email Ingestion and Parsing Module (Objective 1)."""

import pytest
from src.ingestion import EmailParser, EmailAttachment, ExtractedLink


def test_plain_email_ingestion():
    raw_email = (
        "From: Alice <alice@example.com>\n"
        "To: Bob <bob@example.com>\n"
        "Subject: Project Status Update\n"
        "Date: Mon, 12 Oct 2026 10:00:00 +0000\n\n"
        "Hi Bob,\nHere is the updated link: https://company.com/project"
    )
    parsed = EmailParser.parse(raw_email)

    assert parsed.sender_email == "alice@example.com"
    assert parsed.sender_name == "Alice"
    assert parsed.sender_domain == "example.com"
    assert parsed.subject == "Project Status Update"
    assert len(parsed.links) == 1
    assert parsed.links[0].url == "https://company.com/project"
    assert parsed.links[0].domain == "company.com"


def test_html_and_masked_link_extraction():
    raw_html_email = (
        "From: Service <service@security.org>\n"
        "Subject: Security Notice\n"
        "Content-Type: text/html; charset=\"utf-8\"\n\n"
        "<html><body>"
        "<p>Please click <a href=\"http://attacker.com/steal\">https://paypal.com/login</a> to verify.</p>"
        "</body></html>"
    )
    parsed = EmailParser.parse(raw_html_email)

    assert len(parsed.links) >= 1
    html_link = next(l for l in parsed.links if l.source == "html_anchor")
    assert html_link.url == "http://attacker.com/steal"
    assert html_link.anchor_text == "https://paypal.com/login"
    assert html_link.domain == "attacker.com"


def test_attachment_and_double_extension():
    att1 = EmailAttachment("invoice.pdf", "application/pdf", 1024)
    assert att1.extension == "pdf"
    assert not att1.has_double_extension

    att2 = EmailAttachment("report.pdf.exe", "application/x-dosexec", 2048)
    assert att2.extension == "exe"
    assert att2.has_double_extension

    att3 = EmailAttachment("document.docx.vbs", "application/x-vbs", 512)
    assert att3.extension == "vbs"
    assert att3.has_double_extension

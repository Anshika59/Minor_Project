"""Unit tests for Attachment Risk Module (Module 9.5)."""

import pytest
from src.ingestion import EmailParser, EmailAttachment
from src.attachment_analyzer import AttachmentAnalyzer


def test_executable_and_double_extension():
    analyzer = AttachmentAnalyzer()
    email_obj = EmailParser.parse("Subject: Delivery Notice\n\nSee attachment.")
    email_obj.attachments.append(EmailAttachment("order_details.pdf.exe", "application/x-dosexec", 50000))

    res = analyzer.analyze(email_obj)
    assert res["double_extension_count"] == 1
    assert res["risky_attachment_count"] == 1
    assert res["risk_score"] >= 80.0


def test_safe_pdf_attachment():
    analyzer = AttachmentAnalyzer()
    email_obj = EmailParser.parse("Subject: Document\n\nAttached is the receipt.")
    email_obj.attachments.append(EmailAttachment("receipt.pdf", "application/pdf", 12000))

    res = analyzer.analyze(email_obj)
    assert res["double_extension_count"] == 0
    assert res["risky_attachment_count"] == 0
    assert res["risk_score"] == 0.0

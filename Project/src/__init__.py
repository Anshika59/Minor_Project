"""Phishing Email Detector Package."""

from src.ingestion import EmailParser, ParsedEmail
from src.header_analyzer import HeaderAnalyzer
from src.url_analyzer import URLAnalyzer
from src.content_analyzer import ContentAnalyzer
from src.attachment_analyzer import AttachmentAnalyzer
from src.ml_engine import MLEngine
from src.risk_aggregator import RiskAggregator
from src.pipeline import PhishingDetectorPipeline

__all__ = [
    "EmailParser",
    "ParsedEmail",
    "HeaderAnalyzer",
    "URLAnalyzer",
    "ContentAnalyzer",
    "AttachmentAnalyzer",
    "MLEngine",
    "RiskAggregator",
    "PhishingDetectorPipeline"
]

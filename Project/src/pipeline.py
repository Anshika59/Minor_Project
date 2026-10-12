"""
End-to-End Phishing Detection Pipeline

Coordinates the complete analysis workflow:
Email Input -> Header & Sender Parsing -> URL Extraction ->
Content/NLP Analysis -> Attachment Risk Analysis -> ML Classification ->
Rule-Based Risk Aggregation -> Result & Explanation Display
"""

from datetime import datetime
from typing import Dict, Any, Union
import os

from src.ingestion import EmailParser, ParsedEmail
from src.header_analyzer import HeaderAnalyzer
from src.url_analyzer import URLAnalyzer
from src.content_analyzer import ContentAnalyzer
from src.attachment_analyzer import AttachmentAnalyzer
from src.ml_engine import MLEngine
from src.risk_aggregator import RiskAggregator


class PhishingDetectorPipeline:
    """Unified orchestration pipeline for analyzing emails."""

    def __init__(self, model_path: str = None, blacklist_path: str = None, brands_path: str = None):
        self.parser = EmailParser()
        self.header_analyzer = HeaderAnalyzer(brands_path=brands_path)
        self.url_analyzer = URLAnalyzer(blacklist_path=blacklist_path)
        self.content_analyzer = ContentAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.ml_engine = MLEngine(model_path=model_path)
        self.risk_aggregator = RiskAggregator()

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze an email from a file path (.eml or text)."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Email file not found: {file_path}")

        with open(file_path, "rb") as f:
            content = f.read()

        return self.analyze(content)

    def analyze(self, raw_input: Union[str, bytes]) -> Dict[str, Any]:
        """Execute the end-to-end multi-layer detection pipeline."""
        start_time = datetime.now()

        # Step 1: Ingestion & Parsing
        parsed: ParsedEmail = self.parser.parse(raw_input)

        # Step 2: Sender & Header Authentication Analysis
        header_result = self.header_analyzer.analyze(parsed)

        # Step 3: URL and Link Safety Analysis
        url_result = self.url_analyzer.analyze(parsed)

        # Step 4: Content and NLP Linguistic Analysis
        content_result = self.content_analyzer.analyze(parsed.body_text, parsed.subject)

        # Step 5: Attachment Risk Analysis
        attachment_result = self.attachment_analyzer.analyze(parsed)

        # Step 6: Machine Learning Classification Engine
        ml_result = self.ml_engine.predict(
            parsed, header_result, url_result, content_result, attachment_result
        )

        # Step 7: Risk Aggregation & Final Classification
        verdict = self.risk_aggregator.aggregate(
            header_result, url_result, content_result, attachment_result, ml_result
        )

        duration_ms = round((datetime.now() - start_time).total_seconds() * 1000, 2)

        return {
            "timestamp": start_time.isoformat(),
            "execution_time_ms": duration_ms,
            "parsed_email": parsed.to_dict(),
            "header_analysis": header_result,
            "url_analysis": url_result,
            "content_analysis": content_result,
            "attachment_analysis": attachment_result,
            "ml_classification": ml_result,
            "final_verdict": verdict
        }

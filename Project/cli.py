"""
Phishing Email Detector — Command Line Interface (CLI)

Usage:
  python cli.py --file <path-to-eml-or-txt>
  python cli.py --text "raw email content"
  python cli.py --file <path> --json
"""

import argparse
import json
import sys
from src.pipeline import PhishingDetectorPipeline


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detector — Multi-layer email triage and analysis tool."
    )
    parser.add_argument("--file", "-f", help="Path to email file (.eml or .txt)")
    parser.add_argument("--text", "-t", help="Raw email text to analyze")
    parser.add_argument("--json", "-j", action="store_true", help="Output raw JSON results")

    args = parser.parse_args()

    if not args.file and not args.text:
        parser.print_help()
        sys.exit(1)

    pipeline = PhishingDetectorPipeline()

    try:
        if args.file:
            result = pipeline.analyze_file(args.file)
        else:
            result = pipeline.analyze(args.text)
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # Formatted Terminal Report
    verdict = result["final_verdict"]
    parsed = result["parsed_email"]
    sender = parsed["sender"]
    auth = result["header_analysis"]["authentication"]

    color_prefix = {
        "Safe": "\033[92m[SAFE]\033[0m",
        "Suspicious": "\033[93m[SUSPICIOUS]\033[0m",
        "Phishing": "\033[91m[PHISHING]\033[0m"
    }.get(verdict["final_label"], verdict["final_label"])

    print("=" * 65)
    print(f"  PHISHING EMAIL DETECTOR — ANALYSIS REPORT")
    print("=" * 65)
    print(f"Final Classification:  {color_prefix}")
    print(f"Overall Risk Score:    {verdict['risk_score']}/100")
    print(f"Confidence Level:      {int(verdict['confidence'] * 100)}%")
    print(f"Execution Time:        {result['execution_time_ms']} ms")
    print("-" * 65)
    print(f"Subject:      {parsed['subject'] or '(No Subject)'}")
    print(f"From:         {sender['name']} <{sender['email']}>")
    print(f"Reply-To:     {parsed['reply_to']['email'] or 'Same as From'}")
    print(f"SPF Status:   {auth.get('spf', 'N/A').upper()}")
    print(f"DKIM Status:  {auth.get('dkim', 'N/A').upper()}")
    print(f"DMARC Status: {auth.get('dmarc', 'N/A').upper()}")
    print(f"Total Links:  {parsed['link_count']} (Masked: {result['url_analysis']['masked_count']})")
    print(f"Attachments:  {parsed['attachment_count']} (Risky: {result['attachment_analysis']['risky_attachment_count']})")
    print(f"ML Phishing Probability: {result['ml_classification']['phishing_percentage']}%")
    print("-" * 65)
    print("Plain-Language Risk Reasons:")
    for reason in verdict["plain_language_reasons"]:
        print(f"  * {reason}")

    print("-" * 65)
    print("Recommended Action:")
    print(f"  {verdict['recommendation']}")
    print("=" * 65)


if __name__ == "__main__":
    main()

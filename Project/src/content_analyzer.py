"""
Content and Linguistic Analysis Module (Objective 4)

Analyzes email text for social engineering cues, psychological manipulation,
and linguistic patterns typical of phishing attacks:
- Urgency cues & artificial deadlines (e.g., 'within 24 hours', 'immediate action required')
- Threats & fear appeals (e.g., 'account suspension', 'legal prosecution', 'unauthorized access')
- Sensitive credential & financial information requests (e.g., 'verify password', 'confirm credit card')
- Financial lure / prize / reward exploitation (e.g., 'lottery winner', 'wire transfer', 'crypto bonus')
- Impersonal / generic salutations (e.g., 'Dear Valued Customer', 'Dear User')
- Punctuation & capitalization anomalies (e.g., excessive exclamation marks and ALL CAPS)
"""

import re
from typing import Dict, List, Any


class ContentAnalyzer:
    """Evaluates psychological and linguistic patterns in email body and subject."""

    # Curated regex pattern libraries mapped to risk categories and weights
    URGENCY_PATTERNS = [
        (r'\b(?:immediate(?:ly)?|urgent(?:ly)?|promptly)\s+(?:action|attention|verification|response|update)', 25.0, "High urgency action required"),
        (r'\b(?:account|access|service)\s+(?:will be|has been|is)\s+(?:suspended|terminated|restricted|locked|deactivated|closed)\b', 25.0, "Account suspension threat"),
        (r'\bwithin\s+(?:24|48|12|72)\s*(?:hours|hrs)\b', 20.0, "Artificial tight deadline"),
        (r'\bfinal\s+(?:warning|notice|reminder)\b', 20.0, "Final warning pressure"),
        (r'\bact\s+(?:now|fast|today|immediately)\b', 15.0, "Immediate action push"),
        (r'\bexpire(?:s|d)?\s+(?:today|soon|within)\b', 15.0, "Expiration urgency"),
        (r'\bfailure\s+to\s+(?:respond|update|verify)\b', 20.0, "Negative consequence warning")
    ]

    THREAT_PATTERNS = [
        (r'\bunauthorized\s+(?:activity|access|transaction|login|charges?)\b', 20.0, "Claim of unauthorized account activity"),
        (r'\bsecurity\s+(?:breach|compromise|alert|incident)\b', 15.0, "Security compromise claim"),
        (r'\blegal\s+(?:action|proceedings|consequences)\b', 25.0, "Threat of legal repercussions"),
        (r'\blaw\s+enforcement\b', 20.0, "Law enforcement invocation"),
        (r'\bpermanent(?:ly)?\s+(?:deleted?|disabled?|removed?)\b', 20.0, "Threat of permanent deletion")
    ]

    CREDENTIAL_PATTERNS = [
        (r'\b(?:verify|confirm|validate|update)\s+your\s+(?:account|identity|password|credentials|information|pin|details)\b', 25.0, "Request to verify account or password"),
        (r'\benter\s+your\s+(?:password|pin|security code|ssn|social security)\b', 30.0, "Direct solicitation of credentials"),
        (r'\b(?:credit|debit)\s+card\s+(?:number|details|expiration|cvv)\b', 30.0, "Request for banking/card information"),
        (r'\b(?:login|sign\s*in)\s+(?:to\s+(?:verify|confirm|restore|reactivate))\b', 20.0, "Link prompting credential sign-in"),
        (r'\bclick\s+(?:here|the link below)\s+to\s+(?:verify|unlock|reactivate)\b', 20.0, "Directive to click link for authentication")
    ]

    FINANCIAL_LURE_PATTERNS = [
        (r'\b(?:lottery|jackpot|sweepstakes)\s+winner\b', 25.0, "Lottery or prize scam phrasing"),
        (r'\bclaim\s+your\s+(?:reward|prize|inheritance|refund|cash)\b', 25.0, "Lure to claim fake reward or refund"),
        (r'\b(?:wire\s*transfer|inheritance\s*fund|beneficiary)\b', 20.0, "Inheritance / advance-fee fraud keyword"),
        (r'\b(?:bitcoin|cryptocurrency|wallet)\s+(?:transfer|deposit|gift)\b', 15.0, "Cryptocurrency lure")
    ]

    GENERIC_GREETINGS = [
        (r'^(?:dear|hello|attention)\s+(?:customer|user|client|member|account\s+holder|sir/madam|subscriber)\b', 15.0, "Generic impersonal greeting"),
        (r'^(?:dear\s+friend|dear\s+beloved)\b', 20.0, "Spam greeting pattern")
    ]

    def analyze(self, body_text: str, subject: str = "") -> Dict[str, Any]:
        """Perform NLP and linguistic pattern analysis on email subject and body."""
        full_text = f"{subject}\n{body_text}".strip()
        indicators: List[Dict[str, Any]] = []
        flagged_phrases: List[Dict[str, Any]] = []
        raw_score: float = 0.0

        if not full_text:
            return {
                "module": "content_analysis",
                "risk_score": 0.0,
                "urgency_score": 0.0,
                "threat_score": 0.0,
                "credential_request_score": 0.0,
                "financial_lure_score": 0.0,
                "generic_greeting_detected": False,
                "uppercase_ratio": 0.0,
                "flagged_phrases": [],
                "indicators": []
            }

        text_lower = full_text.lower()

        # 1. Check Urgency Patterns
        urgency_points = 0.0
        for pattern, weight, label in self.URGENCY_PATTERNS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            if matches:
                urgency_points += weight
                for m in matches[:2]:  # Limit duplicates
                    flagged_phrases.append({
                        "category": "urgency",
                        "matched_text": m.group(0),
                        "label": label
                    })

        if urgency_points > 0:
            raw_score += urgency_points
            indicators.append({
                "module": "content",
                "severity": "HIGH" if urgency_points >= 30 else "MEDIUM",
                "rule": "urgency_cues",
                "message": f"Urgency language detected: email pressures the recipient into rapid compliance."
            })

        # 2. Check Threat / Coercion Patterns
        threat_points = 0.0
        for pattern, weight, label in self.THREAT_PATTERNS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            if matches:
                threat_points += weight
                for m in matches[:2]:
                    flagged_phrases.append({
                        "category": "threat",
                        "matched_text": m.group(0),
                        "label": label
                    })

        if threat_points > 0:
            raw_score += threat_points
            indicators.append({
                "module": "content",
                "severity": "HIGH",
                "rule": "coercion_threats",
                "message": f"Fear appeal / threat detected: email warns of negative consequences or unauthorized access."
            })

        # 3. Check Credential Harvesting Patterns
        credential_points = 0.0
        for pattern, weight, label in self.CREDENTIAL_PATTERNS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            if matches:
                credential_points += weight
                for m in matches[:2]:
                    flagged_phrases.append({
                        "category": "credential_request",
                        "matched_text": m.group(0),
                        "label": label
                    })

        if credential_points > 0:
            raw_score += credential_points
            indicators.append({
                "module": "content",
                "severity": "CRITICAL" if credential_points >= 40 else "HIGH",
                "rule": "credential_harvesting",
                "message": "Solicitation for login credentials, passwords, or personal identity verification detected."
            })

        # 4. Check Financial Lure Patterns
        financial_points = 0.0
        for pattern, weight, label in self.FINANCIAL_LURE_PATTERNS:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            if matches:
                financial_points += weight
                for m in matches[:2]:
                    flagged_phrases.append({
                        "category": "financial_lure",
                        "matched_text": m.group(0),
                        "label": label
                    })

        if financial_points > 0:
            raw_score += financial_points
            indicators.append({
                "module": "content",
                "severity": "HIGH",
                "rule": "financial_lure",
                "message": "Unsolicited reward, lottery, or financial lure detected in message body."
            })

        # 5. Generic Salutation Check
        generic_greeting_found = False
        first_few_lines = "\n".join(full_text.splitlines()[:6])
        for pattern, weight, label in self.GENERIC_GREETINGS:
            m = re.search(pattern, first_few_lines.strip(), re.IGNORECASE | re.MULTILINE)
            if m:
                generic_greeting_found = True
                raw_score += weight
                flagged_phrases.append({
                    "category": "generic_greeting",
                    "matched_text": m.group(0),
                    "label": label
                })
                indicators.append({
                    "module": "content",
                    "severity": "LOW",
                    "rule": "generic_greeting",
                    "message": f"Impersonal greeting '{m.group(0)}' used instead of recipient's actual name."
                })
                break

        # 6. Capitalization and Exclamation Intensity
        letters = [c for c in body_text if c.isalpha()]
        uppercase_ratio = (sum(1 for c in letters if c.isupper()) / len(letters)) if letters else 0.0
        exclamations = body_text.count("!")

        if uppercase_ratio > 0.35 and len(letters) > 50:
            raw_score += 15.0
            indicators.append({
                "module": "content",
                "severity": "LOW",
                "rule": "excessive_capitalization",
                "message": f"Abnormally high proportion of ALL-CAPS text ({round(uppercase_ratio * 100)}%), indicating artificial alarm."
            })

        if exclamations >= 4:
            raw_score += 10.0
            indicators.append({
                "module": "content",
                "severity": "LOW",
                "rule": "excessive_punctuation",
                "message": f"Excessive exclamation marks ({exclamations}) used to create tension."
            })

        bounded_score = max(0.0, min(100.0, raw_score))

        return {
            "module": "content_analysis",
            "risk_score": round(bounded_score, 1),
            "urgency_score": round(min(100.0, urgency_points), 1),
            "threat_score": round(min(100.0, threat_points), 1),
            "credential_request_score": round(min(100.0, credential_points), 1),
            "financial_lure_score": round(min(100.0, financial_points), 1),
            "generic_greeting_detected": generic_greeting_found,
            "uppercase_ratio": round(uppercase_ratio, 3),
            "flagged_phrases": flagged_phrases,
            "indicators": indicators
        }

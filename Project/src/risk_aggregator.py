"""
Risk Scoring and Final Classification Engine (Objective 6)

Combines machine learning predictions with rule-based indicators and
deterministic security escalation rules into three final labels:
- Safe (Score 0 - 39)
- Suspicious (Score 40 - 69)
- Phishing (Score 70 - 100)

Retains every contributing indicator with severity ratings and plain-language explanations.
"""

from typing import Dict, List, Any


class RiskAggregator:
    """Aggregates ML probabilities and rule-based heuristics into final classification."""

    SAFE_MAX_THRESHOLD = 39.0
    SUSPICIOUS_MAX_THRESHOLD = 69.0

    def aggregate(
        self,
        header_res: Dict[str, Any],
        url_res: Dict[str, Any],
        content_res: Dict[str, Any],
        att_res: Dict[str, Any],
        ml_res: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Produce the final risk label, score, and plain-language breakdown."""
        ml_prob = ml_res.get("phishing_probability", 0.0)
        ml_score = ml_prob * 100.0

        h_score = header_res.get("risk_score", 0.0)
        u_score = url_res.get("risk_score", 0.0)
        c_score = content_res.get("risk_score", 0.0)
        a_score = att_res.get("risk_score", 0.0)

        # Baseline composite score (weighted fusion of ML engine and domain heuristics)
        # ML gets 40% weight, URLs 25%, Headers 20%, Content 10%, Attachments 5%
        weighted_score = (ml_score * 0.40) + (u_score * 0.25) + (h_score * 0.20) + (c_score * 0.10) + (a_score * 0.05)

        # Collect all indicators across modules
        all_indicators: List[Dict[str, Any]] = []
        all_indicators.extend(header_res.get("indicators", []))
        all_indicators.extend(url_res.get("indicators", []))
        all_indicators.extend(content_res.get("indicators", []))
        all_indicators.extend(att_res.get("indicators", []))

        # Check Hard Security Escalation Rules (Deterministic Overrides)
        hard_rules_triggered: List[str] = []

        # 1. Blacklisted / PhishTank domain found in URL
        if url_res.get("blacklisted_count", 0) > 0:
            hard_rules_triggered.append("Email contains known blacklisted / PhishTank malicious domains.")
            weighted_score = max(weighted_score, 90.0)

        # 2. Deceptive double-extension executable attachment (e.g. invoice.pdf.exe)
        if att_res.get("double_extension_count", 0) > 0:
            hard_rules_triggered.append("Attachment uses a deceptive double extension disguise (e.g., .pdf.exe).")
            weighted_score = max(weighted_score, 95.0)

        # 3. Direct executable attachment
        if att_res.get("risky_attachment_count", 0) > 0 and any(
            i.get("rule") == "executable_attachment" for i in att_res.get("indicators", [])
        ):
            hard_rules_triggered.append("Email carries a direct executable payload attachment.")
            weighted_score = max(weighted_score, 90.0)

        # 4. Masked link + Credential Harvesting
        has_masked_link = url_res.get("masked_count", 0) > 0
        has_cred_request = content_res.get("credential_request_score", 0.0) >= 20.0
        if has_masked_link and has_cred_request:
            hard_rules_triggered.append("Masked hyperlink combined with urgent credential harvesting prompt.")
            weighted_score = max(weighted_score, 88.0)

        # 5. Display name impersonates brand + sending domain is mismatch or free mail
        has_spoofed_display = any(
            i.get("rule") in ("display_name_spoofing", "embedded_display_address")
            for i in header_res.get("indicators", [])
        )
        if has_spoofed_display and (has_cred_request or url_res.get("total_urls", 0) > 0):
            hard_rules_triggered.append("Brand display name spoofing combined with active call-to-action.")
            weighted_score = max(weighted_score, 85.0)

        # 6. Typosquatting domain
        has_typosquat = any(i.get("rule") == "domain_typosquatting" for i in header_res.get("indicators", []))
        if has_typosquat:
            hard_rules_triggered.append("Sender domain is an intentional typosquatted brand look-alike.")
            weighted_score = max(weighted_score, 85.0)

        # 7. Raw IP address URL + urgency/threat
        if url_res.get("ip_url_count", 0) > 0 and (c_score >= 20.0 or h_score >= 20.0):
            hard_rules_triggered.append("Numeric IP host URL combined with suspicious email context.")
            weighted_score = max(weighted_score, 85.0)

        # Positive Mitigations (Legitimate Email Safety Promotion)
        auth = header_res.get("authentication", {})
        spf_pass = auth.get("spf") == "pass"
        dkim_pass = auth.get("dkim") == "pass"
        dmarc_pass = auth.get("dmarc") == "pass"

        # If authenticated sender with 0 hard rules, 0 masked links, 0 risky attachments
        if (spf_pass or dkim_pass or dmarc_pass) and not hard_rules_triggered:
            if url_res.get("masked_count", 0) == 0 and att_res.get("risky_attachment_count", 0) == 0:
                if not has_spoofed_display and not has_typosquat:
                    # Healthy legitimate trust discount
                    weighted_score = min(weighted_score, 35.0 if weighted_score < 50.0 else weighted_score - 15.0)

        # Bound final score
        final_score = round(max(0.0, min(100.0, weighted_score)), 1)

        # Determine Final Label
        if final_score <= self.SAFE_MAX_THRESHOLD:
            final_label = "Safe"
            badge_color = "success"  # Green
            confidence = round(max(0.60, 1.0 - (final_score / 100.0)), 2)
            recommendation = "This email demonstrates legitimate characteristics and passed key authenticity checks. Standard caution is still advised."
        elif final_score <= self.SUSPICIOUS_MAX_THRESHOLD:
            final_label = "Suspicious"
            badge_color = "warning"  # Amber
            confidence = round(0.50 + abs(final_score - 55.0) / 100.0, 2)
            recommendation = "Proceed with extreme caution. This email contains several anomalies (such as urgency phrasing, routing inconsistencies, or unverified links). Do not provide sensitive credentials."
        else:
            final_label = "Phishing"
            badge_color = "danger"  # Red
            confidence = round(max(0.75, final_score / 100.0), 2)
            recommendation = "HIGH THREAT DETECTED. Do not click any links, enter credentials, or open attachments. Report this email immediately to your security administrator or delete it."

        # Plain language summary explanation
        reasons = self._generate_plain_language_reasons(
            final_label, hard_rules_triggered, all_indicators, ml_res
        )

        return {
            "module": "risk_aggregator",
            "final_label": final_label,
            "badge_color": badge_color,
            "risk_score": final_score,
            "confidence": confidence,
            "hard_rules_triggered": hard_rules_triggered,
            "recommendation": recommendation,
            "plain_language_reasons": reasons,
            "score_breakdown": {
                "ml_score": round(ml_score, 1),
                "url_score": round(u_score, 1),
                "header_score": round(h_score, 1),
                "content_score": round(c_score, 1),
                "attachment_score": round(a_score, 1)
            },
            "contributing_indicators": all_indicators
        }

    def _generate_plain_language_reasons(
        self,
        label: str,
        hard_rules: List[str],
        indicators: List[Dict[str, Any]],
        ml_res: Dict[str, Any]
    ) -> List[str]:
        reasons: List[str] = []

        if hard_rules:
            for rule in hard_rules:
                reasons.append(f"Security Alert: {rule}")

        # Highlight critical and high severity findings
        crit_high = [i for i in indicators if i.get("severity") in ("CRITICAL", "HIGH")]
        for item in crit_high:
            msg = item.get("message")
            if msg and msg not in reasons:
                reasons.append(msg)

        # Highlight ML model finding
        ml_prob = ml_res.get("phishing_probability", 0.0)
        if ml_prob >= 0.70:
            reasons.append(f"Machine learning model classified language and structural features as high phishing risk ({round(ml_prob * 100)}% probability).")
        elif ml_prob <= 0.20 and label == "Safe":
            reasons.append("Machine learning model detected normal communication patterns with no phishing signatures.")

        # If safe and no critical flags
        if label == "Safe" and not reasons:
            reasons.append("No spoofing, masked links, blacklisted domains, or deceptive wording were detected.")
            reasons.append("Email headers and authentication checks align with normal legitimate communications.")

        return reasons[:6]  # Concise top reasons

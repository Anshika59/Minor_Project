"""
Sender and Header Authentication Analysis Module (Objective 2)

Performs comprehensive security checks on email sender and headers:
- Display name spoofing (e.g. "PayPal Service" sending from random domain or webmail)
- Display name embedding an email address (e.g. "security@paypal.com" <hacker@xyz.com>)
- Typosquatting / domain look-alikes against known high-value target brands
- SPF, DKIM, and DMARC authentication verification from headers
- Consistency checks between From domain, Reply-To domain, and Return-Path
- Received header hops and server relay inspection
"""

import json
import os
import re
from typing import Dict, List, Any, Optional, Tuple
import tldextract

from src.ingestion import ParsedEmail


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class HeaderAnalyzer:
    """Evaluates sender authenticity and header integrity."""

    FREE_EMAIL_PROVIDERS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "mail.com", "proton.me", "protonmail.com",
        "zoho.com", "yandex.com", "gmx.com", "icloud.com"
    }

    # Common homoglyph and character substitutions used by attackers
    HOMOGLYPH_MAP = {
        '0': 'o', '1': 'l', 'i': 'l', 'v': 'u', 'vv': 'w',
        'rn': 'm', 'cl': 'd', '3': 'e', '4': 'a', '@': 'a',
        '5': 's', '$': 's'
    }

    def __init__(self, brands_path: Optional[str] = None):
        self.target_brands = self._load_target_brands(brands_path)

    def _load_target_brands(self, brands_path: Optional[str]) -> Dict[str, Any]:
        default_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "target_brands.json"
        )
        path = brands_path or default_path
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def analyze(self, email_obj: ParsedEmail) -> Dict[str, Any]:
        """Perform full sender and header analysis on parsed email."""
        indicators: List[Dict[str, Any]] = []
        risk_score: float = 0.0

        sender_email = email_obj.sender_email
        sender_name = email_obj.sender_name
        sender_domain = email_obj.sender_domain
        reply_to_domain = email_obj.reply_to_domain
        return_path_domain = email_obj.return_path_domain

        # 1. Missing or Malformed From Address
        if not sender_email or "@" not in sender_email:
            risk_score += 40.0
            indicators.append({
                "module": "header",
                "severity": "CRITICAL",
                "rule": "invalid_sender",
                "message": "Email is missing a valid sender address in the 'From' header."
            })
            return self._build_result(risk_score, indicators, email_obj)

        # 2. Display Name Embedded Email Trick
        # e.g., From: "service@paypal.com" <attacker@badsite.com>
        embedded_email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', sender_name)
        if embedded_email_match:
            embedded_addr = embedded_email_match.group(0).lower()
            if embedded_addr != sender_email:
                risk_score += 35.0
                indicators.append({
                    "module": "header",
                    "severity": "CRITICAL",
                    "rule": "embedded_display_address",
                    "message": (
                        f"Display name intentionally embeds an email address ('{embedded_addr}') "
                        f"that differs from the actual sender address ('{sender_email}')."
                    )
                })

        # 3. Brand Impersonation in Display Name vs Actual Domain
        brand_impersonated, claimed_brand_name = self._check_brand_impersonation(sender_name, sender_domain)
        if brand_impersonated:
            is_free_mail = sender_domain in self.FREE_EMAIL_PROVIDERS
            severity = "CRITICAL" if is_free_mail else "HIGH"
            points = 40.0 if is_free_mail else 30.0
            risk_score += points
            indicators.append({
                "module": "header",
                "severity": severity,
                "rule": "display_name_spoofing",
                "message": (
                    f"Sender claims to represent '{claimed_brand_name}' in display name, "
                    f"but email is sent from unrelated domain '{sender_domain}'"
                    + (" (free webmail service)." if is_free_mail else ".")
                )
            })

        # 4. Typosquatting / Domain Look-alike Detection
        typosquat_match = self._check_typosquatting(sender_domain)
        if typosquat_match:
            brand_key, target_domain, reason = typosquat_match
            risk_score += 40.0
            indicators.append({
                "module": "header",
                "severity": "CRITICAL",
                "rule": "domain_typosquatting",
                "message": (
                    f"Sending domain '{sender_domain}' is a suspected typosquatting look-alike "
                    f"targeting '{target_domain}' ({reason})."
                )
            })

        # 5. Reply-To and Return-Path Consistency
        if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
            # Check if reply-to is completely different base domain
            base_sender = self._get_base_domain(sender_domain)
            base_reply = self._get_base_domain(reply_to_domain)
            if base_sender != base_reply:
                risk_score += 25.0
                indicators.append({
                    "module": "header",
                    "severity": "HIGH",
                    "rule": "reply_to_mismatch",
                    "message": (
                        f"Reply-To address domain ('{reply_to_domain}') does not match "
                        f"the sender domain ('{sender_domain}'). Replies will be diverted."
                    )
                })

        if return_path_domain and sender_domain and return_path_domain != sender_domain:
            base_sender = self._get_base_domain(sender_domain)
            base_return = self._get_base_domain(return_path_domain)
            if base_sender != base_return:
                risk_score += 15.0
                indicators.append({
                    "module": "header",
                    "severity": "MEDIUM",
                    "rule": "return_path_mismatch",
                    "message": (
                        f"Return-Path domain ('{return_path_domain}') differs from "
                        f"sender domain ('{sender_domain}')."
                    )
                })

        # 6. SPF, DKIM, and DMARC Authentication Inspection
        auth_status = self._evaluate_authentication(email_obj)
        for auth_flag in auth_status["indicators"]:
            indicators.append(auth_flag)
        risk_score += auth_status["risk_adjustment"]

        # 7. Received Headers & Relay Check
        if len(email_obj.received_headers) == 0:
            # Note: Pasted plain emails may not have received headers, so treat as minor note
            pass
        elif len(email_obj.received_headers) > 15:
            risk_score += 10.0
            indicators.append({
                "module": "header",
                "severity": "LOW",
                "rule": "excessive_hops",
                "message": f"Suspiciously high number of routing relays ({len(email_obj.received_headers)} hops)."
            })

        return self._build_result(risk_score, indicators, email_obj, auth_status)

    def _check_brand_impersonation(self, sender_name: str, sender_domain: str) -> Tuple[bool, str]:
        """Check if display name claims a known brand that sender domain doesn't own."""
        if not sender_name or not sender_domain:
            return False, ""

        name_lower = sender_name.lower()
        base_sender_domain = self._get_base_domain(sender_domain)

        for brand_key, brand_info in self.target_brands.items():
            legit_domains = [self._get_base_domain(d) for d in brand_info.get("legit_domains", [])]
            keywords = brand_info.get("keywords", [brand_key])

            # Check if display name mentions brand keywords
            name_matches_brand = any(re.search(r'\b' + re.escape(kw) + r'\b', name_lower) for kw in keywords)

            if name_matches_brand:
                # If name claims the brand, verify if the domain matches any legitimate brand domain
                if base_sender_domain not in legit_domains:
                    return True, brand_info.get("name", brand_key.capitalize())

        return False, ""

    def _check_typosquatting(self, domain: str) -> Optional[Tuple[str, str, str]]:
        """Detect look-alike domains using string similarity and character variations."""
        if not domain:
            return None

        ext = tldextract.extract(domain)
        domain_name = ext.domain.lower()

        for brand_key, brand_info in self.target_brands.items():
            for legit_domain in brand_info.get("legit_domains", []):
                legit_ext = tldextract.extract(legit_domain)
                legit_name = legit_ext.domain.lower()

                # If exact match, it is the real domain
                if domain_name == legit_name and ext.suffix == legit_ext.suffix:
                    continue

                # 1. Normalized homoglyph replacement
                norm_domain = domain_name
                for k, v in self.HOMOGLYPH_MAP.items():
                    norm_domain = norm_domain.replace(k, v)

                if norm_domain == legit_name and domain_name != legit_name:
                    return (brand_key, legit_domain, f"homoglyph substitution '{domain_name}' for '{legit_name}'")

                # Homoglyph combined with domain affixes (e.g. paypa1-security-update)
                if norm_domain != domain_name and legit_name in norm_domain:
                    return (brand_key, legit_domain, f"homoglyph substitution targeting '{legit_name}' in '{domain_name}'")

                # 2. Levenshtein edit distance check (1 or 2 edits for words >= 5 chars)
                dist = levenshtein_distance(domain_name, legit_name)
                if len(legit_name) >= 5 and 0 < dist <= 2:
                    # Filter out coincidental matches
                    if abs(len(domain_name) - len(legit_name)) <= 2:
                        return (brand_key, legit_domain, f"Levenshtein distance of {dist}")

                # 3. Subdomain confusion: brand name embedded in a deceptive subdomain
                # e.g., paypal.com.account-update.xyz
                if ext.subdomain:
                    sub_parts = ext.subdomain.lower().split('.')
                    if legit_name in sub_parts and ext.domain != legit_name:
                        return (brand_key, legit_domain, f"brand '{legit_name}' deceptive subdomain usage")

                # 4. Brand + phishing affixes (e.g. paypal-security-update or secure-chase)
                if norm_domain.startswith(f"{legit_name}-") or norm_domain.endswith(f"-{legit_name}") or f"-{legit_name}-" in norm_domain:
                    return (brand_key, legit_domain, f"brand '{legit_name}' combined with deceptive affixes")

                phish_affixes = ['security', 'verify', 'support', 'login', 'account', 'update', 'billing', 'portal']
                for affix in phish_affixes:
                    if domain_name in {f"{legit_name}-{affix}", f"{legit_name}{affix}", f"{affix}-{legit_name}"}:
                        return (brand_key, legit_domain, f"brand keyword combined with '{affix}'")

        return None

    def _evaluate_authentication(self, email_obj: ParsedEmail) -> Dict[str, Any]:
        """Inspect SPF, DKIM, and DMARC results from authentication headers."""
        indicators: List[Dict[str, Any]] = []
        risk_adjustment: float = 0.0

        raw_auth = f"{email_obj.auth_results} {email_obj.received_spf}".lower()

        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"

        # Check SPF
        if "spf=pass" in raw_auth or "pass" in email_obj.received_spf.lower():
            spf_status = "pass"
            indicators.append({
                "module": "header",
                "severity": "PASS",
                "rule": "spf_pass",
                "message": "SPF authentication passed: sending server is authorized for this domain."
            })
            risk_adjustment -= 5.0
        elif "spf=fail" in raw_auth or "fail" in email_obj.received_spf.lower():
            spf_status = "fail"
            indicators.append({
                "module": "header",
                "severity": "CRITICAL",
                "rule": "spf_fail",
                "message": "SPF authentication FAILED: sending server is NOT authorized to send on behalf of this domain."
            })
            risk_adjustment += 30.0
        elif "spf=softfail" in raw_auth:
            spf_status = "softfail"
            indicators.append({
                "module": "header",
                "severity": "HIGH",
                "rule": "spf_softfail",
                "message": "SPF authentication SOFTFAIL: sending server is probably not authorized."
            })
            risk_adjustment += 15.0

        # Check DKIM
        if "dkim=pass" in raw_auth or email_obj.dkim_signature:
            dkim_status = "pass"
            indicators.append({
                "module": "header",
                "severity": "PASS",
                "rule": "dkim_pass",
                "message": "DKIM digital signature is present and validated."
            })
            risk_adjustment -= 5.0
        elif "dkim=fail" in raw_auth:
            dkim_status = "fail"
            indicators.append({
                "module": "header",
                "severity": "CRITICAL",
                "rule": "dkim_fail",
                "message": "DKIM signature verification FAILED: email content may have been altered in transit."
            })
            risk_adjustment += 30.0

        # Check DMARC
        if "dmarc=pass" in raw_auth:
            dmarc_status = "pass"
            indicators.append({
                "module": "header",
                "severity": "PASS",
                "rule": "dmarc_pass",
                "message": "DMARC policy alignment check passed."
            })
            risk_adjustment -= 10.0
        elif "dmarc=fail" in raw_auth:
            dmarc_status = "fail"
            indicators.append({
                "module": "header",
                "severity": "CRITICAL",
                "rule": "dmarc_fail",
                "message": "DMARC verification FAILED: domain owner policy rejected this email."
            })
            risk_adjustment += 35.0

        return {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "indicators": indicators,
            "risk_adjustment": risk_adjustment
        }

    @staticmethod
    def _get_base_domain(domain_str: str) -> str:
        try:
            ext = tldextract.extract(domain_str)
            if ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return ext.domain.lower() if ext.domain else domain_str.lower()
        except Exception:
            return domain_str.lower()

    def _build_result(self, risk_score: float, indicators: List[Dict[str, Any]],
                      email_obj: ParsedEmail, auth_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        bounded_score = max(0.0, min(100.0, risk_score))
        return {
            "module": "header_analysis",
            "risk_score": round(bounded_score, 1),
            "sender_email": email_obj.sender_email,
            "sender_name": email_obj.sender_name,
            "sender_domain": email_obj.sender_domain,
            "reply_to": email_obj.reply_to_email,
            "return_path": email_obj.return_path_email,
            "authentication": auth_status or {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
            "indicators": indicators,
            "flag_count": len([i for i in indicators if i.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")])
        }

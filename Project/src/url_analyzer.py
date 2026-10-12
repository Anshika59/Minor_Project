"""
URL and Link Analysis Module (Objective 3)

Identifies and evaluates the security risks of links embedded in an email:
- Masked link detection (displayed text shows legitimate URL, but target href points elsewhere)
- Blacklist and reputation feed checking (PhishTank / OpenPhish snapshot feeds)
- Suspicious URL shorteners (bit.ly, tinyurl, t.co, etc.)
- Raw IP addresses used as URL hosts (e.g., http://192.168.1.1/...)
- High-risk / suspicious top-level domains (.xyz, .top, .tk, .icu, etc.)
- Deceptive subdomains attempting to mimic trusted institutions
- Suspicious URL entropy and abnormal port numbers
"""

import os
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Set
import tldextract

from src.ingestion import ParsedEmail, ExtractedLink


class URLAnalyzer:
    """Evaluates links for phishing, deception, masking, and reputation risks."""

    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
        "cutt.ly", "buff.ly", "goo.gl", "tiny.cc", "rb.gy",
        "shorturl.at", "bl.ink", "rebrandly.com", "snip.ly"
    }

    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz",
        "club", "work", "monster", "shop", "icu", "cam", "fit",
        "link", "click", "rest", "support", "stream", "online"
    }

    IP_PATTERN = re.compile(
        r'^(?:https?://)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/.*)?$',
        re.IGNORECASE
    )

    def __init__(self, blacklist_path: Optional[str] = None):
        self.blacklisted_domains = self._load_blacklist(blacklist_path)

    def _load_blacklist(self, blacklist_path: Optional[str]) -> Set[str]:
        default_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "blacklist_domains.txt"
        )
        path = blacklist_path or default_path
        blacklist: Set[str] = set()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            blacklist.add(line.lower())
            except Exception:
                pass
        return blacklist

    def analyze(self, email_obj: ParsedEmail) -> Dict[str, Any]:
        """Analyze all extracted links in the email."""
        links_data: List[Dict[str, Any]] = []
        indicators: List[Dict[str, Any]] = []
        url_risk_score: float = 0.0

        if not email_obj.links:
            return {
                "module": "url_analysis",
                "risk_score": 0.0,
                "total_urls": 0,
                "masked_count": 0,
                "blacklisted_count": 0,
                "shortener_count": 0,
                "suspicious_tld_count": 0,
                "ip_url_count": 0,
                "analyzed_links": [],
                "indicators": indicators
            }

        masked_count = 0
        blacklisted_count = 0
        shortener_count = 0
        suspicious_tld_count = 0
        ip_url_count = 0

        for link in email_obj.links:
            link_eval = self._evaluate_single_url(link)
            links_data.append(link_eval)

            if link_eval["is_masked"]:
                masked_count += 1
            if link_eval["is_blacklisted"]:
                blacklisted_count += 1
            if link_eval["is_shortener"]:
                shortener_count += 1
            if link_eval["has_suspicious_tld"]:
                suspicious_tld_count += 1
            if link_eval["is_ip_address"]:
                ip_url_count += 1

            for flag in link_eval["flags"]:
                indicators.append(flag)

            url_risk_score += link_eval["risk_points"]

        # Aggregate risk summary indicators
        if blacklisted_count > 0:
            url_risk_score += 50.0  # Heavy escalation for blacklisted destinations

        bounded_score = max(0.0, min(100.0, url_risk_score))

        return {
            "module": "url_analysis",
            "risk_score": round(bounded_score, 1),
            "total_urls": len(email_obj.links),
            "masked_count": masked_count,
            "blacklisted_count": blacklisted_count,
            "shortener_count": shortener_count,
            "suspicious_tld_count": suspicious_tld_count,
            "ip_url_count": ip_url_count,
            "analyzed_links": links_data,
            "indicators": indicators
        }

    def _evaluate_single_url(self, link: ExtractedLink) -> Dict[str, Any]:
        flags: List[Dict[str, Any]] = []
        risk_points: float = 0.0
        url = link.url
        anchor = link.anchor_text

        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
        subdomain = ext.subdomain.lower() if ext.subdomain else ""
        tld = ext.suffix.lower() if ext.suffix else ""

        is_masked = False
        is_blacklisted = False
        is_shortener = False
        has_suspicious_tld = False
        is_ip_address = False

        # 1. Masked Link Detection
        # Check if anchor text looks like a URL or domain that doesn't match the destination
        if anchor:
            anchor_clean = anchor.strip().lower()
            # If anchor contains a URL-like structure
            if re.search(r'https?://|[a-zA-Z0-9-]+\.(?:com|org|net|gov|edu|io|co|ai)', anchor_clean):
                anchor_ext = tldextract.extract(anchor_clean)
                anchor_reg_domain = f"{anchor_ext.domain}.{anchor_ext.suffix}".lower() if anchor_ext.suffix else anchor_ext.domain.lower()
                
                if anchor_reg_domain and registered_domain and anchor_reg_domain != registered_domain:
                    is_masked = True
                    risk_points += 45.0
                    flags.append({
                        "module": "url",
                        "severity": "CRITICAL",
                        "rule": "masked_hyperlink",
                        "message": (
                            f"Masked link detected: visible text pretends to lead to '{anchor_reg_domain}', "
                            f"but the actual destination points to '{registered_domain}' ({url})."
                        )
                    })

        # 2. Blacklist & Reputation Lookup
        if registered_domain in self.blacklisted_domains or url.lower() in self.blacklisted_domains:
            is_blacklisted = True
            risk_points += 50.0
            flags.append({
                "module": "url",
                "severity": "CRITICAL",
                "rule": "blacklisted_domain",
                "message": f"Destination domain '{registered_domain}' is flagged in malicious / PhishTank feeds."
            })

        # 3. URL Shortener Detection
        if registered_domain in self.KNOWN_SHORTENERS:
            is_shortener = True
            risk_points += 20.0
            flags.append({
                "module": "url",
                "severity": "MEDIUM",
                "rule": "url_shortener",
                "message": f"Shortened link detected ('{registered_domain}'). Shorteners conceal real destinations."
            })

        # 4. IP Address Host Detection
        parsed_parsed = urllib.parse.urlparse(url)
        host = parsed_parsed.hostname or ""
        if self.IP_PATTERN.match(url) or re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', host):
            is_ip_address = True
            risk_points += 40.0
            flags.append({
                "module": "url",
                "severity": "CRITICAL",
                "rule": "ip_address_url",
                "message": f"Link uses a raw numeric IP address ('{host}') instead of a legitimate registered domain name."
            })

        # 5. Suspicious TLD Detection
        if tld in self.SUSPICIOUS_TLDS:
            has_suspicious_tld = True
            risk_points += 20.0
            flags.append({
                "module": "url",
                "severity": "HIGH",
                "rule": "suspicious_tld",
                "message": f"Link uses top-level domain '.{tld}', commonly associated with low-cost spam and disposable phishing infrastructure."
            })

        # 6. Deceptive Subdomain Confusion
        # e.g., paypal.com.attacker.com or secure-chase.com.something.xyz
        if subdomain:
            high_value_targets = ['paypal', 'apple', 'microsoft', 'google', 'chase', 'wellsfargo', 'bofa', 'netflix', 'amazon']
            for brand in high_value_targets:
                if brand in subdomain and brand != ext.domain:
                    risk_points += 30.0
                    flags.append({
                        "module": "url",
                        "severity": "HIGH",
                        "rule": "deceptive_subdomain",
                        "message": f"Subdomain '{subdomain}' embeds trusted brand '{brand}', while real domain is '{registered_domain}'."
                    })
                    break

        # 7. Non-standard port
        if parsed_parsed.port and parsed_parsed.port not in (80, 443):
            risk_points += 15.0
            flags.append({
                "module": "url",
                "severity": "MEDIUM",
                "rule": "non_standard_port",
                "message": f"Link connects to unusual network port :{parsed_parsed.port}."
            })

        return {
            "url": url,
            "anchor_text": anchor,
            "domain": registered_domain,
            "subdomain": subdomain,
            "tld": tld,
            "is_masked": is_masked,
            "is_blacklisted": is_blacklisted,
            "is_shortener": is_shortener,
            "has_suspicious_tld": has_suspicious_tld,
            "is_ip_address": is_ip_address,
            "risk_points": risk_points,
            "flags": flags
        }

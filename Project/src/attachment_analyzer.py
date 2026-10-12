"""
Attachment Risk Module (Module 9.5)

Evaluates risks associated with email attachments:
- High-risk executable extensions (.exe, .scr, .bat, .vbs, .js, .hta, .ps1, etc.)
- Macro-enabled Office files (.docm, .xlsm, .pptm)
- Disk image payloads used for evasion (.iso, .img, .vhd)
- Double-extension disguise techniques (e.g. 'invoice.pdf.exe')
- Suspicious archive files (.zip, .rar, .7z containing potential payloads)
"""

from typing import Dict, List, Any
from src.ingestion import ParsedEmail, EmailAttachment


class AttachmentAnalyzer:
    """Evaluates the security risk of email attachments."""

    EXECUTABLE_EXTENSIONS = {
        "exe", "scr", "bat", "cmd", "vbs", "js", "hta",
        "pif", "com", "ps1", "cpl", "jar", "wsf", "msp", "msi"
    }

    MACRO_EXTENSIONS = {
        "docm", "xlsm", "pptm", "dotm", "xltm"
    }

    DISK_IMAGE_EXTENSIONS = {
        "iso", "img", "vhd", "vhdx", "dmg"
    }

    ARCHIVE_EXTENSIONS = {
        "zip", "rar", "7z", "tar", "gz", "cab"
    }

    def analyze(self, email_obj: ParsedEmail) -> Dict[str, Any]:
        """Analyze all attachments in the parsed email."""
        indicators: List[Dict[str, Any]] = []
        analyzed_attachments: List[Dict[str, Any]] = []
        raw_risk_score: float = 0.0

        if not email_obj.attachments:
            return {
                "module": "attachment_analysis",
                "risk_score": 0.0,
                "attachment_count": 0,
                "risky_attachment_count": 0,
                "double_extension_count": 0,
                "analyzed_attachments": [],
                "indicators": []
            }

        risky_count = 0
        double_ext_count = 0

        for att in email_obj.attachments:
            att_risk, att_flags = self._evaluate_attachment(att)
            analyzed_attachments.append({
                "filename": att.filename,
                "extension": att.extension,
                "content_type": att.content_type,
                "size_bytes": att.size_bytes,
                "has_double_extension": att.has_double_extension,
                "risk_points": att_risk,
                "flags": att_flags
            })

            if att_risk > 0:
                risky_count += 1
            if att.has_double_extension:
                double_ext_count += 1

            for flag in att_flags:
                indicators.append(flag)

            raw_risk_score += att_risk

        bounded_score = max(0.0, min(100.0, raw_risk_score))

        return {
            "module": "attachment_analysis",
            "risk_score": round(bounded_score, 1),
            "attachment_count": len(email_obj.attachments),
            "risky_attachment_count": risky_count,
            "double_extension_count": double_ext_count,
            "analyzed_attachments": analyzed_attachments,
            "indicators": indicators
        }

    def _evaluate_attachment(self, att: EmailAttachment) -> tuple[float, List[Dict[str, Any]]]:
        flags: List[Dict[str, Any]] = []
        risk = 0.0
        ext = att.extension.lower()

        # 1. Double extension deception (e.g. invoice.pdf.exe)
        if att.has_double_extension:
            risk += 50.0
            flags.append({
                "module": "attachment",
                "severity": "CRITICAL",
                "rule": "double_extension_disguise",
                "message": (
                    f"Attachment '{att.filename}' employs a deceptive double extension to "
                    f"disguise an executable payload as a safe document."
                )
            })

        # 2. Direct Executable / Script
        if ext in self.EXECUTABLE_EXTENSIONS:
            risk += 50.0
            flags.append({
                "module": "attachment",
                "severity": "CRITICAL",
                "rule": "executable_attachment",
                "message": f"Attachment '{att.filename}' has high-risk executable extension (.{ext})."
            })
        # 3. Macro-enabled document
        elif ext in self.MACRO_EXTENSIONS:
            risk += 35.0
            flags.append({
                "module": "attachment",
                "severity": "HIGH",
                "rule": "macro_enabled_document",
                "message": f"Attachment '{att.filename}' contains Office VBA macros (.{ext}), frequently used for dropper infections."
            })
        # 4. Disk Image Container
        elif ext in self.DISK_IMAGE_EXTENSIONS:
            risk += 35.0
            flags.append({
                "module": "attachment",
                "severity": "HIGH",
                "rule": "disk_image_container",
                "message": f"Attachment '{att.filename}' is a disk image container (.{ext}), commonly used to evade anti-malware scanners."
            })
        # 5. Archive
        elif ext in self.ARCHIVE_EXTENSIONS:
            risk += 15.0
            flags.append({
                "module": "attachment",
                "severity": "MEDIUM",
                "rule": "archive_attachment",
                "message": f"Compressed archive attached ('{att.filename}'). Archives can conceal malicious scripts or binaries."
            })

        return risk, flags

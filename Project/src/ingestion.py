"""
Email Ingestion and Feature Parsing Module (Objective 1)

Parses raw email text or .eml files into a structured representation:
- Headers (From, To, Subject, Date, Reply-To, Return-Path, Received hops, Auth headers)
- Sender information (Display name, email address, domain)
- Body content (Plaintext and HTML representation)
- Embedded URLs and anchor text
- Attachment metadata (Filename, size, MIME type, extension, double-extension flag)
"""

import email
from email import policy
from email.utils import parseaddr
import re
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
import tldextract


class EmailAttachment:
    """Represents an attachment extracted from an email."""
    def __init__(self, filename: str, content_type: str, size_bytes: int = 0):
        self.filename = filename
        self.content_type = content_type
        self.size_bytes = size_bytes
        self.extension = self._extract_extension(filename)
        self.has_double_extension = self._check_double_extension(filename)

    @staticmethod
    def _extract_extension(filename: str) -> str:
        if not filename or '.' not in filename:
            return ""
        return filename.rsplit('.', 1)[-1].lower()

    @staticmethod
    def _check_double_extension(filename: str) -> bool:
        if not filename:
            return False
        parts = filename.split('.')
        # More than one dot, e.g., 'invoice.pdf.exe'
        if len(parts) >= 3:
            common_safe_first = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'png'}
            dangerous_second = {'exe', 'scr', 'bat', 'cmd', 'vbs', 'js', 'hta', 'pif', 'com', 'ps1'}
            ext1 = parts[-2].lower()
            ext2 = parts[-1].lower()
            if ext1 in common_safe_first and ext2 in dangerous_second:
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "extension": self.extension,
            "has_double_extension": self.has_double_extension
        }


class ExtractedLink:
    """Represents a hyperlink extracted from email body."""
    def __init__(self, url: str, anchor_text: str = "", source: str = "body"):
        self.url = url.strip()
        self.anchor_text = (anchor_text or "").strip()
        self.source = source  # 'html_anchor' or 'plain_regex'
        self.domain = self._extract_domain(self.url)

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            ext = tldextract.extract(url)
            if ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return ext.domain.lower() if ext.domain else ""
        except Exception:
            return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "anchor_text": self.anchor_text,
            "source": self.source,
            "domain": self.domain
        }


class ParsedEmail:
    """Structured representation of an ingested email."""
    def __init__(self):
        self.raw_headers: Dict[str, str] = {}
        self.all_headers_list: List[tuple] = []
        self.from_raw: str = ""
        self.sender_name: str = ""
        self.sender_email: str = ""
        self.sender_domain: str = ""
        self.to_raw: str = ""
        self.subject: str = ""
        self.date: str = ""
        self.reply_to_raw: str = ""
        self.reply_to_email: str = ""
        self.reply_to_domain: str = ""
        self.return_path_raw: str = ""
        self.return_path_email: str = ""
        self.return_path_domain: str = ""
        self.message_id: str = ""
        self.received_headers: List[str] = []
        self.auth_results: str = ""
        self.received_spf: str = ""
        self.dkim_signature: str = ""
        self.body_plain: str = ""
        self.body_html: str = ""
        self.body_text: str = ""  # Consolidated normalized plain text for NLP
        self.links: List[ExtractedLink] = []
        self.attachments: List[EmailAttachment] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": {
                "raw": self.from_raw,
                "name": self.sender_name,
                "email": self.sender_email,
                "domain": self.sender_domain
            },
            "reply_to": {
                "raw": self.reply_to_raw,
                "email": self.reply_to_email,
                "domain": self.reply_to_domain
            },
            "return_path": {
                "raw": self.return_path_raw,
                "email": self.return_path_email,
                "domain": self.return_path_domain
            },
            "recipient": self.to_raw,
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "received_hops": len(self.received_headers),
            "received_headers": self.received_headers,
            "authentication_headers": {
                "auth_results": self.auth_results,
                "received_spf": self.received_spf,
                "dkim_signature": bool(self.dkim_signature)
            },
            "body_snippet": (self.body_text[:200] + "...") if len(self.body_text) > 200 else self.body_text,
            "body_length": len(self.body_text),
            "link_count": len(self.links),
            "links": [link.to_dict() for link in self.links],
            "attachment_count": len(self.attachments),
            "attachments": [att.to_dict() for att in self.attachments]
        }


class EmailParser:
    """Parses raw text or .eml files into structured ParsedEmail objects."""

    URL_REGEX = re.compile(
        r'(?:https?://|www\.)[a-zA-Z0-9.\-_~:/?#\[\]@!$&\'()*+,;=%]+',
        re.IGNORECASE
    )

    @classmethod
    def parse(cls, raw_input: str | bytes) -> ParsedEmail:
        """Main parsing entry point accepting raw string or bytes."""
        parsed = ParsedEmail()
        
        if isinstance(raw_input, bytes):
            msg = email.message_from_bytes(raw_input, policy=policy.default)
        else:
            # Check if input looks like raw RFC822 or loose email text
            msg = cls._prepare_message(raw_input)

        # Extract Headers
        cls._extract_headers(msg, parsed)

        # Extract Body and Attachments
        cls._extract_payload(msg, parsed)

        # Consolidate text representation
        if not parsed.body_text:
            if parsed.body_plain:
                parsed.body_text = parsed.body_plain.strip()
            elif parsed.body_html:
                soup = BeautifulSoup(parsed.body_html, "html.parser")
                parsed.body_text = soup.get_text(separator=" ").strip()
            else:
                parsed.body_text = ""

        # Extract Links from HTML and Plain Text
        cls._extract_links(parsed)

        return parsed

    @classmethod
    def _prepare_message(cls, raw_text: str) -> email.message.EmailMessage:
        raw_text = raw_text.strip()
        # If user pasted raw email with headers
        if re.search(r'^(?:From|To|Subject|Date|Return-Path):', raw_text, re.MULTILINE | re.IGNORECASE):
            try:
                return email.message_from_string(raw_text, policy=policy.default)
            except Exception:
                pass
        
        # If raw text lacks formal MIME headers, wrap it into a message
        synthetic_msg = f"Subject: (Pasted Content)\n\n{raw_text}"
        return email.message_from_string(synthetic_msg, policy=policy.default)

    @classmethod
    def _extract_headers(cls, msg: email.message.EmailMessage, parsed: ParsedEmail):
        for header, val in msg.items():
            parsed.all_headers_list.append((header, str(val)))
            parsed.raw_headers[header.lower()] = str(val)

        # From
        parsed.from_raw = str(msg.get("From", ""))
        name, address = parseaddr(parsed.from_raw)
        parsed.sender_name = name.strip()
        parsed.sender_email = address.strip().lower()
        if "@" in parsed.sender_email:
            parsed.sender_domain = parsed.sender_email.split("@")[-1].strip().lower()

        # To
        parsed.to_raw = str(msg.get("To", ""))

        # Subject & Date & Message-ID
        parsed.subject = str(msg.get("Subject", ""))
        parsed.date = str(msg.get("Date", ""))
        parsed.message_id = str(msg.get("Message-ID", ""))

        # Reply-To
        parsed.reply_to_raw = str(msg.get("Reply-To", ""))
        if parsed.reply_to_raw:
            _, reply_addr = parseaddr(parsed.reply_to_raw)
            parsed.reply_to_email = reply_addr.strip().lower()
            if "@" in parsed.reply_to_email:
                parsed.reply_to_domain = parsed.reply_to_email.split("@")[-1].strip().lower()

        # Return-Path
        parsed.return_path_raw = str(msg.get("Return-Path", ""))
        if parsed.return_path_raw:
            _, ret_addr = parseaddr(parsed.return_path_raw)
            parsed.return_path_email = ret_addr.strip().lower()
            if "@" in parsed.return_path_email:
                parsed.return_path_domain = parsed.return_path_email.split("@")[-1].strip().lower()

        # Received headers
        received = msg.get_all("Received", [])
        parsed.received_headers = [str(r).strip() for r in received if r]

        # Auth headers
        parsed.auth_results = str(msg.get("Authentication-Results", ""))
        parsed.received_spf = str(msg.get("Received-SPF", ""))
        parsed.dkim_signature = str(msg.get("DKIM-Signature", ""))

    @classmethod
    def _extract_payload(cls, msg: email.message.EmailMessage, parsed: ParsedEmail):
        if not msg.is_multipart():
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            decoded_text = ""
            if payload:
                try:
                    decoded_text = payload.decode(charset, errors="replace")
                except Exception:
                    decoded_text = str(payload)
            else:
                raw_p = msg.get_payload()
                decoded_text = str(raw_p) if raw_p else ""

            if content_type == "text/html":
                parsed.body_html = decoded_text
            elif content_type == "text/plain":
                parsed.body_plain = decoded_text
            else:
                # Might be an attachment if filename exists
                filename = msg.get_filename()
                if filename:
                    parsed.attachments.append(
                        EmailAttachment(filename=filename, content_type=content_type, size_bytes=len(payload or b""))
                    )
                else:
                    parsed.body_plain = decoded_text
            return

        # Multipart message
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            # Check if this part is an attachment
            if "attachment" in content_disposition.lower() or filename:
                att_name = filename or f"unnamed_attachment_{len(parsed.attachments)+1}"
                parsed.attachments.append(
                    EmailAttachment(filename=att_name, content_type=content_type, size_bytes=size)
                )
                continue

            charset = part.get_content_charset() or "utf-8"
            decoded = ""
            if payload:
                try:
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    decoded = str(payload)

            if content_type == "text/plain" and not parsed.body_plain:
                parsed.body_plain = decoded
            elif content_type == "text/html" and not parsed.body_html:
                parsed.body_html = decoded

    @classmethod
    def _extract_links(cls, parsed: ParsedEmail):
        seen_urls = set()

        # 1. HTML Links (<a href="...">anchor text</a>)
        if parsed.body_html:
            try:
                soup = BeautifulSoup(parsed.body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if href.startswith(("http://", "https://", "www.")):
                        anchor_text = a_tag.get_text(separator=" ").strip()
                        if href not in seen_urls:
                            seen_urls.add(href)
                            parsed.links.append(
                                ExtractedLink(url=href, anchor_text=anchor_text, source="html_anchor")
                            )
            except Exception:
                pass

        # 2. Text / Regex links from plain text or consolidated body
        combined_text = f"{parsed.body_plain}\n{parsed.body_text}"
        found_urls = cls.URL_REGEX.findall(combined_text)
        for url in found_urls:
            cleaned_url = url.strip().rstrip('.,;:)]}>"\'')
            if cleaned_url and cleaned_url not in seen_urls:
                seen_urls.add(cleaned_url)
                parsed.links.append(
                    ExtractedLink(url=cleaned_url, anchor_text="", source="plain_regex")
                )

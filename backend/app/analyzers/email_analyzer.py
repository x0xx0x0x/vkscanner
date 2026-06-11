"""
Email content analyzer for VK Scanner.
Parses complete emails (.eml/.msg or manual input) and delegates to sub-analyzers.
Handles attachment extraction and scanning.
"""

from __future__ import annotations

import email
import re
from email import policy
from pathlib import Path
from typing import Optional

from app.models import Finding, FindingSeverity
from app.utils.debug_trace import DebugTracer
from app.analyzers import header_analyzer, link_extractor

SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".hta",
    ".cpl", ".reg", ".inf", ".lnk", ".iso", ".img", ".jar",
    ".html", ".htm",  # HTML attachments can be phishing pages
}


def parse_eml_file(file_bytes: bytes, tracer: DebugTracer) -> dict:
    """
    Parse a .eml file into its constituent parts.
    Returns dict with: subject, sender, reply_to, return_path,
    body_text, body_html, raw_headers, attachments.
    """
    tracer.step("email_parser", "parse_eml", detail=f"Parsing .eml file ({len(file_bytes)} bytes)")

    msg = email.message_from_bytes(file_bytes, policy=policy.default)

    # Extract headers
    raw_headers_lines = []
    for key, value in msg.items():
        raw_headers_lines.append(f"{key}: {value}")
    raw_headers = "\n".join(raw_headers_lines)

    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    tracer.step("email_parser", "headers_extracted",
                detail=f"Subject: {subject[:60]}, From: {sender[:60]}")

    # Extract body parts and attachments
    body_text = ""
    body_html = ""
    attachments: list[dict] = []  # [{filename, content_type, data}]

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename or "attachment" in content_disposition:
                # This is an attachment
                payload = part.get_payload(decode=True)
                if payload and filename:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "data": payload,
                    })
                    tracer.step("email_parser", "attachment_found",
                                detail=f"{filename} ({content_type}, {len(payload)} bytes)")
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="replace")
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode("utf-8", errors="replace")
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            if content_type == "text/html":
                body_html = payload.decode("utf-8", errors="replace")
            else:
                body_text = payload.decode("utf-8", errors="replace")

    tracer.step("email_parser", "parse_complete",
                detail=f"text={len(body_text)} chars, html={len(body_html)} chars, "
                       f"attachments={len(attachments)}")

    return {
        "subject": subject,
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "body_text": body_text,
        "body_html": body_html,
        "raw_headers": raw_headers,
        "attachments": attachments,
    }


def parse_msg_file(file_bytes: bytes, tracer: DebugTracer) -> dict:
    """
    Parse a .msg (Outlook) file into its constituent parts.
    Requires the extract-msg library.
    """
    tracer.step("email_parser", "parse_msg", detail=f"Parsing .msg file ({len(file_bytes)} bytes)")

    try:
        import extract_msg
        import io
        import tempfile
        import os

        # extract_msg needs a file path or file-like object
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            msg = extract_msg.Message(tmp_path)

            subject = msg.subject or ""
            sender = msg.sender or ""
            body_text = msg.body or ""
            body_html = msg.htmlBody.decode("utf-8", errors="replace") if msg.htmlBody else ""

            # Extract headers from msg
            raw_headers = msg.header.as_string() if msg.header else ""

            # Reply-To and Return-Path from headers
            reply_to = ""
            return_path = ""
            if msg.header:
                reply_to = msg.header.get("Reply-To", "")
                return_path = msg.header.get("Return-Path", "")

            # Extract attachments
            attachments: list[dict] = []
            for att in msg.attachments:
                att_data = att.data
                att_name = att.longFilename or att.shortFilename or "unknown"
                if att_data:
                    attachments.append({
                        "filename": att_name,
                        "content_type": "application/octet-stream",
                        "data": att_data if isinstance(att_data, bytes) else att_data.encode(),
                    })
                    tracer.step("email_parser", "attachment_found",
                                detail=f"{att_name} ({len(att_data)} bytes)")

            msg.close()
        finally:
            os.unlink(tmp_path)

        tracer.step("email_parser", "msg_parse_complete",
                    detail=f"text={len(body_text)}, html={len(body_html)}, "
                           f"attachments={len(attachments)}")

        return {
            "subject": subject,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "body_text": body_text,
            "body_html": body_html,
            "raw_headers": raw_headers,
            "attachments": attachments,
        }

    except ImportError:
        tracer.step("email_parser", "msg_error",
                    detail="extract-msg not installed", result="falling back to raw parse")
        # Fallback: try parsing as raw bytes
        return {
            "subject": "", "sender": "", "reply_to": "", "return_path": "",
            "body_text": file_bytes.decode("utf-8", errors="replace"),
            "body_html": "", "raw_headers": "", "attachments": [],
        }


def analyze_email_file(
    file_bytes: bytes,
    filename: str,
    tracer: DebugTracer,
    use_osint: bool = False,
) -> tuple[dict[str, list[Finding]], list[dict]]:
    """
    Parse and analyze an uploaded .eml or .msg file.
    Returns (findings_by_analyzer, attachments).
    """
    ext = Path(filename).suffix.lower()

    if ext == ".msg":
        parsed = parse_msg_file(file_bytes, tracer)
    else:
        parsed = parse_eml_file(file_bytes, tracer)

    # Analyze the parsed email
    results = analyze_email(
        tracer,
        subject=parsed["subject"] or None,
        body_text=parsed["body_text"] or None,
        body_html=parsed["body_html"] or None,
        raw_headers=parsed["raw_headers"] or None,
        sender=parsed["sender"] or None,
        reply_to=parsed["reply_to"] or None,
        return_path=parsed["return_path"] or None,
        use_osint=use_osint,
    )

    # Save email html body to tracer for the UI preview
    tracer.email_body_html = parsed.get("body_html", "") or ""

    # Analyze attachments
    attachment_findings = _analyze_attachments(parsed["attachments"], tracer)
    if attachment_findings:
        results.setdefault("email_analyzer", []).extend(attachment_findings)

    return results, parsed["attachments"]


def _analyze_attachments(
    attachments: list[dict],
    tracer: DebugTracer,
) -> list[Finding]:
    """Analyze email attachments for suspicious indicators."""
    findings: list[Finding] = []

    if not attachments:
        return findings

    tracer.step("email_analyzer", "attachment_analysis",
                detail=f"Analyzing {len(attachments)} attachment(s)")

    for att in attachments:
        filename = att["filename"]
        data = att["data"]
        ext = Path(filename).suffix.lower()

        # Suspicious extension
        if ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            findings.append(Finding(
                category="email", title=f"Suspicious attachment: {filename}",
                description=f"Attachment '{filename}' has a dangerous extension ({ext}) "
                            "commonly used for malware delivery.",
                severity=FindingSeverity.CRITICAL, score_impact=30.0,
                evidence=f"filename={filename}, size={len(data)} bytes",
            ))
            tracer.step("email_analyzer", "suspicious_attachment",
                        detail=f"{filename} ({ext})", score_impact=30.0)

        # Double extension
        stem = Path(filename).stem
        if "." in stem:
            findings.append(Finding(
                category="email", title=f"Double extension: {filename}",
                description=f"Attachment '{filename}' uses a double extension to disguise its type.",
                severity=FindingSeverity.HIGH, score_impact=20.0,
                evidence=filename,
            ))

        # Password-protected archive/doc (detected by existence, actual cracking
        # happens in document_analyzer when attachment is scanned)
        if ext in (".zip", ".pdf", ".docx", ".xlsx", ".pptx"):
            tracer.step("email_analyzer", "scannable_attachment",
                        detail=f"{filename} can be deep-scanned via document analyzer")

    return findings


def analyze_email(
    tracer: DebugTracer,
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    raw_headers: Optional[str] = None,
    sender: Optional[str] = None,
    reply_to: Optional[str] = None,
    return_path: Optional[str] = None,
    use_osint: bool = False,
) -> dict[str, list[Finding]]:
    """
    Analyze an email for phishing indicators.
    Returns a dict of analyzer_name -> findings.
    """
    results: dict[str, list[Finding]] = {
        "email_analyzer": [],
        "header_analyzer": [],
        # Removed nlp_analyzer
        "link_extractor": [],
    }

    tracer.step("email_analyzer", "start", detail="Beginning email analysis")

    # ── Sender analysis ──
    if sender:
        tracer.step("email_analyzer", "sender_check", detail=f"From: {sender}")
        sender_domain = _extract_domain(sender)

        # Check for display name spoofing
        display_match = re.match(r"(.+)\s*<(.+)>", sender)
        if display_match:
            display_name = display_match.group(1).strip()
            actual_email = display_match.group(2).strip()

            # Display name contains an email that differs from actual
            fake_email = re.search(r"[\w.+-]+@[\w.-]+", display_name)
            if fake_email and fake_email.group(0).lower() != actual_email.lower():
                results["email_analyzer"].append(Finding(
                    category="email", title="Display name spoofing",
                    description=f"Display name '{display_name}' contains a different email than the actual sender ({actual_email}).",
                    severity=FindingSeverity.HIGH, score_impact=20.0,
                    evidence=f"Display: {display_name}, Actual: {actual_email}",
                ))
                tracer.step("email_analyzer", "display_name_spoof", result="Spoofing detected", score_impact=20.0)

        # Reply-To mismatch
        if reply_to and sender:
            sender_domain = _extract_domain(sender)
            reply_domain = _extract_domain(reply_to)
            if sender_domain and reply_domain and sender_domain != reply_domain:
                results["email_analyzer"].append(Finding(
                    category="email", title="Reply-To domain mismatch",
                    description=f"Sender domain ({sender_domain}) differs from Reply-To domain ({reply_domain}).",
                    severity=FindingSeverity.HIGH, score_impact=18.0,
                    evidence=f"Sender: {sender}, Reply-To: {reply_to}",
                ))
                tracer.step("email_analyzer", "reply_to_mismatch", score_impact=18.0)

        # Return-Path mismatch
        if return_path and sender:
            sender_domain = _extract_domain(sender)
            rp_domain = _extract_domain(return_path)
            if sender_domain and rp_domain and sender_domain != rp_domain:
                results["email_analyzer"].append(Finding(
                    category="email", title="Return-Path mismatch",
                    description=f"Sender domain ({sender_domain}) differs from Return-Path domain ({rp_domain}).",
                    severity=FindingSeverity.MEDIUM, score_impact=10.0,
                ))

        # OSINT / Domain Age Check
        if use_osint and sender:
            sender_domain = _extract_domain(sender)
            if sender_domain:
                try:
                    import whois
                    from datetime import datetime
                    w = whois.whois(sender_domain)
                    creation_date = w.creation_date
                    if type(creation_date) is list:
                        creation_date = creation_date[0]
                    if creation_date:
                        age_days = (datetime.now() - creation_date).days
                        if age_days < 30:
                            results["email_analyzer"].append(Finding(
                                category="osint", title="Newly Registered Domain (NRD)",
                                description=f"The sender domain '{sender_domain}' was registered very recently ({age_days} days ago). This is highly indicative of disposable infrastructure used in phishing.",
                                severity=FindingSeverity.HIGH, score_impact=25.0,
                                evidence=f"Creation Date: {creation_date}"
                            ))
                            tracer.step("email_analyzer", "domain_age", result=f"{age_days} days old", score_impact=25.0)
                        else:
                            tracer.step("email_analyzer", "domain_age", result=f"{age_days} days old (Safe)")
                except Exception as e:
                    tracer.step("email_analyzer", "domain_age_error", detail=str(e))
                
                # Typosquatting Check
                popular_domains = ["paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com", "netflix.com", "bankofamerica.com", "chase.com", "wellsfargo.com", "dhl.com", "fedex.com"]
                if sender_domain not in popular_domains:
                    from difflib import SequenceMatcher
                    for pop_domain in popular_domains:
                        ratio = SequenceMatcher(None, sender_domain, pop_domain).ratio()
                        if ratio > 0.85:
                            results["email_analyzer"].append(Finding(
                                category="osint", title="Typosquatting Detected",
                                description=f"The sender domain '{sender_domain}' is highly similar to the known brand '{pop_domain}'. This is a common typosquatting technique.",
                                severity=FindingSeverity.CRITICAL, score_impact=30.0,
                                evidence=f"Matched brand: {pop_domain} (Similarity: {ratio:.2f})"
                            ))
                            tracer.step("email_analyzer", "typosquatting", detail=f"{sender_domain} ~ {pop_domain}", score_impact=30.0)
                            break

    # ── Header analysis ──
    if raw_headers:
        results["header_analyzer"] = header_analyzer.analyze_headers(
            raw_headers, tracer, sender=sender or ""
        )

    # ── NLP analysis on subject + body ──
    text_content = ""
    if subject:
        text_content += subject + " "
    if body_text:
        text_content += body_text
    elif body_html:
        # Strip HTML tags for NLP
        text_content += _strip_html(body_html)

    # NLP analysis removed

    # ── Link extraction ──
    link_findings, urls = link_extractor.analyze_links(
        body_text, body_html, tracer
    )
    results["link_extractor"] = link_findings

    # ── Subject analysis ──
    if subject:
        _analyze_subject(subject, results["email_analyzer"], tracer)

    tracer.step("email_analyzer", "complete",
                detail=f"Total findings: {sum(len(f) for f in results.values())}")
    return results


def _analyze_subject(subject: str, findings: list[Finding], tracer: DebugTracer) -> None:
    """Analyze the email subject line for phishing patterns."""
    subject_lower = subject.lower()

    # RE: or FW: prefixes when it's not a real reply
    re_count = len(re.findall(r"\b(re|fw|fwd):\s*", subject_lower))
    if re_count >= 2:
        findings.append(Finding(
            category="email", title="Multiple RE/FW prefixes",
            description="Subject has multiple reply/forward prefixes, possibly faking a conversation thread.",
            severity=FindingSeverity.LOW, score_impact=5.0,
            evidence=subject[:100],
        ))

    # All-caps subject
    if subject == subject.upper() and len(subject) > 10:
        findings.append(Finding(
            category="email", title="ALL CAPS subject",
            description="Subject line is entirely in uppercase, suggesting urgency/spam.",
            severity=FindingSeverity.LOW, score_impact=4.0,
        ))

    # Excessive punctuation
    if subject.count("!") >= 3 or subject.count("?") >= 3:
        findings.append(Finding(
            category="email", title="Excessive punctuation in subject",
            description="Subject contains excessive exclamation/question marks.",
            severity=FindingSeverity.LOW, score_impact=3.0,
        ))

    tracer.step("email_analyzer", "subject_analyzed", detail=f"Subject: {subject[:60]}")


def _extract_domain(email_str: str) -> Optional[str]:
    match = re.search(r"[\w.+-]+@([\w.-]+)", email_str)
    return match.group(1).lower() if match else None


def _strip_html(html: str) -> str:
    """Simple HTML tag stripping."""
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html, "html.parser").get_text(separator=" ", strip=True)
    except ImportError:
        return re.sub(r"<[^>]+>", " ", html)

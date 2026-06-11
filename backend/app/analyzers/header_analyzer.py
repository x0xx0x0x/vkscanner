"""
Email header analyzer for VK Scanner.
Checks SPF, DKIM, DMARC alignment and header anomalies.
"""

from __future__ import annotations

import re
from typing import Optional

from app.models import Finding, FindingSeverity
from app.utils.debug_trace import DebugTracer

SUSPICIOUS_MAILERS = [
    "PHPMailer", "SwiftMailer", "ActionMailer", "Mass Mailer",
    "Bulk Mailer", "MailChimp", "SendGrid",
]


def _parse_header_dict(raw_headers: str) -> dict[str, list[str]]:
    """Parse raw email headers into a dict of name -> [values]."""
    headers: dict[str, list[str]] = {}
    current_key = ""
    current_value = ""
    for line in raw_headers.split("\n"):
        if line and line[0] in (" ", "\t"):
            current_value += " " + line.strip()
        else:
            if current_key:
                headers.setdefault(current_key.lower(), []).append(current_value.strip())
            if ":" in line:
                current_key, _, current_value = line.partition(":")
                current_value = current_value.strip()
            else:
                current_key = ""
                current_value = ""
    if current_key:
        headers.setdefault(current_key.lower(), []).append(current_value.strip())
    return headers


def extract_auth_status(raw_headers: str) -> tuple[str, str, str, str]:
    """
    Parses raw headers to extract SPF, DKIM, DMARC, and SenderIP.
    Returns (spf_status, dkim_status, dmarc_status, sender_ip)
    """
    headers = _parse_header_dict(raw_headers)

    # 1. Parse SPF
    spf_status = "NONE"
    spf_vals = headers.get("received-spf", [])
    if spf_vals:
        val = spf_vals[0].lower()
        if "pass" in val:
            spf_status = "PASS"
        elif "fail" in val:
            if "softfail" in val:
                spf_status = "SOFTFAIL"
            else:
                spf_status = "FAIL"
        elif "neutral" in val:
            spf_status = "NEUTRAL"
        elif "none" in val:
            spf_status = "NONE"
    else:
        # Try authentication-results
        auth_results = headers.get("authentication-results", [])
        for ar in auth_results:
            ar_lower = ar.lower()
            if "spf=" in ar_lower:
                if "spf=pass" in ar_lower:
                    spf_status = "PASS"
                elif "spf=fail" in ar_lower:
                    spf_status = "FAIL"
                elif "spf=softfail" in ar_lower:
                    spf_status = "SOFTFAIL"
                elif "spf=none" in ar_lower:
                    spf_status = "NONE"
                elif "spf=neutral" in ar_lower:
                    spf_status = "NEUTRAL"

    # 2. Parse DKIM
    dkim_status = "NONE"
    dkim_sig = headers.get("dkim-signature", [])
    auth_results = headers.get("authentication-results", [])
    if dkim_sig:
        dkim_status = "PRESENT (Unverified)"
        for ar in auth_results:
            ar_lower = ar.lower()
            if "dkim=pass" in ar_lower:
                dkim_status = "PASS"
                break
            elif "dkim=fail" in ar_lower:
                dkim_status = "FAIL"
                break
    else:
        for ar in auth_results:
            ar_lower = ar.lower()
            if "dkim=pass" in ar_lower:
                dkim_status = "PASS"
                break
            elif "dkim=fail" in ar_lower:
                dkim_status = "FAIL"
                break

    # 3. Parse DMARC
    dmarc_status = "NONE"
    for ar in auth_results:
        ar_lower = ar.lower()
        if "dmarc=pass" in ar_lower:
            dmarc_status = "PASS"
            break
        elif "dmarc=fail" in ar_lower:
            dmarc_status = "FAIL"
            break
        elif "dmarc=" in ar_lower:
            match = re.search(r"dmarc=([a-z]+)", ar_lower)
            if match:
                dmarc_status = match.group(1).upper()
                break

    # 4. Parse SenderIP
    sender_ip = "Unknown"
    for val in spf_vals:
        match = re.search(r"client-ip=([0-9a-f.:]+)", val, re.I)
        if match:
            sender_ip = match.group(1)
            break
    
    if sender_ip == "Unknown":
        for ar in auth_results:
            match = re.search(r"designates\s+([0-9a-f.:]+)", ar, re.I)
            if match:
                sender_ip = match.group(1)
                break
                
    if sender_ip == "Unknown":
        received_vals = headers.get("received", [])
        if received_vals:
            for r_val in reversed(received_vals):
                match = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]", r_val)
                if match:
                    sender_ip = match.group(1)
                    break
                match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", r_val)
                if match:
                    sender_ip = match.group(0)
                    break

    return spf_status, dkim_status, dmarc_status, sender_ip


def analyze_headers(
    raw_headers: str,
    tracer: DebugTracer,
    sender: str = "",
) -> list[Finding]:
    """Analyze email headers for SPF/DKIM/DMARC and anomalies."""
    findings: list[Finding] = []
    if not raw_headers:
        tracer.step("header_analyzer", "skip", detail="No headers provided")
        return findings

    tracer.step("header_analyzer", "start", detail=f"Parsing {len(raw_headers)} chars of headers")
    headers = _parse_header_dict(raw_headers)
    tracer.step("header_analyzer", "parsed", detail=f"Found {len(headers)} unique header names")

    # Extract auth status and Sender IP
    spf_status, dkim_status, dmarc_status, sender_ip = extract_auth_status(raw_headers)
    tracer.step("header_analyzer", "auth_status", 
                detail=f"SPF: {spf_status}, DKIM: {dkim_status}, DMARC: {dmarc_status}, IP: {sender_ip}")

    # ── Local Security Analysis on Auth Results ──
    
    # 1. SPF Check findings
    if spf_status == "FAIL":
        findings.append(Finding(
            category="header", title="SPF Authentication Failed",
            description=f"SPF verification failed. The sending server IP ({sender_ip}) is not authorized to send emails on behalf of this domain.",
            severity=FindingSeverity.HIGH, score_impact=20.0,
            evidence=f"SPF status: FAIL, Sender IP: {sender_ip}"
        ))
        tracer.step("header_analyzer", "spf_result", result="FAIL", score_impact=20.0)
    elif spf_status == "SOFTFAIL":
        findings.append(Finding(
            category="header", title="SPF Soft Fail",
            description="SPF soft-failed. The sending domain has a permissive SPF policy (~all) which tags unauthorized senders but does not block them.",
            severity=FindingSeverity.MEDIUM, score_impact=10.0,
            evidence=f"SPF status: SOFTFAIL, Sender IP: {sender_ip}"
        ))
        tracer.step("header_analyzer", "spf_result", result="SOFTFAIL", score_impact=10.0)
    elif spf_status == "NONE":
        findings.append(Finding(
            category="header", title="Missing SPF Security Policy",
            description="No SPF record found in the email headers. The domain cannot authorize specific sending servers, making it vulnerable to spoofing.",
            severity=FindingSeverity.LOW, score_impact=5.0,
        ))
        tracer.step("header_analyzer", "spf_result", result="NONE", score_impact=5.0)

    # 2. DKIM Check findings
    if dkim_status == "FAIL":
        findings.append(Finding(
            category="header", title="DKIM Signature Verification Failed",
            description="DKIM signature failed validation. The message content may have been altered in transit or the signature is spoofed.",
            severity=FindingSeverity.HIGH, score_impact=15.0,
        ))
        tracer.step("header_analyzer", "dkim_result", result="FAIL", score_impact=15.0)
    elif dkim_status == "NONE":
        findings.append(Finding(
            category="header", title="Missing DKIM Signature",
            description="No DKIM signature present in the email headers. Integrity of the email cannot be validated mathematically.",
            severity=FindingSeverity.LOW, score_impact=5.0,
        ))
        tracer.step("header_analyzer", "dkim_result", result="NONE", score_impact=5.0)

    # 3. DMARC Check findings
    if dmarc_status == "FAIL":
        findings.append(Finding(
            category="header", title="DMARC Alignment Failed",
            description="DMARC validation failed. This indicates the email domain claims to be a specific brand, but headers do not align with SPF or DKIM domains.",
            severity=FindingSeverity.HIGH, score_impact=20.0,
        ))
        tracer.step("header_analyzer", "dmarc_result", result="FAIL", score_impact=20.0)
    elif dmarc_status == "NONE":
        findings.append(Finding(
            category="header", title="Missing DMARC Alignment Policy",
            description="DMARC authentication record not found. Without DMARC, receiving email servers cannot enforce brand spoofing protections.",
            severity=FindingSeverity.MEDIUM, score_impact=8.0,
        ))
        tracer.step("header_analyzer", "dmarc_result", result="NONE", score_impact=8.0)

    # 4. Joint authentication failure (SPF Fail + DMARC Fail) -> Spoofing High Alert
    if (spf_status in ("FAIL", "SOFTFAIL")) and dmarc_status == "FAIL":
        findings.append(Finding(
            category="header", title="Severe Identity Spoofing Indicator",
            description="Both SPF (Sender Authorization) and DMARC alignment checks have failed. Extremely high probability of malicious email spoofing.",
            severity=FindingSeverity.CRITICAL, score_impact=25.0,
            evidence=f"Sender IP: {sender_ip}, SPF: {spf_status}, DMARC: {dmarc_status}"
        ))
        tracer.step("header_analyzer", "joint_auth_fail", result="SPOOFING_ALERT", score_impact=25.0)

    # 5. Local IP Checks
    if sender_ip != "Unknown":
        is_private = False
        if sender_ip.startswith("127.") or sender_ip == "::1":
            is_private = True
        elif sender_ip.startswith("10."):
            is_private = True
        elif sender_ip.startswith("192.168."):
            is_private = True
        elif sender_ip.startswith("172."):
            try:
                second_octet = int(sender_ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    is_private = True
            except Exception:
                pass
        
        if is_private:
            findings.append(Finding(
                category="header", title="Internal/Private Sender IP Address",
                description=f"The email headers report the sender originating from a private IP address ({sender_ip}). This is common in internal testing or header manipulation spoofing.",
                severity=FindingSeverity.MEDIUM, score_impact=10.0,
                evidence=f"Sender IP: {sender_ip}"
            ))
            tracer.step("header_analyzer", "private_sender_ip", result="PRIVATE_IP", score_impact=10.0)

    # ── 6. From/Reply-To mismatch ──
    from_vals = headers.get("from", [])
    reply_to_vals = headers.get("reply-to", [])
    if from_vals and reply_to_vals:
        from_domain = _extract_domain(from_vals[0])
        reply_domain = _extract_domain(reply_to_vals[0])
        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append(Finding(
                category="header", title="From/Reply-To domain mismatch",
                description=f"From domain ({from_domain}) differs from Reply-To ({reply_domain}). Replies would go to a different domain.",
                severity=FindingSeverity.HIGH, score_impact=18.0,
                evidence=f"From: {from_vals[0]}, Reply-To: {reply_to_vals[0]}",
            ))
            tracer.step("header_analyzer", "reply_to_check", result=f"Mismatch: {from_domain} vs {reply_domain}", score_impact=18.0)

    # ── 7. Return-Path mismatch ──
    return_path_vals = headers.get("return-path", [])
    if from_vals and return_path_vals:
        from_domain = _extract_domain(from_vals[0])
        rp_domain = _extract_domain(return_path_vals[0])
        if from_domain and rp_domain and from_domain != rp_domain:
            findings.append(Finding(
                category="header", title="Return-Path mismatch",
                description=f"From domain ({from_domain}) differs from Return-Path ({rp_domain}).",
                severity=FindingSeverity.MEDIUM, score_impact=10.0,
            ))

    # ── 8. Received hop analysis ──
    received = headers.get("received", [])
    if len(received) > 8:
        findings.append(Finding(
            category="header", title="Excessive mail hops",
            description=f"Email passed through {len(received)} servers, which is unusually high.",
            severity=FindingSeverity.LOW, score_impact=4.0,
        ))

    # ── 9. X-Mailer check ──
    x_mailer = headers.get("x-mailer", [])
    user_agent = headers.get("user-agent", [])
    for mailer_val in x_mailer + user_agent:
        for suspicious in SUSPICIOUS_MAILERS:
            if suspicious.lower() in mailer_val.lower():
                findings.append(Finding(
                    category="header", title="Suspicious mail client",
                    description=f"Email sent with '{suspicious}', commonly used in bulk/phishing campaigns.",
                    severity=FindingSeverity.MEDIUM, score_impact=8.0,
                    evidence=mailer_val[:100],
                ))
                break

    tracer.step("header_analyzer", "complete", detail=f"{len(findings)} findings")
    return findings


def _extract_domain(email_str: str) -> Optional[str]:
    """Extract domain from an email address string."""
    match = re.search(r"[\w.+-]+@([\w.-]+)", email_str)
    return match.group(1).lower() if match else None

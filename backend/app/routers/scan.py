"""
VK Scanner API routes.
Endpoints for URL, email, email-file, and document scanning.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional
import urllib.parse

from fastapi import APIRouter, File, Form, UploadFile, HTTPException, Header

from app.models import (
    EmailScanRequest,
    Finding,
    ScanResult,
    ScanType,
    URLScanRequest,
)
from app.analyzers import (
    url_analyzer,
    email_analyzer,
    link_extractor,
    heuristic_engine,
    document_analyzer,
)
from app.utils.debug_trace import DebugTracer
from app.utils.scoring import aggregate_scores, generate_summary

router = APIRouter(prefix="/api/scan", tags=["scan"])


def apply_context_filtering(result: ScanResult) -> ScanResult:
    if result.scan_type == ScanType.DOCUMENT:
        result.email_extracted_headers = None
        result.email_attachment_tree = None
        # We now keep url_redirect_chain and url_extracted_scripts
        result.url_resolved_ip = None
        result.url_domain_created = None
        result.url_technologies = None
        result.url_site_preview = None
    elif result.scan_type == ScanType.URL:
        result.email_extracted_headers = None
        result.email_extracted_ips = None
        result.email_extracted_urls = None
        result.email_extracted_emails = None
        result.email_attachment_tree = None
        result.document_password_found = None
        result.document_password_attempts = None
        result.document_screenshot = None
        result.document_file_previews = None
        result.document_file_checks = None
        result.document_file_metadata = None
        result.document_file_contexts = None
        result.document_file_deobfuscated = None
        result.document_file_strings = None
        result.document_file_entropy = None
    elif result.scan_type == ScanType.EMAIL:
        # We now keep url_redirect_chain and url_extracted_scripts
        result.url_resolved_ip = None
        result.url_domain_created = None
        result.url_technologies = None
        result.url_site_preview = None
    return result

def _aggregate_iocs_and_recursive_urls(
    tracer: DebugTracer,
    findings: list[Finding],
    found_urls: list[str],
    found_ips: list[str],
    found_emails: list[str],
    use_osint: bool
) -> dict:
    iocs = {"urls": found_urls, "ips": found_ips, "emails": found_emails, "domains": [], "hashes": []}
    import urllib.parse
    for u in found_urls:
        try:
            d = urllib.parse.urlparse(u).hostname
            if d and d not in iocs["domains"]:
                iocs["domains"].append(d)
        except Exception:
            pass

    # Recursive URL connection analysis for up to 3 URLs
    from app.analyzers.url_analyzer import _run_local_url_connect_analysis
    
    all_redirect_chains = getattr(tracer, "url_redirect_chain", [])
    all_extracted_scripts = getattr(tracer, "url_extracted_scripts", [])
    
    for u in found_urls[:3]:
        try:
            temp_findings = []
            _run_local_url_connect_analysis(u, tracer, temp_findings, use_whois=use_osint, follow_redirects=True)
            findings.extend(temp_findings)
            if hasattr(tracer, "url_redirect_chain") and tracer.url_redirect_chain:
                # To distinguish which redirect chain belongs to which URL
                if len(tracer.url_redirect_chain) > 0:
                    tracer.url_redirect_chain[0]["source_url"] = u
                all_redirect_chains.extend(tracer.url_redirect_chain)
            if hasattr(tracer, "url_extracted_scripts") and tracer.url_extracted_scripts:
                for script in tracer.url_extracted_scripts:
                    script["source_url"] = u
                all_extracted_scripts.extend(tracer.url_extracted_scripts)
        except Exception as e:
            tracer.step("orchestrator", "recursive_url_error", detail=f"Failed connecting to {u}: {e}")

    tracer.url_redirect_chain = all_redirect_chains
    tracer.url_extracted_scripts = all_extracted_scripts
    
    return iocs

@router.post("/url", response_model=ScanResult, response_model_exclude_none=True)
async def scan_url(
    request: URLScanRequest,
    x_virustotal_key: Optional[str] = Header(None, alias="X-VirusTotal-Key"),
    x_urlscan_key: Optional[str] = Header(None, alias="X-URLScan-Key"),
    x_abuseipdb_key: Optional[str] = Header(None, alias="X-AbuseIPDB-Key"),
    run_third_party: Optional[bool] = Header(False, alias="X-Run-Third-Party")
) -> ScanResult:
    """Scan a single URL for phishing indicators."""
    import hashlib
    from app.database import get_cached_scan
    cache_key = hashlib.sha256(f"URL_{request.url}_{request.use_whois}_{request.follow_redirects}_{run_third_party}".encode()).hexdigest()
    cached = get_cached_scan(cache_key)
    if cached:
        # Append an indicator that it was cached if needed
        cached["summary"] = "[CACHED] " + cached.get("summary", "")
        return ScanResult(**cached)

    tracer = DebugTracer()
    scan_id = str(uuid.uuid4())[:8]

    tracer.step("orchestrator", "scan_start", detail=f"URL scan: {request.url}")

    url_findings = url_analyzer.analyze_url(
        request.url, tracer,
        use_whois=request.use_whois,
        follow_redirects=request.follow_redirects,
    )

    context = {"url": request.url}
    heuristic_findings = heuristic_engine.run_heuristic_engine(context, tracer)

    findings_by_analyzer = {
        "url_analyzer": url_findings,
        "heuristic_engine": heuristic_findings,
    }

    all_findings = url_findings + heuristic_findings
    
    iocs = {
        "urls": [request.url], 
        "ips": [getattr(tracer, "url_resolved_ip", None)] if getattr(tracer, "url_resolved_ip", None) else [], 
        "emails": [], 
        "domains": [urllib.parse.urlparse(request.url).hostname] if getattr(tracer, "url_resolved_ip", None) else [], 
        "hashes": []
    }
    
    risk_score, classification, confidence, breakdowns = aggregate_scores(findings_by_analyzer)
    summary = generate_summary(risk_score, classification, all_findings)

    # Optional URLScan.io submission
    third_party_res = {}
    if run_third_party and x_urlscan_key:
        from app.utils.third_party import scan_urlscan
        tracer.step("orchestrator", "third_party_urlscan", detail=f"Submitting {request.url} to URLScan...")
        res = await scan_urlscan(request.url, x_urlscan_key)
        if res:
            third_party_res["urlscan"] = res

    tracer.step("orchestrator", "scan_complete", detail=f"Score: {risk_score}, Class: {classification.value}")

    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.URL,
        target=request.url,
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        summary=summary,
        findings=all_findings,
        analyzer_breakdown=breakdowns,
        debug_trace=tracer.get_steps(),
        document_file_previews=tracer.file_previews,
        document_file_checks=tracer.file_checks,
        document_file_metadata=tracer.file_metadata,
        document_file_contexts=tracer.file_contexts,
        document_file_deobfuscated=tracer.file_deobfuscated,
        document_file_strings=tracer.file_strings,
        third_party_results=third_party_res,
        url_redirect_chain=getattr(tracer, "url_redirect_chain", []),
        url_resolved_ip=getattr(tracer, "url_resolved_ip", None),
        url_domain_created=getattr(tracer, "url_domain_created", None),
        url_technologies=getattr(tracer, "url_technologies", []),
        url_extracted_scripts=getattr(tracer, "url_extracted_scripts", []),
        url_site_preview=getattr(tracer, "url_site_preview", {}),
        iocs=iocs,
        cache_key=cache_key,
    )
    result = apply_context_filtering(result)
    try:
        from app.database import save_scan
        save_scan(result.model_dump())
    except Exception:
        pass
    return result


@router.post("/email", response_model=ScanResult, response_model_exclude_none=True)
async def scan_email(request: EmailScanRequest) -> ScanResult:
    """Scan email content (manual fields) for phishing indicators."""
    import hashlib
    from app.database import get_cached_scan
    cache_key = hashlib.sha256(f"EMAIL_{request.subject}_{request.sender}_{request.body_text}_{request.body_html}_{request.use_osint}".encode()).hexdigest()
    cached = get_cached_scan(cache_key)
    if cached:
        cached["summary"] = "[CACHED] " + cached.get("summary", "")
        return ScanResult(**cached)

    tracer = DebugTracer()
    scan_id = str(uuid.uuid4())[:8]

    target = request.subject or request.sender or "Email content"
    tracer.step("orchestrator", "scan_start", detail=f"Email scan: {target}")

    results = email_analyzer.analyze_email(
        tracer,
        subject=request.subject,
        body_text=request.body_text,
        body_html=request.body_html,
        raw_headers=request.raw_headers,
        sender=request.sender,
        reply_to=request.reply_to,
        return_path=request.return_path,
        use_osint=request.use_osint,
    )

    context = {
        "text": request.body_text or "",
        "html": request.body_html or "",
        "subject": request.subject or "",
        "url": "",
    }
    heuristic_findings = heuristic_engine.run_heuristic_engine(context, tracer)
    results["heuristic_engine"] = heuristic_findings

    all_findings: list[Finding] = []
    for f_list in results.values():
        all_findings.extend(f_list)

    risk_score, classification, confidence, breakdowns = aggregate_scores(results)
    summary = generate_summary(risk_score, classification, all_findings)

    tracer.step("orchestrator", "scan_complete", detail=f"Score: {risk_score}")

    # 1. Extracted email headers dictionary
    from app.analyzers.header_analyzer import extract_auth_status
    spf_status, dkim_status, dmarc_status, sender_ip = extract_auth_status(request.raw_headers or "")
    extracted_hdrs = {
        "Subject": request.subject or "",
        "From": request.sender or "",
        "Reply-To": request.reply_to or "",
        "Return-Path": request.return_path or "",
        "Raw": request.raw_headers or "",
        "SPF": spf_status,
        "DKIM": dkim_status,
        "DMARC": dmarc_status,
        "SenderIP": sender_ip
    }

    # 2. Extract public IPs using regex
    import re
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    all_email_content = (request.raw_headers or "") + "\n" + (request.body_text or "") + "\n" + (request.body_html or "")
    found_ips = list(set(ip_pattern.findall(all_email_content)))
    public_ips = [
        ip for ip in found_ips 
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("0."))
    ]

    # 3. Extract URLs using regex
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    found_urls = list(set(url_pattern.findall(all_email_content)))

    # 4. Extract email addresses using regex
    email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    found_emails = list(set(email_pattern.findall(all_email_content)))

    # Aggregate IoCs and run recursive URL connection analysis
    iocs = _aggregate_iocs_and_recursive_urls(
        tracer=tracer,
        findings=all_findings,
        found_urls=found_urls,
        found_ips=public_ips,
        found_emails=found_emails,
        use_osint=request.use_osint
    )

    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.EMAIL,
        target=target,
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        summary=summary,
        findings=all_findings,
        analyzer_breakdown=breakdowns,
        debug_trace=tracer.get_steps(),
        document_file_previews=tracer.file_previews,
        document_file_checks=tracer.file_checks,
        document_file_metadata=tracer.file_metadata,
        document_file_contexts=tracer.file_contexts,
        document_file_deobfuscated=tracer.file_deobfuscated,
        email_extracted_headers=extracted_hdrs,
        email_extracted_ips=public_ips,
        email_extracted_urls=found_urls,
        email_extracted_emails=found_emails,
        email_attachment_tree=[],
        email_body_html=tracer.email_body_html,
        iocs=iocs,
        url_redirect_chain=getattr(tracer, "url_redirect_chain", []),
        url_extracted_scripts=getattr(tracer, "url_extracted_scripts", []),
        cache_key=cache_key,
    )
    result = apply_context_filtering(result)
    try:
        from app.database import save_scan
        save_scan(result.model_dump())
    except Exception:
        pass
    return result


@router.post("/email-file", response_model=ScanResult, response_model_exclude_none=True)
async def scan_email_file(
    file: UploadFile = File(...),
    x_virustotal_key: Optional[str] = Header(None, alias="X-VirusTotal-Key"),
    x_urlscan_key: Optional[str] = Header(None, alias="X-URLScan-Key"),
    x_abuseipdb_key: Optional[str] = Header(None, alias="X-AbuseIPDB-Key"),
    run_third_party: Optional[bool] = Header(False, alias="X-Run-Third-Party")
) -> ScanResult:
    """
    Scan an uploaded .eml or .msg email file.
    Parses headers, body, and attachments automatically.
    Attachments are also scanned via the document analyzer.
    """
    tracer = DebugTracer()
    scan_id = str(uuid.uuid4())[:8]

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".eml", ".msg"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported email format '{ext}'. Use .eml or .msg files."
        )

    file_bytes = await file.read()
    
    import hashlib
    from app.database import get_cached_scan
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    cache_key = hashlib.sha256(f"EML_{file_hash}_{run_third_party}".encode()).hexdigest()
    cached = get_cached_scan(cache_key)
    if cached:
        cached["summary"] = "[CACHED] " + cached.get("summary", "")
        return ScanResult(**cached)

    tracer.step("orchestrator", "scan_start", detail=f"Email file scan: {file.filename}")

    # Parse and analyze the email file
    results, attachments = email_analyzer.analyze_email_file(
        file_bytes, file.filename, tracer, use_osint=run_third_party
    )

    # Deep-scan attachments through the document analyzer
    doc_findings: list[Finding] = []
    for att in attachments:
        # Forensic magic type check
        att_ext = document_analyzer.detect_extension_by_magic(att["data"], att["filename"])
        if att_ext in document_analyzer.SUPPORTED_EXTENSIONS:
            tracer.step("orchestrator", "scanning_attachment",
                        detail=f"Deep-scanning attachment: {att['filename']} (Detected type: {att_ext})")
            att_findings, _, _, _ = document_analyzer.analyze_document(
                att["data"], att["filename"], tracer
            )
            doc_findings.extend(att_findings)
        else:
            tracer.step("orchestrator", "skip_attachment",
                        detail=f"Omit attachment: {att['filename']} (Unsupported type: {att_ext})")

    if doc_findings:
        results["document_analyzer"] = doc_findings

    # Run heuristic engine
    # Build context from parsed email content
    parsed = email_analyzer.parse_eml_file(file_bytes, tracer) if ext == ".eml" \
        else email_analyzer.parse_msg_file(file_bytes, tracer)
    
    body_text = parsed.get("body_text", "")
    body_html = parsed.get("body_html", "")
    subject = parsed.get("subject", "")
    sender = parsed.get("sender", "")
    raw_hdrs = parsed.get("raw_headers", "")

    context = {
        "text": body_text,
        "html": body_html,
        "subject": subject,
        "url": "",
    }
    heuristic_findings = heuristic_engine.run_heuristic_engine(context, tracer)
    results["heuristic_engine"] = heuristic_findings

    # 1. Extracted email headers dictionary
    from app.analyzers.header_analyzer import extract_auth_status
    spf_status, dkim_status, dmarc_status, sender_ip = extract_auth_status(raw_hdrs)
    extracted_hdrs = {
        "Subject": subject,
        "From": sender,
        "Reply-To": parsed.get("reply_to", ""),
        "Return-Path": parsed.get("return_path", ""),
        "Raw": raw_hdrs,
        "SPF": spf_status,
        "DKIM": dkim_status,
        "DMARC": dmarc_status,
        "SenderIP": sender_ip
    }

    # 2. Extract public IPs using regex
    import re
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    all_email_content = raw_hdrs + "\n" + body_text + "\n" + body_html
    found_ips = list(set(ip_pattern.findall(all_email_content)))
    public_ips = [
        ip for ip in found_ips 
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("0."))
    ]

    # 3. Extract URLs using regex
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    found_urls = list(set(url_pattern.findall(all_email_content)))

    # 4. Extract email addresses using regex
    email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    found_emails = list(set(email_pattern.findall(all_email_content)))

    # 4. Build a beautiful attachment ZIP-aware file tree structure
    import zipfile
    import io
    attachment_tree = []
    
    for att in attachments:
        att_name = att["filename"]
        att_size = len(att["data"])
        att_type = att.get("content_type", "application/octet-stream")
        children = []
        
        # If it is a ZIP, list its internal structure
        if att_name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(att["data"])) as z:
                    for z_info in z.infolist():
                        children.append({
                            "name": z_info.filename,
                            "size": z_info.file_size,
                            "type": "directory" if z_info.is_dir() else "file"
                        })
            except Exception:
                pass
                
        attachment_tree.append({
            "name": att_name,
            "size": att_size,
            "type": att_type,
            "children": children
        })

    # Aggregate scores
    all_findings: list[Finding] = []
    for f_list in results.values():
        all_findings.extend(f_list)

    risk_score, classification, confidence, breakdowns = aggregate_scores(results)
    target = subject or file.filename
    summary = generate_summary(risk_score, classification, all_findings)

    # 5. Optional third-party dynamic checkups
    third_party_res = {}
    if run_third_party:
        import hashlib
        from app.utils.third_party import scan_virustotal_hash, scan_abuseipdb, scan_urlscan
        
        # Check attachment hashes on VT
        if x_virustotal_key and attachments:
            tracer.step("orchestrator", "third_party_virustotal_attachments", detail=f"Querying VT for {len(attachments)} attachment hash(es)")
            vt_attachments = {}
            for att in attachments:
                att_hash = hashlib.sha256(att["data"]).hexdigest()
                res = await scan_virustotal_hash(att_hash, x_virustotal_key)
                if res:
                    vt_attachments[att["filename"]] = res
            if vt_attachments:
                third_party_res["vt_attachments"] = vt_attachments

        # Check public IPs on AbuseIPDB
        if x_abuseipdb_key and public_ips:
            tracer.step("orchestrator", "third_party_abuseipdb", detail=f"Checking {len(public_ips[:5])} public IPs on AbuseIPDB...")
            abuse_ips = {}
            for ip in public_ips[:5]:
                res = await scan_abuseipdb(ip, x_abuseipdb_key)
                if res:
                    abuse_ips[ip] = res
            if abuse_ips:
                third_party_res["abuseipdb_ips"] = abuse_ips

        # Check URLs on URLScan
        if x_urlscan_key and found_urls:
            tracer.step("orchestrator", "third_party_urlscan_links", detail=f"Submitting {len(found_urls[:3])} URLs to URLScan...")
            urlscan_res = {}
            for url in found_urls[:3]:
                res = await scan_urlscan(url, x_urlscan_key)
                if res:
                    urlscan_res[url] = res
            if urlscan_res:
                third_party_res["urlscan_urls"] = urlscan_res

    tracer.step("orchestrator", "scan_complete",
                detail=f"Score: {risk_score}, Attachments tree size: {len(attachments)}")

    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.EMAIL,
        target=target,
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        summary=summary,
        findings=all_findings,
        analyzer_breakdown=breakdowns,
        debug_trace=tracer.get_steps(),
        document_file_previews=tracer.file_previews,
        document_file_checks=tracer.file_checks,
        document_file_metadata=tracer.file_metadata,
        document_file_contexts=tracer.file_contexts,
        document_file_deobfuscated=tracer.file_deobfuscated,
        email_extracted_headers=extracted_hdrs,
        email_extracted_ips=public_ips,
        email_extracted_urls=found_urls,
        email_extracted_emails=found_emails,
        email_attachment_tree=attachment_tree,
        third_party_results=third_party_res,
        cache_key=cache_key,
    )
    result = apply_context_filtering(result)
    try:
        from app.database import save_scan
        save_scan(result.model_dump())
    except Exception:
        pass
    return result
    return result


@router.post("/document", response_model=ScanResult, response_model_exclude_none=True)
async def scan_document(
    file: UploadFile = File(...),
    password: Optional[str] = Form(None),
    custom_passwords: Optional[str] = Form(None),
    wordlist_file: Optional[UploadFile] = File(None),
    x_virustotal_key: Optional[str] = Header(None, alias="X-VirusTotal-Key"),
    x_urlscan_key: Optional[str] = Header(None, alias="X-URLScan-Key"),
    x_abuseipdb_key: Optional[str] = Header(None, alias="X-AbuseIPDB-Key"),
    run_third_party: Optional[bool] = Header(False, alias="X-Run-Third-Party"),
) -> ScanResult:
    """
    Scan a document for phishing/malicious indicators.
    Supports an optional wordlist file (.txt) for brute-force cracking.
    """
    tracer = DebugTracer()
    scan_id = str(uuid.uuid4())[:8]

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    file_bytes = await file.read()
    filename = file.filename

    # Calculate SHA256 of the document
    import hashlib
    from app.database import get_cached_scan
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    cache_key = hashlib.sha256(f"DOC_{file_hash}_{password}_{custom_passwords}_{run_third_party}".encode()).hexdigest()
    cached = get_cached_scan(cache_key)
    if cached:
        cached["summary"] = "[CACHED] " + cached.get("summary", "")
        return ScanResult(**cached)

    tracer.step("orchestrator", "scan_start", detail=f"Document scan: {filename}")

    # Build wordlist from comma-separated text + uploaded file
    wordlist: list[str] = []
    if custom_passwords:
        wordlist.extend(p.strip() for p in custom_passwords.split(",") if p.strip())

    if wordlist_file and wordlist_file.filename:
        tracer.step("orchestrator", "wordlist_upload",
                    detail=f"Loading wordlist: {wordlist_file.filename}")
        wl_bytes = await wordlist_file.read()
        try:
            wl_text = wl_bytes.decode("utf-8", errors="replace")
            wl_passwords = [line.strip() for line in wl_text.splitlines() if line.strip()]
            wordlist.extend(wl_passwords)
            tracer.step("orchestrator", "wordlist_loaded",
                        detail=f"Loaded {len(wl_passwords)} passwords from {wordlist_file.filename}")
        except Exception as e:
            tracer.step("orchestrator", "wordlist_error", detail=str(e), result="skipped")

    # Run document analyzer
    doc_findings, pw_found, pw_attempts, screenshot_base64 = document_analyzer.analyze_document(
        file_bytes, filename, tracer,
        password=password,
        custom_wordlist=wordlist if wordlist else None,
    )

    # Run heuristic engine
    context = {"url": "", "text": "", "html": ""}
    heuristic_findings = heuristic_engine.run_heuristic_engine(context, tracer)

    findings_by_analyzer = {
        "document_analyzer": doc_findings,
        "heuristic_engine": heuristic_findings,
    }

    all_findings = doc_findings + heuristic_findings
    risk_score, classification, confidence, breakdowns = aggregate_scores(findings_by_analyzer)
    summary = generate_summary(risk_score, classification, all_findings)

    # Optional third-party VirusTotal hash check
    third_party_res = {}
    if run_third_party:
        from app.utils.third_party import scan_virustotal_hash
        if x_virustotal_key:
            tracer.step("orchestrator", "third_party_virustotal_document", detail=f"Querying VT for document hash: {file_hash}")
            res = await scan_virustotal_hash(file_hash, x_virustotal_key)
            if res:
                third_party_res["virustotal"] = res

    # Extract URLs and IPs from document previews (including OCR text)
    import re
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    
    doc_text_parts = []
    for text in (tracer.file_previews or {}).values():
        if text:
            doc_text_parts.append(text)
            
    all_doc_content = "\n".join(doc_text_parts)
    found_urls = list(set(url_pattern.findall(all_doc_content)))
    found_ips = list(set(ip_pattern.findall(all_doc_content)))
    found_emails = list(set(email_pattern.findall(all_doc_content)))
    public_ips = [
        ip for ip in found_ips 
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("0."))
    ]

    # Optional reputation checks for document links/IPs
    if run_third_party:
        if x_abuseipdb_key and public_ips:
            tracer.step("orchestrator", "third_party_abuseipdb_document", detail=f"Checking {len(public_ips[:5])} document IPs on AbuseIPDB...")
            abuse_ips = {}
            for ip in public_ips[:5]:
                from app.utils.third_party import scan_abuseipdb
                res = await scan_abuseipdb(ip, x_abuseipdb_key)
                if res:
                    abuse_ips[ip] = res
            if abuse_ips:
                third_party_res["abuseipdb_ips"] = abuse_ips

        if x_urlscan_key and found_urls:
            tracer.step("orchestrator", "third_party_urlscan_document_links", detail=f"Checking {len(found_urls[:3])} document URLs on URLScan...")
            urlscan_res = {}
            for url in found_urls[:3]:
                from app.utils.third_party import scan_urlscan
                res = await scan_urlscan(url, x_urlscan_key)
                if res:
                    urlscan_res[url] = res
            if urlscan_res:
                third_party_res["urlscan_urls"] = urlscan_res

    # Aggregate IoCs and run recursive URL connection analysis
    # (By default use_osint is True for URL recursive check since we want live info if run_third_party is true, else false)
    iocs = _aggregate_iocs_and_recursive_urls(
        tracer=tracer,
        findings=all_findings,
        found_urls=found_urls,
        found_ips=public_ips,
        found_emails=found_emails,
        use_osint=run_third_party
    )
    if pw_found:
        iocs["hashes"] = [] # Initialize if we had hashes
        
    tracer.step("orchestrator", "scan_complete", detail=f"Score: {risk_score}")

    result = ScanResult(
        scan_id=scan_id,
        scan_type=ScanType.DOCUMENT,
        target=filename,
        risk_score=risk_score,
        classification=classification,
        confidence=confidence,
        summary=summary,
        findings=all_findings,
        analyzer_breakdown=breakdowns,
        debug_trace=tracer.get_steps(),
        document_password_found=pw_found,
        document_password_attempts=pw_attempts,
        document_screenshot=screenshot_base64,
        document_file_previews=tracer.file_previews,
        document_file_checks=tracer.file_checks,
        document_file_metadata=tracer.file_metadata,
        document_file_contexts=tracer.file_contexts,
        document_file_deobfuscated=tracer.file_deobfuscated,
        document_file_entropy=getattr(tracer, "file_entropy", {}),
        email_extracted_ips=public_ips,
        email_extracted_urls=found_urls,
        email_extracted_emails=found_emails,
        third_party_results=third_party_res,
        iocs=iocs,
        url_redirect_chain=getattr(tracer, "url_redirect_chain", []),
        url_extracted_scripts=getattr(tracer, "url_extracted_scripts", []),
        cache_key=cache_key,
    )
    result = apply_context_filtering(result)
    try:
        from app.database import save_scan
        save_scan(result.model_dump())
    except Exception:
        pass
    return result


@router.get("/history")
async def get_scan_history():
    """Retrieve all past local scans (metadata only)."""
    from app.database import get_history
    try:
        return get_history()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_iocs(q: str):
    """Search history for scans containing specific IoCs."""
    from app.database import search_history
    if not q or len(q) < 2:
        return {"results": []}
    try:
        return {"results": search_history(q)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieve complete scan details including screenshots and traces by ID."""
    from app.database import get_scan
    try:
        scan_details = get_scan(scan_id)
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan record not found")
        return scan_details
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/history/{scan_id}")
async def delete_scan_record(scan_id: str):
    """Delete a single scan record from local history."""
    from app.database import delete_scan
    try:
        success = delete_scan(scan_id)
        if not success:
            raise HTTPException(status_code=404, detail="Scan record not found")
        return {"status": "success", "message": f"Scan {scan_id} deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/history")
async def clear_scan_history():
    """Clear all past scan records from local database."""
    from app.database import clear_history
    try:
        clear_history()
        return {"status": "success", "message": "All scan records cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/yara/rules")
async def list_yara_rules():
    """List all custom YARA rules from rules directory."""
    import os
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
    os.makedirs(rules_dir, exist_ok=True)
    rules = []
    
    for filename in os.listdir(rules_dir):
        if filename.endswith((".yar", ".yara")):
            path = os.path.join(rules_dir, filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                rules.append({
                    "filename": filename,
                    "is_builtin": filename == "builtin_vkscanner_rules.yara",
                    "content": content
                })
            except Exception:
                pass
    return rules


@router.post("/yara/rules")
async def add_yara_rule(file: UploadFile = File(...)):
    """Upload a new custom YARA rule file (.yar or .yara)."""
    import os
    if not file.filename or not file.filename.endswith((".yar", ".yara")):
        raise HTTPException(status_code=400, detail="Only .yar or .yara files are supported")
    
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
    os.makedirs(rules_dir, exist_ok=True)
    
    path = os.path.join(rules_dir, file.filename)
    try:
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8", errors="ignore")
        
        # Validate YARA rule syntax before saving
        import yara
        try:
            yara.compile(source=content_str)
        except Exception as compile_err:
            raise HTTPException(status_code=400, detail=f"YARA syntax compilation error: {str(compile_err)}")
            
        with open(path, "wb") as f:
            f.write(content_bytes)
            
        from app.analyzers.document_analyzer import compile_yara_rules
        compile_yara_rules()
        return {"status": "success", "message": f"YARA rule '{file.filename}' uploaded and compiled successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/yara/rules/{filename}")
async def delete_yara_rule(filename: str):
    """Delete a custom YARA rule file."""
    import os
    if filename == "builtin_vkscanner_rules.yara":
        raise HTTPException(status_code=400, detail="Cannot delete built-in YARA rules")
        
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
    path = os.path.join(rules_dir, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="YARA rule file not found")
        
    try:
        os.remove(path)
        from app.analyzers.document_analyzer import compile_yara_rules
        compile_yara_rules()
        return {"status": "success", "message": f"YARA rule '{filename}' deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


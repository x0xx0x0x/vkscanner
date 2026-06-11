"""
Pydantic models for VK Scanner API requests and responses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional, Any

from pydantic import BaseModel, Field


# ──────────────────────────── Enums ────────────────────────────

class RiskClassification(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanType(str, Enum):
    URL = "url"
    EMAIL = "email"
    DOCUMENT = "document"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ──────────────────────────── Request Models ────────────────────────────

class URLScanRequest(BaseModel):
    """Request to scan a single URL."""
    url: str = Field(..., description="URL to analyze", min_length=1)
    follow_redirects: bool = Field(True, description="Whether to follow redirect chains")
    use_whois: bool = Field(True, description="Whether to perform WHOIS lookup")


class EmailScanRequest(BaseModel):
    """Request to scan email content."""
    subject: Optional[str] = Field(None, description="Email subject line")
    body_text: Optional[str] = Field(None, description="Plain text body")
    body_html: Optional[str] = Field(None, description="HTML body content")
    raw_headers: Optional[str] = Field(None, description="Raw email headers")
    sender: Optional[str] = Field(None, description="Sender email address")
    reply_to: Optional[str] = Field(None, description="Reply-to address")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    use_osint: bool = Field(False, description="Enable third-party lookups like WHOIS")


# ──────────────────────────── Response Models ────────────────────────────

class DebugStep(BaseModel):
    """A single step in the analysis debug trace."""
    timestamp: str = Field(..., description="ISO timestamp of this step")
    analyzer: str = Field(..., description="Name of the analyzer module")
    action: str = Field(..., description="What the analyzer did")
    detail: str = Field("", description="Additional detail or data examined")
    result: str = Field("", description="Outcome of this step")
    score_impact: float = Field(0.0, description="Points added/removed by this step")


class Finding(BaseModel):
    """An individual finding from analysis."""
    category: str = Field(..., description="Category (url, email, header, nlp, link, document)")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description")
    severity: FindingSeverity = Field(..., description="Severity level")
    score_impact: float = Field(0.0, description="Points contributed to total score")
    evidence: Optional[str] = Field(None, description="Raw evidence/data that triggered this finding")


class AnalyzerBreakdown(BaseModel):
    """Score contribution from a single analyzer."""
    analyzer: str
    score: float = Field(0.0, description="Score from this analyzer (0-100 scale contribution)")
    weight: float = Field(0.0, description="Weight of this analyzer in the final score")
    weighted_score: float = Field(0.0, description="score * weight")
    findings_count: int = Field(0)


class ScanResult(BaseModel):
    """Complete scan result."""
    scan_id: str = Field(..., description="Unique scan identifier")
    scan_type: ScanType = Field(..., description="Type of scan performed")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    target: str = Field(..., description="What was scanned (URL, email subject, filename)")
    cache_key: Optional[str] = Field(None, description="Cache hash key")

    # Risk assessment
    risk_score: float = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    classification: RiskClassification = Field(..., description="Risk classification")
    confidence: float = Field(..., ge=0, le=100, description="Confidence in the assessment")
    summary: str = Field(..., description="Human-readable summary of the assessment")

    # Detailed results
    findings: list[Finding] = Field(default_factory=list)
    analyzer_breakdown: list[AnalyzerBreakdown] = Field(default_factory=list)

    # Debug trace
    debug_trace: list[DebugStep] = Field(default_factory=list)

    # Document-specific
    document_password_found: Optional[str] = Field(None, description="Password if brute-forced")
    document_password_attempts: Optional[int] = Field(None, description="Number of attempts tried")
    document_screenshot: Optional[str] = Field(None, description="Base64 encoded PNG screenshot of the document's first page")
    document_file_previews: Optional[dict[str, str]] = Field(default_factory=dict, description="Mapping of filename to content preview")
    document_file_checks: Optional[dict[str, list[dict]]] = Field(default_factory=dict, description="Mapping of filename to checklist status")
    document_file_metadata: Optional[dict[str, dict]] = Field(default_factory=dict, description="Mapping of filename to metadata dict")
    document_file_contexts: Optional[dict[str, str]] = Field(default_factory=dict, description="Mapping of filename to classification context string")
    document_file_deobfuscated: Optional[dict[str, list[dict]]] = Field(default_factory=dict, description="Mapping of filename to list of deobfuscated payload dictionaries")
    document_file_strings: Optional[dict[str, str]] = Field(default_factory=dict, description="Mapping of filename to extracted strings")
    
    # Email forensic details
    email_extracted_headers: Optional[dict[str, str]] = Field(default_factory=dict, description="Extracted email headers dictionary")
    email_extracted_ips: Optional[list[str]] = Field(default_factory=list, description="Extracted IP addresses")
    email_extracted_urls: Optional[list[str]] = Field(default_factory=list, description="Extracted URLs")
    email_extracted_emails: Optional[list[str]] = Field(default_factory=list, description="Extracted email addresses")
    email_attachment_tree: Optional[list[dict]] = Field(default_factory=list, description="Extracted attachments tree structure")
    email_body_html: Optional[str] = Field(None, description="Extracted raw HTML body of the email")
    
    # Third-party scan results
    third_party_results: Optional[dict[str, Any]] = Field(default_factory=dict, description="Optional third-party threat feeds results")

    # Local URL Scan details (urlscan.io simulation)
    url_redirect_chain: Optional[list[dict]] = Field(default_factory=list, description="Redirect chain metadata")
    url_resolved_ip: Optional[str] = Field(None, description="Resolved IP address")
    url_domain_created: Optional[str] = Field(None, description="Domain WHOIS creation date")
    url_technologies: Optional[list[str]] = Field(default_factory=list, description="Technologies detected on site")
    url_extracted_scripts: Optional[list[dict]] = Field(default_factory=list, description="Extracted javascript scripts and their analysis")
    url_site_preview: Optional[dict] = Field(default_factory=dict, description="HTML site text/input structure preview")

    # Entropy and IoCs
    document_file_entropy: Optional[dict[str, float]] = Field(default_factory=dict, description="Mapping of filename to Shannon entropy value")
    iocs: Optional[dict[str, list[str]]] = Field(default_factory=dict, description="Extracted Indicators of Compromise grouped by type (ips, urls, emails, domains, hashes)")




"""
Link extractor for VK Scanner.
Extracts and analyzes URLs from plain text and HTML content.
Detects display-vs-href mismatches and shortened URLs.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from app.models import Finding, FindingSeverity
from app.utils.debug_trace import DebugTracer

# Regex to extract URLs from plain text
URL_REGEX = re.compile(
    r"https?://[^\s<>\"')\]]+|"
    r"www\.[^\s<>\"')\]]+|"
    r"ftp://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
    "rb.gy", "v.gd", "qr.ae", "tiny.cc",
}


def extract_links_from_text(text: str) -> list[str]:
    """Extract all URLs from plain text."""
    return URL_REGEX.findall(text)


def extract_links_from_html(html: str) -> list[dict[str, str]]:
    """Extract links from HTML, capturing both href and display text."""
    links: list[dict[str, str]] = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            display = a_tag.get_text(strip=True)
            links.append({"href": href, "display": display})

        # Also extract from meta refresh, iframe src, form action
        for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            content = meta.get("content", "")
            url_match = re.search(r"url=(.+)", content, re.I)
            if url_match:
                links.append({"href": url_match.group(1).strip(), "display": "[meta-refresh]"})

        for iframe in soup.find_all("iframe", src=True):
            links.append({"href": iframe["src"], "display": "[iframe]"})

        for form in soup.find_all("form", action=True):
            links.append({"href": form["action"], "display": "[form-action]"})

    except ImportError:
        # Fallback: regex extraction
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.I)
        for match in href_pattern.finditer(html):
            links.append({"href": match.group(1), "display": ""})

    return links


def analyze_links(
    text: Optional[str],
    html: Optional[str],
    tracer: DebugTracer,
) -> tuple[list[Finding], list[str]]:
    """
    Extract and analyze links from text and HTML.
    Returns (findings, all_urls_extracted).
    """
    findings: list[Finding] = []
    all_urls: list[str] = []

    tracer.step("link_extractor", "start", detail="Extracting links from content")

    # Extract from plain text
    if text:
        text_urls = extract_links_from_text(text)
        all_urls.extend(text_urls)
        tracer.step("link_extractor", "text_extraction", detail=f"Found {len(text_urls)} URLs in text")

    # Extract from HTML
    html_links: list[dict[str, str]] = []
    if html:
        html_links = extract_links_from_html(html)
        html_urls = [link["href"] for link in html_links]
        all_urls.extend(html_urls)
        tracer.step("link_extractor", "html_extraction", detail=f"Found {len(html_links)} links in HTML")

    # Deduplicate
    unique_urls = list(dict.fromkeys(all_urls))
    tracer.step("link_extractor", "dedup", detail=f"{len(unique_urls)} unique URLs")

    if not unique_urls:
        tracer.step("link_extractor", "complete", result="No links found")
        return findings, []

    # ── 1. Display vs href mismatch ──
    for link in html_links:
        href = link["href"]
        display = link["display"]
        if not display or display.startswith("["):
            continue
        # Check if display text looks like a URL
        if re.match(r"https?://", display, re.I) or "www." in display.lower():
            display_domain = _extract_domain(display)
            href_domain = _extract_domain(href)
            if display_domain and href_domain and display_domain != href_domain:
                findings.append(Finding(
                    category="link", title="Display/href mismatch",
                    description=f"Link shows '{display_domain}' but actually goes to '{href_domain}'. Classic phishing technique.",
                    severity=FindingSeverity.CRITICAL, score_impact=35.0,
                    evidence=f"Display: {display[:80]}, Href: {href[:80]}",
                ))
                tracer.step("link_extractor", "mismatch_detected",
                           detail=f"{display_domain} vs {href_domain}", score_impact=35.0)

    # ── 2. Shortened URLs ──
    for url in unique_urls:
        domain = _extract_domain(url)
        if domain and domain in SHORTENER_DOMAINS:
            findings.append(Finding(
                category="link", title="Shortened URL detected",
                description=f"Link uses URL shortener '{domain}' to hide the real destination.",
                severity=FindingSeverity.MEDIUM, score_impact=8.0,
                evidence=url[:100],
            ))
            tracer.step("link_extractor", "shortener_found", detail=f"Shortener: {domain}", score_impact=8.0)

    # ── 3. Too many unique domains ──
    domains = set()
    for url in unique_urls:
        d = _extract_domain(url)
        if d:
            domains.add(d)
    if len(domains) >= 5:
        findings.append(Finding(
            category="link", title="Multiple domains in links",
            description=f"Content contains links to {len(domains)} different domains, suggesting scattered/suspicious infrastructure.",
            severity=FindingSeverity.LOW, score_impact=5.0,
            evidence=", ".join(list(domains)[:10]),
        ))

    # ── 4. Data URIs ──
    for url in unique_urls:
        if url.strip().startswith("data:"):
            findings.append(Finding(
                category="link", title="Data URI link",
                description="Link uses a data: URI, which can embed malicious content.",
                severity=FindingSeverity.HIGH, score_impact=20.0,
                evidence=url[:60],
            ))

    # ── 5. JavaScript URIs ──
    for link in html_links:
        href = link["href"].strip().lower()
        if href.startswith("javascript:"):
            findings.append(Finding(
                category="link", title="JavaScript URI",
                description="Link uses javascript: protocol to execute code.",
                severity=FindingSeverity.CRITICAL, score_impact=30.0,
                evidence=link["href"][:80],
            ))

    tracer.step("link_extractor", "complete", detail=f"{len(findings)} findings, {len(unique_urls)} URLs extracted")
    return findings, unique_urls


def _extract_domain(url_or_text: str) -> Optional[str]:
    """Extract domain from a URL string."""
    try:
        if not url_or_text.startswith(("http://", "https://")):
            url_or_text = "http://" + url_or_text
        parsed = urlparse(url_or_text)
        return parsed.hostname
    except Exception:
        return None

"""Tests for link extractor."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.link_extractor import (
    extract_links_from_text,
    extract_links_from_html,
    analyze_links,
)
from app.utils.debug_trace import DebugTracer


def test_extract_from_text():
    text = "Visit https://example.com and http://test.org/page for info."
    urls = extract_links_from_text(text)
    assert len(urls) == 2
    assert "https://example.com" in urls


def test_extract_from_html():
    html = '<a href="https://evil.com">Click here</a><a href="https://safe.com">Safe</a>'
    links = extract_links_from_html(html)
    assert len(links) >= 2
    hrefs = [l["href"] for l in links]
    assert "https://evil.com" in hrefs


def test_display_href_mismatch():
    tracer = DebugTracer()
    html = '<a href="https://evil.com/steal">https://paypal.com/login</a>'
    findings, urls = analyze_links(None, html, tracer)
    titles = [f.title for f in findings]
    assert "Display/href mismatch" in titles


def test_shortener_detection():
    tracer = DebugTracer()
    text = "Click this link: https://bit.ly/abc123"
    findings, urls = analyze_links(text, None, tracer)
    titles = [f.title for f in findings]
    assert "Shortened URL detected" in titles


def test_javascript_uri():
    tracer = DebugTracer()
    html = '<a href="javascript:alert(1)">Click</a>'
    findings, urls = analyze_links(None, html, tracer)
    titles = [f.title for f in findings]
    assert "JavaScript URI" in titles


def test_no_links():
    tracer = DebugTracer()
    findings, urls = analyze_links("No links here", None, tracer)
    assert len(urls) == 0

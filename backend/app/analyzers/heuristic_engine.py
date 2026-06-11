"""
Heuristic engine for VK Scanner.
Consolidates analysis from all modules and provides ML pipeline hooks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from app.models import Finding, FindingSeverity
from app.utils.debug_trace import DebugTracer


class HeuristicRule:
    """A single heuristic rule."""

    def __init__(self, name: str, description: str, weight: float, check_fn):
        self.name = name
        self.description = description
        self.weight = weight
        self.check_fn = check_fn

    def evaluate(self, context: dict) -> Optional[Finding]:
        return self.check_fn(context)


def _check_mixed_scripts(context: dict) -> Optional[Finding]:
    """Check for mixed Unicode scripts in URLs or text."""
    import unicodedata
    target = context.get("url", "") or context.get("text", "")
    scripts = set()
    for ch in target:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch, "")
                if "LATIN" in name:
                    scripts.add("Latin")
                elif "CYRILLIC" in name:
                    scripts.add("Cyrillic")
                elif "GREEK" in name:
                    scripts.add("Greek")
                elif "ARABIC" in name:
                    scripts.add("Arabic")
            except ValueError:
                pass
    if len(scripts) > 1:
        return Finding(
            category="heuristic", title="Mixed Unicode scripts",
            description=f"Content uses multiple scripts ({', '.join(scripts)}), possible IDN homograph attack.",
            severity=FindingSeverity.HIGH, score_impact=15.0,
            evidence=f"Scripts: {', '.join(scripts)}",
        )
    return None


def _check_data_exfil_patterns(context: dict) -> Optional[Finding]:
    """Check for potential data exfiltration patterns."""
    import re
    text = context.get("text", "") or context.get("body_text", "")
    html = context.get("html", "") or context.get("body_html", "")
    content = text + " " + html

    # Forms that POST to external domains
    form_actions = re.findall(r'action=["\']?(https?://[^"\'>\s]+)', content, re.I)
    if form_actions:
        return Finding(
            category="heuristic", title="External form submission",
            description=f"Content contains form(s) submitting to: {', '.join(form_actions[:3])}",
            severity=FindingSeverity.HIGH, score_impact=20.0,
            evidence=", ".join(form_actions[:5]),
        )
    return None


def _check_credential_harvesting(context: dict) -> Optional[Finding]:
    """Check for credential harvesting indicators."""
    import re
    html = context.get("html", "") or context.get("body_html", "")
    if not html:
        return None

    password_inputs = re.findall(r'type=["\']password["\']', html, re.I)
    login_forms = re.findall(r'<form[^>]*>', html, re.I)

    if password_inputs and login_forms:
        return Finding(
            category="heuristic", title="Credential harvesting form",
            description="HTML contains a login form with password field, likely a phishing page.",
            severity=FindingSeverity.CRITICAL, score_impact=35.0,
            evidence=f"Password inputs: {len(password_inputs)}, Forms: {len(login_forms)}",
        )
    return None


def _check_base64_obfuscation(context: dict) -> Optional[Finding]:
    """Check for base64-encoded content in HTML."""
    import re
    html = context.get("html", "") or context.get("body_html", "")
    if not html:
        return None

    b64_blocks = re.findall(r"(?:atob|base64,)['\"]?([A-Za-z0-9+/=]{50,})", html)
    if b64_blocks:
        return Finding(
            category="heuristic", title="Base64 obfuscation detected",
            description=f"HTML contains {len(b64_blocks)} base64-encoded block(s), possibly hiding malicious content.",
            severity=FindingSeverity.HIGH, score_impact=18.0,
            evidence=f"{len(b64_blocks)} blocks found",
        )
    return None


# Default rules
DEFAULT_RULES = [
    HeuristicRule("mixed_scripts", "Detect mixed Unicode scripts", 1.0, _check_mixed_scripts),
    HeuristicRule("data_exfil", "Detect data exfiltration patterns", 1.0, _check_data_exfil_patterns),
    HeuristicRule("credential_harvest", "Detect credential harvesting forms", 1.0, _check_credential_harvesting),
    HeuristicRule("base64_obfuscation", "Detect base64 obfuscation in HTML", 1.0, _check_base64_obfuscation),
]


def run_heuristic_engine(
    context: dict,
    tracer: DebugTracer,
    extra_rules: Optional[list[HeuristicRule]] = None,
) -> list[Finding]:
    """
    Run all heuristic rules against the provided context.
    Context should contain keys like: url, text, html, subject, etc.
    """
    findings: list[Finding] = []
    rules = DEFAULT_RULES + (extra_rules or [])

    tracer.step("heuristic_engine", "start", detail=f"Running {len(rules)} heuristic rules")

    for rule in rules:
        try:
            result = rule.evaluate(context)
            if result:
                findings.append(result)
                tracer.step("heuristic_engine", f"rule:{rule.name}",
                           detail=rule.description, result="TRIGGERED", score_impact=result.score_impact)
            else:
                tracer.step("heuristic_engine", f"rule:{rule.name}", result="PASS")
        except Exception as e:
            tracer.step("heuristic_engine", f"rule:{rule.name}", detail=f"Error: {e}", result="ERROR")

    tracer.step("heuristic_engine", "complete", detail=f"{len(findings)} rules triggered")
    return findings



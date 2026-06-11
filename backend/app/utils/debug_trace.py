"""
Debug trace collector for VK Scanner.

Provides a DebugTracer class that analyzers use to record each step
of their analysis pipeline, producing a timestamped, ordered trace
that the frontend renders in the debug panel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.models import DebugStep


class DebugTracer:
    """Collects timestamped analysis steps across all analyzers."""

    def __init__(self) -> None:
        self._steps: list[DebugStep] = []
        self.file_previews: dict[str, str] = {}
        self.file_checks: dict[str, list[dict]] = {}
        self.file_metadata: dict[str, dict] = {}
        self.file_contexts: dict[str, str] = {}
        self.file_deobfuscated: dict[str, list[dict]] = {}
        self.file_strings: dict[str, str] = {}
        self.file_entropy: dict[str, float] = {}
        self.iocs: dict[str, list[str]] = {"ips": [], "urls": [], "emails": [], "domains": [], "hashes": []}
        self.url_redirect_chain: list[dict] = []
        self.email_extracted_ips: list[str] = []
        self.email_extracted_urls: list[str] = []
        self.email_extracted_emails: list[str] = []
        self.email_attachment_tree: list[dict] = []
        self.email_body_html: Optional[str] = None
        self.url_resolved_ip: str | None = None
        self.url_domain_created: str | None = None
        self.url_technologies: list[str] = []
        self.url_extracted_scripts: list[dict] = []
        self.url_site_preview: dict = {}


    def step(
        self,
        analyzer: str,
        action: str,
        detail: str = "",
        result: str = "",
        score_impact: float = 0.0,
    ) -> None:
        """Record a single analysis step."""
        self._steps.append(
            DebugStep(
                timestamp=datetime.now(timezone.utc).isoformat(),
                analyzer=analyzer,
                action=action,
                detail=detail,
                result=result,
                score_impact=score_impact,
            )
        )

    def get_steps(self) -> list[DebugStep]:
        """Return all recorded steps in order."""
        return list(self._steps)

    def clear(self) -> None:
        """Reset the tracer."""
        self._steps.clear()

"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import detect_injection  # noqa: F401  (used by triage)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}


class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply. See README.md for the exact seven-step order."""
    text = raw.strip()
    lines = text.splitlines()
    if len(lines) >= 2 and lines[0].strip() in ("```json", "```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        raise Rejected("not_json")
    if not isinstance(obj, dict):
        raise Rejected("not_json")

    action_keys = {"action", "actions", "tool_call", "tool_calls", "function_call"}
    next_step = obj.get("next_step")
    if any(key in obj for key in action_keys):
        raise Rejected("forbidden_action")
    if isinstance(next_step, str) and "close" in next_step.lower():
        raise Rejected("forbidden_action")

    severity = obj.get("severity")
    if severity not in SEVERITIES:
        raise Rejected("bad_severity")
    if next_step not in NEXT_STEPS:
        raise Rejected("bad_next_step")
    summary = obj.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary.strip()) > 600:
        raise Rejected("bad_summary")
    summary = summary.strip()
    related = obj.get("related_alert_ids", [])
    if not isinstance(related, list) or any(not isinstance(item, str) for item in related):
        raise Rejected("bad_related_alert_ids")

    for other_tenant in re.findall(r"TEN-\d{3}", summary):
        if other_tenant != tenant_id:
            raise Rejected("cross_tenant_reference")

    flags: set[str] = set()
    seen_ids: list[str] = []
    for alert_id in related:
        if alert_id not in seen_ids:
            seen_ids.append(alert_id)
    kept_ids: list[str] = []
    for alert_id in seen_ids:
        if alert_id in known_alert_ids:
            kept_ids.append(alert_id)
        else:
            flags.add("unknown_alert_id")

    cleaned = summary
    image_pattern = re.compile(r"!\[[^\]]*\]\([^)]*\)")
    if image_pattern.search(cleaned):
        flags.add("image_removed")
    cleaned = image_pattern.sub("[image removed]", cleaned)

    kept_links: list[str] = []

    def _link_replacement(match: re.Match) -> str:
        link_text, url = match.group(1), match.group(2)
        try:
            parsed = urlsplit(url)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.scheme in ("http", "https") and parsed.hostname in ALLOWED_LINK_HOSTS:
            kept_links.append(match.group(0))
            return f"\x00{len(kept_links) - 1}\x00"
        flags.add("link_removed")
        return link_text

    cleaned = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", _link_replacement, cleaned)

    def _bare_replacement(match: re.Match) -> str:
        url = match.group(0)
        trailing = ""
        while url and url[-1] in ".,;:!?":
            trailing = url[-1] + trailing
            url = url[:-1]
        try:
            parsed = urlsplit(url)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.scheme in ("http", "https") and parsed.hostname in ALLOWED_LINK_HOSTS:
            return match.group(0)
        flags.add("link_removed")
        return "[link removed]" + trailing

    cleaned = re.sub(r"https?://[^\s<>\")\]]+", _bare_replacement, cleaned)
    for index, link in enumerate(kept_links):
        cleaned = cleaned.replace(f"\x00{index}\x00", link)

    summary_html = html.escape(cleaned, quote=True)
    return TriageResult(
        severity=severity,
        summary_html=summary_html,
        next_step=next_step,
        related_alert_ids=kept_ids,
        flags=sorted(flags),
    )


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output; if any signal
    fired, add flags and never let the result end up quieter than it would otherwise be."""
    signals: set[str] = set()

    def _walk(value) -> None:
        if isinstance(value, str):
            signals.update(detect_injection(value))
        elif isinstance(value, dict):
            for key, item in value.items():
                _walk(key)
                _walk(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                _walk(item)

    _walk(alert)
    result = parse_model_output(raw_output, tenant_id=tenant_id, known_alert_ids=known_alert_ids)
    if signals:
        flags = set(result.flags)
        flags.add("possible_injection")
        for code in signals:
            flags.add(f"signal:{code}")
        result.flags = sorted(flags)
        if SEVERITIES.index(result.severity) < SEVERITIES.index("high"):
            result.severity = "high"
        if result.next_step == "monitor":
            result.next_step = "escalate_to_analyst"
    return result

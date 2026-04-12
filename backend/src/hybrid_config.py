"""
hybrid_config.py — Shared contract between AI agents and detection engines
═══════════════════════════════════════════════════════════════════════════
This file defines the DynamicConfig dataclass that flows FROM the
orchestrator agent TO the bridge, allowing the LLM reasoning layer
to influence the rule-based detection layer.

Flow:
  1. Bridge runs engines with DEFAULT thresholds  → produces alarms
  2. Agents receive alarms + metrics             → reason about context
  3. Orchestrator agent emits DynamicConfig JSON → written here
  4. Bridge re-runs with ADJUSTED thresholds     → produces final alarms

This is the hybrid architecture:
  Rule-based (fast, auditable, deterministic)  +
  LLM reasoning (contextual, adaptive, explainable)
  working TOGETHER instead of sequentially.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class DynamicConfig:
    """
    Configuration emitted by the orchestrator agent after initial detection.
    The bridge reads this to adjust engine thresholds for the second pass.

    All fields have safe defaults — if the agent emits nothing, behavior
    is identical to the original fixed-threshold pipeline.
    """

    # ── Threshold overrides ───────────────────────────────────────────────
    # Set to None to keep the engine's built-in default
    ssh_high_risk_threshold:    float | None = None   # default 38
    ssh_med_risk_threshold:     float | None = None   # default 22
    web_high_risk_threshold:    float | None = None   # default 55
    web_med_risk_threshold:     float | None = None   # default 30
    ftp_high_risk_threshold:    float | None = None   # default 55
    ftp_med_risk_threshold:     float | None = None   # default 30
    kernel_high_risk_threshold: float | None = None   # default 50
    session_high_risk_threshold: float | None = None  # default 50
    session_med_risk_threshold:  float | None = None  # default 25
    correlation_window_min:     float | None = None   # default 30

    # ── Escalation decisions ──────────────────────────────────────────────
    # IPs the agent explicitly wants force-escalated to BLOCK regardless of score
    escalate_ips: list[str] = field(default_factory=list)

    # IPs the agent wants suppressed (known false positives, whitelisted)
    suppress_ips: list[str] = field(default_factory=list)

    # ── Targeted re-analysis ──────────────────────────────────────────────
    # Engine names the agent wants re-run (e.g. ["session"] after post-breach signal)
    rerun_engines: list[str] = field(default_factory=list)

    # ── Reasoning trace ───────────────────────────────────────────────────
    # The agent's plain-language justification — stored in memory + report
    reasoning: str = ""
    threat_level: str = "NORMAL"   # NORMAL / ELEVATED / CRITICAL

    # ── Meta ──────────────────────────────────────────────────────────────
    issued_by: str = "default"     # "orchestrator_agent" when set by LLM
    confidence: float = 1.0        # 0.0–1.0, lower = agent was uncertain

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> "DynamicConfig":
        """
        Safely parse agent output into DynamicConfig.
        Handles partial JSON, extra fields, and plain-text fallbacks.
        """
        # Strip markdown code fences if present
        text = text.strip()
        for fence in ("```json", "```"):
            if text.startswith(fence):
                text = text[len(fence):]
            if text.endswith("```"):
                text = text[:-3]
        text = text.strip()

        try:
            data = json.loads(text)
        except Exception:
            # Agent returned plain text — extract what we can
            data = _parse_plain_text_config(text)

        # Only keep known fields — ignore anything extra the LLM hallucinated
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in data.items() if k in known}

        # Type coercion for threshold fields (LLM sometimes returns strings)
        for thresh_field in (
            "ssh_high_risk_threshold", "ssh_med_risk_threshold",
            "web_high_risk_threshold", "web_med_risk_threshold",
            "ftp_high_risk_threshold", "ftp_med_risk_threshold",
            "kernel_high_risk_threshold",
            "session_high_risk_threshold", "session_med_risk_threshold",
            "correlation_window_min",
            "confidence",
        ):
            if thresh_field in clean and clean[thresh_field] is not None:
                try:
                    clean[thresh_field] = float(clean[thresh_field])
                except (ValueError, TypeError):
                    clean[thresh_field] = None

        for list_field in ("escalate_ips", "suppress_ips", "rerun_engines"):
            if list_field in clean and not isinstance(clean[list_field], list):
                clean[list_field] = []

        return cls(**clean)

    @classmethod
    def default(cls) -> "DynamicConfig":
        """Returns a no-op config — engines use their built-in thresholds."""
        return cls(issued_by="default")

    def is_default(self) -> bool:
        """True if this config has no overrides — bridge skips second pass."""
        return (
            self.ssh_high_risk_threshold    is None and
            self.ssh_med_risk_threshold     is None and
            self.web_high_risk_threshold    is None and
            self.web_med_risk_threshold     is None and
            self.ftp_high_risk_threshold    is None and
            self.ftp_med_risk_threshold     is None and
            self.kernel_high_risk_threshold is None and
            self.session_high_risk_threshold is None and
            self.session_med_risk_threshold  is None and
            self.correlation_window_min     is None and
            not self.escalate_ips and
            not self.suppress_ips and
            not self.rerun_engines
        )

    def summary(self) -> str:
        """One-line human-readable summary for logs."""
        parts = []
        if self.ssh_high_risk_threshold is not None:
            parts.append(f"SSH_thresh={self.ssh_high_risk_threshold}")
        if self.web_high_risk_threshold is not None:
            parts.append(f"WEB_thresh={self.web_high_risk_threshold}")
        if self.ftp_high_risk_threshold is not None:
            parts.append(f"FTP_thresh={self.ftp_high_risk_threshold}")
        if self.session_high_risk_threshold is not None:
            parts.append(f"SESSION_thresh={self.session_high_risk_threshold}")
        if self.escalate_ips:
            parts.append(f"escalate={self.escalate_ips}")
        if self.suppress_ips:
            parts.append(f"suppress={self.suppress_ips}")
        if self.rerun_engines:
            parts.append(f"rerun={self.rerun_engines}")
        if not parts:
            return "no overrides (default pass)"
        return " | ".join(parts)


def _parse_plain_text_config(text: str) -> dict[str, Any]:
    """
    Fallback parser for when the agent returns plain text instead of JSON.
    Extracts threshold numbers and IP lists using simple heuristics.
    """
    import re
    result: dict[str, Any] = {}

    # Threat level
    if "CRITICAL" in text.upper():
        result["threat_level"] = "CRITICAL"
    elif "ELEVATED" in text.upper():
        result["threat_level"] = "ELEVATED"

    # Threshold hints
    m = re.search(r'ssh.*?threshold.*?(\d+\.?\d*)', text, re.I)
    if m:
        result["ssh_high_risk_threshold"] = float(m.group(1))

    m = re.search(r'ftp.*?threshold.*?(\d+\.?\d*)', text, re.I)
    if m:
        result["ftp_high_risk_threshold"] = float(m.group(1))

    # IP addresses to escalate
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    if ips and ("block" in text.lower() or "escalat" in text.lower()):
        result["escalate_ips"] = ips

    # Engine rerun hints
    rerun = []
    for engine in ("ssh", "web", "ftp", "kernel", "session"):
        if f"rerun {engine}" in text.lower() or f"re-run {engine}" in text.lower():
            rerun.append(engine)
    if rerun:
        result["rerun_engines"] = rerun

    result["reasoning"] = text[:300]
    result["issued_by"]  = "orchestrator_agent_plaintext"
    result["confidence"] = 0.6   # lower confidence for plain-text parse

    return result
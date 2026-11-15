"""
MirageSSH - Tarpit Throttling & Deception Engine
Introduces artificial, human-like delay patterns to suspicious reconnaissance
and exploit commands to waste attacker resources and prolong intelligence gathering.
"""

from __future__ import annotations
import random
import re
import time
from typing import Any, Dict, Optional


class TarpitEngine:
    """Manages dynamic response delays and sticky-shell throttling."""

    SUSPICIOUS_PATTERNS = [
        r"\b(nmap|masscan|zmap)\b",
        r"\b(curl|wget)\b.*(sh|bash|py|pl|elf|bin)",
        r"\bfind\s+/.*-perm",
        r"\b(cat\s+/etc/shadow|unshadow)\b",
        r"\b(python|perl|bash|sh|nc)\s+-.*socket",
        r"\b(base64\s+-d)\b",
        r"\b(gcc|clang|make)\b",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.min_delay_ms = cfg.get("min_delay_ms", 250)
        self.max_delay_ms = cfg.get("max_delay_ms", 1200)
        self.suspicious_delay_ms = cfg.get("suspicious_command_delay_ms", 2000)

    def is_suspicious(self, command_line: str) -> bool:
        """Determines if a command matches aggressive enumeration or attack patterns."""
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, command_line, re.IGNORECASE):
                return True
        return False

    def calculate_delay(self, command_line: str) -> float:
        """Returns delay in seconds to apply before returning terminal output."""
        if not self.enabled:
            return 0.0

        if self.is_suspicious(command_line):
            # Suspicious command delay with slight jitter
            jitter = random.uniform(-0.3, 0.5)
            delay = (self.suspicious_delay_ms / 1000.0) + jitter
            return max(0.2, delay)

        # Baseline typing/processing jitter
        delay_ms = random.randint(self.min_delay_ms, self.max_delay_ms)
        return delay_ms / 1000.0

    def apply_delay(self, command_line: str):
        """Sleeps for the computed tarpit delay."""
        delay = self.calculate_delay(command_line)
        if delay > 0:
            time.sleep(delay)

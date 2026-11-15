"""
MirageSSH - Structured JSONL Audit Logger & Event Pipeline
Provides SIEM-compatible structured logging and human-readable audit trails.
"""

from __future__ import annotations
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("miragessh.audit")


class HoneypotLogger:
    """Writes machine-readable JSONL logs and formatted console/file logs."""

    def __init__(
        self,
        jsonl_path: str = "data/logs/miragessh_events.jsonl",
        text_log_path: str = "data/logs/miragessh.log",
        log_level: str = "INFO",
    ):
        self.jsonl_path = jsonl_path
        self.text_log_path = text_log_path

        os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)
        os.makedirs(os.path.dirname(text_log_path), exist_ok=True)

        self._init_logging(log_level)

    def _init_logging(self, level: str):
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        root_logger = logging.getLogger("miragessh")
        root_logger.setLevel(numeric_level)

        if not root_logger.handlers:
            # Console handler
            console_fmt = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            ch = logging.StreamHandler()
            ch.setFormatter(console_fmt)
            root_logger.addHandler(ch)

            # File handler
            fh = logging.FileHandler(self.text_log_path, encoding="utf-8")
            fh.setFormatter(console_fmt)
            root_logger.addHandler(fh)

    def emit_event(self, event_type: str, session_id: str, data: Dict[str, Any]):
        """Appends a structured event object to the JSONL log file."""
        event = {
            "timestamp": time.time(),
            "datetime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event_type,
            "session_id": session_id,
            **data,
        }

        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write event to JSONL: {e}")

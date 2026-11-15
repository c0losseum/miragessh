"""
MirageSSH - Honeytoken Tripwire Engine
Monitors decoy credentials and sensitive file paths to immediately detect
and alert on unauthorized data exfiltration or access.
"""

from __future__ import annotations
import logging
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("miragessh.honeytokens")


@dataclass
class HoneytokenEvent:
    token_id: str
    path: str
    action: str  # 'read' or 'write'
    user: str
    session_id: str
    client_ip: str
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM'
    timestamp: float
    description: str


class HoneytokenManager:
    """Manages honeytoken definitions and triggers intrusion alerts."""

    DEFAULT_HONEYTOKENS = {
        "/home/ubuntu/.env": {
            "id": "HT-ENV-PROD-SECRETS",
            "severity": "CRITICAL",
            "description": "Production .env file containing fake AWS keys, Stripe key, and database passwords.",
        },
        "/home/ubuntu/.aws/credentials": {
            "id": "HT-AWS-CREDENTIALS",
            "severity": "CRITICAL",
            "description": "AWS CLI credentials file containing decoy access keys.",
        },
        "/root/.ssh/id_rsa": {
            "id": "HT-ROOT-SSH-KEY",
            "severity": "CRITICAL",
            "description": "Root SSH private key exfiltration attempt.",
        },
        "/etc/shadow": {
            "id": "HT-ETC-SHADOW",
            "severity": "HIGH",
            "description": "System password hash database access attempt.",
        },
        "/var/backups/prod_database.sql": {
            "id": "HT-DB-DUMP",
            "severity": "CRITICAL",
            "description": "Customer database backup dump file accessed.",
        },
        "/opt/payment-service/config.json": {
            "id": "HT-PAYMENT-CONFIG",
            "severity": "HIGH",
            "description": "Payment microservice configuration file accessed.",
        },
    }

    def __init__(self, monitored_paths: Optional[List[str]] = None):
        self.monitored = dict(self.DEFAULT_HONEYTOKENS)
        if monitored_paths:
            for p in monitored_paths:
                if p not in self.monitored:
                    self.monitored[p] = {
                        "id": f"HT-CUSTOM-{hash(p) % 10000}",
                        "severity": "HIGH",
                        "description": f"Decoy file {p} accessed.",
                    }

        self.listeners: List[Callable[[HoneytokenEvent], None]] = []
        self.triggered_events: List[HoneytokenEvent] = []

    def add_listener(self, listener: Callable[[HoneytokenEvent], None]):
        """Registers a callback for honeytoken trigger alerts."""
        self.listeners.append(listener)

    def check_access(
        self,
        path: str,
        user: str,
        session_id: str = "unknown",
        client_ip: str = "unknown",
        action: str = "read",
    ) -> Optional[HoneytokenEvent]:
        """Checks if accessed path matches a honeytoken and notifies listeners."""
        # Normalize
        norm_path = path.rstrip("/")

        # Check direct match or parent path
        meta = self.monitored.get(norm_path)
        if not meta:
            # Check if any monitored file is inside this path
            for m_path, m_meta in self.monitored.items():
                if norm_path == m_path:
                    meta = m_meta
                    break

        if meta:
            event = HoneytokenEvent(
                token_id=meta["id"],
                path=norm_path,
                action=action,
                user=user,
                session_id=session_id,
                client_ip=client_ip,
                severity=meta["severity"],
                timestamp=time.time(),
                description=meta["description"],
            )
            self.triggered_events.append(event)
            logger.warning(
                f"🚨 HONEYTOKEN TRIPPED! [{event.severity}] {event.token_id} at {event.path} by {user}@{client_ip}"
            )

            for listener in self.listeners:
                try:
                    listener(event)
                except Exception as e:
                    logger.error(f"Error executing honeytoken listener: {e}")

            return event

        return None

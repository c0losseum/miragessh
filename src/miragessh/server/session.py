"""
MirageSSH - Attacker Session State & Forensics Model
Encapsulates session lifecycle, keystroke recorder, attacker IP context,
command history, and real-time risk scoring.
"""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from miragessh.telemetry.geoip import GeoIPData
from miragessh.telemetry.recorder import SessionRecorder


@dataclass
class CommandRecord:
    timestamp: float
    command: str
    output: str
    cwd: str
    user: str
    provider: str
    exit_code: int
    duration: float
    mitre_ids: List[str] = field(default_factory=list)


class AttackerSession:
    """Manages the full lifecycle and forensics data of an SSH attacker session."""

    def __init__(
        self,
        client_ip: str,
        client_port: int,
        session_id: Optional[str] = None,
        recordings_dir: str = "data/recordings",
    ):
        self.session_id: str = session_id or str(uuid.uuid4())[:8]
        self.client_ip: str = client_ip
        self.client_port: int = client_port
        self.client_version: str = "unknown"
        self.geo: GeoIPData = GeoIPData(ip=client_ip)

        self.start_time: float = time.time()
        self.end_time: Optional[float] = None
        self.is_active: bool = True

        self.authenticated_user: str = "ubuntu"
        self.auth_attempts: List[Dict[str, Any]] = []

        self.commands: List[CommandRecord] = []
        self.honeytokens_triggered: List[Dict[str, Any]] = []
        self.risk_score: int = 10  # Baseline connection risk

        # Keystroke session recorder
        self.recorder = SessionRecorder(
            session_id=self.session_id,
            recordings_dir=recordings_dir,
            title=f"MirageSSH Session - {self.client_ip} ({self.session_id})",
        )

    @property
    def duration_seconds(self) -> float:
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)

    @property
    def total_commands(self) -> int:
        return len(self.commands)

    def add_command(
        self,
        command: str,
        output: str,
        cwd: str,
        user: str,
        provider: str,
        exit_code: int,
        duration: float,
        mitre_ids: Optional[List[str]] = None,
    ):
        """Records executed command and recalculates session risk score."""
        m_ids = mitre_ids or []
        rec = CommandRecord(
            timestamp=time.time(),
            command=command,
            output=output,
            cwd=cwd,
            user=user,
            provider=provider,
            exit_code=exit_code,
            duration=duration,
            mitre_ids=m_ids,
        )
        self.commands.append(rec)

        # Dynamic risk scoring
        self.risk_score += 5
        if m_ids:
            self.risk_score += len(m_ids) * 15
        self.risk_score = min(100, self.risk_score)

    def trigger_honeytoken(self, token_data: Dict[str, Any]):
        """Records honeytoken tripwire breach and elevates risk to maximum."""
        self.honeytokens_triggered.append(token_data)
        self.risk_score = 100

    def close(self):
        """Closes session and finalizes recording."""
        self.is_active = False
        self.end_time = time.time()
        try:
            self.recorder.close()
        except Exception:
            pass

    def to_summary_dict(self) -> dict:
        """Returns a high-level summary suitable for dashboard APIs."""
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "client_version": self.client_version,
            "country": self.geo.country,
            "country_code": self.geo.country_code,
            "city": self.geo.city,
            "isp": self.geo.isp,
            "user": self.authenticated_user,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration_seconds,
            "is_active": self.is_active,
            "command_count": len(self.commands),
            "honeytoken_count": len(self.honeytokens_triggered),
            "risk_score": self.risk_score,
            "cast_file": f"{self.session_id}.cast",
        }

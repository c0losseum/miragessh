"""
MirageSSH - Security Operations Center (SOC) Web Dashboard Backend
FastAPI web application providing REST APIs for session monitoring,
real-time statistics, MITRE ATT&CK analytics, and session replay playback.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles


def create_app(honeypot_daemon=None, config: Optional[Dict[str, Any]] = None) -> FastAPI:
    """Factory creating the FastAPI dashboard application."""
    app = FastAPI(title="MirageSSH SOC Dashboard", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    base_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # Store daemon reference
    app.state.daemon = honeypot_daemon
    app.state.config = config or {}

    @app.get("/", response_class=HTMLResponse)
    async def get_dashboard(request: Request):
        template_path = os.path.join(templates_dir, "dashboard.html")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                return f.read()
        return "<h1>MirageSSH Dashboard Template Not Found</h1>"

    @app.get("/api/stats")
    async def get_stats():
        daemon = app.state.daemon
        if not daemon:
            return {
                "active_sessions": 0,
                "total_sessions": 0,
                "unique_ips": 0,
                "total_commands": 0,
                "honeytoken_breaches": 0,
                "mitre_summary": {},
            }

        all_sess = daemon.all_sessions
        active_sess = list(daemon.active_sessions.values())
        unique_ips = len(set(s.client_ip for s in all_sess))
        total_cmds = sum(s.total_commands for s in all_sess)
        ht_breaches = len(daemon.honeytokens.triggered_events)

        mitre_counts: Dict[str, int] = {}
        for s in all_sess:
            for cmd in s.commands:
                for mid in cmd.mitre_ids:
                    mitre_counts[mid] = mitre_counts.get(mid, 0) + 1

        return {
            "active_sessions": len(active_sess),
            "total_sessions": len(all_sess),
            "unique_ips": unique_ips,
            "total_commands": total_cmds,
            "honeytoken_breaches": ht_breaches,
            "mitre_summary": mitre_counts,
        }

    @app.get("/api/sessions")
    async def get_sessions():
        daemon = app.state.daemon
        if not daemon:
            return []
        return [s.to_summary_dict() for s in reversed(daemon.all_sessions)]

    @app.get("/api/sessions/{session_id}")
    async def get_session_detail(session_id: str):
        daemon = app.state.daemon
        if not daemon:
            raise HTTPException(status_code=404, detail="Daemon not active")

        for s in daemon.all_sessions:
            if s.session_id == session_id:
                return {
                    "summary": s.to_summary_dict(),
                    "commands": [
                        {
                            "timestamp": c.timestamp,
                            "command": c.command,
                            "output": c.output,
                            "cwd": c.cwd,
                            "user": c.user,
                            "provider": c.provider,
                            "duration": round(c.duration, 3),
                            "mitre_ids": c.mitre_ids,
                        }
                        for c in s.commands
                    ],
                    "honeytokens": s.honeytokens_triggered,
                }
        raise HTTPException(status_code=404, detail="Session not found")

    @app.get("/api/sessions/{session_id}/cast")
    async def get_session_cast(session_id: str):
        daemon = app.state.daemon
        recordings_dir = "data/recordings"
        if daemon and daemon.config:
            recordings_dir = daemon.config.get("telemetry", {}).get("recordings_dir", recordings_dir)

        cast_path = os.path.join(recordings_dir, f"{session_id}.cast")
        if os.path.exists(cast_path):
            return FileResponse(cast_path, media_type="text/plain", filename=f"{session_id}.cast")
        raise HTTPException(status_code=404, detail="Recording cast file not found")

    return app

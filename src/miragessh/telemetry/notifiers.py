"""
MirageSSH - Alert Dispatcher (Discord, Telegram, Generic Webhooks)
Dispatches real-time security alerts on attacker logins, honeytoken triggers,
and MITRE ATT&CK high-severity commands.
"""

from __future__ import annotations
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

logger = logging.getLogger("miragessh.notifiers")


class AlertDispatcher:
    """Dispatches real-time alerts across configured notification channels."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.discord_cfg = cfg.get("discord", {})
        self.telegram_cfg = cfg.get("telegram", {})
        self.webhook_cfg = cfg.get("generic_webhook", {})

        # Discord
        self.discord_enabled = self.discord_cfg.get("enabled", False)
        self.discord_url = os.getenv(
            self.discord_cfg.get("webhook_url_env", "DISCORD_WEBHOOK_URL"), ""
        )

        # Telegram
        self.telegram_enabled = self.telegram_cfg.get("enabled", False)
        self.tg_bot_token = os.getenv(
            self.telegram_cfg.get("bot_token_env", "TELEGRAM_BOT_TOKEN"), ""
        )
        self.tg_chat_id = os.getenv(
            self.telegram_cfg.get("chat_id_env", "TELEGRAM_CHAT_ID"), ""
        )

        # Generic Webhook
        self.webhook_enabled = self.webhook_cfg.get("enabled", False)
        self.webhook_url = os.getenv(
            self.webhook_cfg.get("webhook_url_env", "GENERIC_WEBHOOK_URL"), ""
        )

    def send_login_alert(self, session_id: str, ip: str, user: str, country: str, client_version: str):
        """Sends alert on successful attacker authentication."""
        title = "🚨 [MirageSSH] Attacker Authenticated!"
        desc = (
            f"**Attacker IP**: `{ip}` ({country})\n"
            f"**Username Trap**: `{user}`\n"
            f"**Client**: `{client_version}`\n"
            f"**Session ID**: `{session_id}`"
        )
        self._dispatch(title=title, description=desc, color=0xFFA500)

    def send_honeytoken_alert(self, event):
        """Sends urgent alert when a Honeytoken file is accessed."""
        title = f"🔥 [MirageSSH] HONEYTOKEN TRIPPED: {event.token_id}"
        desc = (
            f"**Severity**: `{event.severity}`\n"
            f"**Decoy Path**: `{event.path}`\n"
            f"**Action**: `{event.action}` by `{event.user}`\n"
            f"**Attacker IP**: `{event.client_ip}`\n"
            f"**Description**: {event.description}"
        )
        self._dispatch(title=title, description=desc, color=0xFF0000)

    def send_high_risk_command_alert(self, session_id: str, ip: str, command: str, mitre_tactics: str):
        """Sends alert when a high-risk exploit command is executed."""
        title = "⚠️ [MirageSSH] High-Risk Command Detected"
        desc = (
            f"**Attacker IP**: `{ip}`\n"
            f"**Command**: `{command}`\n"
            f"**MITRE ATT&CK**: `{mitre_tactics}`\n"
            f"**Session ID**: `{session_id}`"
        )
        self._dispatch(title=title, description=desc, color=0xE74C3C)

    def _dispatch(self, title: str, description: str, color: int = 0x3498DB):
        """Sends payload to all enabled alert sinks."""
        if self.discord_enabled and self.discord_url:
            self._send_discord(title, description, color)
        if self.telegram_enabled and self.tg_bot_token and self.tg_chat_id:
            self._send_telegram(title, description)
        if self.webhook_enabled and self.webhook_url:
            self._send_generic_webhook(title, description)

    def _send_discord(self, title: str, description: str, color: int):
        payload = {
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "color": color,
                    "footer": {"text": "MirageSSH Honeypot Threat Intel"},
                }
            ]
        }
        try:
            req = urllib.request.Request(
                self.discord_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "MirageSSH-Alerter"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception as e:
            logger.warning(f"Failed to dispatch Discord alert: {e}")

    def _send_telegram(self, title: str, description: str):
        text = f"*{title}*\n\n{description}"
        url = f"https://api.telegram.org/bot{self.tg_bot_token}/sendMessage"
        payload = {
            "chat_id": self.tg_chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception as e:
            logger.warning(f"Failed to dispatch Telegram alert: {e}")

    def _send_generic_webhook(self, title: str, description: str):
        payload = {
            "event": "miragessh_alert",
            "title": title,
            "description": description,
        }
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3.0)
        except Exception as e:
            logger.warning(f"Failed to dispatch generic webhook alert: {e}")

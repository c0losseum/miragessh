"""
MirageSSH - OpenAI / Ollama Compatible AI Responder Client
Supports any OpenAI-compatible API endpoint (OpenAI, Ollama, LocalAI, vLLM).
"""

from __future__ import annotations
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Optional

from miragessh.ai.prompts import build_system_prompt

logger = logging.getLogger("miragessh.ai.openai")


class OpenAIClient:
    """Client for OpenAI-compatible chat completion endpoints."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 4.0,
    ):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        # For local Ollama, an API key is not strictly required
        if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
            return True
        return bool(self.api_key and self.api_key.strip())

    def generate(
        self,
        command_line: str,
        user: str = "ubuntu",
        cwd: str = "/home/ubuntu",
        vfs_summary: str = "",
    ) -> Optional[str]:
        """Sends command context to OpenAI-compatible endpoint."""
        if not self.is_configured:
            return None

        system_instruction = build_system_prompt(user=user, cwd=cwd, vfs_summary=vfs_summary)
        user_prompt = f"Command executed by {user} in {cwd}:\n{command_line}"

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))

            choices = resp_json.get("choices", [])
            if not choices:
                return None

            raw_text = choices[0].get("message", {}).get("content", "")
            return self._sanitize_output(raw_text)

        except Exception as e:
            logger.warning(f"OpenAI API request failed: {e}")
            return None

    def _sanitize_output(self, text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines)
        if not cleaned.endswith("\n") and cleaned:
            cleaned += "\n"
        return cleaned

"""
MirageSSH - AI Responder Coordinator
Orchestrates AI shell responses with intelligent fallback to offline mock heuristics.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from miragessh.ai.gemini_client import GeminiClient
from miragessh.ai.mock_ai import MockAIResponder
from miragessh.ai.openai_client import OpenAIClient

logger = logging.getLogger("miragessh.ai.coordinator")


class AIResponderCoordinator:
    """Manages AI provider selection, execution, and graceful degradation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.provider_name = cfg.get("provider", "gemini").lower()
        self.fallback_to_mock = cfg.get("fallback_to_mock", True)

        # Clients
        self.gemini = GeminiClient(
            model=cfg.get("model", "gemini-1.5-flash"),
            temperature=cfg.get("temperature", 0.2),
            max_tokens=cfg.get("max_tokens", 1024),
            timeout=cfg.get("timeout_seconds", 4.0),
        )
        self.openai = OpenAIClient(
            base_url=cfg.get("openai_base_url", "https://api.openai.com/v1"),
            model=cfg.get("openai_model", "gpt-4o-mini"),
            temperature=cfg.get("temperature", 0.2),
            max_tokens=cfg.get("max_tokens", 1024),
            timeout=cfg.get("timeout_seconds", 4.0),
        )
        self.mock = MockAIResponder()

    def respond(
        self,
        command_line: str,
        user: str = "ubuntu",
        cwd: str = "/home/ubuntu",
        vfs_summary: str = "",
    ) -> Tuple[str, str]:
        """
        Generates realistic output for an unhandled shell command.
        Returns: (output_text, provider_used)
        """
        if not self.enabled:
            return self.mock.generate_response(command_line, user, cwd), "mock_disabled"

        # Try active LLM provider first
        response = None
        if self.provider_name == "gemini" and self.gemini.is_configured:
            try:
                response = self.gemini.generate(command_line, user, cwd, vfs_summary)
                if response is not None:
                    return response, "gemini"
            except Exception as e:
                logger.warning(f"Gemini provider failed: {e}")

        elif self.provider_name in ["openai", "ollama"] and self.openai.is_configured:
            try:
                response = self.openai.generate(command_line, user, cwd, vfs_summary)
                if response is not None:
                    return response, self.provider_name
            except Exception as e:
                logger.warning(f"OpenAI provider failed: {e}")

        # Fallback to offline mock heuristics
        if self.fallback_to_mock:
            mock_output = self.mock.generate_response(command_line, user, cwd)
            return mock_output, "mock_heuristic"

        # Standard fallback if mock disabled
        first_word = command_line.strip().split()[0] if command_line.strip() else ""
        return f"bash: {first_word}: command not found\n", "fallback_none"

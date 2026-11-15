"""
MirageSSH - Interactive Fake Shell Interpreter
Handles terminal line buffer, keystroke parsing, command routing
between local VFS builtins and AI responder, and telemetry recording.
"""

from __future__ import annotations
import logging
import time
from typing import Callable, List, Optional, Tuple

from miragessh.ai.responder import AIResponderCoordinator
from miragessh.shell.builtin_commands import BuiltinCommandsHandler
from miragessh.shell.prompt import PromptFormatter
from miragessh.shell.vfs import VirtualFileSystem

logger = logging.getLogger("miragessh.shell")


class FakeShell:
    """Simulates an interactive POSIX bash shell session."""

    def __init__(
        self,
        vfs: VirtualFileSystem,
        ai_responder: AIResponderCoordinator,
        user: str = "ubuntu",
        hostname: str = "prod-db-gateway-01",
        initial_cwd: str = "/home/ubuntu",
        color_prompt: bool = True,
        on_command_callback: Optional[Callable] = None,
    ):
        self.vfs = vfs
        self.ai = ai_responder
        self.user = user
        self.hostname = hostname
        self.cwd = initial_cwd
        self.color_prompt = color_prompt
        self.on_command_callback = on_command_callback

        self.builtin = BuiltinCommandsHandler(vfs)
        self.history: List[str] = []
        self.line_buffer: str = ""
        self.should_exit: bool = False

    def get_prompt(self) -> str:
        """Returns the current formatted shell prompt."""
        return PromptFormatter.format_prompt(
            user=self.user,
            hostname=self.hostname,
            cwd=self.cwd,
            color=self.color_prompt,
        )

    def handle_line(self, command_line: str) -> Tuple[str, bool]:
        """
        Processes a full command line string.
        Returns: (output_text, should_exit)
        """
        raw_cmd = command_line.strip()
        if not raw_cmd:
            return "", False

        # Record in history
        self.history.append(raw_cmd)
        start_time = time.time()

        first_word = raw_cmd.split()[0] if raw_cmd.split() else ""

        # Determine route: Local Builtin vs. AI Responder
        output = ""
        provider_used = "builtin"
        exit_code = 0

        # Check if local builtin can handle this command
        if self.builtin.can_handle(first_word) and "|" not in raw_cmd and ";" not in raw_cmd and "&&" not in raw_cmd:
            output, new_cwd, exit_code, should_exit = self.builtin.execute(
                raw_cmd, self.cwd, self.user, self.history
            )
            self.cwd = new_cwd
            if should_exit:
                self.should_exit = True
        else:
            # Route to AI Responder
            vfs_summary = self.vfs.get_structure_summary(max_items=40)
            output, provider_used = self.ai.respond(
                raw_cmd,
                user=self.user,
                cwd=self.cwd,
                vfs_summary=vfs_summary,
            )

        duration = time.time() - start_time

        # Notify telemetry listener
        if self.on_command_callback:
            try:
                self.on_command_callback(
                    command=raw_cmd,
                    output=output,
                    cwd=self.cwd,
                    user=self.user,
                    provider=provider_used,
                    exit_code=exit_code,
                    duration=duration,
                )
            except Exception as e:
                logger.error(f"Error in on_command_callback: {e}")

        # Ensure newline at the end of output
        if output and not output.endswith("\n"):
            output += "\n"

        # Convert standard LF to CRLF for SSH PTY compatibility
        crlf_output = output.replace("\r\n", "\n").replace("\n", "\r\n")
        return crlf_output, self.should_exit

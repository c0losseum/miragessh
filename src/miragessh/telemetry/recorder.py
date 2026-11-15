"""
MirageSSH - Asciinema v2 Keystroke & Session Replay Recorder
Records full interactive SSH sessions into industry-standard .cast format,
enabling pixel-perfect terminal replay in CLI and Web SOC dashboards.
"""

from __future__ import annotations
import json
import os
import time
from typing import TextIO


class SessionRecorder:
    """Records terminal session streams into Asciinema v2 format."""

    def __init__(
        self,
        session_id: str,
        recordings_dir: str = "data/recordings",
        width: int = 80,
        height: int = 24,
        title: str = "MirageSSH Honeypot Session",
    ):
        self.session_id = session_id
        self.recordings_dir = recordings_dir
        self.width = width
        self.height = height
        self.title = title

        self.start_time: float = 0.0
        self.file_path: str = ""
        self._file: TextIO | None = None
        self.is_recording: bool = False

    def start(self):
        """Initializes the .cast recording file and writes the v2 header."""
        os.makedirs(self.recordings_dir, exist_ok=True)
        self.file_path = os.path.join(self.recordings_dir, f"{self.session_id}.cast")
        self.start_time = time.time()

        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(self.start_time),
            "title": self.title,
            "env": {
                "SHELL": "/bin/bash",
                "TERM": "xterm-256color",
            },
        }

        self._file = open(self.file_path, "w", encoding="utf-8", buffering=1)
        self._file.write(json.dumps(header) + "\n")
        self.is_recording = True

    def record_output(self, text: str):
        """Records terminal output sent to the client."""
        if not self.is_recording or not self._file or not text:
            return
        elapsed = round(time.time() - self.start_time, 4)
        entry = [elapsed, "o", text]
        self._file.write(json.dumps(entry) + "\n")

    def record_input(self, text: str):
        """Records raw keystrokes received from the client."""
        if not self.is_recording or not self._file or not text:
            return
        elapsed = round(time.time() - self.start_time, 4)
        entry = [elapsed, "i", text]
        self._file.write(json.dumps(entry) + "\n")

    def close(self):
        """Closes the recording file."""
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()
        self.is_recording = False

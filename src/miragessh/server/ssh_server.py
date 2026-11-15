"""
MirageSSH - Paramiko SSH Server Daemon & PTY Handler
Implements custom SSH ServerInterface, authentication honeypot traps,
pseudo-terminal (PTY) emulation, and non-interactive exec commands.
"""

from __future__ import annotations
import logging
import os
import socket
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import paramiko

from miragessh.ai.responder import AIResponderCoordinator
from miragessh.server.session import AttackerSession
from miragessh.server.tarpit import TarpitEngine
from miragessh.shell.fake_shell import FakeShell
from miragessh.shell.vfs import VirtualFileSystem
from miragessh.telemetry.geoip import GeoIPResolver
from miragessh.telemetry.honeytokens import HoneytokenManager
from miragessh.telemetry.logger import HoneypotLogger
from miragessh.telemetry.mitre import MitreClassifier
from miragessh.telemetry.notifiers import AlertDispatcher

logger = logging.getLogger("miragessh.server")


class HoneypotServerInterface(paramiko.ServerInterface):
    """Paramiko SSH server interface handling authentication and channel requests."""

    def __init__(
        self,
        session: AttackerSession,
        auth_config: Dict[str, Any],
        on_auth_attempt: Callable,
    ):
        super().__init__()
        self.session = session
        self.auth_config = auth_config
        self.on_auth_attempt = on_auth_attempt
        self.auth_count = 0
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        self.auth_count += 1
        mode = self.auth_config.get("mode", "tarpit_then_allow")
        tarpit_threshold = self.auth_config.get("tarpit_fail_attempts", 2)

        accepted = False
        if mode == "allow_all":
            accepted = True
        elif mode == "tarpit_then_allow":
            # Fail the first N attempts to simulate brute-force resistance, then succeed
            if self.auth_count > tarpit_threshold:
                accepted = True
            else:
                accepted = False
        elif mode == "trap_credentials_only":
            allowed = self.auth_config.get("allowed_users", ["root", "ubuntu", "admin"])
            accepted = username in allowed

        self.on_auth_attempt(
            session=self.session,
            username=username,
            password=password,
            accepted=accepted,
            attempt_number=self.auth_count,
        )

        if accepted:
            self.session.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.on_auth_attempt(
            session=self.session,
            username=username,
            password=f"[PUBLIC_KEY:{key.get_name()}:{key.get_base64()[:16]}...]",
            accepted=True,
            attempt_number=1,
        )
        self.session.authenticated_user = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: str,
    ) -> bool:
        self.session.recorder.width = width
        self.session.recorder.height = height
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.session.exec_command = command.decode("utf-8", errors="replace")
        self.event.set()
        return True


class SSHHoneypotDaemon:
    """Core multithreaded SSH server listening for incoming attacker connections."""

    UBUNTU_MOTD = (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        "  System information as of Sun Nov 15 19:20:00 UTC 2026\r\n\r\n"
        "  System load:  0.08               Processes:             112\r\n"
        "  Usage of /:   16.4% of 78.72GB   Users logged in:       1\r\n"
        "  Memory usage: 18%                IPv4 address for eth0: 10.0.1.5\r\n"
        "  Swap usage:   0%\r\n\r\n"
        " * Strictly for internal management traffic. Unauthorized access is monitored.\r\n\r\n"
        "Last login: Fri Nov 13 14:02:12 2026 from 10.0.1.12\r\n"
    )

    def __init__(
        self,
        config: Dict[str, Any],
        vfs: VirtualFileSystem,
        ai_responder: AIResponderCoordinator,
        honeytokens: HoneytokenManager,
        logger_engine: HoneypotLogger,
        alerter: AlertDispatcher,
        geoip: GeoIPResolver,
    ):
        self.config = config
        self.vfs = vfs
        self.ai = ai_responder
        self.honeytokens = honeytokens
        self.logger_engine = logger_engine
        self.alerter = alerter
        self.geoip = geoip

        self.server_cfg = config.get("server", {})
        self.host = self.server_cfg.get("host", "0.0.0.0")
        self.port = self.server_cfg.get("port", 2222)
        self.banner = self.server_cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7")
        self.host_key_path = self.server_cfg.get("host_key_path", "data/host_keys/miragessh_rsa")

        self.tarpit = TarpitEngine(config.get("tarpit", {}))
        self.active_sessions: Dict[str, AttackerSession] = {}
        self.all_sessions: List[AttackerSession] = []
        self._is_running = False
        self._sock: Optional[socket.socket] = None

        self._ensure_host_key()

    def _ensure_host_key(self):
        """Ensures an RSA host key exists on disk or generates one."""
        os.makedirs(os.path.dirname(self.host_key_path), exist_ok=True)
        if not os.path.exists(self.host_key_path):
            logger.info(f"Generating new RSA host key at {self.host_key_path}...")
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(self.host_key_path)
        self.host_key = paramiko.RSAKey(filename=self.host_key_path)

    def start(self, block: bool = True):
        """Starts the SSH listener socket and accepts clients."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        self._is_running = True
        logger.info(f"🛡️ MirageSSH Honeypot listening on {self.host}:{self.port} (banner: {self.banner})")

        if block:
            self._serve_loop()
        else:
            t = threading.Thread(target=self._serve_loop, daemon=True)
            t.start()

    def stop(self):
        """Stops the SSH daemon."""
        self._is_running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        for s in list(self.active_sessions.values()):
            s.close()

    def _serve_loop(self):
        while self._is_running:
            try:
                client_sock, client_addr = self._sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception as e:
                if self._is_running:
                    logger.error(f"Error accepting connection: {e}")
                break

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
        ip, port = client_addr[0], client_addr[1]
        session = AttackerSession(
            client_ip=ip,
            client_port=port,
            recordings_dir=self.config.get("telemetry", {}).get("recordings_dir", "data/recordings"),
        )
        session.geo = self.geoip.lookup(ip)
        self.active_sessions[session.session_id] = session
        self.all_sessions.append(session)

        # Wire honeytoken callback to session
        def on_honeytoken_trip(path, user, action="read"):
            ev = self.honeytokens.check_access(
                path=path,
                user=user,
                session_id=session.session_id,
                client_ip=ip,
                action=action,
            )
            if ev:
                session.trigger_honeytoken(ev.__dict__)
                self.alerter.send_honeytoken_alert(ev)

        self.vfs.register_honeytoken_listener(on_honeytoken_trip)

        logger.info(f"Incoming connection from {ip}:{port} [{session.geo.country}] (Session: {session.session_id})")
        self.logger_engine.emit_event(
            "SESSION_CONNECT",
            session.session_id,
            {"client_ip": ip, "client_port": port, "geo": session.geo.to_dict()},
        )

        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = self.banner
            transport.add_server_key(self.host_key)

            def auth_callback(session, username, password, accepted, attempt_number):
                self.logger_engine.emit_event(
                    "AUTH_ATTEMPT",
                    session.session_id,
                    {
                        "username": username,
                        "password": password,
                        "accepted": accepted,
                        "attempt": attempt_number,
                    },
                )
                if accepted:
                    self.alerter.send_login_alert(
                        session_id=session.session_id,
                        ip=session.client_ip,
                        user=username,
                        country=session.geo.country,
                        client_version=session.client_version,
                    )

            server_iface = HoneypotServerInterface(
                session=session,
                auth_config=self.config.get("authentication", {}),
                on_auth_attempt=auth_callback,
            )

            transport.start_server(server=server_iface)
            session.client_version = transport.remote_version or "unknown"

            channel = transport.accept(20)
            if channel is None:
                return

            server_iface.event.wait(10)

            # Check if this was a non-interactive exec request (e.g. ssh host "cmd")
            exec_cmd = getattr(session, "exec_command", None)
            if exec_cmd:
                self._handle_exec_channel(channel, session, exec_cmd)
            else:
                self._handle_interactive_shell(channel, session)

        except Exception as e:
            logger.debug(f"Session {session.session_id} exception: {e}")
        finally:
            session.close()
            self.active_sessions.pop(session.session_id, None)
            self.logger_engine.emit_event(
                "SESSION_DISCONNECT",
                session.session_id,
                {
                    "duration": session.duration_seconds,
                    "commands_count": session.total_commands,
                    "risk_score": session.risk_score,
                },
            )
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
            logger.info(f"Session {session.session_id} closed from {ip}. Duration: {session.duration_seconds}s")

    def _handle_interactive_shell(self, channel: paramiko.Channel, session: AttackerSession):
        """Runs the interactive PTY loop for the connected attacker."""
        session.recorder.start()

        def on_command_exec(command, output, cwd, user, provider, exit_code, duration):
            mitre_matches = MitreClassifier.classify(command)
            mitre_ids = [m.id for m in mitre_matches]
            session.add_command(
                command=command,
                output=output,
                cwd=cwd,
                user=user,
                provider=provider,
                exit_code=exit_code,
                duration=duration,
                mitre_ids=mitre_ids,
            )
            self.logger_engine.emit_event(
                "COMMAND_EXECUTED",
                session.session_id,
                {
                    "command": command,
                    "provider": provider,
                    "exit_code": exit_code,
                    "cwd": cwd,
                    "user": user,
                    "duration": duration,
                    "mitre_techniques": [m.__dict__ for m in mitre_matches],
                },
            )
            if mitre_matches and any(m.tactic in ["Credential Access", "Execution"] for m in mitre_matches):
                tactics_str = ", ".join(f"{m.id} ({m.name})" for m in mitre_matches)
                self.alerter.send_high_risk_command_alert(
                    session_id=session.session_id,
                    ip=session.client_ip,
                    command=command,
                    mitre_tactics=tactics_str,
                )

        shell = FakeShell(
            vfs=self.vfs,
            ai_responder=self.ai,
            user=session.authenticated_user,
            hostname=self.config.get("shell", {}).get("hostname", "prod-db-gateway-01"),
            initial_cwd=self.config.get("shell", {}).get("initial_cwd", f"/home/{session.authenticated_user}"),
            on_command_callback=on_command_exec,
        )

        # Send MOTD banner
        channel.send(self.UBUNTU_MOTD)
        session.recorder.record_output(self.UBUNTU_MOTD)

        # Send initial prompt
        initial_prompt = shell.get_prompt()
        channel.send(initial_prompt)
        session.recorder.record_output(initial_prompt)

        line_buffer = ""

        while not shell.should_exit and not channel.closed:
            try:
                char_bytes = channel.recv(1)
                if not char_bytes:
                    break

                char = char_bytes.decode("utf-8", errors="replace")
                session.recorder.record_input(char)

                # Enter (CR or LF)
                if char in ["\r", "\n"]:
                    channel.send("\r\n")
                    session.recorder.record_output("\r\n")

                    cmd = line_buffer.strip()
                    line_buffer = ""

                    if cmd:
                        # Apply Tarpit delay
                        self.tarpit.apply_delay(cmd)
                        output, should_exit = shell.handle_line(cmd)
                        if output:
                            channel.send(output)
                            session.recorder.record_output(output)
                        if should_exit:
                            break

                    prompt = shell.get_prompt()
                    channel.send(prompt)
                    session.recorder.record_output(prompt)

                # Backspace (\x08 or \x7f)
                elif char in ["\x08", "\x7f"]:
                    if len(line_buffer) > 0:
                        line_buffer = line_buffer[:-1]
                        channel.send("\b \b")
                        session.recorder.record_output("\b \b")

                # Ctrl+C (\x03)
                elif char == "\x03":
                    line_buffer = ""
                    channel.send("^C\r\n")
                    session.recorder.record_output("^C\r\n")
                    prompt = shell.get_prompt()
                    channel.send(prompt)
                    session.recorder.record_output(prompt)

                # Ctrl+D (\x04)
                elif char == "\x04":
                    if not line_buffer:
                        channel.send("exit\r\n")
                        session.recorder.record_output("exit\r\n")
                        break

                # Ignore or buffer escape sequences (e.g. arrow keys)
                elif char == "\x1b":
                    # Read escape sequence remainder
                    try:
                        seq = channel.recv(2).decode("utf-8", errors="ignore")
                    except Exception:
                        pass

                # Normal printable characters
                else:
                    if ord(char) >= 32:
                        line_buffer += char
                        channel.send(char)
                        session.recorder.record_output(char)

            except Exception as e:
                break

    def _handle_exec_channel(self, channel: paramiko.Channel, session: AttackerSession, cmd: str):
        """Handles non-interactive one-off commands (e.g. automated SSH droppers)."""
        session.recorder.start()
        session.recorder.record_input(cmd + "\n")

        shell = FakeShell(
            vfs=self.vfs,
            ai_responder=self.ai,
            user=session.authenticated_user,
            hostname=self.config.get("shell", {}).get("hostname", "prod-db-gateway-01"),
            initial_cwd=self.config.get("shell", {}).get("initial_cwd", f"/home/{session.authenticated_user}"),
        )

        self.tarpit.apply_delay(cmd)
        output, _ = shell.handle_line(cmd)
        channel.send(output)
        session.recorder.record_output(output)
        channel.send_exit_status(0)

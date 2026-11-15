"""
MirageSSH - Offline Heuristic Deception Engine (Mock AI)
Provides authentic, simulated Linux responses when LLM APIs are offline,
unconfigured, or rate-limited. Handles complex attack patterns, recon,
and exploit payloads out of the box.
"""

from __future__ import annotations
import re
from typing import Dict, Optional, Tuple


class MockAIResponder:
    """Intelligent rule-based terminal simulator for offline honeypot operations."""

    def __init__(self):
        pass

    def generate_response(
        self,
        command_line: str,
        user: str = "ubuntu",
        cwd: str = "/home/ubuntu",
    ) -> str:
        """Analyzes command pattern and generates realistic terminal output."""
        cmd = command_line.strip()
        if not cmd:
            return ""

        # Sudo execution
        if cmd.startswith("sudo "):
            inner = cmd[5:].strip()
            if inner == "-l" or inner == "-l ":
                return (
                    f"Matching Defaults entries for {user} on prod-db-gateway-01:\n"
                    f"    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n"
                    f"User {user} may run the following commands on prod-db-gateway-01:\n"
                    f"    (ALL : ALL) ALL\n"
                )

        # Network download probes (curl, wget)
        if cmd.startswith("curl ") or cmd.startswith("curl\t"):
            return self._handle_curl(cmd)
        if cmd.startswith("wget ") or cmd.startswith("wget\t"):
            return self._handle_wget(cmd)

        # Port scanning & network enumeration
        if cmd.startswith("netstat") or cmd.startswith("ss "):
            return self._handle_netstat(cmd)
        if cmd.startswith("nmap"):
            return self._handle_nmap(cmd)
        if cmd.startswith("iptables"):
            return self._handle_iptables(cmd, user)

        # Privilege escalation & SUID search
        if "find " in cmd and ("-perm" in cmd or "-4000" in cmd or "-u=s" in cmd):
            return self._handle_suid_find()

        # Crontab persistence inspection
        if cmd.startswith("crontab"):
            if "-l" in cmd:
                return (
                    "# m h  dom mon dow   command\n"
                    "0 2 * * * /usr/local/bin/backup-db.sh > /dev/null 2>&1\n"
                    "*/15 * * * * /opt/payment-service/healthcheck.sh\n"
                )
            return "crontab: installing new crontab\n"

        # Docker container queries
        if cmd.startswith("docker"):
            return self._handle_docker(cmd)

        # Systemctl / service queries
        if cmd.startswith("systemctl") or cmd.startswith("service"):
            return self._handle_systemctl(cmd)

        # Base64 decoder pipeline: echo ... | base64 -d | sh
        if "base64" in cmd and ("|" in cmd or "-d" in cmd):
            return ""  # Silent execution simulation

        # Environment inspection
        if cmd in ["env", "export", "printenv"]:
            return self._handle_env(user, cwd)

        # Script execution (python, perl, php, bash)
        if any(cmd.startswith(prefix) for prefix in ["python", "python3", "perl", "php", "ruby", "node"]):
            return ""  # Many droppers produce zero output on initial staging

        # Package manager installation attempts
        if cmd.startswith("apt ") or cmd.startswith("apt-get "):
            return self._handle_apt(cmd, user)

        # Fallback to realistic bash command not found
        first_token = cmd.split()[0]
        return f"bash: {first_token}: command not found\n"

    def _handle_curl(self, cmd: str) -> str:
        # Check if silent
        if "-s" in cmd or "-sS" in cmd:
            return ""
        # Simulate realistic curl output
        match = re.search(r"https?://([^\s/]+)", cmd)
        host = match.group(1) if match else "198.51.100.24"
        return (
            f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
            f"100  4210  100  4210    0     0  28400      0 --:--:-- --:--:-- --:--:-- 28639\n"
        )

    def _handle_wget(self, cmd: str) -> str:
        if "-q" in cmd:
            return ""
        match = re.search(r"https?://([^\s]+)", cmd)
        url = match.group(0) if match else "http://update.repo-cache.org/payload.sh"
        filename = url.rstrip("/").split("/")[-1] or "index.html"
        return (
            f"--2026-11-15 19:24:12--  {url}\n"
            f"Resolving ... connected.\n"
            f"HTTP request sent, awaiting response... 200 OK\n"
            f"Length: 4210 (4.1K) [application/x-sh]\n"
            f"Saving to: '{filename}'\n\n"
            f"{filename}           100%[===================>]   4.11K  --.-KB/s    in 0.002s\n\n"
            f"2026-11-15 19:24:12 (2.05 MB/s) - '{filename}' saved [4210/4210]\n"
        )

    def _handle_netstat(self, cmd: str) -> str:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      780/sshd: /usr/sbin\n"
            "tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN      1024/postgres\n"
            "tcp        0      0 0.0.0.0:8443            0.0.0.0:*               LISTEN      1280/server\n"
            "tcp6       0      0 :::22                   :::*                    LISTEN      780/sshd: /usr/sbin\n"
            "tcp6       0      0 :::5432                 :::*                    LISTEN      1024/postgres\n"
        )

    def _handle_nmap(self, cmd: str) -> str:
        return (
            "Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-15 19:25 UTC\n"
            "Nmap scan report for localhost (127.0.0.1)\n"
            "Host is up (0.00012s latency).\n"
            "Not shown: 997 closed ports\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "5432/tcp open  postgresql\n"
            "8443/tcp open  https-alt\n\n"
            "Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds\n"
        )

    def _handle_iptables(self, cmd: str, user: str) -> str:
        if user != "root":
            return "iptables: Permission denied (you must be root)\n"
        return (
            "Chain INPUT (policy ACCEPT)\n"
            "target     prot opt source               destination\n"
            "ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED\n"
            "ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh\n\n"
            "Chain FORWARD (policy DROP)\n"
            "target     prot opt source               destination\n\n"
            "Chain OUTPUT (policy ACCEPT)\n"
            "target     prot opt source               destination\n"
        )

    def _handle_suid_find(self) -> str:
        return (
            "/usr/bin/sudo\n"
            "/usr/bin/passwd\n"
            "/usr/bin/newgrp\n"
            "/usr/bin/chsh\n"
            "/usr/bin/chfn\n"
            "/usr/bin/gpasswd\n"
            "/usr/lib/openssh/ssh-keysign\n"
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper\n"
        )

    def _handle_docker(self, cmd: str) -> str:
        if "ps" in cmd:
            return (
                "CONTAINER ID   IMAGE                 COMMAND                  CREATED        STATUS        PORTS                    NAMES\n"
                "4f81c9a102b1   postgres:14-alpine    \"docker-entrypoint.s…\"   6 days ago     Up 6 days     0.0.0.0:5432->5432/tcp   prod-postgres\n"
                "a19b882c3d0e   redis:7-alpine        \"docker-entrypoint.s…\"   6 days ago     Up 6 days     6379/tcp                 prod-redis\n"
            )
        if "images" in cmd:
            return (
                "REPOSITORY   TAG       IMAGE ID       CREATED        SIZE\n"
                "postgres     14-alpine c4a9b218f0a1   2 weeks ago    214MB\n"
                "redis        7-alpine  83f940bb2c19   3 weeks ago    32.4MB\n"
            )
        return "docker: 'docker' daemon running with overlay2 storage driver.\n"

    def _handle_systemctl(self, cmd: str) -> str:
        if "status" in cmd:
            service = cmd.split()[-1]
            return (
                f"● {service}.service - Production Background Service\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)\n"
                f"     Active: active (running) since Wed 2026-11-12 00:00:15 UTC; 6 days ago\n"
                f"   Main PID: 1280 (server)\n"
                f"      Tasks: 4 (limit: 18940)\n"
                f"     Memory: 62.6M\n"
                f"        CPU: 30.150s\n"
                f"     CGroup: /system.slice/{service}.service\n"
                f"             └─1280 /opt/payment-service/bin/server\n"
            )
        return ""

    def _handle_env(self, user: str, cwd: str) -> str:
        return (
            f"SHELL=/bin/bash\n"
            f"USER={user}\n"
            f"PWD={cwd}\n"
            f"LOGNAME={user}\n"
            f"HOME={'/root' if user == 'root' else '/home/' + user}\n"
            f"LANG=en_US.UTF-8\n"
            f"SSH_CONNECTION=192.168.1.105 54128 10.0.1.5 22\n"
            f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\n"
            f"TERM=xterm-256color\n"
        )

    def _handle_apt(self, cmd: str, user: str) -> str:
        if user != "root":
            return (
                "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
            )
        return (
            "Reading package lists... Done\n"
            "Building dependency tree... Done\n"
            "Reading state information... Done\n"
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
        )

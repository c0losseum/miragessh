"""
MirageSSH - MITRE ATT&CK Framework Mapping
Classifies attacker commands against MITRE ATT&CK tactics, techniques,
and sub-techniques for automated threat intelligence and SOC reporting.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    description: str


class MitreClassifier:
    """Classifies Linux shell commands against MITRE ATT&CK for Enterprise."""

    RULES = [
        # Discovery
        (r"\b(whoami|id|groups)\b", MitreTechnique(
            id="T1033",
            name="System Owner/User Discovery",
            tactic="Discovery",
            description="Adversary attempting to identify current user account and privileges."
        )),
        (r"\b(uname|hostname|uptime|cat\s+/proc/version|cat\s+/etc/os-release|lsb_release)\b", MitreTechnique(
            id="T1082",
            name="System Information Discovery",
            tactic="Discovery",
            description="Adversary querying operating system version, kernel, and hardware details."
        )),
        (r"\b(netstat|ss|ip\s+a|ifconfig|arp|route)\b", MitreTechnique(
            id="T1016",
            name="System Network Configuration Discovery",
            tactic="Discovery",
            description="Adversary gathering IP addresses, routing tables, and network interfaces."
        )),
        (r"\b(ps|top|htop|pstree)\b", MitreTechnique(
            id="T1057",
            name="Process Discovery",
            tactic="Discovery",
            description="Adversary enumerating running processes."
        )),
        (r"\b(cat\s+/etc/passwd|getent\s+passwd)\b", MitreTechnique(
            id="T1087.001",
            name="Account Discovery: Local Account",
            tactic="Discovery",
            description="Adversary enumerating system user accounts."
        )),
        (r"\b(find\s+/.*-perm\s+-[0-9]+)\b", MitreTechnique(
            id="T1083",
            name="File and Directory Discovery (SUID Hunting)",
            tactic="Discovery",
            description="Adversary searching for binaries with SUID/SGID permissions for privilege escalation."
        )),

        # Credential Access
        (r"\b(cat\s+/etc/shadow|unshadow|john|hashcat)\b", MitreTechnique(
            id="T1003.008",
            name="OS Credential Dumping: /etc/passwd and /etc/shadow",
            tactic="Credential Access",
            description="Adversary attempting to dump password hashes from /etc/shadow."
        )),
        (r"\b(\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys)\b", MitreTechnique(
            id="T1552.004",
            name="Unsecured Credentials: Private Keys",
            tactic="Credential Access",
            description="Adversary attempting to steal SSH private keys."
        )),
        (r"\b(\.env|config\.json|wp-config\.php|\.aws/credentials)\b", MitreTechnique(
            id="T1552.001",
            name="Unsecured Credentials: Credentials in Files",
            tactic="Credential Access",
            description="Adversary searching configuration files for API keys and database credentials."
        )),

        # Ingress Tool Transfer / Execution
        (r"\b(curl|wget|fetch)\b", MitreTechnique(
            id="T1105",
            name="Ingress Tool Transfer",
            tactic="Command and Control",
            description="Adversary downloading external tools, scripts, or malware payloads."
        )),
        (r"\b(bash\s+-i|sh\s+-i|nc\s+-[a-z]*e|python.*socket|perl.*socket|socat)\b", MitreTechnique(
            id="T1059.004",
            name="Command and Scripting Interpreter: Unix Shell (Reverse Shell)",
            tactic="Execution",
            description="Adversary attempting to establish an interactive reverse shell."
        )),
        (r"\b(chmod\s+\+x|chmod\s+777|chmod\s+755)\b", MitreTechnique(
            id="T1222.002",
            name="File and Directory Permissions Modification: Linux Permissions",
            tactic="Defense Evasion",
            description="Adversary changing permissions to make downloaded tools executable."
        )),

        # Persistence
        (r"\b(crontab|/etc/cron\.|systemctl\s+enable)\b", MitreTechnique(
            id="T1053.003",
            name="Scheduled Task/Job: Cron",
            tactic="Persistence",
            description="Adversary establishing persistence via cron jobs or systemd services."
        )),

        # Defense Evasion
        (r"\b(history\s+-c|rm\s+.*\.bash_history|unset\s+HISTFILE)\b", MitreTechnique(
            id="T1070.003",
            name="Indicator Removal: Clear Command History",
            tactic="Defense Evasion",
            description="Adversary clearing shell history to conceal malicious actions."
        )),
    ]

    @classmethod
    def classify(cls, command_line: str) -> List[MitreTechnique]:
        """Returns all matching MITRE ATT&CK techniques for a given command."""
        matches = []
        for pattern, tech in cls.RULES:
            if re.search(pattern, command_line, re.IGNORECASE):
                matches.append(tech)
        return matches

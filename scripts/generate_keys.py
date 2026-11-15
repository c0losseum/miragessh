"""
MirageSSH - Host Key Generator Utility
Generates cryptographic RSA host keys for the honeypot SSH listener.
"""

import os
import sys

try:
    import paramiko
except ImportError:
    print("Paramiko not found. Run: pip install paramiko")
    sys.exit(1)


def generate_host_key(output_path: str = "data/host_keys/miragessh_rsa", bits: int = 2048):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if os.path.exists(output_path):
        print(f"[*] Host key already exists at: {output_path}")
        return

    print(f"[*] Generating {bits}-bit RSA host key...")
    key = paramiko.RSAKey.generate(bits)
    key.write_private_key_file(output_path)
    print(f"[+] Saved host key to: {output_path}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/host_keys/miragessh_rsa"
    generate_host_key(path)

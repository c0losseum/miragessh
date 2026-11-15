"""
MirageSSH - Command Line Interface (CLI) & Runtime Orchestrator
Coordinates configuration loading, SSH daemon execution, and Web SOC dashboard.
"""

from __future__ import annotations
import argparse
import logging
import os
import sys
import threading
import time
from typing import Any, Dict

import yaml

from miragessh.ai.responder import AIResponderCoordinator
from miragessh.server.ssh_server import SSHHoneypotDaemon
from miragessh.shell.vfs import VirtualFileSystem
from miragessh.telemetry.geoip import GeoIPResolver
from miragessh.telemetry.honeytokens import HoneytokenManager
from miragessh.telemetry.logger import HoneypotLogger
from miragessh.telemetry.notifiers import AlertDispatcher
from miragessh.web.app import create_app

BANNER = r"""
  __  __ _                    ____ ____  _   _ 
 |  \/  (_)_ __ __ _  __ _  / ___/ ___|| | | |
 | |\/| | | '__/ _` |/ _` | \___ \___ \| |_| |
 | |  | | | | | (_| | (_| |  ___) |__) |  _  |
 |_|  |_|_|_|  \__,_|\__, | |____/____/|_| |_|
                      |___/                    
 [ AI-Augmented Adaptive SSH Honeypot & Forensics Tarpit ]
"""


def load_config(config_path: str = "config/default_config.yaml") -> Dict[str, Any]:
    """Loads configuration from YAML file or falls back to defaults."""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def run_dashboard_server(app, host: str, port: int):
    """Runs the FastAPI dashboard via Uvicorn in a background thread."""
    try:
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except Exception as e:
        logging.getLogger("miragessh.web").error(f"Dashboard failed to start: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="MirageSSH - AI-Augmented Adaptive SSH Honeypot & Forensics Tarpit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config", default="config/default_config.yaml", help="Path to config YAML file"
    )
    parser.add_argument("-p", "--port", type=int, default=None, help="SSH port to listen on (default: 2222)")
    parser.add_argument("--host", default=None, help="Host/IP to bind to (default: 0.0.0.0)")
    parser.add_argument("--dashboard-port", type=int, default=None, help="Web dashboard port (default: 8080)")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable Web SOC dashboard")
    parser.add_argument("--ai-provider", choices=["gemini", "openai", "mock"], help="Override AI responder provider")

    args = parser.parse_args()

    print(BANNER)

    # 1. Load configuration
    config = load_config(args.config)
    if args.port:
        config.setdefault("server", {})["port"] = args.port
    if args.host:
        config.setdefault("server", {})["host"] = args.host
    if args.ai_provider:
        config.setdefault("ai_responder", {})["provider"] = args.ai_provider

    # 2. Initialize Telemetry & Logging
    tel_cfg = config.get("telemetry", {})
    logger_engine = HoneypotLogger(
        jsonl_path=tel_cfg.get("jsonl_log_path", "data/logs/miragessh_events.jsonl"),
        text_log_path=tel_cfg.get("text_log_path", "data/logs/miragessh.log"),
        log_level=tel_cfg.get("log_level", "INFO"),
    )
    log = logging.getLogger("miragessh.main")

    # 3. Initialize VFS
    manifest_path = config.get("shell", {}).get("vfs_manifest", "config/vfs_manifest.json")
    vfs = VirtualFileSystem(manifest_path=manifest_path)
    log.info(f"Loaded Virtual File System with {len(vfs.nodes)} nodes.")

    # 4. Initialize AI Responder
    ai_responder = AIResponderCoordinator(config.get("ai_responder", {}))
    log.info(f"AI Responder provider: {ai_responder.provider_name.upper()} (Fallback to mock: {ai_responder.fallback_to_mock})")

    # 5. Initialize Honeytokens & GeoIP
    ht_cfg = config.get("honeytokens", {})
    honeytokens = HoneytokenManager(monitored_paths=ht_cfg.get("paths", []))
    geoip = GeoIPResolver(enabled=config.get("geoip", {}).get("enabled", True))
    alerter = AlertDispatcher(config.get("alerts", {}))

    # 6. Initialize SSH Honeypot Daemon
    daemon = SSHHoneypotDaemon(
        config=config,
        vfs=vfs,
        ai_responder=ai_responder,
        honeytokens=honeytokens,
        logger_engine=logger_engine,
        alerter=alerter,
        geoip=geoip,
    )

    # 7. Start Web Dashboard (if enabled)
    web_cfg = config.get("web_dashboard", {})
    dash_enabled = web_cfg.get("enabled", True) and not args.no_dashboard
    dash_port = args.dashboard_port or web_cfg.get("port", 8080)
    dash_host = web_cfg.get("host", "127.0.0.1")

    if dash_enabled:
        app = create_app(honeypot_daemon=daemon, config=config)
        dash_thread = threading.Thread(
            target=run_dashboard_server, args=(app, dash_host, dash_port), daemon=True
        )
        dash_thread.start()
        print(f"📊 Web SOC Dashboard active at: http://{dash_host}:{dash_port}")

    print(f"🔒 MirageSSH Server listening on {daemon.host}:{daemon.port}")
    print("Press Ctrl+C to stop the honeypot gracefully.\n")

    try:
        daemon.start(block=True)
    except KeyboardInterrupt:
        print("\n[!] Shutting down MirageSSH Honeypot...")
        daemon.stop()
        print("[+] Goodbye!")


if __name__ == "__main__":
    main()

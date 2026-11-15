import pytest
from miragessh.telemetry.honeytokens import HoneytokenManager


def test_honeytoken_detection():
    mgr = HoneytokenManager()
    events = []

    def on_alert(ev):
        events.append(ev)

    mgr.add_listener(on_alert)

    # Access .env
    ev = mgr.check_access(
        path="/home/ubuntu/.env",
        user="ubuntu",
        session_id="test-sess-01",
        client_ip="198.51.100.5",
        action="read",
    )

    assert ev is not None
    assert ev.token_id == "HT-ENV-PROD-SECRETS"
    assert ev.severity == "CRITICAL"
    assert len(events) == 1
    assert events[0].client_ip == "198.51.100.5"


def test_honeytoken_non_monitored_file():
    mgr = HoneytokenManager()
    ev = mgr.check_access(
        path="/home/ubuntu/normal_file.txt",
        user="ubuntu",
    )
    assert ev is None

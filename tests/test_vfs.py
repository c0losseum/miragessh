import pytest
from miragessh.shell.vfs import VirtualFileSystem, VFSNode


def test_vfs_initialization():
    vfs = VirtualFileSystem()
    assert vfs.exists("/")
    assert vfs.is_dir("/")
    assert vfs.exists("/etc/hostname")


def test_vfs_path_resolution():
    vfs = VirtualFileSystem()
    assert vfs.resolve("etc/passwd", "/root") == "/root/etc/passwd"
    assert vfs.resolve("/etc/passwd", "/home/ubuntu") == "/etc/passwd"
    assert vfs.resolve("~/.bashrc", "/tmp") == "/home/ubuntu/.bashrc"
    assert vfs.resolve("../bin", "/home/ubuntu") == "/home/bin"


def test_vfs_read_write_file():
    vfs = VirtualFileSystem()
    ok, err = vfs.write_file("/tmp/test.txt", "Hello Honeypot", user="ubuntu")
    assert ok is True
    assert vfs.exists("/tmp/test.txt")

    ok, content = vfs.read_file("/tmp/test.txt", user="ubuntu")
    assert ok is True
    assert content == "Hello Honeypot"


def test_vfs_mkdir_and_remove():
    vfs = VirtualFileSystem()
    ok, err = vfs.mkdir("/tmp/malware_dir", user="ubuntu")
    assert ok is True
    assert vfs.is_dir("/tmp/malware_dir")

    ok, err = vfs.remove("/tmp/malware_dir", user="ubuntu", recursive=True)
    assert ok is True
    assert not vfs.exists("/tmp/malware_dir")


def test_honeytoken_listener_trigger():
    vfs = VirtualFileSystem()
    vfs.nodes["/home/ubuntu/.env"] = VFSNode(
        path="/home/ubuntu/.env",
        type="file",
        content="SECRET=12345",
    )

    triggered = []

    def mock_listener(path, user, action="read"):
        triggered.append((path, user, action))

    vfs.register_honeytoken_listener(mock_listener)
    ok, _ = vfs.read_file("/home/ubuntu/.env", user="ubuntu")

    assert ok is True
    assert len(triggered) == 1
    assert triggered[0] == ("/home/ubuntu/.env", "ubuntu", "read")

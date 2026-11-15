import pytest
from miragessh.shell.builtin_commands import BuiltinCommandsHandler
from miragessh.shell.vfs import VirtualFileSystem, VFSNode


@pytest.fixture
def vfs():
    fs = VirtualFileSystem()
    fs.nodes["/home/ubuntu/secret.txt"] = VFSNode(
        path="/home/ubuntu/secret.txt",
        type="file",
        owner="ubuntu",
        group="ubuntu",
        content="top_secret_data\n",
    )
    return fs


def test_builtin_pwd(vfs):
    handler = BuiltinCommandsHandler(vfs)
    stdout, cwd, code, should_exit = handler.execute("pwd", "/home/ubuntu", "ubuntu", [])
    assert stdout.strip() == "/home/ubuntu"
    assert code == 0


def test_builtin_whoami_and_id(vfs):
    handler = BuiltinCommandsHandler(vfs)
    stdout, _, _, _ = handler.execute("whoami", "/home/ubuntu", "ubuntu", [])
    assert stdout.strip() == "ubuntu"

    stdout, _, _, _ = handler.execute("id", "/home/ubuntu", "root", [])
    assert "uid=0(root)" in stdout


def test_builtin_cd(vfs):
    handler = BuiltinCommandsHandler(vfs)
    _, new_cwd, code, _ = handler.execute("cd /etc", "/home/ubuntu", "ubuntu", [])
    assert new_cwd == "/etc"
    assert code == 0


def test_builtin_cat(vfs):
    handler = BuiltinCommandsHandler(vfs)
    stdout, _, code, _ = handler.execute("cat secret.txt", "/home/ubuntu", "ubuntu", [])
    assert "top_secret_data" in stdout
    assert code == 0


def test_builtin_echo_redirection(vfs):
    handler = BuiltinCommandsHandler(vfs)
    stdout, _, code, _ = handler.execute("echo 'injected_text' > /tmp/payload.sh", "/home/ubuntu", "ubuntu", [])
    assert code == 0

    assert vfs.exists("/tmp/payload.sh")
    ok, content = vfs.read_file("/tmp/payload.sh", "ubuntu")
    assert "injected_text" in content


def test_builtin_uname(vfs):
    handler = BuiltinCommandsHandler(vfs)
    stdout, _, code, _ = handler.execute("uname -a", "/home/ubuntu", "ubuntu", [])
    assert "Linux" in stdout
    assert "x86_64" in stdout


def test_builtin_exit(vfs):
    handler = BuiltinCommandsHandler(vfs)
    _, _, _, should_exit = handler.execute("exit", "/home/ubuntu", "ubuntu", [])
    assert should_exit is True

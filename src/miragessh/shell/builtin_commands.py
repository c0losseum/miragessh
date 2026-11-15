"""
MirageSSH - Local Fast-Path Builtin Shell Commands
Handles high-frequency Linux commands locally with maximum realism,
sub-millisecond execution time, and safe in-memory state manipulation.
"""

from __future__ import annotations
import datetime
import shlex
import time
from typing import Dict, List, Optional, Tuple

from miragessh.shell.vfs import VirtualFileSystem


class BuiltinCommandsHandler:
    """Dispatches and executes known POSIX terminal commands."""

    def __init__(self, vfs: VirtualFileSystem):
        self.vfs = vfs
        self.start_time = time.time() - (164 * 3600)  # Simulated uptime of 6+ days

    def can_handle(self, command_name: str) -> bool:
        """Returns True if command has a dedicated local implementation."""
        handlers = {
            "ls", "dir", "cd", "pwd", "cat", "whoami", "id", "groups",
            "uname", "hostname", "uptime", "date", "w", "who", "last",
            "ps", "top", "free", "df", "ip", "ifconfig", "ping",
            "mkdir", "touch", "rm", "echo", "history", "clear",
            "exit", "logout", "quit", "help", "head", "tail", "grep"
        }
        return command_name in handlers

    def execute(
        self,
        command_line: str,
        cwd: str,
        user: str,
        session_history: List[str],
    ) -> Tuple[str, str, int, bool]:
        """
        Executes a shell command.
        Returns: (stdout, new_cwd, exit_code, should_exit)
        """
        raw_cmd = command_line.strip()
        if not raw_cmd:
            return "", cwd, 0, False

        # Support output redirection: echo "hello" > file.txt or >> file.txt
        if ">" in raw_cmd and not raw_cmd.startswith("grep"):
            return self._handle_redirection(raw_cmd, cwd, user, session_history)

        try:
            tokens = shlex.split(raw_cmd)
        except ValueError:
            tokens = raw_cmd.split()

        if not tokens:
            return "", cwd, 0, False

        cmd = tokens[0]
        args = tokens[1:]

        # Dispatch
        method_name = f"_cmd_{cmd}"
        handler = getattr(self, method_name, None)

        if handler:
            return handler(args, cwd, user, session_history)

        return f"bash: {cmd}: command not found\n", cwd, 127, False

    def _handle_redirection(self, raw_cmd: str, cwd: str, user: str, history: List[str]):
        """Handles simple bash redirection > and >>."""
        append = ">>" in raw_cmd
        separator = ">>" if append else ">"
        parts = raw_cmd.split(separator, 1)
        command_part = parts[0].strip()
        target_file = parts[1].strip().strip('"').strip("'")

        if not target_file:
            return "bash: syntax error near unexpected token 'newline'\n", cwd, 2, False

        target_path = self.vfs.resolve(target_file, cwd)

        # Get output of left-side command
        stdout, new_cwd, exit_code, should_exit = self.execute(command_part, cwd, user, history)

        if exit_code == 0:
            ok, err = self.vfs.write_file(target_path, stdout, user=user, append=append)
            if not ok:
                return err + "\n", cwd, 1, False
            return "", cwd, 0, False
        else:
            return stdout, cwd, exit_code, False

    # ------------------ Command Implementations ------------------

    def _cmd_pwd(self, args, cwd, user, history):
        return f"{cwd}\n", cwd, 0, False

    def _cmd_cd(self, args, cwd, user, history):
        target = args[0] if args else (f"/home/{user}" if user != "root" else "/root")
        resolved = self.vfs.resolve(target, cwd)

        if not self.vfs.exists(resolved):
            return f"bash: cd: {target}: No such file or directory\n", cwd, 1, False

        if not self.vfs.is_dir(resolved):
            return f"bash: cd: {target}: Not a directory\n", cwd, 1, False

        # Permission check
        if resolved.startswith("/root") and user != "root":
            return f"bash: cd: {target}: Permission denied\n", cwd, 1, False

        return "", resolved, 0, False

    def _cmd_ls(self, args, cwd, user, history):
        show_all = False
        long_format = False
        targets = []

        for arg in args:
            if arg.startswith("-") and len(arg) > 1:
                if "a" in arg:
                    show_all = True
                if "l" in arg or "h" in arg:
                    long_format = True
            else:
                targets.append(arg)

        target_dir = self.vfs.resolve(targets[0] if targets else ".", cwd)
        ok, result = self.vfs.list_dir(target_dir)

        if not ok:
            return f"{result}\n", cwd, 2, False

        output = []
        if long_format:
            output.append(f"total {len(result) * 4}")
            if show_all:
                now_str = datetime.datetime.now().strftime("%b %d %H:%M")
                output.append(f"drwxr-xr-x  2 root root 4096 {now_str} .")
                output.append(f"drwxr-xr-x 20 root root 4096 {now_str} ..")

            for node in result:
                if not show_all and node.name.startswith("."):
                    continue
                d_time = datetime.datetime.fromtimestamp(node.mtime).strftime("%b %d %H:%M")
                links = 2 if node.is_directory else 1
                line = f"{node.permissions:<10} {links:>2} {node.owner:<8} {node.group:<8} {node.size:>6} {d_time} {node.name}"
                output.append(line)
        else:
            names = []
            for node in result:
                if not show_all and node.name.startswith("."):
                    continue
                names.append(node.name)
            if names:
                output.append("  ".join(names))

        return ("\n".join(output) + ("\n" if output else "")), cwd, 0, False

    def _cmd_cat(self, args, cwd, user, history):
        if not args:
            return "", cwd, 0, False

        out = []
        exit_code = 0
        for arg in args:
            path = self.vfs.resolve(arg, cwd)
            ok, content = self.vfs.read_file(path, user=user)
            if not ok:
                out.append(content)
                exit_code = 1
            else:
                out.append(content.rstrip("\n"))

        return ("\n".join(out) + "\n" if out else ""), cwd, exit_code, False

    def _cmd_whoami(self, args, cwd, user, history):
        return f"{user}\n", cwd, 0, False

    def _cmd_id(self, args, cwd, user, history):
        if user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n", cwd, 0, False
        return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)\n", cwd, 0, False

    def _cmd_groups(self, args, cwd, user, history):
        if user == "root":
            return "root\n", cwd, 0, False
        return "ubuntu adm cdrom sudo dip plugdev lxd\n", cwd, 0, False

    def _cmd_uname(self, args, cwd, user, history):
        sys_info = self.vfs.system_info
        if "-a" in args or "--all" in args:
            return f"Linux {sys_info['hostname']} {sys_info['kernel']} #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 {sys_info['architecture']} x86_64 x86_64 GNU/Linux\n", cwd, 0, False
        if "-r" in args:
            return f"{sys_info['kernel']}\n", cwd, 0, False
        if "-m" in args:
            return f"{sys_info['architecture']}\n", cwd, 0, False
        return "Linux\n", cwd, 0, False

    def _cmd_hostname(self, args, cwd, user, history):
        return f"{self.vfs.system_info.get('hostname', 'prod-db-gateway-01')}\n", cwd, 0, False

    def _cmd_uptime(self, args, cwd, user, history):
        elapsed = int(time.time() - self.start_time)
        days = elapsed // 86400
        hours = (elapsed % 86400) // 3600
        mins = (elapsed % 3600) // 60
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        return f" {now_str} up {days} days, {hours}:{mins:02d},  1 user,  load average: 0.12, 0.08, 0.05\n", cwd, 0, False

    def _cmd_date(self, args, cwd, user, history):
        now_str = datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
        return f"{now_str}\n", cwd, 0, False

    def _cmd_who(self, args, cwd, user, history):
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        return f"{user}   pts/0        {now_str} (192.168.1.105)\n", cwd, 0, False

    def _cmd_w(self, args, cwd, user, history):
        up = self._cmd_uptime(args, cwd, user, history)[0].strip()
        header = f" {up}\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        row = f"{user:<8} pts/0    192.168.1.105    19:20    0.00s  0.04s  0.00s w\n"
        return header + row, cwd, 0, False

    def _cmd_last(self, args, cwd, user, history):
        now_str = datetime.datetime.now().strftime("%a %b %d %H:%M")
        lines = [
            f"{user}   pts/0        192.168.1.105    {now_str}   still logged in",
            f"ubuntu   pts/1        10.0.1.12        Fri Nov 14 09:12 - 10:45  (01:33)",
            f"root     pts/0        10.0.1.5         Wed Nov 12 14:02 - 14:30  (00:28)",
            "\nwtmp begins Wed Nov 12 00:00:01 2026\n",
        ]
        return "\n".join(lines) + "\n", cwd, 0, False

    def _cmd_ps(self, args, cwd, user, history):
        arg_str = "".join(args)
        if "aux" in arg_str or "-ef" in arg_str:
            lines = [
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
                "root           1  0.0  0.1 168324 13248 ?        Ss   Nov12   0:05 /sbin/init",
                "root           2  0.0  0.0      0     0 ?        S    Nov12   0:00 [kthreadd]",
                "root         450  0.0  0.2  72104 18240 ?        Ss   Nov12   0:02 /lib/systemd/systemd-journald",
                "root         780  0.0  0.1  18400  7120 ?        Ss   Nov12   0:01 /usr/sbin/sshd -D",
                "postgres    1024  0.1  1.2 384920 98200 ?        Ss   Nov12   1:45 /usr/lib/postgresql/14/bin/postgres",
                "root        1280  0.0  0.8 124800 64200 ?        Ssl  Nov12   0:30 /opt/payment-service/bin/server",
                f"{user}        2450  0.0  0.0  14500  5120 pts/0    Ss   19:20   0:00 -bash",
                f"{user}        2510  0.0  0.0  18900  3400 pts/0    R+   19:21   0:00 ps {arg_str}",
            ]
            return "\n".join(lines) + "\n", cwd, 0, False
        else:
            lines = [
                "  PID TTY          TIME CMD",
                f" 2450 pts/0    00:00:00 bash",
                f" 2512 pts/0    00:00:00 ps",
            ]
            return "\n".join(lines) + "\n", cwd, 0, False

    def _cmd_top(self, args, cwd, user, history):
        return (
            "top - 19:22:04 up 6 days, 20:12,  1 user,  load average: 0.08, 0.04, 0.01\n"
            "Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 97.9 id,  0.1 wa,  0.0 hi,  0.0 si,  0.0 st\n"
            "MiB Mem :  16000.0 total,  11210.4 free,   2840.2 used,   1949.4 buff/cache\n"
            "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.  13159.8 avail Mem\n\n"
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            "   1024 postgres  20   0  375.9m  95.8m  42.1m S   0.7   0.6   1:45.22 postgres\n"
            "   1280 root      20   0  121.8m  62.6m  18.4m S   0.3   0.4   0:30.15 server\n"
            "   2450 ubuntu    20   0   14.2m   5.0m   3.2m S   0.0   0.0   0:00.12 bash\n"
        ), cwd, 0, False

    def _cmd_free(self, args, cwd, user, history):
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:        16384000     2912400    11482012       24500     2708064    13890204\n"
            "Swap:        2097148           0     2097148\n"
        ), cwd, 0, False

    def _cmd_df(self, args, cwd, user, history):
        return (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/root       82544256 12480120  70064136  16% /\n"
            "tmpfs            8192000        0   8192000   0% /dev/shm\n"
            "efivarfs             128       48        76  39% /sys/firmware/efi/efivars\n"
            "/dev/sda15        106858     6180    100678   6% /boot/efi\n"
        ), cwd, 0, False

    def _cmd_ip(self, args, cwd, user, history):
        arg_str = " ".join(args)
        if "a" in arg_str or "addr" in arg_str or not args:
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
                "    link/ether 02:42:0a:00:01:05 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.1.5/24 brd 10.0.1.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever\n"
            ), cwd, 0, False
        if "route" in arg_str:
            return "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.5 metric 100\n10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.5\n", cwd, 0, False
        return "Object not found\n", cwd, 1, False

    def _cmd_ifconfig(self, args, cwd, user, history):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.1.5  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            "        ether 02:42:0a:00:01:05  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 421890  bytes 194820120 (194.8 MB)\n"
            "        TX packets 384102  bytes 142019481 (142.0 MB)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
        ), cwd, 0, False

    def _cmd_ping(self, args, cwd, user, history):
        target = "8.8.8.8"
        for a in args:
            if not a.startswith("-"):
                target = a
                break
        return (
            f"PING {target} ({target}) 56(84) bytes of data.\n"
            f"64 bytes from {target}: icmp_seq=1 ttl=118 time=12.4 ms\n"
            f"64 bytes from {target}: icmp_seq=2 ttl=118 time=11.9 ms\n"
            f"64 bytes from {target}: icmp_seq=3 ttl=118 time=12.1 ms\n\n"
            f"--- {target} ping statistics ---\n"
            f"3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
            f"rtt min/avg/max/mdev = 11.912/12.140/12.418/0.208 ms\n"
        ), cwd, 0, False

    def _cmd_mkdir(self, args, cwd, user, history):
        if not args:
            return "mkdir: missing operand\n", cwd, 1, False
        path = self.vfs.resolve(args[0], cwd)
        ok, err = self.vfs.mkdir(path, user=user)
        if not ok:
            return err + "\n", cwd, 1, False
        return "", cwd, 0, False

    def _cmd_touch(self, args, cwd, user, history):
        if not args:
            return "touch: missing file operand\n", cwd, 1, False
        path = self.vfs.resolve(args[0], cwd)
        if not self.vfs.exists(path):
            ok, err = self.vfs.write_file(path, "", user=user)
            if not ok:
                return err + "\n", cwd, 1, False
        return "", cwd, 0, False

    def _cmd_rm(self, args, cwd, user, history):
        if not args:
            return "rm: missing operand\n", cwd, 1, False
        recursive = "-r" in args or "-rf" in args or "-fr" in args
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return "rm: missing operand\n", cwd, 1, False

        for t in targets:
            path = self.vfs.resolve(t, cwd)
            ok, err = self.vfs.remove(path, user=user, recursive=recursive)
            if not ok:
                return err + "\n", cwd, 1, False
        return "", cwd, 0, False

    def _cmd_echo(self, args, cwd, user, history):
        return " ".join(args) + "\n", cwd, 0, False

    def _cmd_history(self, args, cwd, user, history):
        lines = []
        for i, cmd in enumerate(history, 1):
            lines.append(f"  {i:>4}  {cmd}")
        return "\n".join(lines) + ("\n" if lines else ""), cwd, 0, False

    def _cmd_clear(self, args, cwd, user, history):
        return "\033[H\033[2J", cwd, 0, False

    def _cmd_exit(self, args, cwd, user, history):
        return "logout\n", cwd, 0, True

    def _cmd_logout(self, args, cwd, user, history):
        return "logout\n", cwd, 0, True

    def _cmd_quit(self, args, cwd, user, history):
        return "logout\n", cwd, 0, True

    def _cmd_help(self, args, cwd, user, history):
        return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.  Type 'help' to see this list.\n", cwd, 0, False

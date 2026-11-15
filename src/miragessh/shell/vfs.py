"""
MirageSSH - Virtual In-Memory File System (VFS)
Simulates a realistic Linux hierarchical directory tree with permissions,
honeytoken detection, and dynamic in-memory file persistence.
"""

from __future__ import annotations
import json
import os
import posixpath
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class VFSNode:
    path: str
    type: str  # 'directory' or 'file'
    owner: str = "root"
    group: str = "root"
    permissions: str = "-rw-r--r--"
    content: str = ""
    mtime: float = field(default_factory=time.time)

    @property
    def name(self) -> str:
        if self.path == "/":
            return "/"
        return posixpath.basename(self.path)

    @property
    def size(self) -> int:
        if self.type == "directory":
            return 4096
        return len(self.content.encode("utf-8"))

    @property
    def is_directory(self) -> bool:
        return self.type == "directory"


class VirtualFileSystem:
    """In-memory realistic virtual Linux filesystem."""

    def __init__(self, manifest_path: Optional[str] = None):
        self.nodes: Dict[str, VFSNode] = {}
        self.system_info: Dict[str, str] = {
            "hostname": "prod-db-gateway-01",
            "os_name": "Ubuntu",
            "os_version": "22.04.3 LTS (Jammy Jellyfish)",
            "kernel": "5.15.0-89-generic",
            "architecture": "x86_64",
        }
        self.honeytoken_callbacks = []

        if manifest_path and os.path.exists(manifest_path):
            self.load_from_manifest(manifest_path)
        else:
            self._init_defaults()

    def register_honeytoken_listener(self, callback):
        """Register a callback for honeytoken access events."""
        self.honeytoken_callbacks.append(callback)

    def load_from_manifest(self, filepath: str):
        """Loads filesystem nodes and system metadata from JSON manifest."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "system_info" in data:
            self.system_info.update(data["system_info"])

        for item in data.get("nodes", []):
            path = self._normalize_path(item["path"])
            node = VFSNode(
                path=path,
                type=item.get("type", "file"),
                owner=item.get("owner", "root"),
                group=item.get("group", "root"),
                permissions=item.get("permissions", "-rw-r--r--" if item.get("type") == "file" else "drwxr-xr-x"),
                content=item.get("content", ""),
            )
            self.nodes[path] = node

        # Ensure root directory always exists
        if "/" not in self.nodes:
            self.nodes["/"] = VFSNode(path="/", type="directory", owner="root", group="root", permissions="drwxr-xr-x")

    def _init_defaults(self):
        """Initializes minimal default Linux tree if no manifest is provided."""
        dirs = ["/", "/bin", "/etc", "/home", "/home/ubuntu", "/root", "/tmp", "/var", "/var/log", "/proc"]
        for d in dirs:
            self.nodes[d] = VFSNode(path=d, type="directory", owner="root", group="root", permissions="drwxr-xr-x")
        self.nodes["/home/ubuntu"].owner = "ubuntu"
        self.nodes["/home/ubuntu"].group = "ubuntu"

        self.nodes["/etc/hostname"] = VFSNode(
            path="/etc/hostname",
            type="file",
            owner="root",
            group="root",
            permissions="-rw-r--r--",
            content="prod-db-gateway-01\n",
        )

    def _normalize_path(self, path: str) -> str:
        """Normalizes path using POSIX rules."""
        norm = posixpath.normpath(path)
        if not norm.startswith("/"):
            norm = "/" + norm
        return norm

    def resolve(self, path: str, cwd: str = "/") -> str:
        """Resolves a given path against the current working directory."""
        if not path:
            return cwd
        if path.startswith("~"):
            path = posixpath.join("/home/ubuntu", path[1:].lstrip("/"))
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        return self._normalize_path(path)

    def exists(self, path: str) -> bool:
        return self._normalize_path(path) in self.nodes

    def is_dir(self, path: str) -> bool:
        node = self.nodes.get(self._normalize_path(path))
        return bool(node and node.is_directory)

    def get_node(self, path: str) -> Optional[VFSNode]:
        return self.nodes.get(self._normalize_path(path))

    def list_dir(self, path: str) -> Tuple[bool, List[VFSNode] | str]:
        """Lists child nodes inside a directory."""
        norm = self._normalize_path(path)
        node = self.nodes.get(norm)
        if not node:
            return False, f"ls: cannot access '{path}': No such file or directory"
        if not node.is_directory:
            return True, [node]

        results = []
        target_prefix = norm if norm.endswith("/") else norm + "/"
        for p, child_node in self.nodes.items():
            if p == norm:
                continue
            if p.startswith(target_prefix):
                remainder = p[len(target_prefix):]
                if "/" not in remainder:  # Direct child
                    results.append(child_node)

        # Sort alphabetically
        results.sort(key=lambda n: n.name)
        return True, results

    def read_file(self, path: str, user: str = "ubuntu") -> Tuple[bool, str]:
        """Reads content from a file node."""
        norm = self._normalize_path(path)
        node = self.nodes.get(norm)
        if not node:
            return False, f"cat: {path}: No such file or directory"
        if node.is_directory:
            return False, f"cat: {path}: Is a directory"

        # Check permissions for /etc/shadow or /root
        if norm.startswith("/root") and user != "root":
            return False, f"cat: {path}: Permission denied"
        if norm == "/etc/shadow" and user != "root":
            return False, f"cat: {path}: Permission denied"

        # Honeytoken trigger check
        for cb in self.honeytoken_callbacks:
            try:
                cb(norm, user, action="read")
            except Exception:
                pass

        return True, node.content

    def write_file(self, path: str, content: str, user: str = "ubuntu", append: bool = False) -> Tuple[bool, str]:
        """Writes or appends to a file in memory."""
        norm = self._normalize_path(path)
        parent = posixpath.dirname(norm)
        if parent not in self.nodes or not self.nodes[parent].is_directory:
            return False, f"bash: {path}: No such file or directory"

        # Permission check: unprivileged user writing to root dirs
        if parent in ["/etc", "/bin", "/boot", "/root"] and user != "root":
            return False, f"bash: {path}: Permission denied"

        node = self.nodes.get(norm)
        if node:
            if node.is_directory:
                return False, f"bash: {path}: Is a directory"
            if append:
                node.content += content
            else:
                node.content = content
            node.mtime = time.time()
        else:
            node = VFSNode(
                path=norm,
                type="file",
                owner=user,
                group=user,
                permissions="-rw-r--r--",
                content=content,
                mtime=time.time(),
            )
            self.nodes[norm] = node

        # Honeytoken trigger check
        for cb in self.honeytoken_callbacks:
            try:
                cb(norm, user, action="write")
            except Exception:
                pass

        return True, ""

    def mkdir(self, path: str, user: str = "ubuntu") -> Tuple[bool, str]:
        """Creates a directory node."""
        norm = self._normalize_path(path)
        if norm in self.nodes:
            return False, f"mkdir: cannot create directory '{path}': File exists"

        parent = posixpath.dirname(norm)
        if parent not in self.nodes or not self.nodes[parent].is_directory:
            return False, f"mkdir: cannot create directory '{path}': No such file or directory"

        if parent in ["/etc", "/bin", "/boot", "/root"] and user != "root":
            return False, f"mkdir: cannot create directory '{path}': Permission denied"

        self.nodes[norm] = VFSNode(
            path=norm,
            type="directory",
            owner=user,
            group=user,
            permissions="drwxr-xr-x",
            mtime=time.time(),
        )
        return True, ""

    def remove(self, path: str, user: str = "ubuntu", recursive: bool = False) -> Tuple[bool, str]:
        """Removes a file or directory node."""
        norm = self._normalize_path(path)
        node = self.nodes.get(norm)
        if not node:
            return False, f"rm: cannot remove '{path}': No such file or directory"

        if node.is_directory and not recursive:
            return False, f"rm: cannot remove '{path}': Is a directory"

        if norm in ["/", "/etc", "/bin", "/root", "/var", "/proc", "/sys"]:
            return False, f"rm: cannot remove '{path}': Device or resource busy"

        # Check permissions
        parent = posixpath.dirname(norm)
        if parent in ["/etc", "/bin", "/boot", "/root"] and user != "root":
            return False, f"rm: cannot remove '{path}': Permission denied"

        if node.is_directory and recursive:
            # Delete child nodes as well
            prefix = norm if norm.endswith("/") else norm + "/"
            to_delete = [p for p in self.nodes if p == norm or p.startswith(prefix)]
            for p in to_delete:
                self.nodes.pop(p, None)
        else:
            self.nodes.pop(norm, None)

        return True, ""

    def get_structure_summary(self, max_items: int = 50) -> str:
        """Returns a concise summary of the filesystem for LLM prompt context."""
        lines = []
        for path in sorted(self.nodes.keys())[:max_items]:
            node = self.nodes[path]
            kind = "DIR " if node.is_directory else "FILE"
            lines.append(f"{kind} {node.permissions} {node.owner}:{node.group} {path}")
        return "\n".join(lines)

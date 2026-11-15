"""
MirageSSH - Terminal Prompt Formatter
Generates authentic Ubuntu bash PS1 prompts with ANSI escape codes.
"""


class PromptFormatter:
    """Formats realistic Linux bash prompts."""

    # ANSI Color constants
    GREEN = "\033[01;32m"
    BLUE = "\033[01;34m"
    RESET = "\033[00m"
    RED = "\033[01;31m"

    @classmethod
    def format_prompt(
        cls,
        user: str = "ubuntu",
        hostname: str = "prod-db-gateway-01",
        cwd: str = "/home/ubuntu",
        color: bool = True,
    ) -> str:
        """
        Generates standard Ubuntu bash prompt:
        user@host:path$ (or # if root)
        """
        # Format tilde for home directory
        display_path = cwd
        home_prefix = f"/home/{user}" if user != "root" else "/root"
        if cwd == home_prefix:
            display_path = "~"
        elif cwd.startswith(home_prefix + "/"):
            display_path = "~" + cwd[len(home_prefix):]

        sign = "#" if user == "root" else "$"

        if color:
            user_color = cls.RED if user == "root" else cls.GREEN
            return f"{user_color}{user}@{hostname}{cls.RESET}:{cls.BLUE}{display_path}{cls.RESET}{sign} "
        else:
            return f"{user}@{hostname}:{display_path}{sign} "

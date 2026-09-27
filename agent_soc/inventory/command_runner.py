"""Restricted subprocess execution for local inventory collection."""

from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
import time


ALLOWED_COMMANDS = {
    ("uname", "-r"),
    ("uname", "-m"),
    ("lscpu", "-J"),
    ("free", "-b"),
    ("ip", "-j", "address", "show"),
    ("ip", "-j", "route", "show", "default"),
    ("df", "-B1", "--output=size,used,avail,pcent,target", "/"),
    ("uptime", "-s"),
}


@dataclass(frozen=True)
class CommandResult:
    """Normalized result from an allowlisted command."""

    command: tuple[str, ...]
    return_code: int | None
    stdout: str
    stderr: str
    duration_ms: int

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0


class SafeCommandRunner:
    """Run only exact, read-only commands required by the inventory module."""

    def __init__(
        self,
        timeout_seconds: float = 3.0,
        search_path: str = "/usr/bin:/bin:/usr/sbin:/sbin",
    ):
        self.timeout_seconds = timeout_seconds
        self.search_path = search_path

    def run(self, command: tuple[str, ...]) -> CommandResult:
        if command not in ALLOWED_COMMANDS:
            raise ValueError(f"Command is not allowlisted: {' '.join(command)}")

        executable = shutil.which(command[0], path=self.search_path)
        if executable is None:
            return CommandResult(command, None, "", "command not found", 0)

        started = time.monotonic()
        environment = {
            "PATH": self.search_path,
            "LANG": "C",
            "LC_ALL": "C",
        }
        try:
            completed = subprocess.run(
                [executable, *command[1:]],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
                timeout=self.timeout_seconds,
            )
            return CommandResult(
                command=command,
                return_code=completed.returncode,
                stdout=completed.stdout.strip(),
                stderr=completed.stderr.strip(),
                duration_ms=round((time.monotonic() - started) * 1000),
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                command=command,
                return_code=None,
                stdout="",
                stderr=f"timeout after {self.timeout_seconds:g} seconds",
                duration_ms=round((time.monotonic() - started) * 1000),
            )
        except OSError as error:
            return CommandResult(
                command=command,
                return_code=None,
                stdout="",
                stderr=str(error),
                duration_ms=round((time.monotonic() - started) * 1000),
            )

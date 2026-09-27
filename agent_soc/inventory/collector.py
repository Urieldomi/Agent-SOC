"""Collect and normalize facts about the Linux host running Agent SOC."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import socket
from typing import Any

from .command_runner import CommandResult, SafeCommandRunner
from .models import CommandTrace, InventorySnapshot, NetworkAddress, NetworkInterface


class LocalInventoryCollector:
    """Build a real inventory snapshot using read-only Linux commands and files."""

    def __init__(self, runner: SafeCommandRunner | None = None):
        self.runner = runner or SafeCommandRunner()
        self._traces: list[CommandTrace] = []
        self._warnings: list[str] = []

    def collect(self) -> InventorySnapshot:
        self._traces = []
        self._warnings = []

        kernel_release = self._stdout(("uname", "-r")) or platform.release()
        architecture = self._stdout(("uname", "-m")) or platform.machine()
        memory, swap = self._collect_memory()

        return InventorySnapshot(
            schema_version="1.0",
            collected_at=datetime.now(timezone.utc).isoformat(),
            hostname=socket.gethostname(),
            fqdn=socket.getfqdn(),
            operating_system=self._collect_operating_system(),
            kernel={"release": kernel_release, "architecture": architecture},
            hardware=self._collect_hardware(),
            cpu=self._collect_cpu(),
            memory=memory,
            swap=swap,
            root_disk=self._collect_root_disk(),
            uptime=self._collect_uptime(),
            default_gateway=self._collect_default_gateway(),
            network_interfaces=self._collect_network_interfaces(),
            command_trace=list(self._traces),
            warnings=list(self._warnings),
        )

    def _run(self, command: tuple[str, ...]) -> CommandResult:
        result = self.runner.run(command)
        self._traces.append(CommandTrace(" ".join(command), result.succeeded, result.duration_ms))
        if not result.succeeded:
            detail = result.stderr or f"exit code {result.return_code}"
            self._warnings.append(f"{' '.join(command)}: {detail}")
        return result

    def _stdout(self, command: tuple[str, ...]) -> str | None:
        result = self._run(command)
        return result.stdout if result.succeeded else None

    def _collect_operating_system(self) -> dict[str, str]:
        try:
            release = platform.freedesktop_os_release()
        except OSError as error:
            self._warnings.append(f"os-release: {error}")
            release = {}
        return {
            "id": release.get("ID", "unknown"),
            "name": release.get("NAME", "Linux"),
            "pretty_name": release.get("PRETTY_NAME", platform.platform()),
            "version_id": release.get("VERSION_ID", "unknown"),
            "version_codename": release.get("VERSION_CODENAME", "unknown"),
        }

    def _collect_hardware(self) -> dict[str, str | None]:
        return {
            "vendor": self._read_optional_file("/sys/class/dmi/id/sys_vendor"),
            "product": self._read_optional_file("/sys/class/dmi/id/product_name"),
            "product_version": self._read_optional_file("/sys/class/dmi/id/product_version"),
        }

    @staticmethod
    def _read_optional_file(path: str) -> str | None:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
            return value or None
        except (OSError, UnicodeError):
            return None

    def _collect_cpu(self) -> dict[str, str | int | None]:
        payload = self._stdout(("lscpu", "-J"))
        values: dict[str, str] = {}
        if payload:
            try:
                values = {
                    item["field"].rstrip(":"): item["data"]
                    for item in json.loads(payload).get("lscpu", [])
                    if item.get("field") and item.get("data") is not None
                }
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                self._warnings.append(f"lscpu parse error: {error}")
        return {
            "model": values.get("Model name") or platform.processor() or "unknown",
            "architecture": values.get("Architecture") or platform.machine(),
            "logical_cpus": self._to_int(values.get("CPU(s)")) or os.cpu_count(),
            "cores_per_socket": self._to_int(values.get("Core(s) per socket")),
            "sockets": self._to_int(values.get("Socket(s)")),
            "threads_per_core": self._to_int(values.get("Thread(s) per core")),
        }

    def _collect_memory(self) -> tuple[dict[str, int | float | None], dict[str, int | float | None]]:
        payload = self._stdout(("free", "-b"))
        rows: dict[str, list[str]] = {}
        if payload:
            for line in payload.splitlines()[1:]:
                parts = line.replace(":", "").split()
                if parts:
                    rows[parts[0]] = parts[1:]

        memory_values = rows.get("Mem", [])
        swap_values = rows.get("Swap", [])
        total = self._list_int(memory_values, 0)
        used = self._list_int(memory_values, 1)
        available = self._list_int(memory_values, 5)
        swap_total = self._list_int(swap_values, 0)
        swap_used = self._list_int(swap_values, 1)
        return (
            {
                "total_bytes": total,
                "used_bytes": used,
                "available_bytes": available,
                "used_percent": self._percent(used, total),
            },
            {
                "total_bytes": swap_total,
                "used_bytes": swap_used,
                "used_percent": self._percent(swap_used, swap_total),
            },
        )

    def _collect_root_disk(self) -> dict[str, int | float | str | None]:
        payload = self._stdout(("df", "-B1", "--output=size,used,avail,pcent,target", "/"))
        if not payload or len(payload.splitlines()) < 2:
            return {"mount": "/", "total_bytes": None, "used_bytes": None,
                    "available_bytes": None, "used_percent": None}
        values = payload.splitlines()[-1].split()
        return {
            "mount": values[4] if len(values) > 4 else "/",
            "total_bytes": self._list_int(values, 0),
            "used_bytes": self._list_int(values, 1),
            "available_bytes": self._list_int(values, 2),
            "used_percent": self._to_float(values[3].rstrip("%")) if len(values) > 3 else None,
        }

    def _collect_uptime(self) -> dict[str, int | str | None]:
        boot_time = self._stdout(("uptime", "-s"))
        seconds: int | None = None
        try:
            seconds = round(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError, IndexError):
            self._warnings.append("Could not read /proc/uptime")
        return {"boot_time": boot_time, "seconds": seconds}

    def _collect_network_interfaces(self) -> list[NetworkInterface]:
        payload = self._stdout(("ip", "-j", "address", "show"))
        if not payload:
            return []
        try:
            raw_interfaces: list[dict[str, Any]] = json.loads(payload)
        except json.JSONDecodeError as error:
            self._warnings.append(f"ip address parse error: {error}")
            return []

        interfaces = []
        for item in raw_interfaces:
            addresses = [
                NetworkAddress(
                    family=address.get("family", "unknown"),
                    address=address.get("local", "unknown"),
                    prefix_length=address.get("prefixlen"),
                    scope=address.get("scope", "unknown"),
                )
                for address in item.get("addr_info", [])
                if address.get("local")
            ]
            interfaces.append(
                NetworkInterface(
                    name=item.get("ifname", "unknown"),
                    state=item.get("operstate", "UNKNOWN"),
                    mac_address=item.get("address"),
                    mtu=item.get("mtu"),
                    addresses=addresses,
                )
            )
        return interfaces

    def _collect_default_gateway(self) -> dict[str, str | None]:
        payload = self._stdout(("ip", "-j", "route", "show", "default"))
        if payload:
            try:
                routes = json.loads(payload)
                if routes:
                    return {
                        "address": routes[0].get("gateway"),
                        "interface": routes[0].get("dev"),
                        "source_address": routes[0].get("prefsrc"),
                    }
            except json.JSONDecodeError as error:
                self._warnings.append(f"ip route parse error: {error}")
        return {"address": None, "interface": None, "source_address": None}

    @staticmethod
    def _to_int(value: str | None) -> int | None:
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    @staticmethod
    def _to_float(value: str | None) -> float | None:
        try:
            return float(value) if value is not None else None
        except ValueError:
            return None

    @classmethod
    def _list_int(cls, values: list[str], index: int) -> int | None:
        return cls._to_int(values[index]) if len(values) > index else None

    @staticmethod
    def _percent(used: int | None, total: int | None) -> float | None:
        if used is None or not total:
            return None
        return round((used / total) * 100, 1)

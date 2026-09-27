"""Data contracts for normalized local inventory."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NetworkAddress:
    family: str
    address: str
    prefix_length: int | None
    scope: str


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    state: str
    mac_address: str | None
    mtu: int | None
    addresses: list[NetworkAddress] = field(default_factory=list)


@dataclass(frozen=True)
class CommandTrace:
    command: str
    succeeded: bool
    duration_ms: int


@dataclass(frozen=True)
class InventorySnapshot:
    schema_version: str
    collected_at: str
    hostname: str
    fqdn: str
    operating_system: dict[str, str]
    kernel: dict[str, str]
    hardware: dict[str, str | None]
    cpu: dict[str, str | int | None]
    memory: dict[str, int | float | None]
    swap: dict[str, int | float | None]
    root_disk: dict[str, int | float | str | None]
    uptime: dict[str, int | str | None]
    default_gateway: dict[str, str | None]
    network_interfaces: list[NetworkInterface]
    command_trace: list[CommandTrace]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

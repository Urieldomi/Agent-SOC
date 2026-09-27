import json
import unittest

from agent_soc.inventory.collector import LocalInventoryCollector
from agent_soc.inventory.command_runner import CommandResult
from agent_soc.inventory.service import InventoryService


class FakeCommandRunner:
    responses = {
        ("uname", "-r"): "6.1.0-test",
        ("uname", "-m"): "x86_64",
        ("lscpu", "-J"): json.dumps({"lscpu": [
            {"field": "Architecture:", "data": "x86_64"},
            {"field": "CPU(s):", "data": "8"},
            {"field": "Model name:", "data": "Fixture CPU"},
            {"field": "Core(s) per socket:", "data": "4"},
            {"field": "Socket(s):", "data": "1"},
            {"field": "Thread(s) per core:", "data": "2"},
        ]}),
        ("free", "-b"): "total used free shared buff/cache available\nMem: 1000 400 100 0 500 600\nSwap: 200 50 150",
        ("df", "-B1", "--output=size,used,avail,pcent,target", "/"): "1B-blocks Used Available Use% Mounted on\n1000 250 750 25% /",
        ("uptime", "-s"): "2026-09-25 08:00:00",
        ("ip", "-j", "route", "show", "default"): json.dumps([
            {"gateway": "10.0.0.1", "dev": "eth0", "prefsrc": "10.0.0.10"}
        ]),
        ("ip", "-j", "address", "show"): json.dumps([{
            "ifname": "eth0", "operstate": "UP", "address": "00:11:22:33:44:55", "mtu": 1500,
            "addr_info": [{"family": "inet", "local": "10.0.0.10", "prefixlen": 24, "scope": "global"}],
        }]),
    }

    def run(self, command):
        output = self.responses[command]
        return CommandResult(command, 0, output, "", 1)


class InventoryCollectorTests(unittest.TestCase):
    def test_normalizes_command_outputs(self):
        snapshot = LocalInventoryCollector(FakeCommandRunner()).collect()
        self.assertEqual(snapshot.kernel["release"], "6.1.0-test")
        self.assertEqual(snapshot.cpu["model"], "Fixture CPU")
        self.assertEqual(snapshot.cpu["logical_cpus"], 8)
        self.assertEqual(snapshot.memory["used_percent"], 40.0)
        self.assertEqual(snapshot.swap["used_percent"], 25.0)
        self.assertEqual(snapshot.root_disk["used_percent"], 25.0)
        self.assertEqual(snapshot.default_gateway["source_address"], "10.0.0.10")
        self.assertEqual(snapshot.network_interfaces[0].addresses[0].address, "10.0.0.10")
        self.assertEqual(len(snapshot.command_trace), 8)
        self.assertEqual(snapshot.warnings, [])

    def test_service_caches_and_can_force_refresh(self):
        class CountingCollector:
            def __init__(self):
                self.calls = 0

            def collect(inner_self):
                inner_self.calls += 1
                return LocalInventoryCollector(FakeCommandRunner()).collect()

        collector = CountingCollector()
        service = InventoryService(collector, cache_seconds=60)
        first = service.get_snapshot()
        second = service.get_snapshot()
        refreshed = service.get_snapshot(force=True)
        self.assertIs(first, second)
        self.assertIsNot(second, refreshed)
        self.assertEqual(collector.calls, 2)


if __name__ == "__main__":
    unittest.main()

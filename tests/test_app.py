import unittest

from app import create_app, format_bytes
from agent_soc.inventory.command_runner import SafeCommandRunner
from agent_soc.inventory.models import InventorySnapshot


def sample_snapshot():
    return InventorySnapshot(
        schema_version="1.0",
        collected_at="2026-09-25T12:00:00+00:00",
        hostname="server-under-test",
        fqdn="server-under-test.local",
        operating_system={
            "id": "debian", "name": "Debian GNU/Linux",
            "pretty_name": "Debian GNU/Linux 12", "version_id": "12",
            "version_codename": "bookworm",
        },
        kernel={"release": "6.1.0-test", "architecture": "x86_64"},
        hardware={"vendor": "Test Vendor", "product": "Test Server", "product_version": None},
        cpu={"model": "Test CPU", "architecture": "x86_64", "logical_cpus": 4,
             "cores_per_socket": 2, "sockets": 1, "threads_per_core": 2},
        memory={"total_bytes": 8_589_934_592, "used_bytes": 4_294_967_296,
                "available_bytes": 4_294_967_296, "used_percent": 50.0},
        swap={"total_bytes": 1_073_741_824, "used_bytes": 0, "used_percent": 0.0},
        root_disk={"mount": "/", "total_bytes": 100_000_000_000,
                   "used_bytes": 25_000_000_000, "available_bytes": 75_000_000_000,
                   "used_percent": 25.0},
        uptime={"boot_time": "2026-09-24 10:00:00", "seconds": 93_600},
        default_gateway={"address": "192.0.2.1", "interface": "eth0",
                         "source_address": "192.0.2.10"},
        network_interfaces=[],
        command_trace=[],
        warnings=[],
    )


class FakeInventoryService:
    def __init__(self):
        self.snapshot = sample_snapshot()
        self.force_values = []

    def get_snapshot(self, force=False):
        self.force_values.append(force)
        return self.snapshot


class InventoryWebTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeInventoryService()
        application = create_app(self.service)
        application.config.update(TESTING=True)
        self.client = application.test_client()

    def test_home_displays_real_inventory_contract(self):
        response = self.client.get("/")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("server-under-test", body)
        self.assertIn("192.0.2.10", body)
        self.assertIn("8.0 GiB", body)
        self.assertIn("Seleccionar y continuar", body)
        self.assertNotIn("Implementación progresiva", body)

    def test_inventory_api_returns_normalized_snapshot(self):
        response = self.client.get("/api/inventory")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["hostname"], "server-under-test")
        self.assertEqual(response.json["schema_version"], "1.0")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_refresh_forces_a_new_collection(self):
        response = self.client.post("/inventario/actualizar")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")
        self.assertEqual(self.service.force_values, [True])

    def test_health_endpoint(self):
        self.assertEqual(
            self.client.get("/health").json,
            {"status": "ok", "module": "local-inventory-with-demo-flow"},
        )

    def test_byte_formatter(self):
        self.assertEqual(format_bytes(8_589_934_592), "8.0 GiB")
        self.assertEqual(format_bytes(None), "No disponible")

    def test_real_server_selection_starts_the_compatible_flow(self):
        self.assertEqual(self.client.get("/etapa/1").location, "/")
        selected = self.client.post("/seleccionar")
        self.assertEqual(selected.status_code, 302)
        self.assertEqual(selected.location, "/etapa/1")
        pending = self.client.get("/etapa/1").get_data(as_text=True)
        self.assertIn("LISTO PARA EJECUTAR", pending)
        self.assertIn("Iniciar inspección del host", pending)

    def test_real_inspection_and_mock_stages_remain_sequential(self):
        self.client.post("/seleccionar")
        self.assertEqual(self.client.post("/api/run/2").status_code, 409)

        inspection = self.client.post("/api/run/1")
        self.assertEqual(inspection.status_code, 200)
        self.assertEqual(inspection.json["stages"][0]["mode"], "real")
        self.assertEqual(inspection.json["stages"][0]["facts"][0][1], "server-under-test")

        context = self.client.post("/api/run/2")
        self.assertEqual(context.json["stages"][1]["mode"], "mock")
        self.assertIn("caso de prueba", context.json["stages"][1]["finding"])

        report = self.client.post("/api/run/3")
        self.assertEqual(report.json["step"], 3)
        self.assertEqual(report.json["stages"][2]["mode"], "mock")

    def test_transitional_pdf_requires_the_full_flow(self):
        self.assertEqual(self.client.get("/report.pdf").status_code, 409)
        self.client.post("/seleccionar")
        for stage in (1, 2, 3):
            self.client.post(f"/api/run/{stage}")
        pdf = self.client.get("/report.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF"))

    def test_reset_returns_to_server_selection(self):
        self.client.post("/seleccionar")
        self.client.post("/api/run/1")
        reset = self.client.post("/api/reset")
        self.assertFalse(reset.json["selected"])
        self.assertEqual(reset.json["step"], 0)


class SafeCommandRunnerTests(unittest.TestCase):
    def test_rejects_commands_outside_the_exact_allowlist(self):
        with self.assertRaises(ValueError):
            SafeCommandRunner().run(("sh", "-c", "id"))

    def test_runs_an_allowlisted_command_without_a_shell(self):
        result = SafeCommandRunner().run(("uname", "-m"))
        self.assertTrue(result.succeeded)
        self.assertTrue(result.stdout)


if __name__ == "__main__":
    unittest.main()

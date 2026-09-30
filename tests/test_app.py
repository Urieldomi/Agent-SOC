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


class FakeContextService:
    def __init__(self):
        self.states = {}

    @staticmethod
    def result():
        return {
            "status": "NOT_APPLICABLE",
            "result": "Sin exposición según el contexto verificado",
            "tone": "success",
            "reason": "La versión instalada es posterior a la versión corregida.",
            "confidence": 96,
            "cve_id": "CVE-2026-46300",
            "facts": {
                "documents": 4, "chunks": 8, "cvss_score": 7.8,
                "language_model": "model-under-test",
            },
            "sources": [{"name": "Source", "url": "https://example.test", "detail": "Evidence"}],
            "retrieved": [],
            "explanation": "Las fuentes confirman que la versión está corregida.",
            "recommendation": "Mantener actualizado.",
        }

    def reset(self, analysis_id):
        self.states[analysis_id] = False

    def state(self, analysis_id):
        complete = self.states.get(analysis_id, False)
        return {
            "operations": [], "executions": [], "progress": 100 if complete else 0,
            "complete": complete, "result": self.result() if complete else None, "sources": [],
        }

    def run_all(self, analysis_id, inspection, inventory):
        self.states[analysis_id] = True
        return self.state(analysis_id)

    def execute(self, analysis_id, operation_id, inspection, inventory):
        self.states[analysis_id] = True
        return self.state(analysis_id)


class FakeReportService:
    def __init__(self):
        self.states = {}

    @staticmethod
    def result(analysis_id="analysis-under-test"):
        return {
            "report_id": "ASR-TEST-0001", "analysis_id": analysis_id,
            "generated_at": "2026-09-26T12:00:00+00:00", "version": "1.0",
            "title": "Dictamen de exposición · CVE-2026-46300",
            "status": "NOT_APPLICABLE", "classification": "Sin exposición según el contexto verificado",
            "tone": "success", "priority": "Informativa", "priority_tone": "success",
            "confidence": 96, "cvss_score": 7.8,
            "executive_summary": "El activo evaluado no presenta exposición aplicable.",
            "technical_analysis": "La versión instalada supera la versión corregida.",
            "impact_statement": "No se requiere atención inmediata para este hallazgo.",
            "action_plan": "Mantener la actualización y conservar la evidencia.",
            "reason": "La comparación determinista de versiones no confirma exposición.",
            "host": {"host": "server-under-test", "fqdn": "server-under-test.local", "ip": "192.0.2.10",
                     "os": "Debian GNU/Linux 12", "kernel": "6.1.0-test", "source_package": "linux",
                     "installed_version": "6.1.1", "fixed_version": "6.1.0"},
            "rag": {"documents": 4, "chunks": 8, "retrieved": 4, "embedding_model": "embed-test"},
            "models": {"language_model": "model-under-test", "documenter_model": "model-under-test",
                       "prompt_tokens": 100, "response_tokens": 50, "duration_ms": 250,
                       "nlp_pipeline": "Generación estructurada y fundamentación por evidencia",
                       "generation_status": "neural"},
            "sources": [{"name": "Source", "url": "https://example.test", "detail": "Evidence"}],
            "retrieved": [],
            "verified_claims": [{"claim": "La versión fue verificada.", "evidence": "Inspección"}],
            "unverified_claims": [],
            "review": {"status": "PENDING", "label": "Pendiente", "timestamp": None, "notes": ""},
        }

    def reset(self, analysis_id):
        self.states[analysis_id] = None

    def state(self, analysis_id):
        result = self.states.get(analysis_id)
        return {"operations": [], "executions": [], "progress": 100 if result else 0,
                "complete": bool(result), "result": result, "error": None}

    def run_all(self, analysis_id, inspection, context, inventory):
        self.states[analysis_id] = self.result(analysis_id)
        return self.state(analysis_id)

    def execute(self, analysis_id, operation_id, inspection, context, inventory):
        return self.run_all(analysis_id, inspection, context, inventory)

    def decide(self, analysis_id, decision, notes=""):
        result = self.states[analysis_id]
        result["review"] = {"status": decision, "label": "Validado" if decision == "VALIDATED" else "Rechazado",
                            "timestamp": "2026-09-26T12:05:00+00:00", "notes": notes}
        return self.state(analysis_id)

    def markdown(self, analysis_id):
        return "# Dictamen de exposición\n"


class InventoryWebTests(unittest.TestCase):
    def setUp(self):
        self.service = FakeInventoryService()
        self.context_service = FakeContextService()
        self.report_service = FakeReportService()
        application = create_app(
            self.service, context_service=self.context_service, report_service=self.report_service,
        )
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
            {"status": "ok", "module": "agent-soc-reporting"},
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
        self.assertIn("SECUENCIA DE INSPECCIÓN", pending)
        self.assertIn("Terminal preparada", pending)
        self.assertIn("/etapa/1/comando/system", pending)

    def test_real_inspection_and_context_remain_sequential(self):
        self.client.post("/seleccionar")
        self.assertEqual(self.client.post("/api/run/2").status_code, 409)

        inspection = self.client.post("/api/run/1")
        self.assertEqual(inspection.status_code, 200)
        self.assertEqual(inspection.json["stages"][0]["mode"], "real")
        self.assertEqual(inspection.json["stages"][0]["facts"][0][1], "server-under-test")

        context = self.client.post("/api/run/2")
        self.assertEqual(context.json["stages"][1]["mode"], "real")
        self.assertTrue(context.json["stages"][1]["finding"])
        self.assertIn(
            context.json["stages"][1]["facts"][2][1],
            (
                "Sin exposición según el contexto verificado",
                "Exposición contextual confirmada",
                "Evidencia insuficiente",
            ),
        )

        report = self.client.post("/api/run/3")
        self.assertEqual(report.json["step"], 3)
        self.assertEqual(report.json["stages"][2]["mode"], "real")

    def test_transitional_pdf_requires_the_full_flow(self):
        self.assertEqual(self.client.get("/report.pdf").status_code, 409)
        self.client.post("/seleccionar")
        for stage in (1, 2, 3):
            self.client.post(f"/api/run/{stage}")
        pdf = self.client.get("/report.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF"))

    def test_report_workspace_exports_and_records_human_review(self):
        self.client.post("/seleccionar")
        for stage in (1, 2, 3):
            self.client.post(f"/api/run/{stage}")
        page = self.client.get("/etapa/3").get_data(as_text=True)
        self.assertIn("DICTAMEN EJECUTIVO", page)
        self.assertIn("Trazabilidad del pipeline", page)
        self.assertIn("Validar dictamen", page)
        self.assertEqual(self.client.get("/report.md").status_code, 200)
        self.assertEqual(self.client.get("/report.json").json["report_id"], "ASR-TEST-0001")
        reviewed = self.client.post(
            "/etapa/3/decision",
            data={"decision": "VALIDATED", "notes": "Evidencia revisada."},
            follow_redirects=True,
        ).get_data(as_text=True)
        self.assertIn("Validado", reviewed)
        self.assertIn("Evidencia revisada.", reviewed)

    def test_reset_returns_to_server_selection(self):
        self.client.post("/seleccionar")
        self.client.post("/api/run/1")
        reset = self.client.post("/api/reset")
        self.assertFalse(reset.json["selected"])
        self.assertEqual(reset.json["step"], 0)

    def test_commands_are_sequential_and_render_real_output(self):
        self.client.post("/seleccionar")
        self.assertEqual(self.client.post("/etapa/1/comando/kernel").status_code, 409)
        response = self.client.post("/etapa/1/comando/system", follow_redirects=True)
        body = response.get_data(as_text=True)
        self.assertIn("cat /etc/os-release", body)
        self.assertIn("PRETTY_NAME", body)
        self.assertIn("/etapa/1/comando/kernel", body)

    def test_footer_switch_builds_a_coherent_vulnerable_scenario(self):
        self.client.post("/seleccionar")
        toggled = self.client.post("/modo-prueba", follow_redirects=True)
        self.assertIn("Desactivar", toggled.get_data(as_text=True))
        finished = self.client.post("/api/run/1")
        summary = finished.json["inspection"]["summary"]
        self.assertEqual(summary["status"], "POTENTIALLY_VULNERABLE")
        self.assertEqual(summary["facts"]["kernel"], "6.8.0-120-generic")
        page = self.client.get("/etapa/1").get_data(as_text=True)
        self.assertIn("Exposición potencial detectada", page)
        self.assertIn("6.8.0-120-generic", page)


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

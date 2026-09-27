import tempfile
import unittest
from pathlib import Path

from agent_soc.reporting import ReportGenerationService
from tests.test_app import FakeContextService, sample_snapshot


class FakeOllama:
    def chat_json(self, system, prompt, model, **kwargs):
        return ({
            "executive_summary": "El activo no presenta exposición aplicable según las versiones verificadas.",
            "technical_analysis": "La versión instalada es posterior a la corrección publicada.",
            "impact_statement": "No se requiere atención inmediata para este hallazgo.",
            "action_plan": "Mantener el ciclo de actualización y conservar la evidencia.",
        }, {"model": model, "prompt_tokens": 120, "response_tokens": 48, "duration_ms": 300})


class InvalidJsonOllama:
    def chat_json(self, system, prompt, model, **kwargs):
        raise RuntimeError("El agente no produjo JSON válido")


class ReportGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.service = ReportGenerationService(Path(self.temporary.name), FakeOllama())
        self.inventory = sample_snapshot().to_dict()
        self.context = FakeContextService.result()
        self.context["facts"].update({
            "kernel": "6.1.0-test", "source_package": "linux",
            "installed_version": "6.1.1", "fixed_version": "6.1.0",
            "authoritative_fixed_version": "6.1.0", "cwes": ["CWE-400"],
            "embedding_model": "embed-test",
        })
        self.context["agent_metrics"] = []
        self.inspection = {"facts": {
            "kernel": "6.1.0-test", "source_package": "linux",
            "installed_version": "6.1.1", "fixed_version": "6.1.0",
        }}

    def tearDown(self):
        self.temporary.cleanup()

    def test_pipeline_is_sequential_and_publishes_a_structured_report(self):
        self.service.reset("analysis-1")
        with self.assertRaises(ValueError):
            self.service.execute("analysis-1", "document", self.inspection, self.context, self.inventory)
        state = self.service.run_all("analysis-1", self.inspection, self.context, self.inventory)
        self.assertTrue(state["complete"])
        self.assertEqual(state["result"]["review"]["status"], "PENDING")
        self.assertEqual(state["result"]["priority"], "Informativa")
        self.assertEqual(len(state["result"]["verified_claims"]), 4)
        self.assertTrue(self.service.database_path.exists())

    def test_human_decision_is_persisted_and_restored(self):
        self.service.run_all("analysis-2", self.inspection, self.context, self.inventory)
        self.service.decide("analysis-2", "VALIDATED", "Evidencia revisada.")
        restored = ReportGenerationService(Path(self.temporary.name), FakeOllama()).state("analysis-2")
        self.assertTrue(restored["complete"])
        self.assertEqual(restored["result"]["review"]["status"], "VALIDATED")
        self.assertIn("Evidencia revisada", restored["result"]["review"]["notes"])
        self.assertIn("# Dictamen", self.service.markdown("analysis-2"))

    def test_invalid_model_output_uses_verified_evidence_without_blocking(self):
        service = ReportGenerationService(Path(self.temporary.name) / "recovery", InvalidJsonOllama())
        state = service.run_all("analysis-vulnerable", self.inspection, self.context, self.inventory)
        self.assertTrue(state["complete"])
        self.assertIsNone(state["error"])
        self.assertTrue(state["result"]["executive_summary"])
        self.assertEqual(state["result"]["models"]["generation_status"], "evidence_recovery")

    def test_sources_are_classified_by_their_role_in_the_report(self):
        classify = ReportGenerationService._classify_source
        self.assertEqual(
            classify({"name": "NIST NVD", "url": "https://nvd.nist.gov", "detail": "CVSS"})["category"],
            "dataset",
        )
        self.assertEqual(
            classify({"name": "Parche upstream", "url": "https://lists.openwall.net/netdev/1", "detail": "Patch"})["category"],
            "primary_evidence",
        )
        self.assertEqual(
            classify({"name": "Referencia", "url": "https://example.test", "detail": "Contexto"})["category"],
            "reference",
        )


if __name__ == "__main__":
    unittest.main()

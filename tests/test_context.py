import tempfile
import unittest
from pathlib import Path

from agent_soc.context.service import ContextAnalysisService, OPERATIONS, SOURCES


class FakeOllamaClient:
    def embeddings(self, texts, model):
        return [[float(len(text)), 1.0] for text in texts]

    def chat_json(self, system, prompt, model):
        return ({"status": "NOT_APPLICABLE", "justification": "Verified"}, {
            "model": model, "prompt_tokens": 10, "response_tokens": 5, "duration_ms": 2,
        })


class ContextAnalysisTests(unittest.TestCase):
    def test_operations_are_exposed_in_a_fixed_order(self):
        with tempfile.TemporaryDirectory() as directory:
            service = ContextAnalysisService(Path(directory), FakeOllamaClient())
            service.reset("analysis")
            state = service.state("analysis")
            self.assertEqual(len(state["operations"]), len(OPERATIONS))
            self.assertTrue(state["operations"][0]["available"])
            self.assertFalse(state["operations"][1]["available"])

    def test_debian_version_comparison_is_not_lexicographical(self):
        self.assertEqual(
            ContextAnalysisService._version_status("7.0.0-31.31~24.04.1", "7.0.0-28.28~24.04.1"),
            "NOT_APPLICABLE",
        )
        self.assertEqual(
            ContextAnalysisService._version_status("6.8.0-120.120", "6.8.0-124.124"),
            "APPLICABLE",
        )

    def test_recent_verified_download_is_reused_during_a_transient_outage(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            target.write_text('{"id":"CVE-2026-46300"}', encoding="utf-8")
            payload, status, fetched_at = ContextAnalysisService._fetch_source(SOURCES[0], target)
            self.assertEqual(status, "CACHE")
            self.assertIn(b"CVE-2026-46300", payload)
            self.assertTrue(fetched_at)


if __name__ == "__main__":
    unittest.main()

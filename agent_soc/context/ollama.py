"""Small HTTP client for the local Ollama service."""

from __future__ import annotations

import json
from urllib.error import URLError
from urllib.request import Request, urlopen


class OllamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:11434"):
        self.base_url = base_url.rstrip("/")

    def embeddings(self, texts: list[str], model: str) -> list[list[float]]:
        response = self._post("/api/embed", {"model": model, "input": texts}, timeout=55)
        embeddings = response.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise RuntimeError("Ollama no devolvió todos los embeddings solicitados")
        return embeddings

    def chat_json(
        self,
        system: str,
        prompt: str,
        model: str,
        *,
        schema: dict | None = None,
        num_predict: int = 280,
    ) -> tuple[dict, dict]:
        response = self._post(
            "/api/chat",
            {
                "model": model,
                "stream": False,
                "think": False,
                "format": schema or "json",
                "options": {"temperature": 0.1, "num_predict": num_predict, "num_ctx": 4096},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=55,
        )
        content = str(response.get("message", {}).get("content", "")).strip()
        try:
            parsed = json.loads(content)
        except (TypeError, json.JSONDecodeError) as error:
            # Some small models still wrap structured output in prose or fences.
            start, end = content.find("{"), content.rfind("}")
            if start < 0 or end <= start:
                raise RuntimeError("El agente no produjo JSON válido") from error
            try:
                parsed = json.loads(content[start:end + 1])
            except json.JSONDecodeError as nested_error:
                raise RuntimeError("El agente no produjo JSON válido") from nested_error
        if not isinstance(parsed, dict):
            raise RuntimeError("El agente no produjo un objeto JSON válido")
        metrics = {
            "model": response.get("model", model),
            "prompt_tokens": response.get("prompt_eval_count", 0),
            "response_tokens": response.get("eval_count", 0),
            "duration_ms": round(response.get("total_duration", 0) / 1_000_000),
            "done_reason": response.get("done_reason", "stop"),
        }
        return parsed, metrics

    def _post(self, path: str, payload: dict, timeout: int) -> dict:
        request = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except (OSError, URLError, json.JSONDecodeError) as error:
            raise RuntimeError(f"No fue posible completar la inferencia local: {error}") from error

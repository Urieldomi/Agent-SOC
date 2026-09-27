"""Sequential context analysis backed by official datasets and local RAG."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import html
import json
import math
from pathlib import Path
import re
import sqlite3
import subprocess
from threading import RLock
import time
from typing import Any
from urllib.request import Request, urlopen

from .ollama import OllamaClient


CVE = "CVE-2026-46300"
EMBED_MODEL = "nomic-embed-text-v2-moe"
CHAT_MODEL = "qwen3:0.6b"


@dataclass(frozen=True)
class ContextOperation:
    operation_id: str
    title: str
    action: str


@dataclass(frozen=True)
class SourceDefinition:
    source_id: str
    name: str
    url: str
    record_url: str


OPERATIONS = [
    ContextOperation("sources", "Configurar fuentes", "Verificar catálogo oficial"),
    ContextOperation("download", "Cargar datasets", "Descargar y verificar registros"),
    ContextOperation("normalize", "Normalizar evidencia", "Construir esquema común"),
    ContextOperation("index", "Preparar conocimiento", "Generar embeddings e índice RAG"),
    ContextOperation("retrieve", "Recuperar contexto", "Buscar evidencia relacionada"),
    ContextOperation("triage", "Agente de triaje", "Clasificar la evidencia del host"),
    ContextOperation("analyze", "Agente correlacionador", "Explicar relación entre fuentes"),
    ContextOperation("validate", "Validar resultado", "Verificar y consolidar el hallazgo"),
]

SOURCES = [
    SourceDefinition(
        "nvd", "NIST NVD",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}",
    ),
    SourceDefinition(
        "ubuntu", "Ubuntu Security",
        "https://security-metadata.canonical.com/osv/osv-all.tar.xz",
        "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/"
        f"osv/cve/2026/UBUNTU-{CVE}.json",
    ),
    SourceDefinition(
        "debian", "Debian Security Tracker",
        "https://security-tracker.debian.org/tracker/data/json",
        "https://security-tracker.debian.org/tracker/data/json",
    ),
    SourceDefinition(
        "upstream", "Parche upstream",
        "https://lists.openwall.net/netdev/2026/05/13/79",
        "https://lists.openwall.net/netdev/2026/05/13/79",
    ),
]


class ContextAnalysisService:
    """Runs one real context pipeline for either inspection input state."""

    def __init__(self, data_dir: Path | None = None, ollama_client: OllamaClient | None = None):
        self.data_dir = data_dir or Path(__file__).resolve().parents[2] / "data" / "context"
        self.raw_dir = self.data_dir / "raw"
        self.database_path = self.data_dir / "context.db"
        self.ollama = ollama_client or OllamaClient()
        self._states: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def reset(self, analysis_id: str) -> None:
        with self._lock:
            self._states[analysis_id] = {"executions": [], "artifacts": {}, "result": None, "error": None}

    def state(self, analysis_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._states.setdefault(
                analysis_id, {"executions": [], "artifacts": {}, "result": None, "error": None},
            )
            executions = list(state["executions"])
            result = state["result"]
        completed = len(executions)
        operations = []
        for index, operation in enumerate(OPERATIONS):
            operations.append({
                **asdict(operation),
                "completed": index < completed,
                "available": index == completed,
            })
        return {
            "operations": operations,
            "executions": executions,
            "progress": round(completed / len(OPERATIONS) * 100),
            "complete": completed == len(OPERATIONS),
            "result": result,
            "error": state.get("error"),
            "sources": [asdict(source) for source in SOURCES],
        }

    def execute(
        self,
        analysis_id: str,
        operation_id: str,
        inspection: dict[str, Any],
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            state = self._states.setdefault(
                analysis_id, {"executions": [], "artifacts": {}, "result": None, "error": None},
            )
            position = len(state["executions"])
            if position >= len(OPERATIONS):
                return self.state(analysis_id)
            operation = OPERATIONS[position]
            if operation.operation_id != operation_id:
                raise ValueError(f"Expected operation {operation.operation_id}")
            started = datetime.now(timezone.utc)
            state["error"] = None
            try:
                output = self._run_operation(operation_id, state["artifacts"], inspection, inventory)
            except Exception as error:  # Preserve the current step so it can be retried.
                state["error"] = str(error)
                return self.state(analysis_id)
            elapsed_ms = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            state["executions"].append({
                "operation_id": operation.operation_id,
                "title": operation.title,
                "action": operation.action,
                "output": output,
                "duration_ms": elapsed_ms,
            })
            if operation_id == "validate":
                state["result"] = state["artifacts"]["result"]
        return self.state(analysis_id)

    def run_all(self, analysis_id: str, inspection: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
        self.reset(analysis_id)
        current = self.state(analysis_id)
        while not current["complete"]:
            operation = next(item for item in current["operations"] if item["available"])
            current = self.execute(analysis_id, operation["operation_id"], inspection, inventory)
        return current

    def _run_operation(
        self,
        operation_id: str,
        artifacts: dict[str, Any],
        inspection: dict[str, Any],
        inventory: dict[str, Any],
    ) -> str:
        if operation_id == "sources":
            artifacts["source_catalog"] = [asdict(source) for source in SOURCES]
            return "\n".join(
                [f"CATALOG={len(SOURCES)} fuentes"]
                + [f"READY {source.name}\n  {source.record_url}" for source in SOURCES]
            )
        if operation_id == "download":
            return self._download_sources(artifacts)
        if operation_id == "normalize":
            return self._normalize(artifacts)
        if operation_id == "index":
            return self._index(artifacts)
        if operation_id == "retrieve":
            return self._retrieve(artifacts, inspection, inventory)
        if operation_id == "triage":
            return self._triage(artifacts, inspection, inventory)
        if operation_id == "analyze":
            return self._analyze(artifacts, inspection, inventory)
        if operation_id == "validate":
            return self._validate(artifacts, inspection)
        raise ValueError(f"Unknown operation {operation_id}")

    def _download_sources(self, artifacts: dict[str, Any]) -> str:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        metadata = []
        deadline = time.monotonic() + 55
        for source in SOURCES:
            suffix = ".html" if source.source_id == "upstream" else ".json"
            target = self.raw_dir / f"{source.source_id}-{CVE}{suffix}"
            payload, status, fetched_at = self._fetch_source(source, target, deadline)
            digest = hashlib.sha256(payload).hexdigest()
            metadata.append({
                **asdict(source), "path": str(target), "size": len(payload),
                "sha256": digest, "http_status": status,
                "fetched_at": fetched_at,
            })
        artifacts["downloads"] = metadata
        return "\n".join(
            f"HTTP {item['http_status']} {item['name']} · {item['size']:,} bytes\n"
            f"  SHA256 {item['sha256'][:20]}…" for item in metadata
        )

    @staticmethod
    def _fetch_source(
        source: SourceDefinition,
        target: Path,
        deadline: float | None = None,
    ) -> tuple[bytes, str | int, str]:
        """Fetch a fixed source with retries and a verified recent-cache fallback."""
        if target.exists() and target.stat().st_size > 0:
            age_seconds = time.time() - target.stat().st_mtime
            if age_seconds < 900:
                return (
                    target.read_bytes(), "CACHE",
                    datetime.fromtimestamp(target.stat().st_mtime, timezone.utc).isoformat(),
                )

        last_error: Exception | None = None
        for attempt in range(3):
            try:
                remaining = (deadline - time.monotonic()) if deadline is not None else 55
                if remaining <= 1:
                    raise TimeoutError("se alcanzó el límite de tiempo de la operación")
                request = Request(source.record_url, headers={
                    "User-Agent": "Agent-SOC/1.0",
                    "Accept": "application/json,text/html;q=0.9,*/*;q=0.5",
                    "Connection": "close",
                })
                with urlopen(request, timeout=max(1, min(18, remaining))) as response:
                    payload = response.read()
                    status = response.status
                if not payload:
                    raise RuntimeError(f"{source.name} devolvió una respuesta vacía")
                temporary = target.with_suffix(target.suffix + ".part")
                temporary.write_bytes(payload)
                temporary.replace(target)
                return payload, status, datetime.now(timezone.utc).isoformat()
            except (OSError, RuntimeError) as error:
                last_error = error
                if attempt < 2:
                    remaining = (deadline - time.monotonic()) if deadline is not None else 55
                    if remaining > 2:
                        time.sleep(min(1.5 * (attempt + 1), remaining - 1))

        if target.exists() and target.stat().st_size > 0:
            payload = target.read_bytes()
            return (
                payload, "CACHE",
                datetime.fromtimestamp(target.stat().st_mtime, timezone.utc).isoformat(),
            )
        raise RuntimeError(f"No fue posible cargar {source.name}: {last_error}") from last_error

    def _normalize(self, artifacts: dict[str, Any]) -> str:
        downloads = {item["source_id"]: item for item in artifacts["downloads"]}
        nvd = json.loads(Path(downloads["nvd"]["path"]).read_text(encoding="utf-8"))
        ubuntu = json.loads(Path(downloads["ubuntu"]["path"]).read_text(encoding="utf-8"))
        debian = json.loads(Path(downloads["debian"]["path"]).read_text(encoding="utf-8"))
        cve = nvd["vulnerabilities"][0]["cve"]
        nvd_description = next(
            (item["value"] for item in cve.get("descriptions", []) if item["lang"] == "en"), ""
        )
        metric = (cve.get("metrics", {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        weaknesses = sorted({
            item["value"] for weakness in cve.get("weaknesses", [])
            for item in weakness.get("description", []) if item.get("value", "").startswith("CWE-")
        })
        relevant_ubuntu = []
        for affected in ubuntu.get("affected", []):
            package = affected.get("package", {})
            ecosystem = package.get("ecosystem", "")
            if ecosystem == "Ubuntu:24.04:LTS" and package.get("name") in {"linux", "linux-hwe-7.0"}:
                fixed = next(
                    (event["fixed"] for item in affected.get("ranges", [])
                     for event in item.get("events", []) if "fixed" in event),
                    None,
                )
                relevant_ubuntu.append({"package": package.get("name"), "release": ecosystem, "fixed": fixed})
        debian_record = debian.get("linux", {}).get(CVE, {})
        bookworm = debian_record.get("releases", {}).get("bookworm", {})
        documents = [
            {
                "source_id": "nvd", "source_name": "NIST NVD", "url": downloads["nvd"]["record_url"],
                "title": f"{CVE} · descripción y severidad",
                "text": f"{nvd_description}\nCVSS {metric.get('baseScore', 'N/D')} {metric.get('vectorString', '')}. CWE {', '.join(weaknesses)}.",
            },
            {
                "source_id": "ubuntu", "source_name": "Ubuntu Security", "url": downloads["ubuntu"]["record_url"],
                "title": f"{CVE} · Ubuntu 24.04",
                "text": ubuntu.get("details", "") + "\n" + "\n".join(
                    f"Ubuntu 24.04 source package {row['package']} fixed in {row['fixed']}"
                    for row in relevant_ubuntu
                ),
            },
            {
                "source_id": "debian", "source_name": "Debian Security Tracker", "url": f"https://security-tracker.debian.org/tracker/{CVE}",
                "title": f"{CVE} · Debian bookworm",
                "text": f"{debian_record.get('description', '')}\nDebian bookworm status {bookworm.get('status', 'unknown')}; fixed version {bookworm.get('fixed_version', 'unknown')}.",
            },
            {
                "source_id": "upstream", "source_name": "Parche upstream", "url": downloads["upstream"]["record_url"],
                "title": "Corrección técnica en netdev",
                "text": self._html_text(Path(downloads["upstream"]["path"]).read_text(encoding="utf-8", errors="replace")),
            },
        ]
        normalized = {
            "cve_id": CVE, "description": nvd_description,
            "cvss_score": metric.get("baseScore"), "cvss_vector": metric.get("vectorString"),
            "cwes": weaknesses, "ubuntu_packages": relevant_ubuntu,
            "debian_bookworm": bookworm, "documents": documents,
        }
        artifacts["normalized"] = normalized
        self._store_documents(documents, artifacts["downloads"])
        return (
            f"CVE={CVE}\nCVSS={normalized['cvss_score']}\nCWE={', '.join(weaknesses)}\n"
            f"UBUNTU_PACKAGES={len(relevant_ubuntu)}\nDOCUMENTS={len(documents)}\nSQLITE={self.database_path}"
        )

    def _index(self, artifacts: dict[str, Any]) -> str:
        chunks = []
        for document in artifacts["normalized"]["documents"]:
            text = re.sub(r"\s+", " ", document["text"]).strip()
            for offset in range(0, len(text), 1400):
                chunk_text = text[offset:offset + 1700]
                if chunk_text:
                    chunks.append({**document, "text": chunk_text})
        embeddings = self.ollama.embeddings([chunk["text"] for chunk in chunks], EMBED_MODEL)
        artifacts["chunks"] = chunks
        artifacts["embeddings"] = embeddings
        dimensions = len(embeddings[0]) if embeddings else 0
        return (
            f"MODEL={EMBED_MODEL}\nDOCUMENTS={len(artifacts['normalized']['documents'])}\n"
            f"CHUNKS={len(chunks)}\nEMBEDDINGS={len(embeddings)}\nDIMENSIONS={dimensions}\nINDEX_STATUS=ready"
        )

    def _retrieve(self, artifacts: dict[str, Any], inspection: dict[str, Any], inventory: dict[str, Any]) -> str:
        facts = inspection["facts"]
        query = (
            f"{CVE} {inventory['operating_system']['pretty_name']} kernel {facts['kernel']} "
            f"source package {facts['source_package']} installed {facts['installed_version']} "
            f"fixed {facts['fixed_version']} XFRM ESP"
        )
        query_vector = self.ollama.embeddings([query], EMBED_MODEL)[0]
        ranked = sorted(
            [
                {**chunk, "score": self._cosine(query_vector, vector)}
                for chunk, vector in zip(artifacts["chunks"], artifacts["embeddings"])
            ],
            key=lambda item: item["score"], reverse=True,
        )[:4]
        artifacts["retrieved"] = ranked
        return "\n".join(
            [f"QUERY={query}", f"MATCHES={len(ranked)}"]
            + [f"{index}. {item['source_name']} · score={item['score']:.4f} · {item['title']}"
               for index, item in enumerate(ranked, 1)]
        )

    def _triage(self, artifacts: dict[str, Any], inspection: dict[str, Any], inventory: dict[str, Any]) -> str:
        normalized = artifacts["normalized"]
        facts = inspection["facts"]
        source_package = facts["source_package"]
        ubuntu_match = next(
            (row for row in normalized["ubuntu_packages"] if row["package"] == source_package), None,
        )
        fixed = ubuntu_match["fixed"] if ubuntu_match else facts["fixed_version"]
        deterministic_status = self._version_status(facts["installed_version"], fixed)
        evidence = self._evidence_text(artifacts["retrieved"])
        payload, metrics = self.ollama.chat_json(
            "Eres el Agente de Triaje de Agent SOC. Usa únicamente la evidencia proporcionada. "
            "Devuelve JSON con cve_id, package, installed_version, fixed_version, status y justification. "
            "La justificación debe tener una sola oración. No inventes fuentes ni versiones.",
            f"HOST={inventory['hostname']}\nOS={inventory['operating_system']['pretty_name']}\n"
            f"FACTS={json.dumps(facts, ensure_ascii=False)}\nEXPECTED_STATUS={deterministic_status}\nEVIDENCE:\n{evidence}",
            CHAT_MODEL,
        )
        artifacts["triage"] = payload
        artifacts["triage_metrics"] = metrics
        artifacts["deterministic_status"] = deterministic_status
        artifacts["authoritative_fixed"] = fixed
        return (
            f"MODEL={metrics['model']}\nPROMPT_TOKENS={metrics['prompt_tokens']}\n"
            f"RESPONSE_TOKENS={metrics['response_tokens']}\nDURATION={metrics['duration_ms']} ms\n"
            f"STATUS={payload.get('status')}\nJUSTIFICATION={payload.get('justification', '')}"
        )

    def _analyze(self, artifacts: dict[str, Any], inspection: dict[str, Any], inventory: dict[str, Any]) -> str:
        evidence = self._evidence_text(artifacts["retrieved"])
        payload, metrics = self.ollama.chat_json(
            "Eres el Agente Analista y Correlacionador de Agent SOC. Responde en español y sólo con "
            "los hechos entregados. Devuelve exclusivamente JSON con summary, explanation y "
            "recommendation. Cada valor debe ser una sola oración breve. En explanation menciona "
            "Ubuntu Security y NIST NVD. No incluyas listas ni campos adicionales.",
            f"HOST={inventory['hostname']}\nINSPECTION={json.dumps(inspection, ensure_ascii=False)}\n"
            f"TRIAGE={json.dumps(artifacts['triage'], ensure_ascii=False)}\n"
            f"VERIFIED_STATUS={artifacts['deterministic_status']}\nEVIDENCE:\n{evidence}",
            CHAT_MODEL,
        )
        artifacts["analysis"] = payload
        artifacts["analysis_metrics"] = metrics
        return (
            f"MODEL={metrics['model']}\nPROMPT_TOKENS={metrics['prompt_tokens']}\n"
            f"RESPONSE_TOKENS={metrics['response_tokens']}\nDURATION={metrics['duration_ms']} ms\n"
            f"SUMMARY={payload.get('summary', '')}\nEXPLANATION={payload.get('explanation', '')}"
        )

    def _validate(self, artifacts: dict[str, Any], inspection: dict[str, Any]) -> str:
        facts = inspection["facts"]
        status = artifacts["deterministic_status"]
        fixed = artifacts["authoritative_fixed"]
        expected_values = {CVE, facts["source_package"], facts["installed_version"], fixed}
        serialized_agents = json.dumps(
            {"triage": artifacts["triage"], "analysis": artifacts["analysis"]}, ensure_ascii=False,
        )
        verified_values = sum(value in serialized_agents for value in expected_values if value)
        source_ids = {item["source_id"] for item in artifacts["retrieved"]}
        triage_valid = str(artifacts["triage"].get("status", "")).upper() == status
        if status == "NOT_APPLICABLE":
            result_text, tone = "Sin exposición según el contexto verificado", "success"
            reason = f"La versión instalada {facts['installed_version']} es igual o posterior a {fixed}."
        elif status == "APPLICABLE":
            result_text, tone = "Exposición contextual confirmada", "danger"
            reason = f"La versión instalada {facts['installed_version']} es anterior a la corrección {fixed}."
        else:
            result_text, tone = "Evidencia insuficiente", "warning"
            reason = "No fue posible completar una comparación verificable de versiones."
        generated_explanation = str(artifacts["analysis"].get("explanation", "")).strip()
        lower_explanation = generated_explanation.lower()
        cites_sources = "ubuntu" in lower_explanation and "nvd" in lower_explanation
        contradicts = (
            status == "NOT_APPLICABLE"
            and any(term in lower_explanation for term in ("exposición confirmada", "versión anterior", "es vulnerable"))
        ) or (
            status == "APPLICABLE"
            and any(term in lower_explanation for term in ("sin exposición", "no hay riesgo", "versión posterior"))
        )
        analysis_valid = bool(generated_explanation) and cites_sources and not contradicts
        validated_agents = int(triage_valid) + int(analysis_valid)
        confidence = min(99, 66 + len(source_ids) * 5 + verified_values * 2 + validated_agents * 2)
        final_explanation = (
            f"{reason} {generated_explanation}" if analysis_valid
            else f"{reason} La evidencia fue contrastada con Ubuntu Security y NIST NVD."
        )
        sources = []
        normalized = artifacts["normalized"]
        for source in SOURCES:
            contribution = {
                "nvd": f"Descripción, CVSS {normalized['cvss_score']} y taxonomía {', '.join(normalized['cwes'])}.",
                "ubuntu": f"Estado del paquete para Ubuntu 24.04 y versión corregida {fixed}.",
                "debian": f"Contraste para Debian bookworm: {normalized['debian_bookworm'].get('status', 'unknown')}.",
                "upstream": "Detalle técnico de la corrección del manejo de fragmentos compartidos.",
            }[source.source_id]
            sources.append({"name": source.name, "url": source.record_url, "detail": contribution})
        artifacts["result"] = {
            "status": status, "result": result_text, "tone": tone, "reason": reason,
            "confidence": confidence, "cve_id": CVE,
            "facts": {
                **facts, "authoritative_fixed_version": fixed,
                "cvss_score": normalized["cvss_score"], "cwes": normalized["cwes"],
                "documents": len(normalized["documents"]), "chunks": len(artifacts["chunks"]),
                "embedding_model": EMBED_MODEL, "language_model": CHAT_MODEL,
            },
            "sources": sources,
            "retrieved": [
                {"source": item["source_name"], "title": item["title"],
                 "score": round(item["score"], 4), "url": item["url"]}
                for item in artifacts["retrieved"]
            ],
            "explanation": final_explanation,
            "recommendation": artifacts["analysis"].get("recommendation", "Mantener la evidencia actualizada."),
            "agent_metrics": [artifacts["triage_metrics"], artifacts["analysis_metrics"]],
        }
        return (
            f"VALIDATED_VALUES={verified_values}/{len(expected_values)}\nSOURCES={len(source_ids)}\n"
            f"TRIAGE_VALID={'yes' if triage_valid else 'no'}\nANALYSIS_VALID={'yes' if analysis_valid else 'no'}\n"
            f"CONFIDENCE={confidence}%\nSTATUS={status}\nRESULT={result_text}\nREASON={reason}"
        )

    def _store_documents(self, documents: list[dict[str, Any]], downloads: list[dict[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS documents (source_id TEXT PRIMARY KEY, source_name TEXT, "
                "cve_id TEXT, title TEXT, url TEXT, content TEXT, fetched_at TEXT, sha256 TEXT)"
            )
            download_map = {item["source_id"]: item for item in downloads}
            for document in documents:
                metadata = download_map[document["source_id"]]
                database.execute(
                    "INSERT OR REPLACE INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (document["source_id"], document["source_name"], CVE, document["title"],
                     document["url"], document["text"], metadata["fetched_at"], metadata["sha256"]),
                )

    @staticmethod
    def _html_text(value: str) -> str:
        value = re.sub(r"<(script|style).*?</\1>", " ", value, flags=re.I | re.S)
        value = re.sub(r"<[^>]+>", " ", value)
        return re.sub(r"\s+", " ", html.unescape(value)).strip()[:12000]

    @staticmethod
    def _cosine(left: list[float], right: list[float]) -> float:
        numerator = sum(a * b for a, b in zip(left, right))
        denominator = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
        return numerator / denominator if denominator else 0.0

    @staticmethod
    def _evidence_text(items: list[dict[str, Any]]) -> str:
        return "\n\n".join(
            f"[{item['source_name']}] {item['title']}\n{item['text'][:500]}\nURL: {item['url']}"
            for item in items
        )

    @staticmethod
    def _version_status(installed: str, fixed: str | None) -> str:
        if not installed or not fixed or "unknown" in (installed, fixed):
            return "INSUFFICIENT_EVIDENCE"
        result = subprocess.run(
            ["/usr/bin/dpkg", "--compare-versions", installed, "ge", fixed],
            check=False, capture_output=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        return "NOT_APPLICABLE" if result.returncode == 0 else "APPLICABLE"

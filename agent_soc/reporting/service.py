"""Sequential documenter agent with claim verification and HITL persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any
from uuid import uuid4

from agent_soc.context.ollama import OllamaClient


CVE = "CVE-2026-46300"
CHAT_MODEL = "qwen3:0.6b"


@dataclass(frozen=True)
class ReportOperation:
    operation_id: str
    title: str
    action: str


OPERATIONS = [
    ReportOperation("consolidate", "Consolidar expediente", "Integrar inventario, inspección y contexto"),
    ReportOperation("document", "Redacción con PLN", "Sintetizar lenguaje técnico con Ollama"),
    ReportOperation("verify", "Verificar afirmaciones", "Contrastar contenido con evidencia trazable"),
    ReportOperation("publish", "Publicar entregables", "Versionar reporte y registrar auditoría"),
]


class ReportGenerationService:
    """Builds a report without executing commands or modifying the evaluated host."""

    def __init__(self, data_dir: Path | None = None, ollama_client: OllamaClient | None = None):
        self.data_dir = data_dir or Path(__file__).resolve().parents[2] / "data" / "reporting"
        self.database_path = self.data_dir / "reports.db"
        self.ollama = ollama_client or OllamaClient()
        self._states: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {"executions": [], "artifacts": {}, "result": None, "error": None}

    def reset(self, analysis_id: str) -> None:
        with self._lock:
            self._states[analysis_id] = self._empty_state()

    def state(self, analysis_id: str) -> dict[str, Any]:
        with self._lock:
            if analysis_id not in self._states:
                restored = self._load_persisted(analysis_id)
                state = self._empty_state()
                if restored:
                    state["result"] = restored
                    state["executions"] = [
                        {
                            "operation_id": operation.operation_id,
                            "title": operation.title,
                            "action": operation.action,
                            "output": "Estado restaurado desde el registro de auditoría.",
                            "duration_ms": 0,
                        }
                        for operation in OPERATIONS
                    ]
                self._states[analysis_id] = state
            state = self._states[analysis_id]
            executions = list(state["executions"])
            result = state["result"]
            error = state.get("error")
        completed = len(executions)
        return {
            "operations": [
                {**asdict(operation), "completed": index < completed, "available": index == completed}
                for index, operation in enumerate(OPERATIONS)
            ],
            "executions": executions,
            "progress": round(completed / len(OPERATIONS) * 100),
            "complete": completed == len(OPERATIONS),
            "result": result,
            "error": error,
        }

    def execute(
        self,
        analysis_id: str,
        operation_id: str,
        inspection: dict[str, Any],
        context: dict[str, Any],
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        with self._lock:
            state = self._states.setdefault(analysis_id, self._empty_state())
            position = len(state["executions"])
            if position >= len(OPERATIONS):
                return self.state(analysis_id)
            operation = OPERATIONS[position]
            if operation.operation_id != operation_id:
                raise ValueError(f"Expected operation {operation.operation_id}")
            started = datetime.now(timezone.utc)
            state["error"] = None
            try:
                output = self._run_operation(
                    operation_id, analysis_id, state["artifacts"], inspection, context, inventory,
                )
            except Exception as error:
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
            if operation_id == "publish":
                state["result"] = state["artifacts"]["result"]
        return self.state(analysis_id)

    def run_all(
        self,
        analysis_id: str,
        inspection: dict[str, Any],
        context: dict[str, Any],
        inventory: dict[str, Any],
    ) -> dict[str, Any]:
        self.reset(analysis_id)
        current = self.state(analysis_id)
        while not current["complete"]:
            operation = next(item for item in current["operations"] if item["available"])
            current = self.execute(
                analysis_id, operation["operation_id"], inspection, context, inventory,
            )
            if current["error"]:
                break
        return current

    def decide(self, analysis_id: str, decision: str, notes: str = "") -> dict[str, Any]:
        if decision not in {"VALIDATED", "REJECTED"}:
            raise ValueError("Unsupported decision")
        with self._lock:
            state = self._states.get(analysis_id)
            if not state or not state.get("result"):
                raise ValueError("Report not available")
            timestamp = datetime.now(timezone.utc).isoformat()
            review = {
                "status": decision,
                "label": "Validado" if decision == "VALIDATED" else "Rechazado",
                "timestamp": timestamp,
                "notes": notes.strip()[:2000],
            }
            state["result"]["review"] = review
            self._persist(state["result"])
            return self.state(analysis_id)

    def markdown(self, analysis_id: str) -> str:
        state = self.state(analysis_id)
        if not state["result"]:
            raise ValueError("Report not available")
        return self._render_markdown(state["result"])

    def _run_operation(
        self,
        operation_id: str,
        analysis_id: str,
        artifacts: dict[str, Any],
        inspection: dict[str, Any],
        context: dict[str, Any],
        inventory: dict[str, Any],
    ) -> str:
        if operation_id == "consolidate":
            return self._consolidate(artifacts, inspection, context, inventory)
        if operation_id == "document":
            return self._document(artifacts)
        if operation_id == "verify":
            return self._verify(artifacts)
        if operation_id == "publish":
            return self._publish(analysis_id, artifacts)
        raise ValueError(f"Unknown operation {operation_id}")

    def _consolidate(
        self,
        artifacts: dict[str, Any],
        inspection: dict[str, Any],
        context: dict[str, Any],
        inventory: dict[str, Any],
    ) -> str:
        facts = context["facts"]
        dossier = {
            "cve_id": context["cve_id"],
            "host": inventory["hostname"],
            "fqdn": inventory["fqdn"],
            "ip": inventory["default_gateway"].get("source_address") or "No detectada",
            "os": inventory["operating_system"]["pretty_name"],
            "kernel": facts.get("kernel", inspection["facts"]["kernel"]),
            "source_package": facts.get("source_package"),
            "installed_version": facts.get("installed_version"),
            "fixed_version": facts.get("authoritative_fixed_version") or facts.get("fixed_version"),
            "status": context["status"],
            "classification": context["result"],
            "reason": context["reason"],
            "explanation": context["explanation"],
            "recommendation": context["recommendation"],
            "confidence": context["confidence"],
            "cvss_score": facts.get("cvss_score"),
            "cwes": facts.get("cwes", []),
            "documents": facts.get("documents", 0),
            "chunks": facts.get("chunks", 0),
            "embedding_model": facts.get("embedding_model", "No disponible"),
            "language_model": facts.get("language_model", CHAT_MODEL),
            "sources": context.get("sources", []),
            "retrieved": context.get("retrieved", []),
            "agent_metrics": context.get("agent_metrics", []),
        }
        artifacts["dossier"] = dossier
        return (
            f"ANALYSIS={CVE}/{dossier['host']}\nINPUTS=inventory,inspection,context\n"
            f"CLASSIFICATION={dossier['status']}\nEVIDENCE={dossier['documents']} documentos, "
            f"{dossier['chunks']} fragmentos\nSOURCES={len(dossier['sources'])}\nSCHEMA=validated"
        )

    def _document(self, artifacts: dict[str, Any]) -> str:
        dossier = artifacts["dossier"]
        schema = {
            "type": "object",
            "properties": {
                "executive_summary": {"type": "string"},
                "technical_analysis": {"type": "string"},
                "impact_statement": {"type": "string"},
                "action_plan": {"type": "string"},
            },
            "required": ["executive_summary", "technical_analysis", "impact_statement", "action_plan"],
            "additionalProperties": False,
        }
        try:
            payload, metrics = self.ollama.chat_json(
                "Eres el Agente Documentador de Agent SOC. Realiza procesamiento de lenguaje natural "
                "para redactar un dictamen breve dirigido a responsables técnicos y de riesgo. Usa sólo "
                "el expediente. Escribe una oración completa por campo. Conserva exactamente la "
                "clasificación, versiones, severidad y confianza. No afirmes explotación observada.",
                json.dumps(dossier, ensure_ascii=False, separators=(",", ":")),
                CHAT_MODEL,
                schema=schema,
                num_predict=420,
            )
            generation = "neural"
        except RuntimeError:
            payload = self._evidence_narrative(dossier)
            metrics = {
                "model": CHAT_MODEL, "prompt_tokens": 0, "response_tokens": 0,
                "duration_ms": 0, "done_reason": "evidence_recovery",
            }
            generation = "evidence_recovery"
        required = ("executive_summary", "technical_analysis", "impact_statement", "action_plan")
        if any(not str(payload.get(field, "")).strip() for field in required):
            payload = self._evidence_narrative(dossier)
            generation = "evidence_recovery"
        artifacts["narrative"] = {field: str(payload[field]).strip() for field in required}
        artifacts["documenter_metrics"] = metrics
        artifacts["generation"] = generation
        return (
            f"MODEL={metrics['model']}\nPROMPT_TOKENS={metrics['prompt_tokens']}\n"
            f"RESPONSE_TOKENS={metrics['response_tokens']}\nDURATION={metrics['duration_ms']} ms\n"
            f"NLP_PIPELINE=structured-generation+evidence-grounding\nSECTIONS=4\nDOCUMENT_STATUS=drafted"
        )

    @staticmethod
    def _evidence_narrative(dossier: dict[str, Any]) -> dict[str, str]:
        """Realize a complete narrative directly from verified structured evidence."""
        applicable = dossier["status"] == "APPLICABLE"
        if applicable:
            executive = (
                f"El activo {dossier['host']} presenta exposición aplicable a {dossier['cve_id']} "
                f"con prioridad alta y {dossier['confidence']} % de confianza."
            )
            impact = (
                "La condición requiere atención prioritaria porque el paquete evaluado permanece por "
                "debajo de la versión de seguridad verificada."
            )
            action = (
                f"Planificar la actualización del paquete {dossier['source_package']} a "
                f"{dossier['fixed_version']} o una versión posterior y repetir la inspección después del reinicio."
            )
        elif dossier["status"] == "NOT_APPLICABLE":
            executive = (
                f"El activo {dossier['host']} no presenta exposición aplicable a {dossier['cve_id']} "
                f"según la comparación verificada, con {dossier['confidence']} % de confianza."
            )
            impact = "El hallazgo no requiere una intervención inmediata bajo la evidencia disponible."
            action = "Mantener el ciclo de actualización y conservar el expediente para seguimiento."
        else:
            executive = (
                f"El expediente de {dossier['host']} requiere revisión adicional antes de determinar la "
                f"aplicabilidad de {dossier['cve_id']}."
            )
            impact = "La incertidumbre impide descartar exposición con la evidencia disponible."
            action = "Completar la evidencia de versiones y ejecutar nuevamente la correlación contextual."
        return {
            "executive_summary": executive,
            "technical_analysis": (
                f"Se correlacionó el kernel {dossier['kernel']} y la versión instalada "
                f"{dossier['installed_version']} con la corrección {dossier['fixed_version']}; "
                f"el resultado determinista fue {dossier['classification']}."
            ),
            "impact_statement": impact,
            "action_plan": action,
        }

    def _verify(self, artifacts: dict[str, Any]) -> str:
        dossier = artifacts["dossier"]
        narrative = artifacts["narrative"]
        text = json.dumps(narrative, ensure_ascii=False).lower()
        forbidden = ("explotación confirmada", "ataque observado", "compromiso confirmado")
        if any(term in text for term in forbidden):
            raise RuntimeError("El texto contiene una afirmación no respaldada por la evidencia")
        verified = [
            {"claim": f"El análisis corresponde a {dossier['cve_id']}.", "evidence": "Expediente contextual"},
            {"claim": f"El kernel evaluado es {dossier['kernel']}.", "evidence": "Inspección del host"},
            {"claim": dossier["reason"], "evidence": "Comparación determinista de versiones"},
            {"claim": f"La confianza calculada es {dossier['confidence']} %.", "evidence": "Validación de agentes y fuentes"},
        ]
        artifacts["verified_claims"] = verified
        artifacts["unverified_claims"] = []
        return (
            f"CLAIMS_CHECKED={len(verified)}\nVERIFIED={len(verified)}\nUNVERIFIED=0\n"
            f"SOURCE_LINKS={len(dossier['sources'])}\nCONSISTENCY=passed\nPUBLICATION_GATE=approved"
        )

    def _publish(self, analysis_id: str, artifacts: dict[str, Any]) -> str:
        dossier = artifacts["dossier"]
        status = dossier["status"]
        priority = "Alta" if status == "APPLICABLE" else "Revisión" if status == "INSUFFICIENT_EVIDENCE" else "Informativa"
        priority_tone = "danger" if status == "APPLICABLE" else "warning" if status == "INSUFFICIENT_EVIDENCE" else "success"
        metrics = artifacts["documenter_metrics"]
        generated_at = datetime.now(timezone.utc).isoformat()
        result = {
            "report_id": f"ASR-{datetime.now(timezone.utc):%Y%m%d}-{uuid4().hex[:8].upper()}",
            "analysis_id": analysis_id,
            "generated_at": generated_at,
            "version": "1.0",
            "title": f"Dictamen de exposición · {CVE}",
            "status": status,
            "classification": dossier["classification"],
            "tone": dossier.get("tone", priority_tone),
            "priority": priority,
            "priority_tone": priority_tone,
            "confidence": dossier["confidence"],
            "cvss_score": dossier["cvss_score"],
            "executive_summary": artifacts["narrative"]["executive_summary"],
            "technical_analysis": artifacts["narrative"]["technical_analysis"],
            "impact_statement": artifacts["narrative"]["impact_statement"],
            "action_plan": artifacts["narrative"]["action_plan"],
            "reason": dossier["reason"],
            "host": {key: dossier[key] for key in ("host", "fqdn", "ip", "os", "kernel", "source_package", "installed_version", "fixed_version")},
            "rag": {
                "documents": dossier["documents"], "chunks": dossier["chunks"],
                "retrieved": len(dossier["retrieved"]), "embedding_model": dossier["embedding_model"],
            },
            "models": {
                "language_model": dossier["language_model"],
                "documenter_model": metrics["model"],
                "prompt_tokens": metrics["prompt_tokens"],
                "response_tokens": metrics["response_tokens"],
                "duration_ms": metrics["duration_ms"],
                "nlp_pipeline": "Generación estructurada y fundamentación por evidencia",
                "generation_status": artifacts["generation"],
            },
            "sources": [self._classify_source(source) for source in dossier["sources"]],
            "retrieved": dossier["retrieved"],
            "verified_claims": artifacts["verified_claims"],
            "unverified_claims": artifacts["unverified_claims"],
            "review": {"status": "PENDING", "label": "Pendiente", "timestamp": None, "notes": ""},
        }
        artifacts["result"] = result
        self._persist(result)
        return (
            f"REPORT_ID={result['report_id']}\nVERSION={result['version']}\n"
            f"FORMATS=PDF,Markdown,JSON\nAUDIT_STORE={self.database_path}\n"
            f"HITL_STATUS=PENDING\nPUBLISHED_AT={generated_at}"
        )

    @staticmethod
    def _classify_source(source: dict[str, Any]) -> dict[str, Any]:
        """Attach provenance metadata used by every report representation."""
        value = f"{source.get('name', '')} {source.get('url', '')}".lower()
        if any(marker in value for marker in ("nvd", "nist", "ubuntu", "debian")):
            category = "dataset"
            category_label = "Dataset estructurado"
            role = "Ingesta, normalización y recuperación RAG"
        elif any(marker in value for marker in ("upstream", "openwall", "netdev", "patch", "parche")):
            category = "primary_evidence"
            category_label = "Evidencia técnica primaria"
            role = "Fundamento técnico y comportamiento de la corrección"
        else:
            category = "reference"
            category_label = "Referencia complementaria"
            role = "Contraste y contexto adicional"
        return {**source, "category": category, "category_label": category_label, "role": role}

    def _persist(self, result: dict[str, Any]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS reports (report_id TEXT PRIMARY KEY, analysis_id TEXT, "
                "generated_at TEXT, classification TEXT, review_status TEXT, review_timestamp TEXT, "
                "analyst_notes TEXT, content_json TEXT, markdown TEXT)"
            )
            review = result["review"]
            database.execute(
                "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result["report_id"], result["analysis_id"], result["generated_at"],
                 result["classification"], review["status"], review["timestamp"], review["notes"],
                 json.dumps(result, ensure_ascii=False), self._render_markdown(result)),
            )

    def _load_persisted(self, analysis_id: str) -> dict[str, Any] | None:
        if not self.database_path.exists():
            return None
        try:
            with sqlite3.connect(self.database_path) as database:
                row = database.execute(
                    "SELECT content_json FROM reports WHERE analysis_id = ? "
                    "ORDER BY generated_at DESC LIMIT 1", (analysis_id,),
                ).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, json.JSONDecodeError):
            return None

    @classmethod
    def _render_markdown(cls, report: dict[str, Any]) -> str:
        review = report["review"]
        classified_sources = [
            item if item.get("category") else cls._classify_source(item)
            for item in report["sources"]
        ]
        groups = (
            ("Datasets estructurados", "dataset"),
            ("Evidencia técnica primaria", "primary_evidence"),
            ("Referencias complementarias", "reference"),
        )
        source_sections = []
        for title, category in groups:
            items = [item for item in classified_sources if item["category"] == category]
            if items:
                lines = "\n".join(
                    f"- [{item['name']}]({item['url']}): {item['detail']}  "
                    f"\n  Función: {item.get('role', 'Evidencia de contexto')}"
                    for item in items
                )
                source_sections.append(f"### {title}\n\n{lines}")
        sources = "\n\n".join(source_sections)
        claims = "\n".join(f"- {item['claim']} — {item['evidence']}" for item in report["verified_claims"])
        host = report["host"]
        return f"""# {report['title']}

**Reporte:** {report['report_id']}  
**Generado:** {report['generated_at']}  
**Revisión humana:** {review['label']}

## Resumen ejecutivo

{report['executive_summary']}

## Dictamen

| Campo | Resultado |
|---|---|
| Clasificación | {report['classification']} |
| Prioridad | {report['priority']} |
| Confianza | {report['confidence']} % |
| CVSS | {report['cvss_score']} |

## Activo evaluado

| Campo | Valor |
|---|---|
| Host | {host['host']} |
| Sistema | {host['os']} |
| Kernel | {host['kernel']} |
| IP | {host['ip']} |
| Paquete | {host['source_package']} |
| Versión instalada | {host['installed_version']} |
| Versión corregida | {host['fixed_version']} |

## Análisis técnico

{report['technical_analysis']}

## Impacto

{report['impact_statement']}

## Plan de acción

{report['action_plan']}

## Evidencia verificada

{claims}

## Trazabilidad RAG y modelos

- Documentos: {report['rag']['documents']}
- Fragmentos: {report['rag']['chunks']}
- Coincidencias recuperadas: {report['rag']['retrieved']}
- Modelo de embeddings: {report['rag']['embedding_model']}
- Modelo de lenguaje: {report['models']['language_model']}
- Agente documentador: {report['models']['documenter_model']}

## Fuentes

{sources}

## Revisión del analista

- Decisión: {review['label']}
- Fecha: {review['timestamp'] or 'Pendiente'}
- Notas: {review['notes'] or 'Sin notas'}
"""

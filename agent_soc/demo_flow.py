"""Transitional mock stages that follow the real local inventory module."""

from __future__ import annotations

from typing import Any


CVE = "CVE-2026-46300"
STAGE_NAMES = {1: "Inspección", 2: "Contexto", 3: "Reporte"}
SOURCES = [
    {
        "name": "Debian Security Tracker",
        "url": "https://security-tracker.debian.org/tracker/CVE-2026-46300",
        "detail": "Estado de paquetes y avisos de seguridad de Debian.",
    },
    {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-46300",
        "detail": "Ficha técnica y métricas de la vulnerabilidad.",
    },
    {
        "name": "Parche netdev",
        "url": "https://lists.openwall.net/netdev/2026/05/13/79",
        "detail": "Referencia técnica del caso de estudio.",
    },
]

MOCK_ASSESSMENT = {
    "decision": "Positivo",
    "tone": "danger",
    "confidence": "Alta en el caso de prueba",
    "score": "7.8 / 10",
    "reason": (
        "El caso de prueba presenta una coincidencia entre el kernel evaluado y los "
        "componentes asociados a Fragnesia."
    ),
    "recommendation": (
        "Verificar la versión corregida del paquete, planear la actualización del kernel "
        "y confirmar el estado después del reinicio."
    ),
}


def build_stage_payload(stage: int, inventory: dict[str, Any]) -> dict[str, Any]:
    """Build a real inspection stage followed by explicit transitional mocks."""
    if stage == 1:
        return {
            "number": 1,
            "agent": "Agente de inspección",
            "status": "Inventario real completado",
            "summary": "Datos obtenidos del servidor local mediante comandos de solo lectura.",
            "mode": "real",
            "facts": [
                ["Host", inventory["hostname"]],
                ["Sistema", inventory["operating_system"]["pretty_name"]],
                ["Kernel activo", inventory["kernel"]["release"]],
                ["Arquitectura", inventory["kernel"]["architecture"]],
                ["CPU", inventory["cpu"]["model"]],
                ["CPU lógicas", inventory["cpu"]["logical_cpus"]],
                ["RAM total", inventory["memory"]["total_bytes"]],
                ["IP principal", inventory["default_gateway"]["source_address"] or "No detectada"],
            ],
            "logs": [
                f"REAL  Host detectado: {inventory['hostname']}",
                f"REAL  Sistema: {inventory['operating_system']['pretty_name']}",
                f"REAL  Kernel en ejecución: {inventory['kernel']['release']}",
                *[
                    f"{'OK' if trace['succeeded'] else 'ERROR'}    {trace['command']} · {trace['duration_ms']} ms"
                    for trace in inventory["command_trace"]
                ],
            ],
        }

    if stage == 2:
        return {
            "number": 2,
            "agent": "Agente de contexto",
            "status": "Contexto correlacionado",
            "summary": "Cruce del inventario con el dataset del caso Fragnesia.",
            "mode": "mock",
            "facts": [
                ["Caso", CVE],
                ["Host de entrada", inventory["hostname"]],
                ["Resultado", MOCK_ASSESSMENT["decision"]],
                ["Score", MOCK_ASSESSMENT["score"]],
                ["Confianza", MOCK_ASSESSMENT["confidence"]],
                ["Impacto", "Escalada local de privilegios"],
            ],
            "logs": [
                "DATA  Cargando dataset local: fragnesia-demo-v1",
                f"MATCH Asociando {CVE} con el inventario del host",
                "RULE  Evaluando kernel y componentes relacionados",
                f"RESULT {MOCK_ASSESSMENT['decision']}",
            ],
            "sources": SOURCES,
            "finding": MOCK_ASSESSMENT["reason"],
        }

    if stage == 3:
        return {
            "number": 3,
            "agent": "Agente de reporte",
            "status": "Reporte disponible",
            "summary": "Síntesis estructurada del inventario y la evaluación de Fragnesia.",
            "mode": "mock",
            "facts": [
                ["Host real", inventory["hostname"]],
                ["Clasificación", MOCK_ASSESSMENT["decision"]],
                ["Hallazgo", MOCK_ASSESSMENT["reason"]],
                ["Siguiente acción", MOCK_ASSESSMENT["recommendation"]],
            ],
            "logs": [
                "REPORT Incorporando inventario del servidor",
                "REPORT Consolidando la evaluación de Fragnesia",
                "REPORT Documento técnico listo para descarga",
            ],
            "finding": MOCK_ASSESSMENT["reason"],
        }

    raise ValueError(f"Unsupported stage: {stage}")

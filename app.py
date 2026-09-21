"""Demo determinista del flujo de tres agentes para CVE-2026-46300."""

from __future__ import annotations

from io import BytesIO
import os
import secrets

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

CVE = "CVE-2026-46300"
STAGE_NAMES = {1: "Inspección", 2: "Contexto", 3: "Reporte"}
SOURCES = [
    {"name": "Debian Security Tracker", "url": "https://security-tracker.debian.org/tracker/CVE-2026-46300", "detail": "Estado de paquetes y aviso DSA-6306-1"},
    {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-46300", "detail": "Ficha de la vulnerabilidad"},
    {"name": "Parche netdev", "url": "https://lists.openwall.net/netdev/2026/05/13/79", "detail": "Corrección de SKBFL_SHARED_FRAG"},
    {"name": "PoC pública", "url": "https://github.com/v12-security/pocs/tree/main/fragnesia", "detail": "Referencia de disponibilidad; no se ejecuta"},
]

SCENARIOS = {
    "vulnerable": {
        "host": "lab-debian-01", "label": "Linux vulnerable", "status": "Expuesto (simulado)",
        "kernel": "6.1.0-30-amd64", "package": "linux-image-6.1.0-30-amd64",
        "source_version": "6.1.124-1", "module": "esp4 cargado", "service": "api-gateway.service",
        "decision": "Positivo simulado", "tone": "danger", "confidence": "Alta en el caso de prueba",
        "reason": "El fixture combina kernel anterior a la corrección de Debian 12 y componente ESP disponible. Requiere validación real antes de tomar decisiones operativas.",
        "recommendation": "Verificar kernel en ejecución y versión corregida del paquete; planear actualización y reinicio en laboratorio.",
    },
    "safe": {
        "host": "lab-debian-02", "label": "Linux corregido", "status": "Sin exposición (simulado)",
        "kernel": "6.1.0-39-amd64", "package": "linux-image-6.1.0-39-amd64",
        "source_version": "6.1.174-1", "module": "esp4 no cargado", "service": "api-gateway.service",
        "decision": "Negativo simulado", "tone": "success", "confidence": "Alta en el caso de prueba",
        "reason": "El fixture representa un kernel corregido en ejecución y el módulo ESP no cargado. No equivale a una evaluación del host real.",
        "recommendation": "Mantener el inventario y confirmar periódicamente el kernel en ejecución y los avisos de Debian.",
    },
}


def current_state():
    scenario = session.get("scenario", "vulnerable")
    if scenario not in SCENARIOS:
        scenario = "vulnerable"
    step = session.get("step", 0)
    if not isinstance(step, int) or step not in range(4):
        step = 0
    return scenario, step


def stage_payload(stage, scenario):
    host = SCENARIOS[scenario]
    if stage == 1:
        return {
            "number": 1, "agent": "Agente de inspección", "status": "Inspección completada",
            "summary": "Inventario simulado de servicio, kernel, paquete y módulo asociado.",
            "facts": [
                ["Host", host["host"]], ["Sistema", "Debian GNU/Linux 12 (bookworm)"],
                ["Servicio", f'{host["service"]} · active (running)'],
                ["Kernel activo", host["kernel"]], ["Paquete", host["package"]],
                ["Versión fuente", host["source_version"]], ["Módulo", host["module"]],
            ],
            "logs": [
                f'[09:41:02] INFO  Conexión simulada con {host["host"]}',
                f'[09:41:03] SHELL systemctl status {host["service"]} → active (running)',
                f'[09:41:04] SHELL uname -r → {host["kernel"]}',
                f'[09:41:05] APT   dpkg-query → {host["source_version"]}',
                f'[09:41:06] SHELL lsmod → {host["module"]}',
                '[09:41:07] INFO  Inventario normalizado; sin ejecutar comandos reales.',
            ],
        }
    if stage == 2:
        return {
            "number": 2, "agent": "Agente de contexto", "status": "Contexto correlacionado",
            "summary": "Cruce simulado entre inventario y un dataset fijo sobre Fragnesia.",
            "facts": [
                ["Caso", CVE], ["Resultado", host["decision"]],
                ["Score demo", "7.8 / 10 · valor ilustrativo"],
                ["Impacto", "Escalada local de privilegios"],
                ["Exploit público", "Referencia pública disponible; no ejecutada"],
                ["Debian 12", "DSA-6306-1 · versión fuente corregida 6.1.174-1"],
                ["Confianza", host["confidence"]],
            ],
            "logs": [
                '[09:42:01] DATA  Cargando fixture local: fragnesia-demo-v1',
                '[09:42:02] MATCH CVE-2026-46300 ↔ linux / XFRM ESP-in-TCP',
                f'[09:42:03] RULE  Kernel={host["kernel"]}; módulo={host["module"]}',
                f'[09:42:04] RESULT {host["decision"]}',
                '[09:42:05] INFO  Fuentes mostradas como referencias; sin consulta en vivo.',
            ],
            "sources": SOURCES,
            "finding": host["reason"],
        }
    return {
        "number": 3, "agent": "Agente de reporte", "status": "Reporte disponible",
        "summary": "Síntesis estructurada del caso simulado y PDF descargable.",
        "facts": [
            ["Clasificación", host["decision"]], ["Host", host["host"]],
            ["Hallazgo", host["reason"]], ["Siguiente acción", host["recommendation"]],
        ],
        "logs": [
            '[09:43:01] REPORT Consolidando evidencia de inspección y contexto',
            f'[09:43:02] REPORT Clasificación final: {host["decision"]}',
            '[09:43:03] PDF    Documento de demostración listo para descarga',
        ],
        "finding": host["reason"],
    }


def snapshot():
    scenario, step = current_state()
    return {
        "scenario": scenario, "step": step, "host": SCENARIOS[scenario],
        "stages": [stage_payload(number, scenario) for number in range(1, step + 1)],
    }


@app.get("/")
def index():
    scenario, step = current_state()
    return render_template(
        "index.html", page="overview", scenario=scenario, step=step,
        host=SCENARIOS[scenario], scenarios=SCENARIOS, stage_names=STAGE_NAMES, cve=CVE,
    )


@app.get("/etapa/<int:stage>")
def stage_view(stage):
    if stage not in STAGE_NAMES:
        abort(404)
    scenario, completed_step = current_state()
    if stage > completed_step + 1:
        return redirect(url_for("stage_view", stage=completed_step + 1))
    return render_template(
        "index.html", page="stage", scenario=scenario, step=completed_step,
        current_stage=stage, stage_names=STAGE_NAMES, host=SCENARIOS[scenario],
        payload=stage_payload(stage, scenario) if stage <= completed_step else None,
        cve=CVE,
    )


@app.post("/seleccionar")
def choose_scenario():
    scenario = request.form.get("scenario")
    if scenario not in SCENARIOS:
        abort(400)
    session["scenario"] = scenario
    session["step"] = 0
    return redirect(url_for("stage_view", stage=1))


@app.post("/etapa/<int:stage>/ejecutar")
def execute_stage(stage):
    _, completed_step = current_state()
    if stage not in STAGE_NAMES or stage != completed_step + 1:
        return redirect(url_for("stage_view", stage=min(completed_step + 1, 3)))
    session["step"] = stage
    return redirect(url_for("stage_view", stage=stage))


@app.post("/reiniciar")
def restart_flow():
    session["step"] = 0
    return redirect(url_for("index"))


@app.get("/api/state")
def get_state():
    return jsonify(snapshot())


@app.post("/api/scenario")
def select_scenario():
    scenario = (request.get_json(silent=True) or {}).get("scenario")
    if scenario not in SCENARIOS:
        return jsonify({"error": "Escenario no válido"}), 400
    session["scenario"] = scenario
    session["step"] = 0
    return jsonify(snapshot())


@app.post("/api/run/<int:stage>")
def run_stage(stage):
    _, current_step = current_state()
    if stage != current_step + 1 or stage not in (1, 2, 3):
        return jsonify({"error": "Completa la etapa anterior antes de continuar."}), 409
    session["step"] = stage
    return jsonify(snapshot())


@app.post("/api/reset")
def reset():
    session["step"] = 0
    return jsonify(snapshot())


@app.get("/report.pdf")
def report_pdf():
    scenario, step = current_state()
    if step != 3:
        return jsonify({"error": "Completa los tres agentes para descargar el reporte."}), 409
    host = SCENARIOS[scenario]
    output = BytesIO()
    document = SimpleDocTemplate(output, pagesize=(21 * cm, 29.7 * cm), rightMargin=2 * cm,
                                 leftMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    styles["Title"].fontName = "Helvetica-Bold"
    styles["Title"].fontSize = 19
    styles["Title"].textColor = colors.HexColor("#142235")
    styles["Title"].alignment = TA_CENTER
    styles["Normal"].leading = 15
    story = [Paragraph("AGENT SOC | REPORTE DE DEMOSTRACION", styles["Title"]), Spacer(1, 0.4 * cm),
             Paragraph("Caso fijo: CVE-2026-46300 (Fragnesia)", styles["Heading2"]),
             Paragraph("SIMULACION. Los datos del host, logs, score y resultado son ejemplos; no hubo inspeccion real ni consultas en vivo.", styles["Normal"]),
             Spacer(1, 0.5 * cm)]
    rows = [
        ["Campo", "Evidencia del escenario"],
        ["Host / sistema", f'{host["host"]} / Debian 12'],
        ["Servicio", host["service"]], ["Kernel activo", host["kernel"]],
        ["Version fuente", host["source_version"]], ["Modulo", host["module"]],
        ["Clasificacion", host["decision"]], ["Score demo", "7.8 / 10 (ilustrativo)"],
    ]
    table = Table(rows, colWidths=[4.4 * cm, 12.5 * cm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142235")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F6FA")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D8E2EA")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [table, Spacer(1, 0.5 * cm), Paragraph("Evaluacion", styles["Heading2"]),
              Paragraph(host["reason"], styles["Normal"]), Spacer(1, 0.25 * cm),
              Paragraph("Accion sugerida", styles["Heading2"]),
              Paragraph(host["recommendation"], styles["Normal"]), Spacer(1, 0.35 * cm),
              Paragraph("Fuentes de referencia (no consultadas por el demo)", styles["Heading2"])]
    for source in SOURCES:
        story.append(Paragraph(f'{source["name"]}: {source["url"]}', styles["Normal"]))
    document.build(story)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f'agent-soc-{scenario}-CVE-2026-46300.pdf')


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))

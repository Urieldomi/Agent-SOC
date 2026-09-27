"""Agent SOC web application: real local inventory plus transitional mock stages."""

from __future__ import annotations

from io import BytesIO
import os
import secrets

from flask import Flask, abort, jsonify, redirect, render_template, send_file, session, url_for
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from agent_soc.demo_flow import CVE, MOCK_ASSESSMENT, SOURCES, STAGE_NAMES, build_stage_payload
from agent_soc.inventory.collector import LocalInventoryCollector
from agent_soc.inventory.service import InventoryService


def format_bytes(value: int | None) -> str:
    """Render byte values in a compact, human-readable form."""
    if value is None:
        return "No disponible"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def create_app(inventory_service: InventoryService | None = None) -> Flask:
    """Create the application with an injectable inventory boundary."""
    application = Flask(__name__)
    application.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    application.config.update(
        JSON_SORT_KEYS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    application.jinja_env.filters["bytes"] = format_bytes
    service = inventory_service or InventoryService(LocalInventoryCollector())

    def flow_state() -> tuple[bool, int]:
        selected = session.get("target_selected") is True
        step = session.get("step", 0)
        if not isinstance(step, int) or step not in range(4):
            step = 0
        return selected, step

    def inventory_dict(force: bool = False):
        return service.get_snapshot(force=force).to_dict()

    def flow_snapshot():
        selected, step = flow_state()
        inventory = inventory_dict()
        return {
            "selected": selected,
            "step": step,
            "cve": CVE,
            "inventory": inventory,
            "stages": [build_stage_payload(number, inventory) for number in range(1, step + 1)],
        }

    @application.after_request
    def protect_inventory_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @application.get("/")
    def index():
        selected, step = flow_state()
        return render_template(
            "index.html",
            page="overview",
            inventory=inventory_dict(),
            selected=selected,
            step=step,
            stage_names=STAGE_NAMES,
            cve=CVE,
        )

    @application.post("/inventario/actualizar")
    def refresh_inventory():
        inventory_dict(force=True)
        return redirect(url_for("index"))

    @application.post("/seleccionar")
    def select_local_server():
        inventory_dict(force=True)
        session["target_selected"] = True
        session["step"] = 0
        return redirect(url_for("stage_view", stage=1))

    @application.get("/etapa/<int:stage>")
    def stage_view(stage):
        if stage not in STAGE_NAMES:
            abort(404)
        selected, completed_step = flow_state()
        if not selected:
            return redirect(url_for("index"))
        if stage > completed_step + 1:
            return redirect(url_for("stage_view", stage=completed_step + 1))
        inventory = inventory_dict()
        payload = build_stage_payload(stage, inventory) if stage <= completed_step else None
        return render_template(
            "index.html",
            page="stage",
            inventory=inventory,
            selected=selected,
            step=completed_step,
            current_stage=stage,
            stage_names=STAGE_NAMES,
            payload=payload,
            mock_assessment=MOCK_ASSESSMENT,
            cve=CVE,
        )

    @application.post("/etapa/<int:stage>/ejecutar")
    def execute_stage(stage):
        selected, completed_step = flow_state()
        if not selected:
            return redirect(url_for("index"))
        if stage not in STAGE_NAMES or stage != completed_step + 1:
            return redirect(url_for("stage_view", stage=min(completed_step + 1, 3)))
        session["step"] = stage
        return redirect(url_for("stage_view", stage=stage))

    @application.post("/reiniciar")
    def restart_flow():
        session.clear()
        return redirect(url_for("index"))

    @application.get("/api/inventory")
    def inventory_api():
        return jsonify(inventory_dict())

    @application.get("/api/state")
    def state_api():
        return jsonify(flow_snapshot())

    @application.post("/api/run/<int:stage>")
    def run_stage_api(stage):
        selected, current_step = flow_state()
        if not selected:
            return jsonify({"error": "Selecciona el servidor local antes de continuar."}), 409
        if stage != current_step + 1 or stage not in STAGE_NAMES:
            return jsonify({"error": "Completa la etapa anterior antes de continuar."}), 409
        session["step"] = stage
        return jsonify(flow_snapshot())

    @application.post("/api/reset")
    def reset_api():
        session.clear()
        return jsonify(flow_snapshot())

    @application.get("/health")
    def health():
        return jsonify({"status": "ok", "module": "local-inventory-with-demo-flow"})

    @application.get("/report.pdf")
    def report_pdf():
        selected, step = flow_state()
        if not selected or step != 3:
            return jsonify({"error": "Completa las tres etapas para descargar el reporte."}), 409
        inventory = inventory_dict()
        output = BytesIO()
        document = SimpleDocTemplate(
            output,
            pagesize=(21 * cm, 29.7 * cm),
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        styles["Title"].fontName = "Helvetica-Bold"
        styles["Title"].fontSize = 19
        styles["Title"].textColor = colors.HexColor("#142235")
        styles["Title"].alignment = TA_CENTER
        story = [
            Paragraph("AGENT SOC | REPORTE DE ANALISIS", styles["Title"]),
            Spacer(1, 0.4 * cm),
            Paragraph(f"Caso: {CVE} (Fragnesia)", styles["Heading2"]),
            Paragraph(
                "ENTORNO DE DEMOSTRACION. Resultados generados para el caso de estudio y "
                "sujetos a validacion tecnica antes de cualquier decision operativa.",
                styles["Normal"],
            ),
            Spacer(1, 0.5 * cm),
        ]
        rows = [
            ["Campo", "Valor"],
            ["Host real", inventory["hostname"]],
            ["Sistema real", inventory["operating_system"]["pretty_name"]],
            ["Kernel real", inventory["kernel"]["release"]],
            ["IP principal", inventory["default_gateway"]["source_address"] or "No detectada"],
            ["Clasificación", MOCK_ASSESSMENT["decision"]],
            ["Score", MOCK_ASSESSMENT["score"]],
        ]
        table = Table(rows, colWidths=[4.5 * cm, 12.4 * cm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#142235")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F6FA")]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D8E2EA")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.extend([
            table,
            Spacer(1, 0.5 * cm),
            Paragraph("Evaluacion", styles["Heading2"]),
            Paragraph(MOCK_ASSESSMENT["reason"], styles["Normal"]),
            Paragraph("Referencias del mock", styles["Heading2"]),
        ])
        for source in SOURCES:
            story.append(Paragraph(f"{source['name']}: {source['url']}", styles["Normal"]))
        document.build(story)
        output.seek(0)
        return send_file(
            output,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"agent-soc-{inventory['hostname']}-{CVE}.pdf",
        )

    return application


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )

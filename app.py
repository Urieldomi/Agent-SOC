"""Agent SOC web application with local inventory and vulnerability inspection."""

from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import secrets
from uuid import uuid4
from xml.sax.saxutils import escape

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from agent_soc.demo_flow import CVE, MOCK_ASSESSMENT, SOURCES, STAGE_NAMES, build_stage_payload
from agent_soc.context import ContextAnalysisService
from agent_soc.inventory.collector import LocalInventoryCollector
from agent_soc.inventory.service import InventoryService
from agent_soc.reporting import ReportGenerationService
from agent_soc.vulnerability import VulnerabilityInspectionService


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


def create_app(
    inventory_service: InventoryService | None = None,
    vulnerability_service: VulnerabilityInspectionService | None = None,
    context_service: ContextAnalysisService | None = None,
    report_service: ReportGenerationService | None = None,
) -> Flask:
    """Create the application with an injectable inventory boundary."""
    application = Flask(__name__)
    secret_path = Path(__file__).resolve().parent / ".runtime" / "session-secret"
    configured_secret = os.environ.get("SECRET_KEY")
    if not configured_secret:
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        if not secret_path.exists():
            secret_path.write_text(secrets.token_hex(32), encoding="utf-8")
            secret_path.chmod(0o600)
        configured_secret = secret_path.read_text(encoding="utf-8").strip()
    application.secret_key = configured_secret
    application.config.update(
        JSON_SORT_KEYS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    application.jinja_env.filters["bytes"] = format_bytes
    service = inventory_service or InventoryService(LocalInventoryCollector())
    inspector = vulnerability_service or VulnerabilityInspectionService()
    context_engine = context_service or ContextAnalysisService()
    reporter = report_service or ReportGenerationService()

    def flow_state() -> tuple[bool, int]:
        selected = session.get("target_selected") is True
        step = session.get("step", 0)
        if not isinstance(step, int) or step not in range(4):
            step = 0
        return selected, step

    def inventory_dict(force: bool = False):
        return service.get_snapshot(force=force).to_dict()

    def inspection_state():
        analysis_id = session.get("analysis_id")
        if not analysis_id:
            return None
        return inspector.state(analysis_id, session.get("vulnerable_mode") is True)

    def context_state():
        analysis_id = session.get("analysis_id")
        if not analysis_id:
            return None
        return context_engine.state(analysis_id)

    def report_state():
        analysis_id = session.get("analysis_id")
        if not analysis_id:
            return None
        return reporter.state(analysis_id)

    def flow_snapshot():
        selected, step = flow_state()
        inventory = inventory_dict()
        inspection = inspection_state()
        context = context_state()
        report = report_state()
        return {
            "selected": selected,
            "step": step,
            "cve": CVE,
            "inventory": inventory,
            "inspection": inspection,
            "context": context,
            "report": report,
            "stages": [build_stage_payload(
                           number, inventory,
                           inspection["summary"] if inspection else None,
                           context["result"] if context else None,
                           report["result"] if report else None,
                       )
                       for number in range(1, step + 1)],
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
            vulnerable_mode=session.get("vulnerable_mode") is True,
        )

    @application.post("/inventario/actualizar")
    def refresh_inventory():
        inventory_dict(force=True)
        return redirect(url_for("index"))

    @application.post("/seleccionar")
    def select_local_server():
        inventory_dict(force=True)
        analysis_id = str(uuid4())
        inspector.reset(analysis_id)
        context_engine.reset(analysis_id)
        reporter.reset(analysis_id)
        session["analysis_id"] = analysis_id
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
        inspection = inspection_state()
        context = context_state()
        report = report_state()
        payload = (
            build_stage_payload(
                stage, inventory,
                inspection["summary"] if inspection else None,
                context["result"] if context else None,
                report["result"] if report else None,
            )
            if stage <= completed_step else None
        )
        return render_template(
            "index.html",
            page="stage",
            inventory=inventory,
            selected=selected,
            step=completed_step,
            current_stage=stage,
            stage_names=STAGE_NAMES,
            payload=payload,
            inspection=inspection,
            context=context,
            report=report,
            vulnerable_mode=session.get("vulnerable_mode") is True,
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
        if stage == 1:
            inspector.run_all(session["analysis_id"], session.get("vulnerable_mode") is True)
        elif stage == 2:
            inspection = inspection_state()
            context_engine.run_all(session["analysis_id"], inspection["summary"], inventory_dict())
        elif stage == 3:
            inspection = inspection_state()
            context = context_state()
            state = reporter.run_all(
                session["analysis_id"], inspection["summary"], context["result"], inventory_dict(),
            )
            if not state["complete"]:
                return redirect(url_for("stage_view", stage=3))
        session["step"] = stage
        return redirect(url_for("stage_view", stage=stage))

    @application.post("/etapa/1/comando/<command_id>")
    def execute_inspection_command(command_id):
        selected, _ = flow_state()
        if not selected or not session.get("analysis_id"):
            return redirect(url_for("index"))
        try:
            state = inspector.execute(
                session["analysis_id"],
                command_id,
                session.get("vulnerable_mode") is True,
            )
        except ValueError:
            abort(409)
        if state["complete"]:
            session["step"] = max(session.get("step", 0), 1)
        return redirect(url_for("stage_view", stage=1))

    @application.post("/etapa/2/operacion/<operation_id>")
    def execute_context_operation(operation_id):
        selected, completed_step = flow_state()
        if not selected or completed_step < 1 or not session.get("analysis_id"):
            return redirect(url_for("index"))
        inspection = inspection_state()
        if not inspection or not inspection["summary"]:
            return redirect(url_for("stage_view", stage=1))
        try:
            state = context_engine.execute(
                session["analysis_id"], operation_id, inspection["summary"], inventory_dict(),
            )
        except ValueError:
            abort(409)
        if state["complete"]:
            session["step"] = max(session.get("step", 0), 2)
        return redirect(url_for("stage_view", stage=2))

    @application.post("/etapa/3/operacion/<operation_id>")
    def execute_report_operation(operation_id):
        selected, completed_step = flow_state()
        if not selected or completed_step < 2 or not session.get("analysis_id"):
            return redirect(url_for("index"))
        inspection = inspection_state()
        context = context_state()
        if not inspection or not inspection["summary"] or not context or not context["result"]:
            return redirect(url_for("stage_view", stage=2))
        try:
            state = reporter.execute(
                session["analysis_id"], operation_id, inspection["summary"],
                context["result"], inventory_dict(),
            )
        except ValueError:
            abort(409)
        if state["complete"]:
            session["step"] = max(session.get("step", 0), 3)
        return redirect(url_for("stage_view", stage=3))

    @application.post("/etapa/3/decision")
    def review_report():
        selected, completed_step = flow_state()
        if not selected or completed_step < 3 or not session.get("analysis_id"):
            return redirect(url_for("index"))
        try:
            reporter.decide(
                session["analysis_id"], request.form.get("decision", ""),
                request.form.get("notes", ""),
            )
        except ValueError:
            abort(409)
        return redirect(url_for("stage_view", stage=3) + "#revision-analista")

    @application.post("/modo-prueba")
    def toggle_test_mode():
        enabled = session.get("vulnerable_mode") is True
        session["vulnerable_mode"] = not enabled
        analysis_id = session.get("analysis_id")
        if analysis_id:
            inspector.reset(analysis_id)
            context_engine.reset(analysis_id)
            reporter.reset(analysis_id)
            session["step"] = 0
            return redirect(url_for("stage_view", stage=1))
        return redirect(url_for("index"))

    @application.post("/reiniciar")
    def restart_flow():
        analysis_id = session.get("analysis_id")
        if analysis_id:
            inspector.reset(analysis_id)
            context_engine.reset(analysis_id)
            reporter.reset(analysis_id)
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
        if stage == 1:
            inspector.run_all(session["analysis_id"], session.get("vulnerable_mode") is True)
        elif stage == 2:
            inspection = inspection_state()
            context_engine.run_all(session["analysis_id"], inspection["summary"], inventory_dict())
        elif stage == 3:
            inspection = inspection_state()
            context = context_state()
            result = reporter.run_all(
                session["analysis_id"], inspection["summary"], context["result"], inventory_dict(),
            )
            if not result["complete"]:
                return jsonify({"error": result["error"] or "No se completó el reporte."}), 502
        session["step"] = stage
        return jsonify(flow_snapshot())

    @application.post("/api/reset")
    def reset_api():
        analysis_id = session.get("analysis_id")
        if analysis_id:
            inspector.reset(analysis_id)
            context_engine.reset(analysis_id)
            reporter.reset(analysis_id)
        session.clear()
        return jsonify(flow_snapshot())

    @application.get("/health")
    def health():
        return jsonify({"status": "ok", "module": "agent-soc-reporting"})

    def require_report():
        selected, step = flow_state()
        state = report_state()
        if not selected or step != 3 or not state or not state["result"]:
            return None
        return state["result"]

    @application.get("/report.md")
    def report_markdown():
        report = require_report()
        if not report:
            return jsonify({"error": "Completa las tres etapas para descargar el reporte."}), 409
        content = reporter.markdown(session["analysis_id"])
        return Response(
            content,
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=agent-soc-{CVE}.md"},
        )

    @application.get("/report.json")
    def report_json():
        report = require_report()
        if not report:
            return jsonify({"error": "Completa las tres etapas para descargar el reporte."}), 409
        response = jsonify(report)
        response.headers["Content-Disposition"] = f"attachment; filename=agent-soc-{CVE}.json"
        return response

    @application.get("/report.pdf")
    def report_pdf():
        report = require_report()
        if not report:
            return jsonify({"error": "Completa las tres etapas para descargar el reporte."}), 409
        inventory = inventory_dict()
        output = BytesIO()
        document = SimpleDocTemplate(
            output,
            pagesize=A4, rightMargin=1.8 * cm, leftMargin=1.8 * cm,
            topMargin=2.2 * cm, bottomMargin=1.8 * cm,
            title=report["title"], author="Agent SOC",
        )
        styles = getSampleStyleSheet()
        navy, teal, muted, line = (
            colors.HexColor("#142333"), colors.HexColor("#0D706B"),
            colors.HexColor("#637486"), colors.HexColor("#DCE3E9"),
        )
        styles.add(ParagraphStyle(
            "ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22,
            leading=27, textColor=navy, alignment=TA_LEFT, spaceAfter=8,
        ))
        styles.add(ParagraphStyle(
            "Kicker", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8,
            leading=10, textColor=teal, tracking=1.2, spaceAfter=7,
        ))
        styles.add(ParagraphStyle(
            "Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14,
            leading=18, textColor=navy, spaceBefore=14, spaceAfter=7,
        ))
        styles.add(ParagraphStyle(
            "BodyReport", parent=styles["BodyText"], fontSize=9.3, leading=14,
            textColor=colors.HexColor("#334A5C"), spaceAfter=7,
        ))
        styles.add(ParagraphStyle(
            "SmallReport", parent=styles["BodyText"], fontSize=7.5, leading=10, textColor=muted,
        ))
        styles.add(ParagraphStyle(
            "SourceGroup", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10,
            leading=13, textColor=teal, spaceBefore=10, spaceAfter=3,
        ))

        def p(value, style="BodyReport"):
            return Paragraph(escape(str(value or "No disponible")), styles[style])

        def header_footer(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(line)
            canvas.line(1.8 * cm, 28.25 * cm, 19.2 * cm, 28.25 * cm)
            canvas.setFillColor(navy)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(1.8 * cm, 28.55 * cm, "AGENT SOC")
            canvas.setFillColor(muted)
            canvas.setFont("Helvetica", 7)
            canvas.drawRightString(19.2 * cm, 28.55 * cm, f"{report['report_id']} · v{report['version']}")
            canvas.line(1.8 * cm, 1.25 * cm, 19.2 * cm, 1.25 * cm)
            canvas.drawString(1.8 * cm, .85 * cm, "Documento técnico · uso para revisión del analista")
            canvas.drawRightString(19.2 * cm, .85 * cm, f"Página {doc.page}")
            canvas.restoreState()

        review = report["review"]
        host = report["host"]
        story = [
            Paragraph("REPORTE DE EXPOSICIÓN", styles["Kicker"]),
            Paragraph(escape(report["title"]), styles["ReportTitle"]),
            Paragraph(
                f"Activo {escape(host['host'])} · Generado {escape(report['generated_at'])}",
                styles["SmallReport"],
            ),
            Spacer(1, .35 * cm),
            HRFlowable(width="100%", thickness=2, color=teal),
            Spacer(1, .35 * cm),
        ]
        rows = [
            [p("CLASIFICACIÓN", "Kicker"), p("PRIORIDAD", "Kicker"), p("CONFIANZA", "Kicker"), p("CVSS", "Kicker")],
            [p(report["classification"]), p(report["priority"]), p(f"{report['confidence']} %"), p(report["cvss_score"])],
        ]
        table = Table(rows, colWidths=[7.2 * cm, 3.2 * cm, 3.2 * cm, 2.8 * cm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2F8F7")),
            ("GRID", (0, 0), (-1, -1), .35, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ]))
        story.extend([
            table, Paragraph("Resumen ejecutivo", styles["Section"]), p(report["executive_summary"]),
            Paragraph("Activo y alcance", styles["Section"]),
        ])
        asset_rows = [[p(label, "SmallReport"), p(value)] for label, value in (
            ("Host", host["host"]), ("FQDN / IP", f"{host['fqdn']} · {host['ip']}"),
            ("Sistema operativo", host["os"]), ("Kernel evaluado", host["kernel"]),
            ("Paquete origen", host["source_package"]), ("Versión instalada", host["installed_version"]),
            ("Versión corregida", host["fixed_version"]),
        )]
        asset_table = Table(asset_rows, colWidths=[4.2 * cm, 12.2 * cm])
        asset_table.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
            ("LINEBELOW", (0, 0), (-1, -1), .3, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([
            asset_table,
            Paragraph("Análisis técnico", styles["Section"]), p(report["technical_analysis"]),
            p(report["reason"]),
            Paragraph("Impacto", styles["Section"]), p(report["impact_statement"]),
            Paragraph("Plan de acción", styles["Section"]), p(report["action_plan"]),
            PageBreak(),
            Paragraph("TRAZABILIDAD Y CONTROL", styles["Kicker"]),
            Paragraph("Evidencia, RAG y modelos", styles["ReportTitle"]),
            Paragraph("Evidencia verificada", styles["Section"]),
        ])
        for claim in report["verified_claims"]:
            story.append(p(f"✓ {claim['claim']}  Fuente: {claim['evidence']}"))
        rag = report["rag"]
        models = report["models"]
        story.extend([
            Paragraph("Trazabilidad de inteligencia", styles["Section"]),
            Table([
                [p("Documentos", "SmallReport"), p(rag["documents"]), p("Fragmentos", "SmallReport"), p(rag["chunks"])],
                [p("Coincidencias", "SmallReport"), p(rag["retrieved"]), p("Embeddings", "SmallReport"), p(rag["embedding_model"])],
                [p("Modelo de lenguaje", "SmallReport"), p(models["language_model"]), p("Documentador", "SmallReport"), p(models["documenter_model"])],
                [p("Tokens E/S", "SmallReport"), p(f"{models['prompt_tokens']} / {models['response_tokens']}"), p("Inferencia", "SmallReport"), p(f"{models['duration_ms']} ms")],
            ], colWidths=[3.0 * cm, 5.2 * cm, 3.0 * cm, 5.2 * cm], style=TableStyle([
                ("GRID", (0, 0), (-1, -1), .3, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FA")),
                ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ])),
            Paragraph("Fuentes consultadas", styles["Section"]),
        ])
        classified_sources = [
            source if source.get("category") else ReportGenerationService._classify_source(source)
            for source in report["sources"]
        ]
        source_groups = (
            (
                "Datasets estructurados",
                "Registros normalizados e indexados que alimentaron la búsqueda y recuperación RAG.",
                "dataset",
            ),
            (
                "Evidencia técnica primaria",
                "Publicaciones del proyecto o mantenedor utilizadas para explicar la causa y la corrección.",
                "primary_evidence",
            ),
            (
                "Referencias complementarias",
                "Material utilizado para contraste o contexto adicional del hallazgo.",
                "reference",
            ),
        )
        for group_title, group_detail, category in source_groups:
            group = [source for source in classified_sources if source["category"] == category]
            if not group:
                continue
            story.extend([
                Paragraph(escape(group_title), styles["SourceGroup"]),
                Paragraph(escape(group_detail), styles["SmallReport"]),
                Spacer(1, .08 * cm),
            ])
            source_rows = []
            for source in group:
                safe_url = escape(source["url"], {'"': '&quot;'})
                source_rows.append([
                    Paragraph(
                        f"<b>{escape(source['name'])}</b><br/>"
                        f"<font color=\"#637486\">{escape(source['category_label'])}</font>",
                        styles["BodyReport"],
                    ),
                    Paragraph(
                        f"{escape(source['detail'])}<br/><font color=\"#637486\">Función: "
                        f"{escape(source['role'])}</font><br/>"
                        f"<link href=\"{safe_url}\" color=\"#0D706B\">{safe_url}</link>",
                        styles["BodyReport"],
                    ),
                ])
            source_table = Table(source_rows, colWidths=[4.4 * cm, 12 * cm], hAlign="LEFT")
            source_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), .3, line),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]))
            story.append(source_table)
        story.extend([
            Paragraph("Revisión del analista", styles["Section"]),
            Table([
                [p("Decisión", "SmallReport"), p(review["label"])],
                [p("Fecha", "SmallReport"), p(review["timestamp"] or "Pendiente")],
                [p("Notas", "SmallReport"), p(review["notes"] or "Sin notas")],
            ], colWidths=[4.2 * cm, 12.2 * cm], style=TableStyle([
                ("GRID", (0, 0), (-1, -1), .3, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ])),
        ])
        document.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
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

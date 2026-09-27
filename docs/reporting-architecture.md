# Arquitectura del módulo de reporte

## Objetivo

La etapa 3 implementa el agente documentador y el control humano definidos para el MVP. Consume los contratos ya producidos por Inventario, Inspección y Contexto; no vuelve a inspeccionar el host y no ejecuta remediaciones.

## Flujo

1. **Consolidar expediente.** Integra identidad del activo, kernel, paquete, comparación de versiones, clasificación, confianza, evidencia RAG, métricas de modelos y fuentes.
2. **Redacción con PLN.** Ollama ejecuta `qwen3:0.6b` con un esquema JSON estricto para sintetizar el resumen ejecutivo, análisis técnico, impacto y plan de acción. El parser admite envolturas de texto y, si la inferencia queda truncada, una realización lingüística determinista completa el documento desde los mismos hechos verificados.
3. **Verificar afirmaciones.** Una compuerta determinista contrasta identificador, kernel, versiones, clasificación y confianza. Expresiones que afirmen explotación o compromiso sin evidencia detienen la publicación.
4. **Publicar entregables.** Asigna un identificador estable, genera el contrato de reporte y conserva el expediente en SQLite. La interfaz permite descargar PDF, Markdown y JSON.
5. **Revisión humana.** El analista valida o rechaza el dictamen. La decisión, notas y marca de tiempo se asocian al `analysis_id` y `report_id`.

## Contrato del reporte

El objeto publicado contiene:

- identidad y versión del documento;
- clasificación, prioridad, confianza y CVSS;
- activo evaluado y versiones comparadas;
- resumen ejecutivo, análisis, impacto y plan de acción;
- documentos, fragmentos, coincidencias, modelos y tokens;
- fuentes enlazadas y afirmaciones verificadas;
- estado de revisión humana.

## Persistencia y recuperación

`data/reporting/reports.db` conserva el JSON completo y la representación Markdown. El servicio puede reconstruir el resultado por `analysis_id` después de reiniciar el proceso web, preservando la decisión del analista.

## Controles

- El modelo sólo recibe el expediente estructurado.
- La temperatura es baja y la respuesta exige JSON.
- El esquema fija cuatro campos obligatorios y reserva suficientes tokens para el escenario vulnerable.
- Una salida incompleta del modelo no bloquea la publicación ni altera la clasificación.
- El modelo no decide aplicabilidad, severidad, versiones ni confianza.
- Las afirmaciones críticas pasan por reglas deterministas.
- No se ejecutan parches, exploits, comandos ni cambios sobre el servidor.
- La decisión final permanece bajo supervisión humana.

## Clasificación de fuentes

Las exportaciones separan la procedencia para evitar presentar todas las URLs como equivalentes:

- **Datasets estructurados:** NIST NVD, Ubuntu Security y Debian Security Tracker. Alimentan la ingesta, normalización y recuperación RAG.
- **Evidencia técnica primaria:** publicación upstream del parche en netdev/Openwall. Sustenta la explicación de la causa y la corrección.
- **Referencias complementarias:** cualquier material adicional utilizado únicamente para contraste o contexto.

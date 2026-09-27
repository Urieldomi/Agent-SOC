# Bitácora de Agent SOC

## 2026-09-20 — Revisión inicial

- Se revisó la estructura del repositorio y sus reglas de desarrollo seguro.
- El proyecto aún está en etapa de definición y no contiene código ejecutable.
- Siguiente paso: definir el alcance, las fuentes de alertas y las acciones permitidas del agente.

## 2026-09-25 — Inventario local real

- Se sustituyó la demostración con hosts fijos por un módulo real de inventario local.
- Se separaron ejecución segura, recolección, modelo normalizado, caché e interfaz Flask.
- Se agregó una allowlist de comandos de solo lectura, sin shell ni privilegios elevados.
- Se documentó la arquitectura y el snapshot `1.0` que consumirá el análisis de Fragnesia.
- Siguiente paso: ampliar el inventario con evidencia específica del kernel y CVE-2026-46300.

## 2026-09-26 — Restauración compatible del flujo

- Se restauraron el stepper, la navegación secuencial y el reporte PDF.
- La selección y la inspección utilizan el inventario real del servidor local.
- Contexto y reporte conservan los mocks existentes con etiquetas explícitas.
- Se estableció como regla permanente evolucionar cada módulo sin romper las demás etapas.

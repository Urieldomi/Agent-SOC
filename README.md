# Agent SOC

Agent SOC está evolucionando de una demostración con datos fijos a un sistema real y modular para inspeccionar servidores Linux, correlacionar evidencia con fuentes de vulnerabilidades y producir reportes verificables.

## Features disponibles: inventario, inspección, contexto y reporte

La aplicación detecta automáticamente el servidor donde está instalada y obtiene, mediante operaciones de solo lectura:

- hostname y FQDN;
- distribución, versión, kernel y arquitectura;
- fabricante, modelo y procesador;
- CPU, RAM, swap y disco raíz;
- tiempo de actividad y último arranque;
- gateway, dirección IP e interfaces de red;
- traza de los comandos de inventario ejecutados.

La etapa de inspección ejecuta una secuencia cerrada de comprobaciones de solo lectura y muestra la salida de cada una en una terminal integrada. El dictamen final compara el paquete fuente del kernel con la versión corregida aplicable a la distribución.

La etapa de contexto descarga registros oficiales de NIST NVD, Ubuntu Security, Debian Security Tracker y la referencia upstream. Los normaliza en SQLite, genera un índice RAG con embeddings locales y ejecuta dos agentes mediante Ollama antes de validar el resultado contra las versiones verificadas.

La etapa de reporte ejecuta un agente documentador local, verifica cada afirmación contra el expediente y publica una vista ejecutiva y técnica. Los entregables se generan en PDF, Markdown y JSON; la decisión `Validado/Rechazado` y las notas del analista se conservan en SQLite con marca de tiempo.

Flujo disponible:

1. Detectar y seleccionar el servidor local real.
2. Ejecutar, uno por uno, los comandos de inspección con datos reales.
3. Descargar, indexar y correlacionar el contexto de Fragnesia.
4. Consolidar, redactar, verificar y publicar el reporte técnico.
5. Registrar la revisión humana y exportar el expediente.

El interruptor `Activar/Desactivar` del pie permite repetir la inspección con un escenario vulnerable para demostraciones. Al desactivarlo, todos los resultados vuelven a provenir del servidor actual.

## Arquitectura

El código de inventario está aislado de Flask:

- `agent_soc/inventory/command_runner.py`: ejecutor con lista cerrada de comandos.
- `agent_soc/inventory/collector.py`: recolección y normalización de datos.
- `agent_soc/inventory/models.py`: contrato del snapshot de inventario.
- `agent_soc/inventory/service.py`: caché y actualización explícita.
- `agent_soc/vulnerability/inspection.py`: secuencia, evidencia y dictamen de CVE-2026-46300.
- `agent_soc/context/service.py`: ingesta, normalización, recuperación RAG y validación.
- `agent_soc/context/ollama.py`: inferencia local de embeddings y agentes.
- `agent_soc/reporting/service.py`: documentador, verificación, publicación y control HITL.
- `app.py`: composición y rutas HTTP.

Consulta [docs/architecture.md](docs/architecture.md) para ver el diagrama, las decisiones y el contrato de seguridad.

## Ejecutar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abre <http://127.0.0.1:5000>. La aplicación escucha solamente en loopback de forma predeterminada porque el inventario contiene información sensible de infraestructura.

Endpoints disponibles:

- `GET /`: interfaz del inventario.
- `POST /inventario/actualizar`: fuerza una nueva recolección.
- `GET /api/inventory`: snapshot normalizado en JSON.
- `GET /etapa/<n>`: navegación secuencial de inspección, contexto y reporte.
- `POST /etapa/<n>/ejecutar`: ejecución de la siguiente etapa habilitada.
- `POST /etapa/1/comando/<id>`: ejecuta la siguiente comprobación permitida.
- `POST /modo-prueba`: alterna el escenario vulnerable y reinicia la inspección.
- `POST /etapa/3/operacion/<id>`: ejecuta el siguiente control documental.
- `POST /etapa/3/decision`: registra la validación o rechazo del analista.
- `GET /api/state`: estado completo del flujo.
- `GET /report.pdf`: reporte técnico maquetado.
- `GET /report.md`: versión Markdown del reporte.
- `GET /report.json`: expediente estructurado del reporte.
- `GET /health`: estado básico del servicio.

## Pruebas

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Límites de seguridad

- No se utiliza `shell=True`.
- No se utiliza `sudo`.
- Solo se aceptan comandos exactos incluidos en una allowlist.
- No se reciben comandos desde HTTP ni desde el usuario.
- La salida cruda de los comandos no se conserva en la traza.
- El módulo no modifica el servidor.
- La conclusión se limita a la aplicabilidad por versión y evidencia local; no se ejecuta un exploit.
- Ollama escucha únicamente en `127.0.0.1:11434` y no se publica mediante Tailscale.

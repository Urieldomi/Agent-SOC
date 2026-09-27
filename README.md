# Agent SOC

Agent SOC está evolucionando de una demostración con datos fijos a un sistema real y modular para inspeccionar servidores Linux, correlacionar evidencia con fuentes de vulnerabilidades y producir reportes verificables.

## Feature disponible: inventario local real

La aplicación detecta automáticamente el servidor donde está instalada y obtiene, mediante operaciones de solo lectura:

- hostname y FQDN;
- distribución, versión, kernel y arquitectura;
- fabricante, modelo y procesador;
- CPU, RAM, swap y disco raíz;
- tiempo de actividad y último arranque;
- gateway, dirección IP e interfaces de red;
- traza de los comandos de inventario ejecutados.

La evaluación real de CVE-2026-46300 todavía no se ejecuta. Para mantener funcional el producto completo, el inventario real alimenta las etapas existentes de contexto y reporte, que continúan como mocks claramente etiquetados.

Flujo disponible:

1. Detectar y seleccionar el servidor local real.
2. Ejecutar la inspección con datos reales.
3. Ejecutar el contexto simulado de Fragnesia.
4. Generar un reporte PDF transicional con inventario real y evaluación simulada.

## Arquitectura

El código de inventario está aislado de Flask:

- `agent_soc/inventory/command_runner.py`: ejecutor con lista cerrada de comandos.
- `agent_soc/inventory/collector.py`: recolección y normalización de datos.
- `agent_soc/inventory/models.py`: contrato del snapshot de inventario.
- `agent_soc/inventory/service.py`: caché y actualización explícita.
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
- `GET /api/state`: estado completo del flujo híbrido.
- `GET /report.pdf`: reporte disponible después de las tres etapas.
- `GET /health`: estado básico del servicio.

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Límites de seguridad

- No se utiliza `shell=True`.
- No se utiliza `sudo`.
- Solo se aceptan comandos exactos incluidos en una allowlist.
- No se reciben comandos desde HTTP ni desde el usuario.
- La salida cruda de los comandos no se conserva en la traza.
- El módulo no modifica el servidor.
- La evaluación de vulnerabilidad sigue siendo simulada y está marcada como no operativa.

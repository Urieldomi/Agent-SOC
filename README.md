# Agent SOC · Fragnesia Lab

Prototipo Flask para mostrar un flujo secuencial de tres agentes sobre **CVE-2026-46300 (Fragnesia)**. Presenta dos hosts Debian 12 simulados: uno vulnerable y otro corregido. El agente de inspección muestra inventario y logs; el de contexto cruza un dataset fijo; el de reporte entrega un PDF.

> **Demo:** no se conecta a Linux, no ejecuta shell ni PoC, no consulta datasets en vivo y no determina la exposición real de ningún equipo. Host, logs, score y resultados son datos de ejemplo que se repiten en cada ejecución.

## Ejecutar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abre <http://127.0.0.1:5000>. Elige un host y avanza por pantallas separadas: **Inspección → Contexto → Reporte**. Cada etapa debe ejecutarse antes de que se habilite la siguiente. Puedes volver a revisar una etapa completada. Después de la tercera etapa podrás descargar el PDF. Elegir otro escenario o pulsar **Reiniciar flujo** vuelve al inicio.

## Compartir la demo

Para mostrarla en la misma red local:

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
gunicorn app:app --bind 0.0.0.0:5000
```

Comparte `http://IP_DE_TU_EQUIPO:5000` con tus compañeros. El repositorio incluye `Procfile` para plataformas que aceptan aplicaciones Python con Gunicorn; configura allí `SECRET_KEY` como variable de entorno. Esta demo no incluye cuentas de usuario ni control de acceso.

## Verificación rápida

```bash
python -m unittest discover -s tests -v
```

## Referencias del caso

- [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-46300): en Debian 12, el aviso DSA-6306-1 indica la versión fuente corregida `6.1.174-1`.
- [Parche netdev](https://lists.openwall.net/netdev/2026/05/13/79): preservación de `SKBFL_SHARED_FRAG` durante la coalescencia de buffers.
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-46300) y [PoC pública](https://github.com/v12-security/pocs/tree/main/fragnesia), mostradas como referencias; la aplicación no las consulta ni ejecuta.

La implementación del proyecto real deberá sustituir los fixtures por una recolección autorizada, normalización de evidencias y consultas verificables a fuentes oficiales.

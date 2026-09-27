# Configuración temporal de Tailscale Funnel

## Configuración original de Tecnotime

Antes de las pruebas de Agent SOC, el Funnel público tenía esta ruta:

```text
https://ccomputo-proliant-ml350-gen9.tailfd1c00.ts.net/
  -> http://127.0.0.1:5000
```

Configuración observada el 25 de septiembre de 2026:

```json
{
  "TCP": {"443": {"HTTPS": true}},
  "Web": {
    "ccomputo-proliant-ml350-gen9.tailfd1c00.ts.net:443": {
      "Handlers": {
        "/": {"Proxy": "http://127.0.0.1:5000"}
      }
    }
  },
  "AllowFunnel": {
    "ccomputo-proliant-ml350-gen9.tailfd1c00.ts.net:443": true
  }
}
```

## Restaurar Tecnotime

Tecnotime continúa ejecutándose en el puerto local `5000`. Para volver a publicarlo en el dominio de Tailscale:

```bash
tailscale funnel --bg --https=443 http://127.0.0.1:5000
```

Verificar la restauración:

```bash
tailscale funnel status
curl -I https://ccomputo-proliant-ml350-gen9.tailfd1c00.ts.net/
```

## Publicación temporal de Agent SOC

Durante las pruebas, el mismo dominio y puerto público se asignan a Agent SOC:

```text
https://ccomputo-proliant-ml350-gen9.tailfd1c00.ts.net/
  -> http://127.0.0.1:5055
```

Este cambio afecta únicamente el proxy de Tailscale. No detiene el proceso de Tecnotime en `5000`.

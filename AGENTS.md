# Reglas permanentes de evolución de Agent SOC

## Compatibilidad progresiva

- Agent SOC se implementa módulo por módulo sin romper el flujo completo existente.
- Cuando un módulo real sustituya a un mock, debe conservar el contrato de entrada y salida que consumen las demás etapas o incluir un adaptador de compatibilidad.
- Las etapas todavía no implementadas deben continuar funcionando con mocks claramente etiquetados.
- Un cambio amplio de arquitectura no autoriza eliminar navegación, endpoints, reportes o demostraciones existentes sin proporcionar una transición equivalente.
- Cada pull request debe indicar qué partes son reales, cuáles siguen simuladas y cómo se mantiene la compatibilidad entre ambas.
- Antes de retirar un mock, deben existir pruebas del módulo real y pruebas de integración del flujo completo.

## Principio rector

Evolucionar por reemplazo compatible: mantener el sistema utilizable de inicio a fin mientras cada etapa simulada es sustituida gradualmente por una implementación real.

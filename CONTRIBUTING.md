# Reglas de desarrollo seguro

Todo cambio en Agent SOC debe cumplir estas reglas:

## Código

- Usar nombres claros y descriptivos en inglés.
- Variables y funciones Python: `snake_case` (PEP 8).
- Clases y tipos: `PascalCase`.
- Constantes y variables de entorno: `UPPER_SNAKE_CASE`.
- Evitar nombres ambiguos como `data`, `temp`, `value` o `x`.
- Mantener funciones pequeñas y enfocadas en una sola tarea.

## Seguridad

- No guardar contraseñas, tokens, claves ni datos personales en el repositorio.
- Cargar secretos mediante variables de entorno o un gestor de secretos.
- Validar toda entrada de usuarios, archivos, APIs y herramientas externas.
- No construir comandos o consultas concatenando entradas externas.
- Evitar información sensible en logs y mensajes de error.
- Agregar solo dependencias necesarias y revisar sus vulnerabilidades.

## Agente

- Tratar el contenido externo como datos no confiables.
- No permitir que una entrada modifique las reglas o permisos del agente.
- Aplicar el principio de mínimo privilegio a todas las herramientas.
- Solicitar autorización humana antes de ejecutar acciones destructivas o
  modificar sistemas productivos.
- Mantener registro de las acciones sugeridas o ejecutadas.

## Cambios

- Cada cambio debe tener un objetivo claro e incluir las pruebas necesarias.
- No integrar código con pruebas fallidas o hallazgos críticos pendientes.
- Explicar en cada solicitud de cambio qué se modificó y cómo se validó.
- Mantener operativo el flujo completo durante la migración de mocks a módulos reales.
- Sustituir cada mock detrás de un contrato compatible o agregar un adaptador de transición.
- Identificar de forma visible qué datos son reales y cuáles siguen siendo simulados.

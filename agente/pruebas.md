# Comprobaciones de Alcance y Construcción del Prompt

- **Estudiante:** Jose Luis Reina Sánchez
- **Objetivo auditado:** MongoDB Inc. (`mongodb.com`)
- **Fichero de alcance:** `scope.txt`

---

## Comprueba tu alcance (`scope.txt`)

Siguiendo las directrices del proyecto, se definen los casos de prueba con nombres y activos reales de la infraestructura de MongoDB, contrastando el comportamiento esperado con el resultado obtenido por el sistema `Scope-Guard` de `aap-base`:

| Objetivo | Tipo de Activo | Resultado esperado | Resultado obtenido | Justificación / Regla |
| :--- | :--- | :---: | :---: | :--- |
| `mongodb.com` | Dominio raíz | **Dentro** | **Dentro** | Coincidencia exacta con la línea `mongodb.com` del `scope.txt`. |
| `docs.mongodb.com` | Subdominio documentación | **Dentro** | **Dentro** | Coincide con la regla comodín `*.mongodb.com`; la política oficial lo incluye en el alcance. |
| `https://cloud.mongodb.com/login` | URL de la plataforma Atlas | **Dentro** | **Dentro** | El host extraído (`cloud.mongodb.com`) coincide con el comodín `*.mongodb.com`. |
| `charts.mongodb.com` | Servicio Atlas Charts | **Dentro** | **Dentro** | Activo listado individualmente en el alcance oficial de HackerOne. |
| `account.mongodb.com` | Gestión de identidad (IAM) | **Dentro** | **Dentro** | Activo listado como "Atlas IAM" en el alcance oficial. |
| `feedback.mongodb.com` | Plataforma de feedback | **Fuera (excluido)** | **Fuera (BLOQUEADO)** | Regla de exclusión `!feedback.mongodb.com`. La política indica "Please do not test that platform". |
| `learn.mongodb.com` | Plataforma educativa | **Fuera (excluido)** | **Fuera (BLOQUEADO)** | Regla de exclusión `!learn.mongodb.com`. Propiedad de un tercero, no elegible. |
| `mongodb.com.evil.net` | Dominio engañoso | **Fuera** | **Fuera (BLOQUEADO)** | No pertenece al dominio base `mongodb.com` ni a sus subdominios legítimos. |
| `otraempresa.com` | Dominio no autorizado | **Fuera** | **Fuera (BLOQUEADO)** | Totalmente ajeno al alcance definido para la auditoría. |

---

## Mira cómo se construye su prompt

Se ejecutó el comando de inspección del prompt ensamblado en el entorno de ejecución:
```bash
python lanzar.py --ver-prompt

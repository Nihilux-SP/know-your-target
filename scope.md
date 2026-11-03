## 1. Resumen

**MongoDB, Inc. (operando bajo 10gen, Inc.)** es una compañía global de software (The Intelligent Data Platform for the AI Era) con sede registrada en París, Francia. Cotiza en bolsa (Public Company) y cuenta con una plantilla de 5.001 a 10.000 empleados, con presencia principal en Nueva York. 

Su infraestructura es fuertemente **cloud-native y multinube**, utilizando Amazon Web Services (AWS) y Google Cloud Platform (GCP) para hosting, DNS (Route 53, Cloud DNS), CDN (CloudFront) y correo (Vali Mail). El front-end principal está protegido por **Envoy (Istio)**, utiliza certificados SSL de Let's Encrypt y aplica políticas estrictas de correo (DMARC `p=reject`, SPF) *(Netcraft)*.

El dominio expone una superficie de ataque inmensa, con miles de subdominios de desarrollo, *staging* y corporativos (`*.corp.mongodb.com`) visibles públicamente *(Subfinder)*. Además, se han detectado **repositorios APT públicos** sin indexación cerrada *(Google Dorks)* y servicios de bases de datos MongoDB expuestos en Shodan, alojados en infraestructuras de terceros como Hetzner *(Shodan)*.

---

## 2. Dominios y subdominios

| Subdominio / Dominio | IP | En alcance | Para qué parece servir | Ref. |
| :--- | :--- | :--- | :--- | :--- |
| `mongodb.com` (Raíz) | `3.33.132.188` | Sí | Web principal. AWS Global Accelerator. Servidor: `istio-envoy`. | Huella (Network/SSL) |
| `ns-1047.awsdns-02.org` | `205.251.196.23` | No | Nameserver AWS Route 53. | Registro WhoIs |
| `ns-1636.awsdns-12.co.uk` | `205.251.198.100` | No | Nameserver AWS Route 53. | Registro WhoIs |
| `ns-cloud-e1.googledomains.com`| `216.239.32.110` | No | Nameserver Google Cloud DNS. | Registro WhoIs |
| `repo.mongodb.com` | *n/d* | Sí | Repositorio APT público (índice abierto). Historial de versiones. | Google Dorks |
| `cloud.mongodb.com` | *n/d* | Sí | Panel de control de MongoDB Atlas. | Subdominios |
| `account-qa.mongodb.com` | `52.21.89.200` | Sí | Entorno QA de cuentas. AWS (us-east-1). | Subfinder / DNS JSON |
| `cloud-dev.mongodb.com` | `34.144.128.17` | Sí | Entorno de desarrollo Cloud. GCP (GCLB). | Subfinder / DNS JSON |
| `account-staging.mongodb.com` | `52.21.89.200` | Sí | Entorno Staging de cuentas. AWS (us-east-1). | Subfinder / DNS JSON |
| `api-backup.ap-southeast-2...` | `52.62.201.169` | Sí | Servicio de backup API. AWS (ap-southeast-2). | Subfinder / DNS JSON |
| `agentic-platform-staging...` | `3.24.0.12` | Sí | Plataforma de agentes (Staging). AWS (us-east-2). | Subfinder / DNS JSON |
| `login.corp.mongodb.com` | *n/d* | Sí | Portal de login corporativo interno. | Subdominios |
| `jira-staging.corp.mongodb.com` | *n/d* | Sí | Jira (entorno de pruebas) corporativo. | Subdominios |
| `mongo365.org`, `mongo777.com`, etc. | *n/d* | No | Dominios similares (posible typosquatting / phishing). | Registro WhoIs |

---

## 3. Infraestructura y servicios

*   **Hosting y Red:** La IP principal resuelve a Amazon Technologies Inc. (AS16509) a través de AWS Global Accelerator *(Netcraft)*. El DNS está delegado tanto a AWS Route 53 como a Google Cloud DNS *(WhoIs)*. Se ha detectado una IP secundaria en Hetzner Online GmbH (Finlandia, `135.181.175.223`) apuntando al dominio *(Shodan)*.
*   **Tecnologías Web (Netcraft):**
    *   **Servidor:** Istio-Envoy *(Netcraft SSL)*.
    *   **CDN:** Amazon CloudFront.
    *   **Compresión/Formato:** Gzip, HTML5, CSS externo, Media Queries, UTF-8, JavaScript.
    *   **Analítica:** Adobe Omnitrace (Web Tracker).
*   **Certificados SSL:** Let's Encrypt (común). TLS 1.3, cifrado `TLS_AES_256_GCM_SHA384` *(Netcraft SSL)*.
*   **Correo Electrónico (Netcraft):**
    *   **SPF:** Utiliza `_spf.vali.email` (Vali Mail).
    *   **DMARC:** Política estricta `p=reject`. Reportes agregados a `dmarc_reports@mongodb.com` y forenses a `1eed4417@forensics.dmarc-report.com`.
*   **Shodan:** Expone servicios de MongoDB (puerto 27017 por defecto) alojados en Hetzner (Finlandia) bajo el dominio `mongo.db` (resolver name). *(Nota: El escaneo de Shodan muestra IPs de terceros, lo que sugiere instancias mal configuradas de clientes o despliegues fuera del perímetro principal).*
*   **Robots.txt:** Expone rutas administrativas y de desarrollo, como `/admin/`, `/devcenter-uat*`, `/docs-qa*`, `/community/forums/user-api-key/` y `/well-known/security.txt`. *(Capturas robots.txt)*.

---

## 4. Correos y personas

*   **Patrón de correo:** El patrón es **`nombre.apellido@mongodb.com`** o **`inicial+apellido@mongodb.com`**. 
*   **Directorio (Apollo.io):** Se han identificado **4.162 resultados** de empleados. Destacan:
    *   **Nausheen K.** - Vice President.
    *   **Gary R.** - Vice President of Technical Services.
    *   **Andrea F.** - Regional Vice President.
    *   **Andrew J.** - Regional Director.
*   **Datos de la organización:** Empresa pública, industria de desarrollo de software, tamaño 5001-10,000 empleados, sede en Nueva York. No aceptan "All" (Accept all: NO). *(Apollo)*.
*   **WhoIs:** Los contactos de registro, admin y técnico están redactados por privacidad, pero todos apuntan a la organización **10gen inc** en París.

---

## 5. Puntos de interés (Fase Activa)

Basado en el reconocimiento pasivo, estos son los tres vectores que el equipo debería investigar primero:

1.  **Repositorio APT público (`repo.mongodb.com`):**
    *   *Por qué:* La búsqueda de Google Dorks reveló un "Index of mongodb-enterprise" abierto. Aunque son paquetes de software, un índice abierto puede revelar versiones heredadas (legacy) con vulnerabilidades conocidas, scripts de instalación, o incluso archivos de configuración dejados por error en carpetas de desarrollo/testing dentro del repo.
    *   *Acción:* Enumerar el directorio completo y descargar los paquetes de las ramas `development` y `testing` para buscar secretos o configuraciones por defecto.

2.  **Subdominios de tipo `*.corp.mongodb.com` y `*.staging`:**
    *   *Por qué:* Subfinder ha listado miles de subdominios internos. A menudo, los entornos de *staging* (ej. `jira-staging.corp.mongodb.com`, `login.staging.corp.mongodb.com`) tienen protecciones más débiles, contraseñas por defecto, o exponen paneles de administración que no deberían ser accesibles desde Internet. El `robots.txt` también filtra rutas como `/devcenter-uat*`.
    *   *Acción:* Resolución DNS masiva, fingerprinting de tecnologías (Wappalyzer) y búsqueda de paneles de login no protegidos o APIs de backend expuestas en los entornos QA/Staging.

3.  **Correo Electrónico (Vali Mail / DMARC):**
    *   *Por qué:* Aunque tienen DMARC en `p=reject` (lo cual es bueno), el uso de Vali Mail y la gran cantidad de empleados exponen un vector de *spear-phishing* o *password spraying* si no hay MFA. Además, el patrón de correo es predecible.
    *   *Acción:* Validar la seguridad del correo (BIMI, SPF estricto) y, en un entorno autorizado, simular intentos de autenticación contra los portales de login (como el de `jira.corp` o `cloud.mongodb.com`) utilizando el patrón de nombres descubierto en Apollo.

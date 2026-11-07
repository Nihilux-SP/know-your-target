# Informe de Reconocimiento Pasivo — mongodb.com

**Fecha:** 2026-11-07  
**Alcance autorizado:** mongodb.com, *.mongodb.com  
**Excluido:** feedback.mongodb.com, learn.mongodb.com

---

## 1. Registro WHOIS (whois_dominio)

| Campo | Valor |
|---|---|
| **Dominio** | MONGODB.COM |
| **Fecha de alta** | 2008-07-08 |
| **Fecha de caducidad** | 2034-07-08 |
| **Último cambio** | 2026-10-21 |
| **Registrador** | Entity ID 292 |
| **Estado** | client delete/update/transfer prohibited, server delete/update/transfer prohibited |
| **Nameservers** | `NS-1047.AWSDNS-02.ORG`, `NS-1636.AWSDNS-12.CO.UK`, `NS-276.AWSDNS-34.COM`, `NS-868.AWSDNS-44.NET`, `NS-CLOUD-E1.GOOGLEDOMAINS.COM`, `NS-CLOUD-E2.GOOGLEDOMAINS.COM`, `NS-CLOUD-E3.GOOGLEDOMAINS.COM`, `NS-CLOUD-E4.GOOGLEDOMAINS.COM` |

> Observación: Uso de **AWS Route 53** (awsdns) y **Google Domains** (googledomains) como nameservers, sugiriendo una infraestructura DNS híbrida o una transición migratoria.

---

## 2. Registros DNS (dns_registros)

### A
- `15.197.135.80` (AWS — rango Asia-Pacífico)
- `3.33.132.188` (AWS — rango global/CDN)

### AAAA
- Sin registros IPv6 para el dominio raíz.

### MX
| Prioridad | Servidor |
|---|---|
| 10 | `aspmx.l.google.com.` |
| 20 | `alt1.aspmx.l.google.com.` |
| 20 | `alt2.aspmx.l.google.com.` |
| 30 | `aspmx2.googlemail.com.` |
| 30 | `aspmx3.googlemail.com.` |

> Correo gestionado por **Google Workspace / G Suite**.

### NS
- `ns-1047.awsdns-02.org.`
- `ns-1636.awsdns-12.co.uk.`
- `ns-868.awsdns-44.net.`
- `ns-276.awsdns-34.com.`

### CNAME
- Sin registros CNAME para el dominio raíz.

### SOA
- `ns-868.awsdns-44.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400`

### TXT (resumen de verificaciones y herramientas)
Se identificaron **~50 registros TXT**, incluyendo verificaciones de dominio de:

| Servicio | Herramienta identificada |
|---|---|
| Google Sites | `google-site-verification` (múltiples) |
| Stripe | `stripe-verification` (múltiples) |
| Atlassian | `atlassian-domain-verification` |
| Google AI | `gc-ai-domain-verification` |
| OpenAI | `openai-domain-verification` |
| 1Password | `1password-site-verification` |
| Cisco | `cisco-ci-domain-verification` |
| KnowBe4 | `knowbe4-site-verification` |
| Fastly | `fastly-domain-delegation` |
| Mixpanel | `mixpanel-domain-verify` |
| Adobe | `adobe-sign-verification`, `adobe-idp-site-verification` |
| Apple | `apple-domain-verification` |
| Box | `box-domain-verification` |
| Miro | `miro-verification` |
| Jamf | `jamf-site-verification` |
| OneTrust | `onetrust-domain-verification` |
| SmartSheet | `smartsheet-site-validation` |
| MongoDB | `mongodb-site-verification` |
| Warpstream | `warpstream-verification` |
| Cursor | `cursor-domain-verification` |
| DigiCert | `_globalsign-domain-verification` |
| HCP | `hcp-domain-verification` |

> Observación: Gran cantidad de herramientas SaaS integradas, lo que sugiere una infraestructura cloud muy segmentada y con múltiples integraciones.

---

## 3. Subdominios (subdominios_subfinder + subdominios_crtsh)

| Fuente | Subdominios en alcance | Fuera de alcance |
|---|---|---|
| **subfinder** | **7 114** | 2 |
| **crt.sh** | **547** | 1 |

> Ambos excluyeron correctamente `feedback.mongodb.com` y/o `learn.mongodb.com`.

### Patrones y categorización de subdominios destacados:

| Patrón | Ejemplos | Uso inferido |
|---|---|---|
| **`.mongodb.com` (públicos)** | `api.mongodb.com`, `atlas.mongodb.com`, `blog.mongodb.com`, `account.mongodb.com`, `auth.mongodb.com`, `charts.mongodb.com`, `agentengine.mongodb.com`, `agentic-platform.mongodb.com`, `cedar.mongodb.com` | Servicios públicos y API |
| **`.corp.mongodb.com` (interno)** | `admin.corp.mongodb.com`, `artifactory.corp.mongodb.com`, `bitwarden.infosec.mongodb.com`, `alertmanager.corp.mongodb.com`, `buildbaron.corp.mongodb.com` | Infraestructura corporativa |
| **`.prod.corp.mongodb.com`** | `adm.prod.corp.mongodb.com`, `api.prod.corp.mongodb.com`, `cloud-build.prod.corp.mongodb.com` | Entorno productivo interno |
| **`.staging.corp.mongodb.com`** | `adm.staging.corp.mongodb.com`, `cloud-ops.staging.corp.mongodb.com` | Entorno de staging |
| **`.stitch.mongodb.com`** | `aws.stitch.mongodb.com` | MongoDB Stitch (BaaS) |
| **`.realm.mongodb.com`** | `aws.realm.mongodb.com` | MongoDB Realm |
| **`.cf.mongodb.com`** | `cf.mongodb.com` | Custom Functions / Cloud |
| **Geográficos** | `api-backup.ap-southeast-2.mongodb.com`, `api-backup.eu-central-1.mongodb.com`, `api-backup.us-east-1.mongodb.com` | Backups por región AWS |

---

## 4. robots.txt (robots_txt)

- **Estado:** Existe (HTTP 200)
- **Sitemap:** `https://www.mongodb.com/sitemap-index.xml`
- **Directivas clave:**
  - Bloquean el acceso a `/community/forums/` para múltiples bots (mauibot, semrushbot, ahrefsbot, bingbot).
  - Restricciones generales (`*`): bloquean `/admin/*`, `/data/*`, `/user/*` (login, register, password), `/docs/*.epub`, `/docs/*.pdf`, `/search/`, `/tags/*`.
  - Bloquean explícitamente `/.well-known/security.txt` del rastreo.
  - 87 directivas relevantes encontradas.

---

## 5. security.txt (security_txt)

- **Estado:** Existe en `/.well-known/security.txt`
- **Contenido:** No contiene los campos habituales (Contact, Expires, Encryption, Acknowledgments, Policy).

> Esto podría indicar un security.txt mínimo o con formato no estándar. Merece verificación manual.

---

## 6. Shodan InternetDB (shodan_internetdb)

- **Resultado:** La IP `15.197.135.80` (primera IP de mongodb.com) queda **fuera del alcance** de la consulta Shodan InternetDB. No se obtuvieron puertos, CVEs ni tags.

> Esto es consistente con una infraestructura detrás de CDN/Proxy AWS (las IPs de CloudFront/ALB suelen mostrarse como infraestructura compartida, no como la aplicación concreta).

---

## 7. Correos electrónicos (correos_theharvester)

- **Resultado:** 0 correos públicos encontrados para mongodb.com (con límite de 100).

> Posible explicación: los correos corporativos pueden no estar indexados en las fuentes pasivas consultadas por theHarvester, o estar protegidos/ocultos en directorios internos.

---

## Resumen Ejecutivo

| Dimensión | Hallazgo clave |
|---|---|
| **DNS** | Infraestructura en **AWS** (Route 53), correo en **Google Workspace**, sin IPv6 en el dominio raíz. |
| **Superficie de ataque** | **~7 100 subdominios** identificados, con una clara separación entre público (`.mongodb.com`) e interno (`.corp.mongodb.com`). |
| **Aplicaciones públicas destacadas** | Atlas, API, AgentEngine, Agentic Platform, Stitch, Realm, Charts, Cedar, Blog. |
| **Herramientas SaaS integradas** | Más de 20 servicios verificados vía TXT (Stripe, Atlassian, Fastly, Adobe, OpenAI, Mixpanel, KnowBe4, etc.). |
| **Políticas de rastreo** | robots.txt robusto con 87 directivas; bloques de foros y áreas de administración. |
| **Seguridad** | security.txt presente pero vacío; sin CVEs visibles vía Shodan; sin correos públicos fácilmente indexables. |

---

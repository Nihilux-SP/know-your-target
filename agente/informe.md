# Reconocimiento Pasivo — mongodb.com

## 1. Registro del Dominio (WHOIS)

| Campo | Valor |
|-------|-------|
| **Dominio** | MONGODB.COM |
| **Fecha de alta** | 2008-07-08 |
| **Fecha de caducidad** | 2034-07-08 |
| **Último cambio** | 2026-10-21 |
| **Registrador** | Entidad 292 (Google Domains) |
| **Estado** | client delete/transfer/update prohibited, server delete/transfer/update prohibited |
| **Nameservers (WHOIS)** | NS-1047.AWSDNS-02.ORG, NS-1636.AWSDNS-12.CO.UK, NS-276.AWSDNS-34.COM, NS-868.AWSDNS-44.NET, NS-CLOUD-E1/2/3/4.GOOGLEDOMAINS.COM |

*(Fuente: `whois_dominio`)*

> **Nota:** Los nameservers muestran una infraestructura híbrida AWS Route 53 + Google Domains.

---

## 2. Registros DNS

### A (IPv4)
- `3.33.132.188`
- `15.197.135.80`
*(Fuente: `dns_registros` tipo A)*

> Ambas IPs pertenecen a infraestructura de AWS (CloudFront/CDN).

### AAAA (IPv6)
- Sin registros AAAA.
*(Fuente: `dns_registros` tipo AAAA)*

### MX (Correo)
| Prioridad | Servidor |
|-----------|----------|
| 10 | aspmx.l.google.com |
| 20 | alt1.aspmx.l.google.com |
| 20 | alt2.aspmx.l.google.com |
| 30 | aspmx2.googlemail.com |
| 30 | aspmx3.googlemail.com |

*(Fuente: `dns_registros` tipo MX)*

> Correo gestionado completamente por Google Workspace (Gmail para empresas).

### NS (Nameservers DNS)
- `ns-cloud-e1.googledomains.com`
- `ns-cloud-e2.googledomains.com`
- `ns-cloud-e3.googledomains.com`
- `ns-cloud-e4.googledomains.com`
*(Fuente: `dns_registros` tipo NS)*

### SOA
- `ns-868.awsdns-44.net` admin: `awsdns-hostmaster.amazon.com`
- Serial: 1 | Refresh: 7200 | Retry: 900 | Expire: 1209600 | Minimum TTL: 86400
*(Fuente: `dns_registros` tipo SOA)*

### CNAME
- Sin registros CNAME para mongodb.com.
*(Fuente: `dns_registros` tipo CNAME)*

### TXT (selección destacada)
*(Fuente: `dns_registros` tipo TXT)*

- **SPF:** `v=spf1 include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email -all` → correo reenviado vía Vali.email.
- **Google site-verification:** múltiples tokens (varios productos/servicios).
- **Stripe-verification:** 6 tokens distintos → integración extensiva con Stripe.
- **Verificaciones de terceros:** Atlassian, Netlify, Fastly, Docker, Cisco, Box, Adobe, 1Password, OpenAI, Mixpanel, SuccessFactors, Wrike, KnowBe4, SmartSheet, Warpstream, HCP, GC AI.
- **Jamf site-verification:** gestión de dispositivos Apple (MDM).
- **Fastly domain-delegation:** uso de Fastly como CDN adicional.

---

## 3. Subdominios

| Fuente | En alcance | Fuera de alcance |
|--------|-----------|------------------|
| crt.sh | 1 (mongodb.com) | 547 |
| subfinder | 0 | 7 068 |

*(Fuentes: `subdominios_crtsh`, `subdominios_subfinder`)*

> **Nota:** El alcance autorizado solo incluye `mongodb.com` (sin comodín `*.`). Por ello, todos los subdominios descubiertos (`api.mongodb.com`, `docs.mongodb.com`, `atlas.mongodb.com`, etc.) se consideran fuera de alcance y no se incluyen en el análisis.

---

## 4. Robots.txt

- **Estado:** Existe (200).
- **87 directivas relevantes** identificadas.
- **Sitemap:** `https://www.mongodb.com/sitemap-index.xml`
- **Bloqueos notables:**
  - Crawlers SEO externos (mauibot, semrushbot, ahrefsbot, blexbot) bloqueados en `/community/forums/`.
  - `bingbot` bloqueado en `/community/forums/auth/`, `/email/`, `/session/`, `/admin/`, `/user-api-key/`.
  - User-agent `*`: bloquea `/misc/`, `/profiles/`, `/u/`, `/admin/*`, `/data/*`, `/search/`, `/user/*`, `/docs/*.epub`, `/docs/*.pdf`, `/tags/*`, `/taxonomy/term/*`, `/commercialsupport/`, `/docs-qa*`, `/devcenter-uat*`.
  - **Interesante:** `/.well-known/security.txt` está en **Disallow** para todos los crawlers.

*(Fuente: `robots_txt`)*

---

## 5. Security.txt

- **Estado:** Existe en `/.well-known/security.txt`.
- **Contenido:** No contiene los campos habituales de RFC 9116 (Contact, Expires, Encryption, Acknowledgments, Policy).
- **Curiosidad:** Está explícitamente bloqueado en robots.txt (posiblemente para no indexarlo o por privacidad).

*(Fuente: `security_txt`)*

---

## 6. Shodan InternetDB

- La IP `3.33.132.188` (primera resolución A de mongodb.com) se considera **fuera del alcance** (infraestructura CDN/proxy de AWS CloudFront).
- No se obtuvo información de puertos abiertos, CVEs ni tags.

*(Fuente: `shodan_internetdb`)*

---

## 7. Correos Electrónicos Públicos

- theHarvester no encontró correos electrónicos públicos para mongodb.com.
*(Fuente: `correos_theharvester`)*

---

## Resumen Ejecutivo

| Aspecto | Hallazgo |
|---------|----------|
| **Edad del dominio** | ~18 años (registrado en 2008, vence en 2034) |
| **Infraestructura DNS** | Híbrida: Google Domains (NS) + AWS Route 53 (SOA, IP) |
| **CDN/WAF** | AWS CloudFront (IPs 3.33.x.x, 15.197.x.x) + Fastly |
| **Correo** | Google Workspace + reenvío vía Vali.email (SPF) |
| **Subdominios** | Miles descubiertos (7 068 en subfinder), pero fuera del scope autorizado |
| **Seguridad** | security.txt presente pero sin campos; robots.txt bloquea /.well-known/security.txt |
| **Ecosistema SaaS** | Integraciones muy extensas: Stripe (×6), Google, Atlassian, OpenAI, Docker, Netlify, Cisco, Box, Adobe, 1Password, Jamf (MDM), KnowBe4, etc. |
| **Correos públicos** | Ninguno encontrado con fuentes pasivas |

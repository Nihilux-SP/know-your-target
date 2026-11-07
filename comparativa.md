# Análisis comparativo: reconocimiento manual vs. agente

## 3.1 La comparación

### Tabla por tipo de dato

| Dato | Lo encontré yo | Lo encontró el agente | ¿Coincide? | Observaciones |
|---|---|---|---|---|
| **Registrador WhoIs** | **Gandi SAS** (`whois.gandi.net`) | "Entity ID 292" | **Discrepancia** | Mi cuaderno es explícito: Gandi SAS. El agente da un identificador genérico ("Entity ID 292") que **no es el nombre del registrador**. Dato mal extraído por el agente. |
| **Organización registrante** | `10gen inc`, 63-65 boulevard Massena, Paris 75013, FR | No lo menciona | **Omisión del agente** | Mi WhoIs crudo lo trae; el informe del agente no cita la organización. |
| **Fecha de alta** | 8 julio 2008 | 2008-07-08 | **Sí** | Coinciden. |
| **Fecha de caducidad** | **8 julio 2033** | **2034-07-08** | **Discrepancia** | Un año de diferencia. El agente probablemente redondeó o leyó otra fuente. **Comprobar contra `whois` fresco**. |
| **Última actualización** | 14 octubre 2026 | 2026-10-21 | **Discrepancia leve** | Fechas distintas (14 vs 21 oct). Puede ser que el agente consultara más tarde; no es grave, pero no coinciden. |
| **Nameservers** | 8 NS: 4 AWS Route 53 + 4 Google Cloud DNS (`ns-cloud-e1..e4`) | 8 NS: 4 AWS Route 53 + 4 **Google Domains** | **Parcial** | Coinciden en número y en AWS. **Difieren en el nombre**: yo tengo `ns-cloud-e1.googledomains.com` (Google Cloud DNS); el agente dice "Google Domains". Son productos distintos (Cloud DNS vs Domains). El agente **etiqueta mal**. |
| **IPs de nameservers** | Las tengo (205.251.196.23, 216.239.32.110, etc.) | No las lista | **Omisión del agente** | Mi cuaderno resuelve cada NS a IP; el agente solo da hostnames. |
| **Dominios similares (typosquatting)** | **11**: `mongo365.org`, `mongo56.top`, `mongo7105.com`, `mongo777.com/.org`, `mongo789.com`, `mongoapp.cc/.com`, `mongoapps.com`, `mongo-atlas.com`, `mongo-bbq.de` | No reportado | **Omisión del agente** | Dato de mi WhoIs que el agente no cubre. Relevante para phishing. |
| **DNSDumpster** | Usado (`api.dnsdumpster.com/domain/mongodb.com`) con captura | No lo menciona | **Fuente distinta** | Yo usé DNSDumpster como fuente adicional; el agente no. |
| **Subdominios (subfinder)** | **Volcado crudo** de miles de líneas (mars-e2e-*, *.staging.corp, *.prod.corp, realm, stitch, etc.) | **7 114** (subfinder) + **547** (crt.sh) | **Parcial / no auditable en el agente** | Yo aporto el **dump real**; el agente da un **recuento sin lista**. Mi recuento no está cuantificado, pero es **verificable**. El del agente es **más grande pero no auditable**. |
| **Subdominios (crt.sh)** | El cuaderno **no muestra** una consulta explícita a crt.sh | **547** | **No comparable** | Aquí el agente **sí consultó crt.sh** y yo no lo documenté en el cuaderno (corrijo la observación anterior del `mapa.md`). Punto para el agente. |
| **Patrones de subdominios** | `mars-e2e-*`, `*.staging.corp`, `*.prod.corp`, `*.test.corp`, `*.devops.test`, `realm` (aws/gcp/azure), `stitch`, `charts`, `api-agents`, `agentengine`, `atlas-*`, `cloud-*`, `warpstream`, `minos`, `skunkworks`, `industrysolutions`, `maap`, `deet`, `gtm-*` | Categorías: públicos, `.corp`, `.prod.corp`, `.staging.corp`, `.stitch`, `.realm`, `.cf`, geográficos | **Parcial** | Coinciden en las grandes categorías. **El agente no nombra** `mars-e2e-*` (que domina el dump), ni `skunkworks`, `industrysolutions`, `maap`, `deet`, `gtm-*`. Mi dump es más rico en patrones reales. |
| **Huella tecnológica (Netcraft)** | Capturas de sitereport.netcraft.com (11 imágenes) | No las menciona | **Omisión del agente** | Mi cuaderno documenta Netcraft con capturas; el agente no lo cita como fuente. |
| **Servidor web / proxy** | `istio-envoy` (en `mapa.md`, derivado de Netcraft) | No lo menciona | **Omisión del agente** | Sigue siendo un dato mío que el agente no reporta. |
| **CDN** | CloudFront (en `mapa.md`) | AWS/CDN implícito | **Parcial** | Yo nombro CloudFront; el agente no. |
| **robots.txt** | Capturas (`r1.png`, `r2.png`, `r3.png`) | 87 directivas, sitemap, bloqueo de foros | **Parcial** | Coinciden en existencia. El agente cuantifica (87); yo tengo capturas pero no recuento. El agente **añade valor** aquí. |
| **security.txt** | **"No hay archivo security"** (explícito en el cuaderno) | "Existe en `/.well-known/security.txt`, pero sin campos habituales" | **Contradicción directa** | Tú dices que **no existe**; el agente dice que **existe vacío**. Una de las dos observaciones es incorrecta. **Requiere verificación manual** (curl directo). Es el hallazgo más importante de esta comparativa. |
| **Shodan** | Búsqueda `mongo.db` en shodan.io (captura `m.png`) | InternetDB de `15.197.135.80` (sin puertos/CVEs) | **Fuentes distintas** | Tú buscas por **query de Shodan** (`mongo.db`), el agente consulta **InternetDB de una IP concreta**. No son comparables: tú ves servicios MongoDB expuestos; el agente no ve nada porque la IP es CDN. **El agente no replicó tu consulta**. |
| **Google Dorks** | **Sí**: `intitle:"index of" mongo.db` → `repo.mongodb.com/apt/ubuntu/dists/trusty/mongodb-enterprise/` con índice abierto | No reportado | **Omisión del agente** | Hallazgo clave mío que el agente no cubre. |
| **Correos** | Captura `h.png` con correos vinculados a mongodb.com | **0 correos** (theHarvester) | **Discrepancia de fuente** | Tú tienes correos visibles; el agente reporta 0 con theHarvester. No es contradicción de dato, sino **fuente distinta**: el agente no usó la misma fuente que tú. |
| **TXT de verificación SaaS** | No lo inventarié | **~50 TXT**, >20 servicios | **Ventaja clara del agente** | Sigue siendo el mayor valor añadido del agente. |
| **MX / correo** | No lo detallo en el cuaderno (solo correos de personas) | Google Workspace (5 MX) | **Ventaja del agente** | El agente aporta los MX; yo no los documenté. |
| **DMARC/SPF** | No lo documento en el cuaderno | No reportado | **Empate en omisión** | Ninguno de los dos lo cubre en el cuaderno/informe (aunque `mapa.md` sí lo mencionaba). |
| **IPv4 raíz** | No la documento en el cuaderno (sí en `mapa.md`: `3.33.132.188`) | `15.197.135.80` + `3.33.132.188` | **Parcial** | El agente añade una IP; yo tenía una en el mapa. |
| **IPv6 raíz** | No comprobado | "Sin AAAA" | **Ventaja del agente** | El agente lo verifica. |
| **Certificados SSL** | Capturas Netcraft (incluye SSL) | No reportado | **Omisión del agente** | Tengo capturas; el agente no lo extrae. |

### Resumen numérico

| Métrica | Manual (`cuaderno.md` + `mapa.md`) | Agente (`informe.md`) |
|---|---|---|
| **Subdominios** | Volcado crudo (miles de líneas, sin recuento) | **7 661** (7 114 + 547) |
| **Subdominios auditables** | **Sí** (dump completo en `cuaderno.md`) | **No** (solo recuento, sin lista) |
| **Dominios similares (typosquatting)** | **11** | 0 |
| **Nameservers con IP** | 8 (con IP) | 8 (sin IP) |
| **Registros TXT inventariados** | 0 | **~50** (>20 servicios) |
| **MX documentados** | 0 | 5 |
| **Hallazgos Shodan** | Query `mongo.db` con captura | InternetDB de una IP (sin resultado) |
| **Google Dorks** | **1 hallazgo** (`repo.mongodb.com`) | 0 |
| **Correos** | Captura con correos visibles | 0 (theHarvester) |
| **Ficheros expuestos** | robots.txt + security.txt (dice "no hay") | robots.txt + security.txt (dice "existe vacío") |
| **Tiempo empleado** | *No registrado en el cuaderno* — **no inventar** | *No consta en `informe.md`* — **no inventar** |
| **Coste del agente** | — | *No consta* — **no inventar** |

---

## 3.2 Los fallos del agente

### a) Omisión — algo que estaba ahí y no encontró
- **Registrador real (Gandi SAS)**: el agente pone "Entity ID 292" en lugar de "Gandi SAS". El dato estaba en el WhoIs que él mismo consultó.
- **Organización `10gen inc` y dirección en París**: no aparece en el informe.
- **11 dominios similares (typosquatting)**: `mongo365.org`, `mongo777.com`, etc. El agente no los reporta, pese a ser dato WhoIs pasivo.
- **Google Dorks / `repo.mongodb.com`**: no reportado. El agente no ejecutó dorks.
- **Shodan query `mongo.db`**: el agente solo consultó InternetDB de una IP; **no replicó** la búsqueda por query que tú sí hiciste.
- **Servidor `istio-envoy`, CloudFront, SSL**: presentes en tu Netcraft; ausentes en el informe.
- **Patrones de subdominios** `mars-e2e-*`, `skunkworks`, `industrysolutions`, `maap`, `deet`, `gtm-*`: el agente categoriza por grandes bloques pero **no nombra** estos patrones que dominan tu dump.

### b) Error — dato mal interpretado
- **"Entity ID 292" como registrador**: es un identificador, **no el nombre** del registrador. El registrador es **Gandi SAS**. Error de extracción.
- **"Google Domains" en lugar de "Google Cloud DNS"**: los NS `ns-cloud-e1..e4.googledomains.com` son de **Google Cloud DNS**, no de Google Domains (producto distinto). El agente **etiqueta mal** el proveedor.
- **Fecha de caducidad 2034 vs 2033**: el agente da un año de más. Dato mal leído o redondeado.
- **"Asia-Pacífico" para `15.197.135.80`**: es un rango **anycast** de AWS Global Accelerator; **no tiene geografía única**. Sobreinterpretación.
- **"Sin CVEs visibles"** tras consultar InternetDB de una IP de CDN: el lector puede interpretar "mongodb.com no tiene CVEs", lo cual es **falso**; solo significa que esa IP compartida no expone nada en InternetDB.

### c) Invención (alucinación) — afirma sin respaldo de herramienta
- **No detecto una invención flagrante** en `informe.md`: el documento marca "Observación" cuando infiere (p. ej. "sugiriendo una infraestructura DNS híbrida"). Eso es **inferencia declarada**, no alucinación.
- **Riesgo latente**: "Gran cantidad de herramientas SaaS integradas, lo que sugiere una infraestructura cloud muy segmentada". Los TXT prueban **verificación de dominio**, no necesariamente "segmentación". Es **sobreafirmación** que conviene marcar como hipótesis.
- **El caso security.txt**: el agente afirma que **existe** en `/.well-known/security.txt` "pero sin campos habituales", mientras tu cuaderno dice **"No hay archivo security"**. Si tu comprobación manual es correcta, el agente **inventó la existencia del fichero** (o lo confundió con otra ruta). **Este es el punto que hay que verificar primero** con un `curl` directo.

### d) Intento fuera de alcance — bloqueado por scope-guard
- El `informe.md` declara que subfinder y crt.sh **excluyeron correctamente** `feedback.mongodb.com` y `learn.mongodb.com`. **El scope-guard funcionó**.
- **No hay evidencia en el informe** de un intento fuera de alcance que el guard tuviera que bloquear (no menciona dominios de terceros ni `mongo365.org`). Sin traza, **no lo afirmo**.

---

## 3.3 Reflexión

**¿Qué hizo mejor el agente que yo?**
El agente **escaló el volumen y la sistematicidad**: **7 661 subdominios** (subfinder + crt.sh), **~50 TXT** con **>20 servicios SaaS** (Stripe, OpenAI, Atlassian, Fastly, 1Password…), **5 MX** de Google Workspace, verificación de **AAAA**, y **87 directivas de robots.txt**. En el cuaderno yo tengo el dump de subfinder pero **no lo cuantifiqué ni lo categoricé**; el agente lo hizo. Además, **sí consultó crt.sh** (547), algo que yo no documenté. En cobertura DNS/TXT y en disciplina de recuento, el agente es superior.

**¿Qué hice mejor yo?**
Aporté **evidencia auditable y profundidad cualitativa**. Mi `cuaderno.md` tiene el **dump crudo de subfinder** (reproducible), el **WhoIs completo con Gandi SAS, `10gen inc`, dirección en París y 11 dominios similares**, la **query Shodan `mongo.db`** con captura, el **hallazgo de Google Dorks en `repo.mongodb.com/apt/ubuntu/dists/trusty/mongodb-enterprise/`**, **capturas Netcraft** (11 imágenes) y **correos visibles**. El agente, en cambio, da **recuentos sin lista** (no auditables), **mal etiqueta** el registrador y el proveedor DNS, y **omite** dorks, typosquatting y Shodan por query. Mi evidencia permite **reproducir y verificar**; la suya, en gran parte, no.

**¿Por qué falló donde falló?**
Por **tres causas distintas**:
1. **Fuentes incompletas**: el agente no ejecutó **Google Dorks**, no consultó **Shodan por query** (`mongo.db`), no usó **DNSDumpster** ni **Netcraft** como yo, y no cruzó con la fuente de correos que tú usaste. No es fallo de razonamiento: es **cobertura de fuentes**.
2. **Errores de extracción/etiquetado**: "Entity ID 292" por Gandi SAS, "Google Domains" por Google Cloud DNS, 2034 por 2033, "Asia-Pacífico" para una IP anycast. Son **errores de lectura** de salidas que la herramienta sí devolvió.
3. **Sobreinterpretación**: "sin CVEs" sobre una IP de CDN y "cloud muy segmentada" a partir de TXT de verificación. El modelo convierte **ausencia de dato** en **conclusión**.

**¿Me fiaría del informe del agente sin revisarlo? ¿Qué comprobaría siempre?**
**No me fiaría a ciegas**, y este caso lo demuestra con un ejemplo perfecto: **el agente dice que `security.txt` existe vacío; mi cuaderno dice que no existe**. Una de las dos es falsa, y **sin `curl` manual no lo sabes**. Comprobaría siempre:
1. **El security.txt** con `curl -i https://www.mongodb.com/.well-known/security.txt` — es la contradicción más grave.
2. **El registrador y las fechas** con `whois mongodb.com` fresco (Gandi vs "Entity ID 292"; 2033 vs 2034).
3. **Un muestreo de 20-30 subdominios** del recuento de 7 661 contra `dig`/`crt.sh`, porque **no hay dump** y podría incluir falsos positivos o fuera de alcance.
4. **Cada inferencia geográfica/seguridad**: "Asia-Pacífico" (anycast ≠ geografía), "sin CVEs" (InternetDB de CDN ≠ postura del objetivo).
5. **Los ceros**: "0 correos" con theHarvester no significa "no hay correos"; significa "esa fuente no los indexó". Tu captura de correos lo demuestra.

**Regla práctica que me llevo:** usar el agente como **generador de inventario** (subdominios, TXT, MX, robots) y reservar para revisión humana la **validación** (security.txt, WhoIs, Shodan por query, Dorks, typosquatting, correos) y el **contexto** (Envoy, CloudFront, SSL). El informe del agente es un **buen punto de partida**, no un entregable final: **siempre volcar, muestrear y contrastar las inferencias**. Y, sobre todo, **exigir el dump crudo**: un recuento sin lista no es evidencia.

# Análisis comparativo: reconocimiento manual vs. agente

## 3.1 La comparación

### Tabla por tipo de dato

| Dato | mapa.md | informe.md | ¿Coincide? | Observaciones |
|---|---|---|---|---|
| **Subdominios en alcance** | Muestra cualitativa (~15 nombrados: `cloud`, `repo`, `account-qa/staging`, `login.corp`, `jira-staging.corp`, `api-backup.*`, `agentic-platform-staging`) | **7 114** (subfinder) + **547** (crt.sh) | **Parcial** | El agente cuantifica mucho más y **sí consultó crt.sh** (547). Yo solo aporté ejemplos ilustrativos, no un recuento. El agente gana en cobertura; yo aporté contexto de uso por subdominio. |
| **Nameservers** | AWS Route 53 + Google Cloud DNS (citando `ns-cloud-e1` y `ns-1047`) | AWS Route 53 (4 NS) + Google Domains (4 NS) | **Sí** | Coincidencia total. El agente lista los 8 NS completos; yo solo cité 3. |
| **Servidor de correo** | Google (Vali Mail en SPF) — *según `mapa.md`* | **Google Workspace** (MX `aspmx.l.google.com`, etc.) | **Discrepancia real** | **Aquí el dato de ejemplo "Microsoft 365" no aplica**: mi mapa dice Vali Mail/Google y el agente confirma Google Workspace vía MX. Coinciden en el proveedor (Google); difieren en el matiz SPF (Vali Mail) que el agente **no reporta**. |
| **IPv4 raíz** | `3.33.132.188` (AWS Global Accelerator) | `15.197.135.80` + `3.33.132.188` | **Parcial** | El agente encuentra una IP más (`15.197.135.80`); yo solo tenía una. Coinciden en `3.33.132.188`. |
| **IPv6 raíz** | No reportado | "Sin registros AAAA" | **Complementario** | El agente lo verifica explícitamente; yo no lo comprobé. |
| **Servidor web / proxy** | `istio-envoy` | No lo menciona (solo deduce CDN AWS) | **Omisión del agente** | Yo identifiqué Envoy/Istio; el agente no lo reporta en `informe.md`. |
| **Certificados SSL** | Let's Encrypt, TLS 1.3, `TLS_AES_256_GCM_SHA384` | No reportado | **Omisión del agente** | Dato de Netcraft presente en mi mapa, ausente en el informe. |
| **DMARC / SPF** | `p=reject`, `_spf.vali.email`, reportes forenses | No reportado | **Omisión del agente** | El agente no consultó cabeceras DNS de correo (TXT/DMARC). |
| **TXT de verificación SaaS** | No lo inventarié | **~50 TXT**, >20 servicios (Stripe, Atlassian, OpenAI, etc.) | **Ventaja clara del agente** | Yo no hice este inventario; el agente lo aporta con detalle y es valioso para inferir el stack SaaS. |
| **robots.txt** | Rutas `/admin/`, `/devcenter-uat*`, `/docs-qa*`, `security.txt` | 87 directivas, sitemap, bloqueo de foros y `/.well-known/security.txt` | **Parcial** | Coinciden en la existencia y en rutas admin; el agente cuantifica (87) y añade el sitemap. Yo cité rutas `devcenter-uat`/`docs-qa` que el agente **no menciona**. |
| **security.txt** | Presente | Presente pero **sin campos estándar** | **Parcial** | El agente aporta el matiz de "vacío/no estándar", que yo no verifiqué. |
| **Shodan / IPs de terceros** | MongoDB 27017 en Hetzner (Finlandia, `135.181.175.223`) | IP `15.197.135.80` "fuera de alcance" de InternetDB; sin puertos/CVEs | **Discrepancia** | Yo reporté un hallazgo Shodan concreto (Hetzner); el agente solo dice que su consulta no devolvió nada. **No coinciden**: o son fuentes distintas o el agente no replicó mi consulta. |
| **Correos / empleados** | Patrón `nombre.apellido@`, 4 162 empleados (Apollo), cargos | **0 correos** (theHarvester) | **Discrepancia** | Yo usé Apollo (directorio); el agente usó theHarvester (pasivo). No es contradicción de dato, sino **distinta fuente**: el agente no consultó Apollo. |
| **WhoIs / registrador** | `10gen inc`, París; contactos redactados | Entity ID 292, fechas, estados, 8 NS | **Complementario** | Coinciden en organización; el agente aporta fechas y estados que yo no detallé. |
| **Typosquatting** | `mongo365.org`, `mongo777.com` (fuera de alcance) | No reportado | **Omisión del agente** | Dato de mi mapa ausente en el informe. |
| **Repositorio APT** | `repo.mongodb.com` con índice abierto (Google Dorks) | No reportado | **Omisión del agente** | Hallazgo clave de mi mapa que el agente no cubre (no usó Google Dorks). |
| **CDN** | Amazon CloudFront | AWS (implícito en rangos) | **Parcial** | Yo nombro CloudFront; el agente solo dice "AWS/CDN". |

### Resumen numérico

| Métrica | Manual (`mapa.md`) | Agente (`informe.md`) |
|---|---|---|
| **Subdominios cuantificados** | ~15 nombrados (sin recuento) | **7 661** (7 114 + 547) |
| **Registros TXT inventariados** | 0 | **~50** (>20 servicios) |
| **IPs raíz** | 1 | 2 |
| **Nameservers listados** | 3 | 8 |
| **Fuentes/herramientas citadas** | Netcraft, Subfinder, Shodan, Google Dorks, Apollo, WhoIs | WhoIs, DNS, subfinder, crt.sh, robots.txt, security.txt, Shodan InternetDB, theHarvester |
| **Tiempo empleado** | *No registrado en `mapa.md`* — **no puedo afirmar una cifra sin inventarla** | *No consta en `informe.md`* — **tampoco verificable** |
| **Coste del agente** | — | *No consta en `informe.md`* — **no inventar** |

> **Honestidad metodológica:** el enunciado pide "cuánto tardó y cuánto costó". Ninguno de los dos artefactos contiene esos metadatos. **No los relleno con números inventados**; si se dispone de la traza del agente (logs con timestamps y tokens), deberían añadirse aquí. Lo dejo como *pendiente de instrumentación*.

**Balance rápido:** el agente **gana en volumen y en cobertura DNS/TXT** (miles de subdominios, ~50 TXT, crt.sh incluido). Yo **gané en profundidad cualitativa**: identifiqué Envoy/Istio, CloudFront, DMARC/SPF, el repo APT abierto, Shodan en Hetzner, typosquatting y el patrón de correos con Apollo. Son **perfiles complementarios**, no uno mejor que otro en todo.

---

## 3.2 Los fallos del agente

> Clasifico según la tipología pedida. **No tengo la traza del agente**, así que los ejemplos se anclan en lo que **el propio `informe.md` declara** (secciones y afirmaciones), no en logs que no veo.

### a) Omisión — algo que estaba ahí y no encontró
- **Servidor web `istio-envoy`**: mi mapa lo identifica vía Netcraft SSL; el `informe.md` **no lo menciona** en ninguna sección. Estaba disponible con la misma técnica (SSL/Network).
- **DMARC/SPF**: el agente consultó MX y TXT de verificación, pero **no reporta** `p=reject`, `_spf.vali.email` ni los reportes forenses. La consulta DNS ya la tenía hecha; faltó parsear los TXT de correo.
- **`repo.mongodb.com` (índice APT abierto)**: no aparece. Requería Google Dorks, que el agente **no ejecutó** (su lista de fuentes no incluye dorks).
- **Typosquatting (`mongo365.org`, `mongo777.com`)**: no reportado, pese a ser dato WhoIs/pasivo.
- **Rutas `devcenter-uat*` y `docs-qa*`** en robots.txt: el agente cuenta 87 directivas pero **no cita estas rutas**, que yo sí extraje.

### b) Error — dato mal interpretado
- **Atribución geográfica de IPs**: el informe etiqueta `15.197.135.80` como "AWS — rango Asia-Pacífico" y `3.33.132.188` como "rango global/CDN". Son rangos de **AWS Global Accelerator**, que son *anycast*: **no tienen una geografía única**. Afirmar "Asia-Pacífico" es una **sobreinterpretación** del rango, no un dato devuelto por la herramienta.
- **Shodan InternetDB**: el agente concluye "sin CVEs visibles" para `15.197.135.80`. Eso **no es un hallazgo del objetivo**, es una IP de CDN/anycast; el propio informe lo reconoce ("infraestructura compartida"). El riesgo es que un lector lo lea como "mongodb.com no tiene CVEs", lo cual **es un error de interpretación** del alcance de la consulta.

### c) Invención (alucinación) — afirma sin respaldo de herramienta
- No detecto una invención **flagrante** en `informe.md`: el documento es bastante disciplinado y marca "Observación" cuando infiere (p. ej. "sugiriendo una infraestructura DNS híbrida o una transición migratoria"). Esa frase es **inferencia declarada**, no alucinación.
- **Riesgo latente**: la frase "Gran cantidad de herramientas SaaS integradas, lo que sugiere una infraestructura cloud muy segmentada" es una **conclusión sin evidencia directa** (los TXT prueban verificación de dominio, no necesariamente "segmentación"). No es invención de un dato, pero es **sobreafirmación** que conviene marcar como hipótesis.
- **No puedo confirmar** si en la traza el agente "inventó" un subdominio o una IP, porque el `informe.md` no incluye la lista cruda de 7 114/547. **Ese es precisamente el punto ciego**: sin volcado, no auditable.

### d) Intento fuera de alcance — bloqueado por scope-guard
- El `informe.md` declara que subfinder y crt.sh **excluyeron correctamente** `feedback.mongodb.com` y `learn.mongodb.com` ("Ambos excluyeron correctamente..."). Eso sugiere que **el scope-guard funcionó** y el agente **no** intentó tocarlos (o si lo intentó, fue bloqueado y no lo reporta como hallazgo).
- **No hay evidencia en el informe** de un intento fuera de alcance que el guard tuviera que bloquear (p. ej., no menciona haber consultado dominios de terceros ni `mongo365.org`). Si la traza mostrara un intento a `feedback.mongodb.com`, sería el ejemplo a citar; **sin traza, no lo afirmo**.

---

## 3.3 Reflexión

**¿Qué hizo mejor el agente que yo?**
El agente **escaló el volumen y la sistematicidad**. Donde yo di ~15 subdominios de ejemplo, él devolvió **7 661** con dos fuentes (subfinder + crt.sh) y, sobre todo, **inventarió ~50 TXT y >20 servicios SaaS** (Stripe, OpenAI, Atlassian, Fastly, 1Password…). Ese inventario es **exactamente el tipo de dato que a mí se me escapa** por hacer reconocimiento "a ojo": yo no habría enumerado 50 TXT a mano. También fue más disciplinado en **cuantificar robots.txt (87 directivas)** y en **verificar la ausencia de AAAA**. En cobertura DNS/TXT, el agente es claramente superior.

**¿Qué hice mejor yo?**
Aporté **profundidad cualitativa y contexto de explotación**. Identifiqué el **servidor `istio-envoy`**, el **CDN CloudFront**, la **política DMARC `p=reject` con Vali Mail**, el **repo APT con índice abierto** (`repo.mongodb.com`) vía Google Dorks, el **Shodan en Hetzner (`135.181.175.223`, puerto 27017)** y el **typosquatting** (`mongo365.org`). Son hallazgos que **apuntan a vectores concretos** (repo legacy, staging, spear-phishing) y que el agente **no cubrió** porque **no usó Dorks, ni Apollo, ni parseó SPF/DMARC**. Mi mapa conecta el dato con la **acción de Fase Activa**; el informe del agente se queda más en el inventario.

**¿Por qué falló donde falló?**
Por **tres causas distintas**, y conviene no mezclarlas:
1. **Faltaban herramientas/fuentes**: el agente no ejecutó **Google Dorks** (por eso no vio `repo.mongodb.com`), no consultó **Apollo** (por eso 0 correos frente a mis 4 162) y no parseó **DMARC/SPF** aunque tenía los TXT. No es un fallo de razonamiento: es **cobertura de fuentes incompleta**.
2. **Sobreinterpretación de salidas**: el "Asia-Pacífico" de una IP anycast y el "sin CVEs" sobre una IP de CDN son **errores de lectura**, no de herramienta. El modelo tomó el rango/ausencia de datos como conclusión geográfica/seguridad.
3. **El prompt/scope no pidió explícitamente** el cruce con Dorks, Apollo o cabeceras de correo; el agente hizo **lo que se le pidió** (DNS, subdominios, robots, security.txt, Shodan, theHarvester) y **omitió lo que no estaba en su lista**. Aquí el fallo es **de diseño del prompt**, no del modelo.

**¿Me fiaría del informe sin revisarlo? ¿Qué comprobaría siempre?**
**No me fiaría a ciegas**, por tres razones concretas de este caso:
- **Los números no son auditables**: "7 114 subdominios" y "~50 TXT" vienen **sin volcado**. Un recuento sin lista es **no verificable**; podría incluir falsos positivos o fuera de alcance. **Siempre pediría el dump crudo** y muestrearía 20-30 entradas contra `dig`/`crt.sh`.
- **Las inferencias se leen como hechos**: "Asia-Pacífico", "cloud muy segmentada", "sin CVEs". **Comprobaría cada afirmación geográfica/seguridad** contra la fuente (anycast ≠ geografía; InternetDB de una IP CDN ≠ postura del objetivo).
- **Los ceros son sospechosos**: "0 correos" con theHarvester no significa "no hay correos"; significa "esa fuente no los indexó". **Cruzaría con Apollo/LinkedIn** antes de concluir nada.

**Regla práctica que me llevo:** usar el agente como **generador de inventario** (subdominios, TXT, robots) y reservar la **validación y el contexto** (Envoy, DMARC, Dorks, Shodan real, typosquatting) para revisión humana. El informe del agente es un **buen punto de partida**, no un entregable final: **siempre volcar, muestrear y contrastar las inferencias**.

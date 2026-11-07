"""Herramientas iniciales de reconocimiento. AQUÍ PUEDES AÑADIR LAS TUYAS.

WHOIS (whois.py), DNS y crt.sh ya están implementadas y activas en lanzar.py.
DNS y crt.sh proceden de la solución del profesor (herramientas/recon.py).

Para ampliar: una tarea por función, @protegida, sin shell, con timeout,
salida recortada, errores como texto y resultados filtrados por el alcance.
Importa tu nueva función en lanzar.py y añádela a HERRAMIENTAS.

Ideas: subdominios_subfinder, wayback_urls, correos (theHarvester / hunter.io),
infraestructura_ip, correo_postura (SPF/DMARC/MTA-STS/CAA), urlscan, shodan_host.
"""

import json
import os
import subprocess
import urllib.parse
import urllib.request

from alcance import cargar, en_alcance
from guard import protegida, filtrar
from whois import recortar

UA = "aap-recon/1.0 (educativo; IES Rafael Alberti)"
TIPOS_DNS = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}


def _http(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Utilidades locales (no salen a Internet, no tocan el objetivo)
# ---------------------------------------------------------------------------

@protegida(objetivo="ruta_scope")
def scope_resumen(ruta_scope: str = "scope.txt") -> str:
    """Devuelve un resumen legible del alcance autorizado (scope.txt).

    No consulta Internet ni el objetivo: solo parsea el fichero de alcance.
    Útil para que el agente planifique sin malgastar pasos, y para que el
    informe deje constancia de qué estaba autorizado y qué no.

    - `ruta_scope` es la ruta al fichero de alcance (por defecto "scope.txt").
    - La ruta se valida: debe ser relativa, sin '..', y existir.
    """
    if os.path.isabs(ruta_scope) or ".." in ruta_scope.split(os.sep):
        return "ERROR: ruta_scope debe ser relativa y no contener '..'."

    if not os.path.isfile(ruta_scope):
        return f"ERROR: no existe el fichero de alcance '{ruta_scope}'."

    try:
        with open(ruta_scope, "r", encoding="utf-8") as f:
            lineas = f.readlines()
    except OSError as e:
        return recortar(f"ERROR: no se pudo leer '{ruta_scope}': {e}")

    dentro, fuera = [], []
    for linea in lineas:
        limpia = linea.split("#", 1)[0].strip()
        if not limpia:
            continue
        if limpia.startswith("!"):
            fuera.append(limpia[1:].strip())
        else:
            dentro.append(limpia)

    if not dentro:
        return (f"ERROR: '{ruta_scope}' no tiene entradas 'in scope'. "
                "Añade al menos un dominio o rango antes de lanzar el agente.")

    avisos = []
    scope_cargado = cargar(ruta_scope)
    for d in dentro:
        if not en_alcance(d, scope_cargado):
            avisos.append(f"  - '{d}' no entra en su propio alcance (revisa el patrón)")

    lineas_out = [
        f"Alcance autorizado leído de '{ruta_scope}':",
        f"  in scope  ({len(dentro)}):",
    ]
    lineas_out += [f"    + {d}" for d in dentro]
    lineas_out.append(f"  out of scope / exclusiones ({len(fuera)}):")
    lineas_out += [f"    - {x}" for x in fuera] if fuera else ["    (ninguna)"]

    if avisos:
        lineas_out.append("Avisos de coherencia del propio scope.txt:")
        lineas_out += avisos
    else:
        lineas_out.append("Coherencia interna: OK (todas las entradas se respetan).")

    lineas_out.append(
        "Recordatorio: cualquier consulta a un dominio fuera de esta lista "
        "será BLOQUEADA por el scope-guard y quedará en la traza."
    )
    return recortar("\n".join(lineas_out))


# ---------------------------------------------------------------------------
# Reconocimiento pasivo contra el objetivo (protegido por el scope-guard)
# ---------------------------------------------------------------------------

@protegida(objetivo="dominio")
def dns_registros(dominio: str, tipo: str = "A") -> str:
    """Consulta registros DNS de un dominio. tipo: A, AAAA, MX, NS, TXT, CNAME o SOA.
    Devuelve los valores, uno por línea."""
    tipo = tipo.upper()
    if tipo not in TIPOS_DNS:
        return f"ERROR: tipo DNS no válido ({tipo}). Usa uno de: {', '.join(sorted(TIPOS_DNS))}."
    try:
        r = subprocess.run(["dig", "+short", tipo, dominio],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return "ERROR: dig no respondió en 20 segundos."
    except OSError as e:
        return recortar(f"ERROR: no se pudo ejecutar dig: {e}")
    if r.returncode != 0:
        return recortar(f"ERROR: dig falló ({r.returncode}): {r.stderr.strip() or 'sin detalles'}")
    salida = recortar(r.stdout.strip())
    return salida or f"Sin registros {tipo} para {dominio}."


@protegida(objetivo="dominio")
def subdominios_crtsh(dominio: str) -> str:
    """Enumera subdominios de un dominio por transparencia de certificados (crt.sh).
    Pasivo: no toca el objetivo. Devuelve solo los subdominios dentro del alcance."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dominio)}&output=json"
    try:
        datos = json.loads(_http(url, timeout=90))
    except Exception as e:
        return (f"ERROR: crt.sh no respondió ({e}). crt.sh suele ir lento; "
                "puedes reintentar más tarde o añadir otra fuente de subdominios.")
    if not isinstance(datos, list) or any(
        not isinstance(fila, dict) or not isinstance(fila.get("name_value"), str)
        for fila in datos
    ):
        return "ERROR: crt.sh devolvió un formato de certificados inesperado."
    nombres = set()
    for fila in datos:
        for n in str(fila.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n:
                nombres.add(n)
    dentro, fuera = filtrar(sorted(nombres))
    cab = f"{len(dentro)} subdominios en alcance ({fuera} filtrados por estar fuera):\n"
    return recortar(cab + "\n".join(dentro))


@protegida(objetivo="dominio")
def subdominios_subfinder(dominio: str, timeout: int = 120) -> str:
    """Enumera subdominios de un dominio con subfinder (fuentes pasivas).

    No toca el objetivo: subfinder consulta fuentes públicas. Devuelve solo
    los subdominios dentro del alcance; el resto se cuenta como filtrado.

    - `dominio`: dominio raíz autorizado (p. ej. "empresa.com").
    - `timeout`: segundos máximos de ejecución.
    """
    try:
        r = subprocess.run(
            ["subfinder", "-d", dominio, "-silent", "-all"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"ERROR: subfinder no terminó en {timeout} segundos."
    except FileNotFoundError:
        return ("ERROR: subfinder no está instalado en este Kali. "
                "Instálalo con: sudo apt install subfinder")
    except OSError as e:
        return recortar(f"ERROR: no se pudo ejecutar subfinder: {e}")

    if r.returncode != 0:
        detalle = (r.stderr or "").strip() or "sin detalles"
        return recortar(f"ERROR: subfinder falló ({r.returncode}): {detalle}")

    nombres = {
        linea.strip().lower()
        for linea in r.stdout.splitlines()
        if linea.strip()
    }
    if not nombres:
        return f"Sin subdominios para {dominio} (subfinder no devolvió resultados)."

    dentro, fuera = filtrar(sorted(nombres))
    if not dentro:
        return (
            f"subfinder devolvió {len(nombres)} subdominios, pero ninguno entra "
            f"en el alcance ({fuera} filtrados). Revisa scope.txt."
        )

    cab = (f"{len(dentro)} subdominios en alcance ({fuera} filtrados por estar "
           f"fuera), vía subfinder:\n")
    return recortar(cab + "\n".join(dentro))


@protegida(objetivo="dominio")
def robots_txt(dominio: str) -> str:
    """Obtiene y resume el robots.txt de un dominio.

    Consulta https://<dominio>/robots.txt y devuelve:
    - si existe (200) o no (404 u otro),
    - las directivas User-agent / Disallow / Allow / Sitemap / Crawl-delay
      que encuentre, recortadas.

    Es una petición HTTP GET ligera y pasiva (no escanea puertos ni fuerza rutas).
    """
    url = f"https://{dominio}/robots.txt"
    try:
        texto = _http(url, timeout=15)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"No hay robots.txt en {dominio} (HTTP 404)."
        return f"ERROR: robots.txt devolvió HTTP {e.code} para {dominio}."
    except Exception as e:
        return recortar(f"ERROR: no se pudo obtener robots.txt de {dominio}: {e}")

    # Nos quedamos solo con las directivas que interesan a un recon pasivo.
    interesantes = ("user-agent", "disallow", "allow", "sitemap", "crawl-delay")
    lineas = []
    for linea in texto.splitlines():
        limpia = linea.strip()
        if not limpia or limpia.startswith("#"):
            continue
        clave = limpia.split(":", 1)[0].strip().lower()
        if clave in interesantes:
            lineas.append(limpia)

    if not lineas:
        return f"robots.txt de {dominio} existe pero no tiene directivas relevantes."

    return recortar(
        f"robots.txt de {dominio} ({len(lineas)} directivas relevantes):\n"
        + "\n".join(lineas)
    )


@protegida(objetivo="dominio")
def security_txt(dominio: str) -> str:
    """Busca y resume el security.txt de un dominio (RFC 9116).

    Prueba primero la ruta estándar /.well-known/security.txt y, si no
    responde, la ruta heredada /security.txt. Devuelve los campos
    Contact, Expires, Encryption, Acknowledgments y Policy si existen.

    Es una petición HTTP GET ligera y pasiva.
    """
    rutas = [
        f"https://{dominio}/.well-known/security.txt",
        f"https://{dominio}/security.txt",
    ]
    encontrado = None
    for url in rutas:
        try:
            encontrado = _http(url, timeout=15)
            if encontrado.strip():
                break
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue

    if not encontrado or not encontrado.strip():
        return f"No se encontró security.txt en {dominio} (ni .well-known ni raíz)."

    # Campos habituales de un security.txt.
    campos = ("contact", "expires", "encryption", "acknowledgments",
              "policy", "preferred-languages", "canonical")
    lineas = []
    for linea in encontrado.splitlines():
        limpia = linea.strip()
        if not limpia or limpia.startswith("#"):
            continue
        clave = limpia.split(":", 1)[0].strip().lower()
        if clave in campos:
            lineas.append(limpia)

    if not lineas:
        return (f"security.txt de {dominio} existe pero no contiene los campos "
                "habituales (Contact, Expires, etc.).")

    return recortar(
        f"security.txt de {dominio} ({len(lineas)} campos):\n" + "\n".join(lineas)
    )


@protegida(objetivo="dominio")
def shodan_internetdb(dominio: str) -> str:
    """Consulta la API gratuita Shodan InternetDB para el dominio dado.

    InternetDB solo acepta IPs, así que primero se resuelve el dominio con
    `dig +short A` y se consulta la primera IP obtenida. Devuelve puertos
    abiertos, hostnames, CVEs y tags que Shodan tenga indexados para esa IP.

    Limitaciones importantes (leer antes de usar):
    - Es una foto fija, no tiempo real: los datos pueden tener días o semanas.
    - Las IPs detrás de CDN/proxy (Cloudflare, Akamai…) muestran la
      infraestructura del proxy, no la del sitio concreto.
    - No todas las IPs tienen registro en InternetDB.
    - Los CVEs son heurísticos (banner matching); no confirma explotación.

    No requiere clave de API. Es pasivo: no toca el objetivo.
    """
    # 1) Resolver dominio -> IP.
    try:
        r = subprocess.run(["dig", "+short", "A", dominio],
                           capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError) as e:
        return recortar(f"ERROR: no se pudo resolver {dominio} a IP: {e}")

    ips = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    if not ips:
        return f"No se pudo resolver {dominio} a una IP A para consultar InternetDB."

    ip = ips[0]
    if not en_alcance(ip, cargar("scope.txt")):
        # La IP resuelta puede caer fuera del scope (p. ej. CDN). No la consultamos.
        return (f"La IP {ip} (resuelta de {dominio}) queda fuera del alcance; "
                "no se consulta InternetDB para evitar tocar infraestructura no autorizada.")

    # 2) Consultar InternetDB.
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
    try:
        datos = json.loads(_http(url, timeout=20))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return f"InternetDB no tiene datos para {ip} (resuelta de {dominio})."
        return f"ERROR: InternetDB devolvió HTTP {e.code} para {ip}."
    except Exception as e:
        return recortar(f"ERROR: no se pudo consultar InternetDB para {ip}: {e}")

    if not isinstance(datos, dict):
        return f"ERROR: InternetDB devolvió un formato inesperado para {ip}."

    lineas = [f"Shodan InternetDB para {dominio} (IP {ip}):"]
    if datos.get("ports"):
        lineas.append(f"  Puertos abiertos: {', '.join(str(p) for p in datos['ports'])}")
    if datos.get("hostnames"):
        lineas.append(f"  Hostnames: {', '.join(datos['hostnames'])}")
    if datos.get("vulns"):
        lineas.append(f"  CVEs (heurísticos): {', '.join(datos['vulns'])}")
    if datos.get("tags"):
        lineas.append(f"  Tags: {', '.join(datos['tags'])}")
    if not any(k in datos for k in ("ports", "hostnames", "vulns", "tags")):
        lineas.append("  Sin datos útiles en la respuesta.")

    lineas.append(
        "  Nota: datos de snapshot (no tiempo real); CVEs heurísticos; "
        "IPs de CDN reflejan el proxy, no el sitio."
    )
    return recortar("\n".join(lineas))


@protegida(objetivo="dominio")
def correos_theharvester(dominio: str, limite: int = 100, timeout: int = 120) -> str:
    """Busca correos electrónicos públicos de un dominio con theHarvester.

    Usa fuentes pasivas de motores de búsqueda (duckduckgo por defecto, sin
    necesidad de API key). Devuelve los correos encontrados, uno por línea,
    y el total. No publica listas completas: si hay muchos, se recortan.

    - `limite`: máximo de resultados a pedir a la fuente (default 100).
    - `timeout`: segundos máximos de ejecución.

    theHarvester también puede enumerar subdominios, pero aquí se usa solo
    para correos (salida filtrada por '@'). Para subdominios ya tienes
    subfinder y crt.sh.
    """
    try:
        r = subprocess.run(
            ["theHarvester", "-d", dominio, "-b", "duckduckgo",
             "-l", str(limite), "-f", "/dev/stdout"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return f"ERROR: theHarvester no terminó en {timeout} segundos."
    except FileNotFoundError:
        return ("ERROR: theHarvester no está instalado en este Kali. "
                "Instálalo con: sudo apt install theharvester")
    except OSError as e:
        return recortar(f"ERROR: no se pudo ejecutar theHarvester: {e}")

    if r.returncode != 0:
        detalle = (r.stderr or "").strip() or "sin detalles"
        return recortar(f"ERROR: theHarvester falló ({r.returncode}): {detalle}")

    # Extraemos correos con un filtro simple: token con '@' y dominio.
    import re
    patron = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    correos = set()
    for linea in r.stdout.splitlines():
        for m in patron.findall(linea):
            if dominio.lower() in m.lower():
                correos.add(m.lower())

    if not correos:
        return f"theHarvester no encontró correos públicos para {dominio}."

    ordenados = sorted(correos)
    cab = f"{len(ordenados)} correos encontrados para {dominio} (vía theHarvester/duckduckgo):"
    return recortar(cab + "\n" + "\n".join(ordenados))
"""ComuniGuard. Ejecutar con: streamlit run app.py"""

import csv
import hashlib
import hmac
import io
import json
import math
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

VERSION = "1.0"
ACCIONES = ["PERMITIR", "REVISAR", "OCULTAR"]
CONFIG_DEFAULT = {
    "umbral_revision": 2,
    "umbral_ocultar": 6,
    "ocultar_automaticamente": True,
    "terminos_adicionales": [],
}
REGLAS = [
    {
        "codigo": "insulto",
        "categoria": "Lenguaje ofensivo",
        "peso": 3,
        "patron": r"\b(?:estupid[oa]s?|idiotas?|imbecil(?:es)?|pendej[oa]s?|"
                   r"cerot[ea]s?|cretin[oa]s?|mongolicos?|stupid|idiots?|morons?|dumbass)\b",
    },
    {
        "codigo": "vulgaridad",
        "categoria": "Lenguaje vulgar",
        "peso": 2,
        "patron": r"\b(?:mierdas?|put[oa]s?|carajo|chingad[oa]s?|fuck(?:ing)?|shit)\b",
    },
    {
        "codigo": "ataque_explicito",
        "categoria": "Ataque personal explícito",
        "peso": 6,
        "patron": r"\b(?:hij[oa]s? de (?:la )?puta|fuck you|"
                   r"sos una basura|eres una basura)\b",
    },
    {
        "codigo": "discriminacion",
        "categoria": "Posible ataque discriminatorio",
        "peso": 6,
        "patron": r"\b(?:maricon(?:es)?|negros de mierda|indios de mierda|"
                   r"mujeres inferiores|raza inferior)\b",
    },
    {
        "codigo": "amenaza",
        "categoria": "Posible amenaza",
        "peso": 10,
        "patron": r"\b(?:(?:te|los|las|les) (?:voy|vamos) a (?:matar|golpear|violar)|"
                   r"ojala te mueras|te voy a partir la cara|"
                   r"i (?:will|am going to) kill you)\b",
    },
]
COLUMNAS_BASE = [
    "comentario_id", "usuario_id", "fecha", "fuente", "idioma",
    "texto_protegido", "datos_enmascarados", "fecha_invalida",
]
COLUMNAS_INCIDENCIAS = ["fuente", "fila", "tipo", "detalle"]

def normalizar(texto):
    """Conserva negaciones y palabras; normaliza acentos para comparar reglas."""
    texto = unicodedata.normalize("NFKD", str(texto).casefold())
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", texto).strip()


def enmascarar(texto):
    """Enmascara identificadores explícitos; no es anonimización semántica."""
    texto = str(texto)
    total = 0
    patrones = [
        (r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[CORREO]"),
        (r"(?i)https?://\S+|www\.\S+", "[ENLACE]"),
        (r"(?<!\w)@[A-Za-z0-9_]+", "[USUARIO]"),
        (r"(?<!\d)\d{4}[ -]?\d{5}[ -]?\d{4}(?!\d)", "[DPI]"),
        (r"(?<!\d)\d{12,19}(?!\d)", "[IDENTIFICADOR]"),
        (r"(?<!\w)(?:\+?502[ .-]?)?[2-9]\d{3}[ .-]?\d{4}(?!\d)", "[TELEFONO]"),
    ]
    for patron, sustituto in patrones:
        texto, n = re.subn(patron, sustituto, texto)
        total += n
    return texto, total


def seudonimo(valor, clave, prefijo):
    digest = hmac.new(clave, str(valor).encode("utf-8"), hashlib.sha256).hexdigest()
    return prefijo + digest[:20]


def texto_util(texto):
    texto = re.sub(r"\[(?:USUARIO|ENLACE|CORREO|DPI|IDENTIFICADOR|TELEFONO)\]", " ", texto)
    return bool(re.search(r"[^\W\d_]", texto, flags=re.UNICODE))

def decodificar(datos):
    if datos.startswith((b"\xff\xfe", b"\xfe\xff")):
        return datos.decode("utf-16")
    if b"\x00" in datos[:200]:
        return datos.decode("utf-16le").lstrip("\ufeff")
    return datos.decode("utf-8-sig")


def leer_registros(nombre, datos):
    """Lee CSV, JSON, JSONL y los .txt JSONL UTF-16 entregados."""
    registros, errores = [], []
    fuente = enmascarar(Path(nombre).name)[0]

    def error(fila, tipo, detalle):
        errores.append(dict(fuente=fuente, fila=fila, tipo=tipo, detalle=detalle))

    try:
        texto = decodificar(datos)
    except UnicodeError:
        error(0, "codificacion_invalida", "Se requiere UTF-8 o UTF-16.")
        return registros, errores
    if not texto.strip():
        error(0, "archivo_vacio", "El archivo no contiene registros.")
        return registros, errores
    if Path(nombre).suffix.lower() == ".csv":
        try:
            try:
                dialecto = csv.Sniffer().sniff(texto[:10000], delimiters=",;\t")
            except csv.Error:
                dialecto = csv.excel
            lector = csv.DictReader(io.StringIO(texto), dialect=dialecto)
            for n, registro in enumerate(lector, 2):
                if None in registro:
                    error(n, "csv_invalido", "La fila tiene columnas adicionales.")
                else:
                    registros.append((n, registro))
        except csv.Error:
            error(0, "csv_invalido", "No se pudo interpretar el CSV.")
        return registros, errores
    try:
        objeto = json.loads(texto)
    except json.JSONDecodeError:
        # JSONL: un objeto por línea. Se aísla cada línea dañada.
        if texto.lstrip().startswith("["):
            error(0, "json_invalido", "El arreglo JSON está incompleto o dañado.")
            return registros, errores
        for n, linea in enumerate(texto.splitlines(), 1):
            if not linea.strip():
                continue
            try:
                registros.append((n, json.loads(linea.lstrip("\ufeff"))))
            except json.JSONDecodeError:
                error(n, "json_invalido", "Línea aislada; no se conserva su contenido.")
    else:
        if isinstance(objeto, dict):
            listas = [objeto[k] for k in ("tweets", "data", "records")
                      if isinstance(objeto.get(k), list)]
            objeto = listas[0] if listas else [objeto]
        if not isinstance(objeto, list):
            error(0, "esquema_invalido", "Se esperaba un objeto o una lista de objetos.")
        else:
            registros.extend(enumerate(objeto, 1))
    return registros, errores


def ingestar_archivos(archivos, clave=None):
    """Devuelve únicamente campos protegidos e incidencias sin contenido crudo."""
    clave = clave or secrets.token_bytes(32)
    filas, incidencias, vistos = [], [], {}
    leidos = 0
    for nombre, datos in archivos:
        fuente = enmascarar(Path(nombre).name)[0]
        registros, errores = leer_registros(nombre, datos)
        incidencias.extend(errores)
        for numero, registro in registros:
            leidos += 1
            problema = None
            if not isinstance(registro, dict):
                problema = ("esquema_invalido", "El registro no es un objeto.")
                texto = None
            else:
                texto = next((registro[k] for k in
                              ("rawContent", "texto", "tweet_text", "text", "content", "body", "texto_protegido")
                              if isinstance(registro.get(k), str) and registro[k].strip()), None)
                if texto is None:
                    problema = ("texto_vacio", "Falta un campo de texto no vacío.")
            if problema:
                incidencias.append(dict(fuente=fuente, fila=numero, tipo=problema[0], detalle=problema[1]))
                continue
            identificador = registro.get("id_str") or registro.get("id") or registro.get("comentario_id")
            llave = ("id:" + str(identificador)) if identificador else ("texto:" + normalizar(texto))
            huella = hashlib.sha256(texto.encode()).hexdigest()
            if llave in vistos:
                tipo = "duplicado" if vistos[llave] == huella else "id_conflictivo"
                incidencias.append(dict(fuente=fuente, fila=numero, tipo=tipo,
                                        detalle="Se conserva la primera aparición; fila excluida."))
                continue
            vistos[llave] = huella
            usuario = registro.get("user", registro.get("usuario", registro.get("usuario_id", "")))
            if isinstance(usuario, dict):
                usuario = usuario.get("id_str") or usuario.get("id") or usuario.get("username") or ""
            protegido, n_ocultos = enmascarar(texto)
            valor_fecha = registro.get("date", registro.get("fecha", ""))
            tiene_fecha = valor_fecha is not None and not (
                isinstance(valor_fecha, str) and not valor_fecha.strip())
            # No se interpretan arreglos, objetos o números como fechas implícitas.
            fecha = (pd.to_datetime(valor_fecha, errors="coerce", utc=True)
                     if isinstance(valor_fecha, (str, datetime)) and tiene_fecha else pd.NaT)
            fecha_invalida = tiene_fecha and pd.isna(fecha)
            if pd.isna(fecha):
                dia = ""
            elif isinstance(valor_fecha, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", valor_fecha):
                dia = valor_fecha  # Una fecha sin hora ya representa un día local.
            else:
                dia = fecha.tz_convert("America/Guatemala").strftime("%Y-%m-%d")
            if fecha_invalida:
                incidencias.append(dict(fuente=fuente, fila=numero, tipo="fecha_invalida",
                                        detalle="Se conserva el comentario con fecha vacía."))
            filas.append(dict(
                comentario_id=seudonimo(llave, clave, "c_"),
                usuario_id=seudonimo(usuario, clave, "u_") if usuario else "u_desconocido",
                fecha=dia, fuente=fuente,
                idioma=str(registro.get("lang", registro.get("idioma", "und")) or "und").lower(),
                texto_protegido=protegido, datos_enmascarados=n_ocultos,
                fecha_invalida=bool(fecha_invalida),
            ))
    base = pd.DataFrame(filas, columns=COLUMNAS_BASE)
    incidencias = pd.DataFrame(incidencias, columns=COLUMNAS_INCIDENCIAS)
    resumen = {
        "registros_json_csv_leidos": leidos,
        "comentarios_unicos": len(base),
        "incidencias": len(incidencias),
        "por_tipo": incidencias["tipo"].value_counts().to_dict(),
    }
    return base, incidencias, resumen

def validar_config(config):
    if not 0 < config["umbral_revision"] < config["umbral_ocultar"]:
        raise ValueError("El umbral de revisión debe ser positivo y menor al de ocultamiento.")
    terminos = config.get("terminos_adicionales", [])
    if len(terminos) > 50 or any(not isinstance(t, str) or not t.strip() or len(t) > 50 for t in terminos):
        raise ValueError("Usa hasta 50 términos, de 1 a 50 caracteres cada uno.")


def huella_politica(config):
    contenido = {"version": VERSION, "config": config, "reglas": REGLAS}
    return hashlib.sha256(json.dumps(contenido, sort_keys=True).encode()).hexdigest()[:12]


def evaluar_texto(texto, idioma="es", config=None):
    config = {**CONFIG_DEFAULT, **(config or {})}
    validar_config(config)
    protegido, n_ocultos = enmascarar(texto)
    normal = normalizar(protegido)
    hallazgos = []
    for regla in REGLAS:
        coincidencias = sorted(set(re.findall(regla["patron"], normal)))
        if coincidencias:
            hallazgos.append({**regla, "coincidencias": coincidencias})
    for termino in sorted(set(normalizar(t) for t in config["terminos_adicionales"])):
        if re.search(r"(?<!\w)" + re.escape(termino) + r"(?!\w)", normal):
            hallazgos.append(dict(codigo="termino_adicional", categoria="Término configurado",
                                  peso=3, coincidencias=[termino]))
    codigos = {h["codigo"] for h in hallazgos}
    dirigido = bool(re.search(r"\b(?:eres|sos|sois|son|usted es|ustedes son|"
                              r"you are|youre|you're|callate|callense)\b", normal))
    puntaje = sum(h["peso"] for h in hallazgos)
    if dirigido and codigos.intersection({"insulto", "termino_adicional"}):
        puntaje += 3
    contexto = bool(hallazgos) and bool(re.search(
        r"\b(?:no (?:eres|sos|son|es|soy|somos|seas)|not|nunca dije|no dije|"
        r"la palabra|me dijeron|dijo|dijeron|denuncio|reporto)\b|[\"“”«»]", normal))
    fuera_cobertura = str(idioma).lower() not in {"es", "en"}
    sin_texto = not texto_util(protegido)
    critico = bool(codigos.intersection({"amenaza", "discriminacion"}))
    if sin_texto:
        decision, motivo = "REVISAR", "Sin texto suficiente para aplicar las reglas."
    elif fuera_cobertura:
        decision, motivo = "REVISAR", "Idioma no cubierto o indeterminado."
    elif critico:
        decision, motivo = "REVISAR", "Riesgo alto: requiere revisión prioritaria."
    elif contexto:
        decision, motivo = "REVISAR", "Posible cita, negación o denuncia: revisar contexto."
    elif puntaje >= config["umbral_ocultar"] and config["ocultar_automaticamente"]:
        decision, motivo = "OCULTAR", "Puntaje igual o superior al umbral de ocultamiento local."
    elif puntaje >= config["umbral_revision"]:
        decision, motivo = "REVISAR", "Puntaje igual o superior al umbral de revisión."
    else:
        decision, motivo = "PERMITIR", "No se alcanzó el umbral de revisión."
    categorias = list(dict.fromkeys(h["categoria"] for h in hallazgos))
    palabras = sorted({p for h in hallazgos for p in h["coincidencias"]})
    return dict(
        texto_protegido=protegido, datos_enmascarados=n_ocultos,
        puntaje=puntaje, categoria=" / ".join(categorias) or "Sin señales en las reglas",
        palabras_detectadas=", ".join(palabras), decision_motor=decision,
        prioridad="ALTA" if critico else "NORMAL", motivo=motivo,
        politica=huella_politica(config),
    )


def procesar_lote(base, config=None):
    evaluados = [evaluar_texto(r.texto_protegido, r.idioma, config)
                 for r in base.itertuples(index=False)]
    if not evaluados:
        columnas = ["puntaje", "categoria", "palabras_detectadas", "decision_motor",
                    "prioridad", "motivo", "politica"]
        return base.assign(**{c: pd.Series(dtype="object") for c in columnas})
    salida = pd.DataFrame(evaluados).drop(columns=["texto_protegido", "datos_enmascarados"])
    return pd.concat([base.reset_index(drop=True), salida], axis=1)

def calcular_impacto(resultados, segundos_manual=45, segundos_revision=45,
                     segundos_auditoria=30, porcentaje_auditoria=10,
                     costo_hora=35, costo_herramienta_lote=10,
                     minutos_operacion=5, ahorro_objetivo_pct=20):
    valores = [segundos_manual, segundos_revision, segundos_auditoria, porcentaje_auditoria,
               costo_hora, costo_herramienta_lote, minutos_operacion, ahorro_objetivo_pct]
    if any(not math.isfinite(v) or v < 0 for v in valores):
        raise ValueError("Los parámetros financieros deben ser finitos y no negativos.")
    if porcentaje_auditoria > 100 or ahorro_objetivo_pct > 100:
        raise ValueError("Los porcentajes deben estar entre 0 y 100.")
    n = len(resultados)
    revisar = int((resultados["decision_motor"] == "REVISAR").sum())
    auditoria = math.ceil((n - revisar) * porcentaje_auditoria / 100)
    horas_manual = n * segundos_manual / 3600
    horas_asistido = ((revisar * segundos_revision + auditoria * segundos_auditoria) / 3600
                      + minutos_operacion / 60) if n else 0.0
    costo_manual = horas_manual * costo_hora
    costo_asistido = horas_asistido * costo_hora + (costo_herramienta_lote if n else 0)
    ahorro = costo_manual - costo_asistido
    ahorro_pct = 100 * ahorro / costo_manual if costo_manual else 0.0
    return dict(
        comentarios=n, revisiones=revisar, auditorias_muestreadas=auditoria,
        horas_manual=horas_manual, horas_asistido=horas_asistido,
        horas_ahorradas=horas_manual - horas_asistido,
        costo_manual_q=costo_manual, costo_asistido_q=costo_asistido,
        ahorro_q=ahorro, ahorro_pct=ahorro_pct,
        cumple_objetivo=bool(n and ahorro > 0 and ahorro_pct >= ahorro_objetivo_pct),
    )


def csv_seguro(df):
    """Evita interpretar el contenido del usuario como fórmula al abrir un CSV."""
    def proteger(valor):
        if isinstance(valor, str) and valor.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + valor
        return valor
    protegido = df.copy()
    for columna in protegido:
        protegido[columna] = protegido[columna].map(proteger)
    return protegido.to_csv(index=False).encode("utf-8-sig")

from html import escape

ESTILOS = """
<style>
:root{--bg:#0d0916;--card:#191125;--line:rgba(225,203,255,.11);--muted:#b1a4c6;--ink:#f8f4ff;--lilac:#d6b9ff;--accent:#a46cf2}
html,body,[data-testid="stAppViewContainer"],.stApp{background:#0d0916;color:var(--ink)}
[data-testid="stAppViewContainer"]{background:radial-gradient(ellipse at 83% 7%,#43216c65,transparent 39%),radial-gradient(ellipse at 15% 85%,#301a4d55,transparent 45%),#0d0916}
[data-testid="stHeader"]{background:transparent}
.block-container{max-width:1340px;padding:2.1rem 3rem 3rem}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#160f22,#100b19);border-right:1px solid var(--line)}
section[data-testid="stSidebar"]>div{padding-top:1.5rem}
h1,h2,h3,h4,p,label,li{color:var(--ink)}
p,li{line-height:1.6}h1,h2,h3{letter-spacing:-.035em}
.brand{display:flex;align-items:center;gap:11px;font-size:21px;letter-spacing:-.8px;font-weight:700;margin:2px 0 5px}
.brand-icon{width:37px;height:41px;display:grid;place-items:center;background:linear-gradient(145deg,#e2cdff,#9873d1);color:#27143e;border-radius:13px 13px 17px 17px;font-size:21px}
.brand-sub{color:#9c8cae;font-size:11px;letter-spacing:.1em;margin:0 0 36px 48px}
.side-label,.eyebrow{font-size:10px;font-weight:600;letter-spacing:.17em;text-transform:uppercase;color:#ac9abc}
.side-label{margin:22px 0 10px}
.workspace{border:1px solid var(--line);border-radius:20px;padding:18px;margin-top:26px;background:linear-gradient(140deg,#35204566,#1a1126)}
.workspace strong{display:block;font-size:13px}.workspace p{color:var(--muted);font-size:11px;margin:5px 0 0}
.dot{display:inline-block;height:6px;width:6px;border-radius:50%;background:#a9d9bf;margin-right:6px;vertical-align:middle}
.topline{display:flex;justify-content:space-between;align-items:center;margin:0 0 28px}
.breadcrumb{color:#9e90b0;font-size:12px}.breadcrumb b{color:#eee4fa;font-weight:500}
.account{display:flex;align-items:center;gap:10px;color:#cdbedf;font-size:12px}
.avatar{height:34px;width:34px;display:grid;place-items:center;border-radius:50%;background:linear-gradient(145deg,#d6b7fe,#8050b0);color:#27153a;font-size:11px;font-weight:700}
.mode{display:inline-flex;align-items:center;border:1px solid #b995db33;border-radius:100px;background:#cfb1fb0c;color:#c8b8d9;padding:5px 11px;font-size:10px;letter-spacing:.03em}
.hero{padding:15px 0 4px}.hero h1{font:400 clamp(40px,4.6vw,70px)/1.06 Georgia,'Times New Roman',serif;letter-spacing:-.055em;margin:18px 0 18px;color:#faf6ff}
.hero h1 em{color:#d3affd;font-weight:400}.hero p{max-width:410px;font-size:14px;line-height:1.8;color:#b9a9c9;margin:0 0 12px}
.hero-foot{color:#9585a6;font-size:11px;margin:14px 0 25px}
.orb-scene{position:relative;min-height:345px;display:flex;flex-direction:column;align-items:center;justify-content:center;margin-top:0}
.orb-glow{position:absolute;inset:0;background:radial-gradient(ellipse,#8d42dc55,transparent 67%);filter:blur(20px)}
.orb{position:relative;width:226px;height:226px;border-radius:50%;background:radial-gradient(circle at 39% 27%,#f4d2ffdd 0%,#c784f488 16%,transparent 40%),radial-gradient(circle at 72% 77%,#67ceec70,transparent 35%),radial-gradient(circle at 63% 38%,#a333e9,#7233b5 42%,#351254 77%,#170e2a);box-shadow:inset -17px -22px 36px #12051e99,inset 4px 3px 12px #f5caff75,0 0 90px #9b47dc65;animation:breathe 7s ease-in-out infinite}
.orb:after{content:'';position:absolute;inset:17px;border-radius:50%;border:1px solid #f2d2ff12;transform:rotate(-30deg);box-shadow:inset 0 1px 14px #f8cbff22}
.orb-caption{position:relative;text-align:center;margin-top:24px;color:#d9c8ec;font:italic 22px Georgia,serif;letter-spacing:-.02em}
.float-tag{position:absolute;z-index:2;display:flex;gap:10px;align-items:center;padding:12px 15px;border:1px solid #f0d8ff28;border-radius:17px;background:linear-gradient(135deg,#382644e8,#1f142ddd);backdrop-filter:blur(15px);box-shadow:0 18px 35px #07030f40;font-size:11px;color:#f0e4fc}
.float-tag small{display:block;font-size:9px;color:#b8a4ca;margin-top:3px}.float-tag.left{left:0;top:45px;transform:rotate(-7deg)}.float-tag.right{right:-4px;bottom:80px;transform:rotate(6deg)}
.tag-icon{width:28px;height:28px;border-radius:10px;display:grid;place-items:center;background:#b88be530;color:#e1c5ff;font-size:15px}
.section-head{display:flex;justify-content:space-between;align-items:center;margin:22px 0 17px}.section-head h2{font-size:18px;font-weight:500;letter-spacing:-.03em;margin:0}.section-head span{color:#9988aa;font-size:11px}
.metric-card{min-height:145px;background:linear-gradient(145deg,#2b1b3b99,#17101fee);border:1px solid var(--line);border-radius:23px;padding:21px 22px;margin:2px 0 16px}
.metric-card.light{background:linear-gradient(135deg,#ead8ff,#c2a3e2);color:#2c173e;border-color:#e4cdfb55}.metric-card.light .metric-label,.metric-card.light .metric-note{color:#63467b}
.metric-label{font-size:11px;color:#b5a2c8;margin:0 0 12px}.metric-value{font-size:33px;line-height:1.15;letter-spacing:-.055em;font-weight:500}.metric-note{font-size:10px;color:#9b87af;margin-top:11px}
.glass,.st-key-analysis-box,.st-key-import-box,.st-key-policy-box,.st-key-review-box{background:linear-gradient(145deg,#251631aa,#17101fe8);border:1px solid var(--line);border-radius:25px;padding:23px}
.callout{background:linear-gradient(110deg,#41215799,#20132e);border:1px solid #c69aea22;border-radius:22px;padding:21px 24px;margin:8px 0 22px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.callout h3{font:italic 25px Georgia,serif;margin:0 0 7px;color:#f3e8ff}.callout p{font-size:11px;color:#b9a5cd;margin:0;line-height:1.8}.callout-mark{font-size:29px;color:#d2aff8}
.comment{background:linear-gradient(135deg,#21172cbd,#17101f);border:1px solid var(--line);border-radius:20px;padding:19px 21px;margin:0 0 11px}
.comment-top{display:flex;justify-content:space-between;align-items:center;gap:10px}.comment-person{display:flex;align-items:center;gap:10px}.comment-avatar{height:31px;width:31px;border-radius:50%;display:grid;place-items:center;background:#c49aea20;color:#dec7f5;font-size:10px}
.comment-person strong{font-size:11px;font-weight:500}.comment-person small{display:block;color:#8e7c9f;font-size:9px;margin-top:3px}.comment p{font-size:12px;color:#d9cee4;line-height:1.8;margin:13px 0 11px;overflow-wrap:anywhere;white-space:normal}
.comment-bottom{display:flex;justify-content:space-between;gap:15px;color:#927ca6;font-size:9px;line-height:1.6}.pill{display:inline-block;white-space:nowrap;padding:5px 9px;border:1px solid #cab1df22;border-radius:100px;font-size:9px;line-height:1.1}.pill.allow{background:#a9dcc410;color:#b0d6c4}.pill.review{background:#e1bc7c12;color:#dec49a}.pill.hide{background:#e49db615;color:#e1a9c0}
.split-row{display:flex;justify-content:space-between;align-items:center;font-size:11px;padding:13px 0;border-bottom:1px solid var(--line)}.split-row:last-child{border:0}.split-row span{color:#b9a5ca}.split-row b{font-weight:500;color:#e9dbf6}
.mini-bar{height:6px;background:#d5b6ef13;border-radius:20px;overflow:hidden;margin:8px 0 20px}.mini-bar>div{height:100%;background:linear-gradient(90deg,#7c41ad,#d7adfb);border-radius:20px}
.result-card{border:1px solid #c19be638;background:linear-gradient(135deg,#3b1f53,#1b1227);border-radius:24px;padding:25px;margin:19px 0}.result-card h2{font:italic 30px Georgia,serif;margin:13px 0}.result-card p{color:#c4afd5;font-size:12px}.result-card .result-score{float:right;font-size:28px;color:#d9b8fc}
.privacy-note{font-size:10px;color:#91819f;line-height:1.7;margin:24px 0 4px}.page-title{font:400 40px/1.15 Georgia,serif;letter-spacing:-.04em;margin:12px 0}.page-intro{font-size:13px;color:#b6a4c8;max-width:670px;margin-bottom:25px}
div.stButton>button,div.stDownloadButton>button,div.stFormSubmitButton>button{border:1px solid #ccb2e530;border-radius:100px;background:#241731;color:#ebdff6;min-height:41px;font-size:12px;padding:.45rem 1.2rem;box-shadow:none}
div.stButton>button:hover,div.stDownloadButton>button:hover,div.stFormSubmitButton>button:hover{border-color:#bc8ce6;color:#fff;background:#39224e}
div.stButton>button[kind="primary"],div.stFormSubmitButton>button[kind="primary"]{background:linear-gradient(110deg,#d8b5ff,#ac7edc);color:#291437;border:0;font-weight:600}
div.stButton>button[kind="primary"]:hover{background:#e7ccff}
.st-key-navigation [data-baseweb="radio"]{background:transparent;border-radius:13px;margin:3px 0;padding:10px 12px;width:100%}
.st-key-navigation label[data-baseweb="radio"]:has(input:checked){background:linear-gradient(90deg,#6b36934a,#4b286632);border:1px solid #c59bed20}
.st-key-navigation label p{font-size:12px;color:#c9b5da}
div[data-baseweb="input"]>div,div[data-baseweb="select"]>div,div[data-baseweb="textarea"]{background:#150e20!important;border-color:#af88cc30!important;border-radius:13px;color:#f2e8ff!important}
input,textarea{color:#f4eaff!important;caret-color:#d4a8fb}textarea{background:#150e20!important;border-radius:15px!important}
[data-testid="stWidgetLabel"] p{font-size:11px;color:#b9a5cb}.stCaption p{color:#9e8aaf;font-size:10px}
[data-testid="stFileUploaderDropzone"]{background:#1d1229;border:1px dashed #c59be844;border-radius:18px}
[data-testid="stExpander"]{border:1px solid var(--line);border-radius:18px;background:#1a112455}
[data-testid="stAlert"]{border-radius:16px;font-size:12px}
hr{border-color:var(--line)}a{color:#d7b1ff}.st-key-review-box{margin-bottom:20px}
@keyframes breathe{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-6px) scale(1.025)}}
@media(prefers-reduced-motion:reduce){.orb{animation:none}}
@media(max-width:900px){.block-container{padding:1.5rem 1.2rem}.hero h1{font-size:49px}.orb-scene{min-height:295px}.orb{height:190px;width:190px}.float-tag{font-size:10px;padding:10px}.metric-card{padding:17px;min-height:130px}.metric-value{font-size:28px}.account .account-name{display:none}}
@media(max-width:600px){.hero h1{font-size:44px}.topline{margin-bottom:18px}.float-tag.left{left:7px}.float-tag.right{right:3px}.comment-bottom{flex-direction:column;gap:3px}.callout{padding:20px}.page-title{font-size:34px}}
</style>
"""

COMENTARIOS_EJEMPLO = [
    ("Gracias por resolver mi duda tan rápido.", "es"),
    ("El servicio está lento y deberían mejorar la atención.", "es"),
    ("No estoy de acuerdo con esta decisión.", "es"),
    ("¿Hasta cuándo estará disponible la promoción?", "es"),
    ("stupid", "en"),
    ("You are stupid", "en"),
    ("No eres un idiota", "es"),
    ("Sos un idiota", "es"),
    ("Pueden escribirme a ejemplo@example.com para revisar el caso.", "es"),
    ("Mi teléfono de prueba es +502 5555 1234. Gracias.", "es"),
    ("Te voy a matar", "es"),
    ("El producto llegó tarde, pero el equipo ya me atendió.", "es"),
    ("¿Cuándo vuelve a estar disponible?", "es"),
    ("Me parece una buena propuesta para la comunidad.", "es"),
    ("Qué mierda de servicio.", "es"),
    ('Me dijeron "stupid" en los comentarios.', "es"),
    ("Gracias por escuchar nuestras sugerencias.", "es"),
    ("La información de la publicación está incompleta.", "es"),
]


def cargar_ejemplo(clave):
    filas = [dict(id=f"ejemplo_{i}", user={"username": f"ejemplo_usuario_{i}"},
                  rawContent=texto, lang=idioma)
             for i, (texto, idioma) in enumerate(COMENTARIOS_EJEMPLO, 1)]
    return ingestar_archivos([("comentarios_de_ejemplo.json", json.dumps(filas).encode())], clave)


def aplicar_decisiones(resultados, decisiones):
    salida = resultados.copy()
    salida["decision_actual"] = [decisiones.get(cid, decision) for cid, decision in
                                  zip(salida["comentario_id"], salida["decision_motor"])]
    salida["origen_decision"] = salida["comentario_id"].map(
        lambda cid: "HUMANA" if cid in decisiones else "REGLAS")
    return salida


def etiqueta_decision(accion):
    nombre, clase = {"PERMITIR": ("Permitido", "allow"), "REVISAR": ("En revisión", "review"),
                     "OCULTAR": ("Retirado de la vista", "hide")}[accion]
    return f'<span class="pill {clase}">{nombre}</span>'


def tarjeta_comentario(fila):
    cid = escape(str(fila["comentario_id"]))
    usuario = escape(str(fila["usuario_id"])[-5:].upper())
    fecha = escape(str(fila.get("fecha", "")) or "Sin fecha")
    texto = escape(str(fila["texto_protegido"])).replace("\n", "<br>")
    categoria = escape(str(fila["categoria"]))
    return (f'<div class="comment"><div class="comment-top"><div class="comment-person">'
            f'<div class="comment-avatar">{usuario[:2]}</div><div><strong>Usuario {usuario}</strong>'
            f'<small>{fecha}</small></div></div>{etiqueta_decision(fila["decision_actual"])}</div>'
            f'<p>{texto}</p><div class="comment-bottom"><span>{categoria}</span>'
            f'<span>Puntaje {int(fila["puntaje"])} · {cid[-8:]}</span></div></div>')


def main():
    import streamlit as st

    st.set_page_config(page_title="ComuniGuard · Tu comunidad, en equilibrio", page_icon="◈",
                       layout="wide", initial_sidebar_state="expanded")
    st.markdown(ESTILOS, unsafe_allow_html=True)

    def html(contenido):
        st.markdown(contenido, unsafe_allow_html=True)

    def cambiar_pagina(pagina):
        st.session_state.pagina = pagina

    def fijar_lote(base, incidencias, resumen, modo):
        st.session_state.base = base
        st.session_state.incidencias = incidencias
        st.session_state.resumen = resumen
        st.session_state.modo = modo
        st.session_state.decisiones = {}
        st.session_state.bitacora = []
        st.session_state.ultimo_analisis = None
        st.session_state.carga_version += 1
        st.session_state.pop("pagina_comentarios", None)

    if st.session_state.get("_cg_schema") != "plataforma_v1":
        st.session_state.clave = secrets.token_bytes(32)
        st.session_state.config = json.loads(json.dumps(CONFIG_DEFAULT))
        st.session_state.pagina = "Inicio"
        st.session_state.carga_version = 0
        st.session_state.finanzas = dict(segundos_manual=45, segundos_revision=45,
            segundos_auditoria=30, porcentaje_auditoria=10, costo_hora=35.0,
            costo_herramienta_lote=10.0, minutos_operacion=5, ahorro_objetivo_pct=20)
        fijar_lote(*cargar_ejemplo(st.session_state.clave), "demostracion")
        st.session_state._cg_schema = "plataforma_v1"

    with st.sidebar:
        html('<div class="brand"><span class="brand-icon">◈</span>ComuniGuard</div>'
             '<div class="brand-sub">TU COMUNIDAD, EN EQUILIBRIO</div>'
             '<div class="side-label">ESPACIO DE TRABAJO</div>')
        with st.container(key="navigation"):
            st.radio("Navegación", ["Inicio", "Comunidad", "Moderación", "Impacto", "Configuración"],
                     key="pagina", label_visibility="collapsed")
        modo = "Comentarios de ejemplo" if st.session_state.modo == "demostracion" else "Tus archivos"
        html(f'<div class="workspace"><strong><span class="dot"></span>{modo}</strong>'
             '<p>Reglas activas · Datos protegidos<br/>Las acciones se aplican a esta vista local.</p></div>')
        st.markdown("")
        st.button("Importar comentarios", on_click=cambiar_pagina, args=("Comunidad",),
                  use_container_width=True)
        st.caption("ComuniGuard · Espacio seguro")

    pagina = st.session_state.pagina
    es_demo = st.session_state.modo == "demostracion"
    config = st.session_state.config
    politica = huella_politica(config)
    motor = procesar_lote(st.session_state.base, config)
    resultados = aplicar_decisiones(motor, st.session_state.decisiones)
    conteos = resultados["decision_actual"].value_counts().reindex(ACCIONES, fill_value=0)
    impacto = calcular_impacto(motor, **st.session_state.finanzas)
    etiqueta_modo = "Demostración · comentarios ficticios" if es_demo else "Lote cargado · datos protegidos"
    html(f'<div class="topline"><div class="breadcrumb">Tu espacio &nbsp; / &nbsp; '
         f'<b>{escape(pagina)}</b></div><div class="account"><span class="mode">'
         f'{etiqueta_modo}</span><span class="account-name">Pau &amp; Majo</span>'
         '<span class="avatar">PM</span></div></div>')

    def titulo(titulo, descripcion, etiqueta="COMUNIGUARD"):
        html(f'<div class="eyebrow">{escape(etiqueta)}</div><div class="page-title">'
             f'{titulo}</div><div class="page-intro">{escape(descripcion)}</div>')

    def metricas():
        datos = [("Comentarios", f"{len(resultados):,}", "en el lote actual", True),
                 ("En tu comunidad", f"{int(conteos['PERMITIR']):,}", "visibles en la vista pública", False),
                 ("Para revisar", f"{int(conteos['REVISAR']):,}", "con control humano", False),
                 ("Retirados", f"{int(conteos['OCULTAR']):,}", "fuera de la vista pública", False)]
        for col, (nombre, valor, nota, claro) in zip(st.columns(4), datos):
            with col:
                html(f'<div class="metric-card {"light" if claro else ""}"><div class="metric-label">'
                     f'{nombre}</div><div class="metric-value">{valor}</div><div class="metric-note">{nota}</div></div>')

    if pagina == "Inicio":
        izquierda, derecha = st.columns([1.2, 1], gap="large")
        with izquierda:
            html('<div class="hero"><div class="eyebrow">MENOS RUIDO. MÁS COMUNIDAD.</div>'
                 '<h1>Una comunidad<br/>que da gusto<br/><em>leer.</em></h1>'
                 '<p>Cuida la conversación sin revisar cada comentario desde cero. '
                 'Filtra los ataques y deja espacio para las opiniones.</p></div>')
            c1, c2 = st.columns([1.05, 1.25])
            with c1:
                st.button("Ver mi comunidad ↗", type="primary", on_click=cambiar_pagina,
                          args=("Comunidad",), use_container_width=True)
            with c2:
                st.button("Probar un comentario", on_click=cambiar_pagina,
                          args=("Moderación",), use_container_width=True)
            html('<div class="hero-foot">◈ &nbsp; Protección de datos y decisiones que puedes revisar.</div>')
        with derecha:
            html(f'<div class="orb-scene"><div class="orb-glow"></div><div class="orb"></div>'
                 '<div class="float-tag left"><span class="tag-icon">◈</span><div>Privacidad primero'
                 '<small>Identificadores enmascarados</small></div></div>'
                 f'<div class="float-tag right"><span class="tag-icon">✓</span><div>{int(conteos["PERMITIR"]):,} comentarios visibles'
                 '<small>Tu conversación sigue aquí</small></div></div>'
                 '<div class="orb-caption">Cuida lo que construyes.</div></div>')
        html('<div class="section-head"><h2>Tu comunidad, de un vistazo</h2><span>Lote actual</span></div>')
        metricas()
        izquierda, derecha = st.columns([1.45, 1], gap="large")
        with izquierda:
            html('<div class="section-head"><h2>La conversación continúa</h2><span>Vista pública simulada</span></div>')
            visibles = resultados[resultados.decision_actual == "PERMITIR"].head(3)
            for _, fila in visibles.iterrows():
                html(tarjeta_comentario(fila))
            if visibles.empty:
                st.info("Todavía no hay comentarios permitidos en este lote.")
        with derecha:
            html('<div class="section-head"><h2>A tu ritmo</h2><span>Moderación</span></div>')
            total = max(len(resultados), 1)
            bloques = ''.join(f'<div class="split-row"><span>{nombre}</span><b>{int(conteos[accion]):,}</b></div>'
                              f'<div class="mini-bar"><div style="width:{100*int(conteos[accion])/total:.2f}%"></div></div>'
                              for accion, nombre in [("PERMITIR", "Conversación visible"), ("REVISAR", "Revisión humana"), ("OCULTAR", "Comentarios retirados")])
            html(f'<div class="glass">{bloques}</div>')
            html('<div class="callout"><div><h3>Tu tiempo también cuenta.</h3>'
                 '<p>Estima cuántas horas puede recuperar tu equipo y ajusta los costos de tu operación.</p>'
                 '</div><span class="callout-mark">↗</span></div>')
            st.button("Explorar el impacto", on_click=cambiar_pagina, args=("Impacto",),
                      use_container_width=True)

    elif pagina == "Comunidad":
        titulo("El espacio de tu comunidad.", "Importa tus comentarios y elige qué conversación quieres revisar.")
        with st.expander("Importar mis comentarios", expanded=es_demo or resultados.empty):
            subidos = st.file_uploader("Selecciona uno o varios archivos", type=["txt", "json", "jsonl", "csv"],
                accept_multiple_files=True, key=f"carga_{st.session_state.carga_version}")
            st.caption("Admite los .txt del notebook, JSON y CSV con rawContent, texto, tweet_text, text, content o body.")
            if st.button("Procesar comentarios", type="primary", disabled=not subidos):
                if sum(f.size for f in subidos) > 100 * 1024 * 1024:
                    st.error("El tamaño combinado máximo es 100 MB.")
                else:
                    with st.spinner("Protegiendo datos y revisando comentarios..."):
                        lote = ingestar_archivos([(f.name, f.getvalue()) for f in subidos], st.session_state.clave)
                        fijar_lote(*lote, "archivos")
                    st.rerun()
        metricas()
        c1, c2 = st.columns([1, 2])
        with c1:
            vista = st.selectbox("Vista", ["Comunidad visible", "En revisión", "Retirados", "Todos"])
        with c2:
            busqueda = st.text_input("Buscar en los comentarios", placeholder="Una palabra o una frase")
        accion = {"Comunidad visible": "PERMITIR", "En revisión": "REVISAR", "Retirados": "OCULTAR"}.get(vista)
        filtrado = resultados if accion is None else resultados[resultados.decision_actual == accion]
        if busqueda.strip():
            filtrado = filtrado[filtrado.texto_protegido.str.contains(busqueda.strip(), case=False, regex=False)]
        st.caption(f"{len(filtrado):,} comentarios · Los casos en revisión y los retirados quedan fuera de la comunidad visible.")
        paginas = max(1, math.ceil(len(filtrado) / 8))
        numero = int(st.number_input("Página", min_value=1, max_value=paginas, value=1,
                                     key=f"pagina_comentarios_{vista}_{paginas}"))
        for _, fila in filtrado.iloc[(numero-1)*8:numero*8].iterrows():
            html(tarjeta_comentario(fila))
        if filtrado.empty:
            st.info("No hay comentarios en esta vista.")
        st.download_button("Descargar esta vista", csv_seguro(filtrado), "comunidad_filtrada.csv", "text/csv")

    elif pagina == "Moderación":
        titulo("Cada comentario, con contexto.", "Analiza un texto o resuelve los casos que necesitan una segunda mirada.")
        analizar, revisar, registro = st.tabs(["Analizar comentario", "Revisar decisiones", "Bitácora"])
        with analizar:
            with st.container(key="analysis-box"):
                with st.form("analizar_texto"):
                    texto = st.text_area("¿Qué comentario quieres revisar?", height=135,
                                         placeholder="Escribe o pega un comentario aquí...")
                    idioma = st.selectbox("Idioma", ["Español", "Inglés", "Otro"])
                    enviar = st.form_submit_button("Analizar comentario ↗", type="primary")
                if enviar:
                    if texto.strip():
                        codigo_idioma = {"Español": "es", "Inglés": "en", "Otro": "otro"}[idioma]
                        st.session_state.ultimo_analisis = evaluar_texto(texto, codigo_idioma, config)
                    else:
                        st.session_state.ultimo_analisis = None
                        st.warning("Escribe un comentario para analizarlo.")
            salida = st.session_state.ultimo_analisis
            if salida:
                html(f'<div class="result-card">{etiqueta_decision(salida["decision_motor"])}'
                     f'<span class="result-score">{salida["puntaje"]} pts</span>'
                     f'<h2>{escape(salida["categoria"])}</h2><p>{escape(salida["motivo"])}</p>'
                     f'<p>Expresiones detectadas: <b>{escape(salida["palabras_detectadas"] or "Ninguna coincidencia")}</b></p></div>')
                st.text_area("Texto con datos protegidos", salida["texto_protegido"], disabled=True)
                st.caption("El puntaje corresponde a las reglas aplicadas. Los casos ambiguos requieren revisión humana.")
            else:
                st.caption('Puedes probar con «stupid», «You are stupid» o «El servicio es lento y deben mejorar».')
        with revisar:
            vista = st.selectbox("Cola de trabajo", ["En revisión", "Retirados", "Permitidos", "Todos"])
            accion = {"En revisión": "REVISAR", "Retirados": "OCULTAR", "Permitidos": "PERMITIR"}.get(vista)
            cola = resultados if accion is None else resultados[resultados.decision_actual == accion]
            cola = cola.sort_values(["prioridad", "puntaje"], ascending=[True, False])
            st.caption(f"{len(cola):,} comentarios · Prioridad alta al inicio.")
            if len(cola):
                lookup = cola.set_index("comentario_id")
                cid = st.selectbox("Seleccionar comentario", cola.comentario_id.tolist(),
                    format_func=lambda x: f'{lookup.loc[x, "prioridad"]} · {lookup.loc[x, "texto_protegido"][:80]}')
                fila = lookup.loc[cid].copy()
                fila["comentario_id"] = cid
                html(tarjeta_comentario(fila))
                st.caption(str(fila["motivo"]))
                with st.form(f"resolver_{cid}"):
                    nueva = st.selectbox("Qué quieres hacer", ACCIONES,
                        index=ACCIONES.index(fila["decision_actual"]),
                        format_func=lambda x: {"PERMITIR": "Permitir en la comunidad", "REVISAR": "Mantener en revisión", "OCULTAR": "Retirar de la vista"}[x])
                    motivo = st.text_input("Motivo de la decisión", placeholder="Explica brevemente el contexto...")
                    guardar = st.form_submit_button("Guardar decisión", type="primary")
                if guardar:
                    if len(motivo.strip()) < 5:
                        st.warning("Agrega un motivo de al menos cinco caracteres.")
                    else:
                        st.session_state.decisiones[cid] = nueva
                        st.session_state.bitacora.append(dict(fecha_utc=datetime.now(timezone.utc).isoformat(),
                            comentario_id=cid, anterior=fila["decision_actual"], nueva=nueva,
                            motivo=enmascarar(motivo)[0], politica=politica, actor="moderador_de_la_sesion"))
                        st.rerun()
            else:
                st.success("No quedan comentarios en esta cola.")
        with registro:
            bitacora = pd.DataFrame(st.session_state.bitacora, columns=[
                "fecha_utc", "comentario_id", "anterior", "nueva", "motivo", "politica", "actor"])
            st.dataframe(bitacora, hide_index=True, use_container_width=True)
            st.download_button("Descargar bitácora", csv_seguro(bitacora), "bitacora_moderacion.csv", "text/csv")
            st.download_button("Descargar lote completo", csv_seguro(resultados), "lote_moderado.csv", "text/csv")
            st.caption("Descarga la bitácora antes de cerrar la sesión o cambiar de lote.")

    elif pagina == "Impacto":
        titulo("Más tiempo para tu equipo.", "Compara el trabajo manual con un proceso asistido y ajusta los supuestos a tu operación.")
        if es_demo:
            st.info("Este escenario usa los comentarios ficticios de la demostración. Importa tus archivos para calcular el impacto de tu lote.")
        c1, c2, c3 = st.columns(3)
        for col, nombre, valor, nota in [
            (c1, "Horas potencialmente liberadas", f"{impacto['horas_ahorradas']:,.2f}", "por lote"),
            (c2, "Ahorro neto estimado", f"Q {impacto['ahorro_q']:,.2f}", "incluye costo de herramienta"),
            (c3, "Reducción de costo", f"{impacto['ahorro_pct']:.1f}%", "según los parámetros actuales")]:
            with col:
                html(f'<div class="metric-card"><div class="metric-label">{nombre}</div>'
                     f'<div class="metric-value">{valor}</div><div class="metric-note">{nota}</div></div>')
        resumen = pd.DataFrame({"Proceso": ["Manual", "Asistido"],
            "Horas-hombre": [impacto["horas_manual"], impacto["horas_asistido"]],
            "Costo estimado (Q)": [impacto["costo_manual_q"], impacto["costo_asistido_q"]]})
        a, b = st.columns(2)
        with a:
            st.caption("TIEMPO DE TRABAJO")
            st.bar_chart(resumen.set_index("Proceso")[["Horas-hombre"]], color="#bc8aea")
        with b:
            st.caption("COSTO POR LOTE")
            st.bar_chart(resumen.set_index("Proceso")[["Costo estimado (Q)"]], color="#d6baff")
        st.write("**Objetivo económico:**", "Se alcanza el ahorro objetivo" if impacto["cumple_objetivo"] else "No se alcanza el ahorro objetivo")
        with st.expander("Ajustar tiempos y costos"):
            f = st.session_state.finanzas
            with st.form("finanzas"):
                a, b, c = st.columns(3)
                manual = a.number_input("Lectura manual (segundos)", min_value=1, max_value=1200, value=int(f["segundos_manual"]))
                revision = b.number_input("Revisión humana (segundos)", min_value=1, max_value=1200, value=int(f["segundos_revision"]))
                auditoria = c.number_input("Auditoría por comentario (segundos)", min_value=1, max_value=1200, value=int(f["segundos_auditoria"]))
                a, b, c = st.columns(3)
                hora = a.number_input("Costo por hora (Q)", min_value=0.0, value=float(f["costo_hora"]))
                herramienta = b.number_input("Herramienta por lote (Q)", min_value=0.0, value=float(f["costo_herramienta_lote"]))
                muestra = c.number_input("Muestra de auditoría (%)", min_value=0, max_value=100, value=int(f["porcentaje_auditoria"]))
                a, b = st.columns(2)
                operacion = a.number_input("Operación por lote (minutos)", min_value=0, value=int(f["minutos_operacion"]))
                objetivo = b.number_input("Ahorro mínimo objetivo (%)", min_value=0, max_value=100, value=int(f["ahorro_objetivo_pct"]))
                actualizar = st.form_submit_button("Actualizar escenario", type="primary")
            if actualizar:
                st.session_state.finanzas = dict(segundos_manual=manual, segundos_revision=revision,
                    segundos_auditoria=auditoria, porcentaje_auditoria=muestra, costo_hora=hora,
                    costo_herramienta_lote=herramienta, minutos_operacion=operacion, ahorro_objetivo_pct=objetivo)
                st.rerun()
        st.caption(f"{impacto['revisiones']:,} revisiones y {impacto['auditorias_muestreadas']:,} auditorías estimadas. Se utiliza la decisión inicial del motor para proyectar el proceso.")
        st.caption("Los tiempos y costos son supuestos editables. El cálculo no incluye el impacto de errores de moderación.")
        st.download_button("Descargar escenario", json.dumps(impacto, ensure_ascii=False, indent=2), "impacto_estimado.json", "application/json")

    elif pagina == "Configuración":
        titulo("Tus reglas. Tu comunidad.", "Ajusta el filtro y revisa cómo se protegen los datos de tus comentarios.")
        reglas, privacidad = st.tabs(["Política de moderación", "Privacidad y calidad"])
        with reglas:
            with st.container(key="policy-box"):
                with st.form("politica"):
                    a, b = st.columns(2)
                    revision = a.slider("Umbral de revisión", 1, 10, int(config["umbral_revision"]))
                    ocultamiento = b.slider("Umbral de retiro automático", 2, 20, int(config["umbral_ocultar"]))
                    auto = st.checkbox("Retirar automáticamente los comentarios que alcancen el umbral", value=config["ocultar_automaticamente"])
                    terminos = st.text_area("Términos adicionales, separados por coma", value=", ".join(config["terminos_adicionales"]),
                        placeholder="Agrega solo términos que requieran moderación...")
                    aplicar = st.form_submit_button("Guardar política", type="primary")
                if aplicar:
                    nueva = dict(umbral_revision=revision, umbral_ocultar=ocultamiento,
                        ocultar_automaticamente=auto, terminos_adicionales=[x.strip() for x in terminos.split(",") if x.strip()])
                    try:
                        validar_config(nueva)
                    except ValueError as error:
                        st.error(str(error))
                    else:
                        st.session_state.config = nueva
                        st.session_state.ultimo_analisis = None
                        st.rerun()
            st.caption("Las decisiones humanas se conservan al cambiar la política. Las amenazas y los casos ambiguos se envían a revisión.")
            st.dataframe(pd.DataFrame(REGLAS)[["categoria", "peso"]].rename(columns={"categoria": "Señal", "peso": "Puntos"}),
                         hide_index=True, use_container_width=True)
            st.download_button("Descargar política", json.dumps({"version": VERSION, "huella": politica,
                "config": config, "reglas": REGLAS}, ensure_ascii=False, indent=2), "politica_moderacion.json", "application/json")
        with privacidad:
            n = int(st.session_state.base.datos_enmascarados.sum()) if len(st.session_state.base) else 0
            html(f'<div class="callout"><div><h3>Privacidad desde el primer comentario.</h3>'
                 f'<p>{n:,} sustituciones de identificadores en el lote actual. '
                 'Los perfiles completos y las ubicaciones se descartan.</p></div><span class="callout-mark">◈</span></div>')
            st.write("Se enmascaran menciones, correos, enlaces, DPI, teléfonos y números largos. Los IDs y usuarios se sustituyen por seudónimos.")
            st.caption("La protección es parcial: nombres o direcciones escritos libremente pueden requerir revisión adicional. La clave es temporal y no se exporta.")
            incidencias = st.session_state.incidencias
            st.write(f"**Incidencias registradas:** {len(incidencias):,}")
            st.dataframe(incidencias, hide_index=True, use_container_width=True)
            st.download_button("Descargar incidencias", csv_seguro(incidencias), "incidencias_ingesta.csv", "text/csv")
            st.caption("Las líneas dañadas y los duplicados se aíslan. El detalle no conserva el texto original de la línea dañada.")
            if st.button("Volver a los comentarios de ejemplo"):
                fijar_lote(*cargar_ejemplo(st.session_state.clave), "demostracion")
                st.rerun()

    html('<div class="privacy-note">ComuniGuard · Moderación sobre archivos. Retirar un comentario lo oculta de esta vista; '
         'las publicaciones de X no se modifican. Las decisiones y la bitácora se conservan durante la sesión.</div>')


if __name__ == "__main__":
    main()

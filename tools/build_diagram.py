"""Arma la página del diagrama con fragmentos de código REALES del repo (leídos con ast, no copiados a mano).

Uso: python -I build_diagram.py <ruta_repo> <salida.html>
"""
import ast
import html
import sys
from pathlib import Path

REPO = Path(sys.argv[1])
OUT = Path(sys.argv[2])


def src(rel: str) -> list[str]:
    return (REPO / rel).read_text(encoding="utf-8").splitlines()


def node_lines(rel: str, name: str) -> tuple[int, int]:
    """Líneas (1-based) de una función, clase, método (Clase.metodo) o asignación de nivel superior."""
    tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
    parts = name.split(".")
    scope = tree.body
    for i, part in enumerate(parts):
        for node in scope:
            n = getattr(node, "name", None)
            if n is None and isinstance(node, ast.Assign):
                n = getattr(node.targets[0], "id", None)
            if n == part:
                if i == len(parts) - 1:
                    start = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
                    return start, node.end_lineno
                scope = node.body
                break
        else:
            raise KeyError(f"{name} no está en {rel}")
    raise KeyError(name)


def between(rel: str, start_text: str, end_text: str | None) -> tuple[int, int]:
    """Líneas desde la que contiene start_text hasta la anterior a end_text (o hasta end_text si end_text es None)."""
    lines = src(rel)
    s = next(i for i, l in enumerate(lines) if start_text in l)
    if end_text is None:
        return s + 1, s + 1
    e = next(i for i, l in enumerate(lines) if i > s and end_text in l)
    return s + 1, e  # e es 0-based de la línea end_text => la anterior en 1-based


def snippet(rel: str, a: int, b: int) -> dict:
    lines = src(rel)[a - 1 : b]
    while lines and not lines[-1].strip():
        lines.pop()
        b -= 1
    # quitar indentación común
    ind = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    code = "\n".join(l[ind:] for l in lines)
    return {"file": rel, "a": a, "b": b, "code": code}


def fn(rel, name):
    return snippet(rel, *node_lines(rel, name))


def btw(rel, s, e):
    return snippet(rel, *between(rel, s, e))


S = "src/service.py"

# --- Pasos del flujo -----------------------------------------------------------------------------
# kind: det = determinista (código fijo, siempre igual); ia = probabilístico (un modelo decide); dato = guarda/lee datos
STEPS = [
    {
        "id": "entrada", "kind": "det", "title": "El ticket entra por la línea de comandos",
        "short": "La persona escribe la consulta y elige proveedor, prompt y moderación.",
        "what": "El programa recibe el texto del cliente desde la terminal. Todavía no se habló con ninguna IA: solo se leen las opciones y se cargan las claves del archivo <code>.env</code>. Lo que el cliente escribió se trata siempre como texto, nunca como una orden.",
        "terms": [("CLI", "Programa que se usa escribiendo comandos en la terminal, sin pantallas ni botones."),
                  ("stdout / stderr", "Dos “salidas” de un programa: por stdout sale el resultado (el JSON); por stderr salen avisos y errores, para no mezclarlos.")],
        "risk": "Acá no hay IA, así que no hay riesgo de modelo. El riesgo es humano: una clave pegada en el código o subida a GitHub.",
        "control": "Las claves viven en <code>.env</code>, que <code>.gitignore</code> excluye del repositorio.",
        "measured": None,
        "code": [fn("src/main.py", "main")],
    },
    {
        "id": "guard_in", "kind": "det", "title": "Guardrail de entrada: patrones de ataque",
        "short": "Busca frases conocidas de manipulación. Si encuentra una, no se llama a la IA.",
        "what": "Antes de gastar una llamada, el código revisa el texto con <em>patrones</em>: reglas que reconocen frases típicas de ataque, como “ignorá tus instrucciones” o “modo desarrollador”. Primero pasa todo a minúsculas y sin tildes, para que “Ignorá” e “ignora” se reconozcan igual. Si hay coincidencia, el ticket va directo a una persona.",
        "terms": [("Guardrail", "“Baranda de seguridad”: un control que frena lo peligroso antes o después del modelo."),
                  ("Prompt injection", "Cuando alguien escribe instrucciones dentro del ticket para que la IA desobedezca sus reglas."),
                  ("Regex (expresión regular)", "Una forma de describir patrones de texto, por ejemplo “una palabra que empieza con ignor seguida de instrucciones”."),
                  ("Determinista", "Que con la misma entrada da siempre la misma salida. Lo opuesto a un modelo de IA.")],
        "risk": "Los patrones solo reconocen frases conocidas. <strong>Medido hoy:</strong> 7 trucos de escritura pasan sin ser detectados (espacio invisible, letras cirílicas, números por letras, letras separadas, base64, portugués y sinónimos).",
        "control": "Hay tests sin IA en <code>tests/test_guardrails.py</code> (13). Lo que se escapa lo tiene que frenar la capa siguiente: el moderador.",
        "measured": "Evals adversariales: los patrones frenaron 6 de 10 ataques, a costo 0 y sin latencia.",
        "code": [fn("src/guardrails.py", "INJECTION_PATTERNS"), fn("src/guardrails.py", "check_input")],
    },
    {
        "id": "cache", "kind": "dato", "title": "Caché: ¿ya respondimos esto?",
        "short": "Si la misma consulta ya se respondió, se devuelve la respuesta guardada.",
        "what": "Se arma una “huella” del pedido con el proveedor, el modelo, la versión del prompt y la consulta normalizada. Si esa huella ya está guardada, se devuelve la respuesta anterior: costo 0 y casi sin espera.",
        "terms": [("Caché", "Memoria de respuestas ya calculadas, para no repetir el trabajo."),
                  ("Hash MD5", "Una función que convierte cualquier texto en un código corto y fijo. Acá sirve de etiqueta, no de seguridad.")],
        "risk": "La huella no incluye el modo de moderación: una respuesta guardada con la moderación apagada se reutiliza con la moderación prendida. Y una respuesta mala, una vez guardada, se repite.",
        "control": "Está documentado como limitación en el README. <strong>No hay test</strong> de la caché (el README lo marca como pendiente).",
        "measured": None,
        "code": [fn("src/cache.py", "make_key"), btw(S, "key = cache.make_key", "# Capa 2 de entrada")],
    },
    {
        "id": "mod_in", "kind": "ia", "title": "Moderador IA de entrada",
        "short": "Una IA aparte puntúa de 0 a 1 si el ticket intenta manipular. No lo responde.",
        "what": "Otra IA (Haiku) recibe el ticket entre etiquetas y <em>solo lo puntúa</em> en tres riesgos: inyección, jailbreak y extracción. Si algún puntaje llega a 0,5, se bloquea. Si el moderador falla o responde mal, el ticket <strong>también</strong> se bloquea: ante la duda, decide una persona.",
        "terms": [("LLM", "Modelo de lenguaje: la IA que lee y escribe texto."),
                  ("Jailbreak", "Intentar que la IA salga de sus reglas con un personaje, una ficción o una falsa autoridad."),
                  ("Fail-closed (falla cerrada)", "Si el control se rompe, el sistema bloquea en vez de dejar pasar."),
                  ("Umbral", "El número desde el cual algo cuenta como riesgo. Acá, 0,5.")],
        "risk": "Es una IA: puede equivocarse en los dos sentidos (dejar pasar un ataque o bloquear un ticket normal). Además el atacante escribe justo lo que el moderador lee.",
        "control": "El modo de falla cerrada, más el guardrail y el moderador de salida después. Se mide con los evals adversariales.",
        "measured": "Frenó 3 de los 4 ataques que pasaron los patrones. Haiku: 0,95 s y 0,000072 USD por llamada (264 llamadas).",
        "code": [fn("src/moderation.py", "SYSTEM_INPUT"), fn("src/moderation.py", "moderate")],
    },
    {
        "id": "prompt", "kind": "det", "title": "Prompt versionado + ticket entre etiquetas",
        "short": "Las instrucciones viven en un YAML; el ticket va encerrado entre <ticket> y </ticket>.",
        "what": "Las instrucciones para la IA no están en el código: están en archivos YAML (<code>v1</code> sin ejemplos y <code>v2</code> con ejemplos). El texto del cliente se coloca dentro de etiquetas <code>&lt;ticket&gt;</code>, y el prompt dice que eso es un dato, no una orden.",
        "terms": [("Prompt / system prompt", "Las instrucciones que recibe la IA. El “system prompt” fija su rol y sus reglas."),
                  ("Zero-shot", "Pedirle la tarea solo con instrucciones, sin ejemplos (v1)."),
                  ("Few-shot", "Darle algunos ejemplos resueltos para que imite el criterio y el formato (v2)."),
                  ("YAML", "Un formato de texto simple para guardar configuración.")],
        "risk": "Las etiquetas ayudan, pero no son una pared: un atacante puede escribir <code>&lt;/ticket&gt;</code> para “cerrar” el dato antes de tiempo.",
        "control": "El patrón <code>etiquetas_falsas</code> del guardrail de entrada bloquea esas etiquetas. Se usa <code>replace</code> y no <code>format</code>, para que las llaves del ticket no rompan la plantilla.",
        "measured": "v1 y v2 aciertan lo mismo (98%), pero v2 manda unas 2 veces más tokens de entrada (Haiku: 1.868 contra 729 de promedio).",
        "code": [fn("src/prompts.py", "Prompt.render_user"), snippet("prompts/v1_zero_shot.yaml", 7, 33)],
    },
    {
        "id": "llm", "kind": "ia", "title": "El modelo responde con salida estructurada",
        "short": "Se llama al proveedor elegido pidiéndole un JSON con un esquema fijo.",
        "what": "Se le manda a la IA el prompt y el ticket, y se le exige responder con una forma exacta: un JSON con <code>answer</code>, <code>confidence</code>, <code>category</code> y <code>actions</code>. El razonamiento interno va apagado o bajo, porque sus tokens se comían el tope y cortaban la respuesta.",
        "terms": [("Proveedor", "La empresa que ofrece el modelo por internet (Anthropic, Groq). Los dos se usan con la misma interfaz."),
                  ("Salida estructurada", "Obligar al modelo a responder con un formato fijo (un esquema JSON), en vez de texto libre."),
                  ("Token", "Pedacito de texto (más o menos media palabra). Se cobra y se limita por tokens."),
                  ("MAX_TOKENS", "El máximo de tokens que puede escribir el modelo en una respuesta. Acá, 500."),
                  ("Temperature", "Cuánto varía la respuesta. 0 = lo más estable posible.")],
        "risk": "La IA puede clasificar mal, inventar, prometer cosas o seguir una orden escondida en el ticket. Antes del arreglo, 17 respuestas salieron cortadas justo en 500 tokens.",
        "control": "La validación del paso siguiente, los guardrails de salida y los evals (40 casos etiquetados a mano).",
        "measured": "Haiku v1: 2,03 s y 0,00021 USD por llamada. Groq gpt-oss-120b v1: 1,49 s, gratis. Después del arreglo: 0 respuestas inválidas en 237 llamadas.",
        "code": [fn("src/providers.py", "AnthropicProvider.complete")],
    },
    {
        "id": "validate", "kind": "det", "title": "Validación del contrato y reintentos",
        "short": "Pydantic revisa el JSON; si no cumple, se reintenta hasta 3 veces con el error concreto.",
        "what": "Lo que devolvió la IA se revisa contra el <em>contrato</em>: que la categoría sea una de las cuatro, que la confianza esté entre 0 y 1, que haya al menos una acción. Si algo falla, se le vuelve a preguntar al modelo diciéndole exactamente qué estuvo mal. Después de 3 intentos, el servicio devuelve un error en lugar de inventar.",
        "terms": [("Contrato", "La forma acordada de la respuesta. Si no se cumple, la respuesta no sirve."),
                  ("Pydantic", "Librería de Python que valida que los datos tengan la forma y los tipos esperados."),
                  ("Reintento con feedback", "Volver a pedir, pasando el error, para que el modelo se corrija.")],
        "risk": "Un JSON válido puede ser igual de incorrecto: la forma está bien, pero la categoría o la respuesta están mal.",
        "control": "Los evals miden si la categoría es correcta. <strong>No hay test</strong> de los reintentos sin IA (pendiente en el README).",
        "measured": "Reintentos en las corridas finales: 0.",
        "code": [fn("src/schemas.py", "TriageResponse"), fn(S, "call_llm")],
    },
    {
        "id": "guard_out", "kind": "det", "title": "Guardrail de salida: promesas y fugas",
        "short": "Busca promesas (reintegros, plazos) y pedazos del system prompt en la respuesta.",
        "what": "Antes de que la respuesta llegue al cliente, el código busca promesas que solo puede hacer una persona (“te vamos a devolver”, “de inmediato”) y frases copiadas de las instrucciones internas: 8 palabras seguidas iguales cuentan como fuga.",
        "terms": [("Fuga de prompt", "Cuando la IA revela sus instrucciones internas."),
                  ("Promesa indebida", "Comprometer algo (un reintegro, un plazo) que solo puede decidir un agente humano.")],
        "risk": "Solo se revisa <code>answer</code>: <strong>las <code>actions</code> no pasan por este control</strong> (<code>src/service.py</code>, línea 150). Van al agente humano, no al cliente, pero una acción manipulada podría inducirlo a error.",
        "control": "Tests sin IA: las 40 respuestas reales de Groq no deben marcarse. Si se marca algo, el moderador de salida no hace falta.",
        "measured": "Ataque adv-07 con Groq v1: el modelo escribió “le confirmaré el estado de la devolución”. Ningún patrón la reconoció; la frenó el moderador de salida (promesa_indebida = 0,60).",
        "code": [fn("src/guardrails.py", "PROMISE_PATTERNS"), fn("src/guardrails.py", "check_output")],
    },
    {
        "id": "mod_out", "kind": "ia", "title": "Moderador IA de salida",
        "short": "Si los patrones no vieron nada, una IA busca promesas o fugas dichas con otras palabras.",
        "what": "Los patrones no entienden paráfrasis. Un moderador IA puntúa la respuesta en tres riesgos: promesa indebida, fuga interna y obediencia a la inyección. Si marca algo, la respuesta se reemplaza por una genérica y el agente recibe la tarea de redactarla.",
        "terms": [("Paráfrasis", "Decir lo mismo con otras palabras. Los patrones fallan ahí; una IA no tanto."),
                  ("Falso positivo", "Marcar como peligroso algo que no lo era.")],
        "risk": "Falsos positivos: en los evals con Groq marcó 5 respuestas, y algunas parecen normales. Ahí el cliente recibe una respuesta genérica en vez de una útil.",
        "control": "La revisión humana de los casos marcados (el README los analiza uno por uno).",
        "measured": "Haiku: 1,07 s y 0,000088 USD por llamada (205 llamadas). Con el de entrada, el moderador suma unos 0,00016 USD por ticket: el 74% del costo de generar con v1.",
        "code": [btw(S, "flags = check_output(response.answer, prompt.system)", "if use_cache:")],
    },
    {
        "id": "salida", "kind": "dato", "title": "Caché, métricas y JSON final",
        "short": "Se guarda la respuesta, cada llamada queda medida y el JSON sale para el agente.",
        "what": "La respuesta final se guarda en la caché. Cada llamada a una IA dejó antes una línea en <code>data/metrics.jsonl</code> con tokens, tiempo, costo y si cumplió el contrato. El JSON sale por stdout para el agente humano, que es quien decide.",
        "terms": [("JSONL", "Un archivo de texto con un objeto JSON por línea. Se agrega al final, nunca se borra."),
                  ("Métrica", "Un número medido (tiempo, tokens, costo) que permite comparar y decidir con datos."),
                  ("Human in the loop", "Una persona revisa y decide. La IA propone; no ejecuta acciones.")],
        "risk": "Lo que la IA sugiere en <code>actions</code> puede sonar convincente aunque esté mal. El servicio no ejecuta nada, pero una persona apurada podría seguirlo sin pensar.",
        "control": "El contrato dice explícitamente que las acciones son sugerencias. El costo se recalcula con la fórmula y los tokens de cada línea.",
        "measured": "Gasto real de todo el desarrollo en Anthropic: 0,112 USD (1.184 llamadas a IA en total).",
        "code": [fn("src/metrics.py", "log_request")],
    },
]

BRANCHES = {
    "guard_in": "Si encuentra un patrón → respuesta segura + revisión humana (no se llama a la IA)",
    "cache": "Si ya estaba → devuelve la respuesta guardada",
    "mod_in": "Si hay riesgo o el moderador falla → respuesta segura + revisión humana",
    "validate": "Si falla → reintenta (hasta 3). Si falla 3 veces → error",
    "guard_out": "Si encuentra algo → reemplaza el answer",
    "mod_out": "Si marca riesgo → reemplaza el answer",
}

KIND = {"det": ("Código fijo", "Siempre hace lo mismo. Se puede testear exacto."),
        "ia": ("IA", "Decide un modelo. Puede variar y equivocarse."),
        "dato": ("Datos", "Guarda o lee información.")}

MERMAID = """flowchart TD
  A["Ticket del cliente"] --> B{"Guardrail de entrada<br/>patrones"}
  B -- "vacío o muy largo" --> E1["Error"]
  B -- "patrón de ataque" --> S1["Respuesta segura<br/>y revisión humana"]
  B -- "ok" --> C{"¿Está en la caché?"}
  C -- "sí" --> OUT["JSON para el agente humano"]
  C -- "no" --> D{"Moderador IA<br/>de entrada"}
  D -- "riesgo o falla" --> S1
  D -- "ok" --> P["Prompt YAML<br/>+ ticket entre etiquetas"]
  P --> L["Modelo LLM<br/>salida estructurada"]
  L --> V{"Validación<br/>del contrato"}
  V -- "inválido: reintento" --> L
  V -- "3 fallos" --> E2["Error"]
  V -- "válido" --> G{"Guardrail de salida<br/>patrones"}
  G -- "promesa o fuga" --> R["Reemplazar el answer"]
  G -- "ok" --> M{"Moderador IA<br/>de salida"}
  M -- "riesgo" --> R
  M -- "ok" --> K["Guardar en caché"]
  R --> K
  K --> OUT
"""

RUN = [
    ("Instalar", "python -m venv .venv\n.venv\\Scripts\\Activate.ps1      # Windows\npip install -r requirements.txt\ncp .env.example .env              # y completar las claves"),
    ("Clasificar un ticket", 'python -m src.main "me cobraron dos veces la suscripción"'),
    ("Elegir proveedor, prompt y moderación", 'python -m src.main "no puedo entrar" --provider anthropic --prompt v2 --moderation off'),
    ("Correr los evals (40 casos)", "python evals/runner.py --provider groq --prompt v1"),
    ("Correr los ataques (10)", "python evals/adversarial_runner.py --provider groq --prompt v1"),
    ("Tests sin IA (costo 0)", "python tests/test_guardrails.py"),
]

HEURISTICS = [
    ("Separá lo fijo de lo que decide la IA", "Los pasos de código fijo se testean con certeza. Los pasos de IA se miden con evals: muchos casos y un porcentaje, nunca una sola prueba."),
    ("Defensa en capas", "Ninguna capa alcanza sola: patrones (baratos, rígidos) + moderador IA (entiende paráfrasis, se equivoca) + revisión humana."),
    ("Falla cerrada", "Si un control se rompe, que bloquee. El costo es una respuesta genérica; el beneficio, que no se escape nada."),
    ("Medí antes de cambiar", "Cada decisión de este proyecto tiene un número detrás: tokens, latencia, costo, aciertos. Sin dato, es opinión."),
    ("Test exploratorio", "Probá a mano cosas que nadie anotó: tildes raras, otros idiomas, textos larguísimos, emojis. Así aparecieron los 7 trucos que pasan los patrones."),
    ("La IA propone, la persona decide", "El servicio nunca ejecuta acciones. Si alguna vez lo hiciera, cada acción necesitaría su propio control."),
]


def e(t):
    return html.escape(t, quote=True)


def code_block(sn):
    gh = f"https://github.com/saragismondi/pi-m1-ia-engineer/blob/main/{sn['file']}#L{sn['a']}-L{sn['b']}"
    return (f'<figure class="code"><figcaption><span class="path">{e(sn["file"])}</span>'
            f'<span class="lines">líneas {sn["a"]}–{sn["b"]}</span>'
            f'<a href="{gh}" target="_blank" rel="noopener">ver en GitHub</a></figcaption>'
            f'<pre><code>{e(sn["code"])}</code></pre></figure>')


def step_html(i, st):
    kind_label, kind_tip = KIND[st["kind"]]
    terms = "".join(f'<div class="term"><dt>{e(t)}</dt><dd>{d}</dd></div>' for t, d in st["terms"])
    measured = f'<div class="box measured"><h4>Dato medido</h4><p>{st["measured"]}</p></div>' if st["measured"] else ""
    codes = "".join(code_block(c) for c in st["code"])
    branch = f'<span class="branch"><span class="arrow" aria-hidden="true">↳</span>{e(BRANCHES[st["id"]])}</span>' if st["id"] in BRANCHES else ""
    return f'''
<li class="step k-{st["kind"]}" id="{st["id"]}">
  <div class="rail" aria-hidden="true"><span class="num">{i}</span></div>
  <details class="card">
    <summary>
      <span class="chip c-{st["kind"]}" title="{e(kind_tip)}">{kind_label}</span>
      <span class="stitle">{e(st["title"])}</span>
      <span class="sshort">{e(st["short"])}</span>
      {branch}
      <span class="open-hint">Ver explicación y código</span>
    </summary>
    <div class="body">
      <div class="cols">
        <div class="col">
          <h4>Qué hace, en simple</h4>
          <p>{st["what"]}</p>
          <h4>Palabras técnicas</h4>
          <dl class="terms">{terms}</dl>
        </div>
        <div class="col">
          <div class="box risk"><h4>Qué puede salir mal</h4><p>{st["risk"]}</p></div>
          <div class="box control"><h4>Quién lo controla</h4><p>{st["control"]}</p></div>
          {measured}
        </div>
      </div>
      <details class="codewrap"><summary>Mostrar el código real de este paso</summary>{codes}</details>
    </div>
  </details>
</li>'''


steps = "".join(step_html(i + 1, s) for i, s in enumerate(STEPS))
runs = "".join(f'<div class="run"><h4>{e(t)}</h4><pre><code>{e(c)}</code></pre></div>' for t, c in RUN)
heur = "".join(f'<li><strong>{e(t)}</strong><span>{e(d)}</span></li>' for t, d in HEURISTICS)
glossary = {}
for s in STEPS:
    for t, d in s["terms"]:
        glossary.setdefault(t, d)
gloss = "".join(f'<div class="term"><dt>{e(t)}</dt><dd>{d}</dd></div>' for t, d in sorted(glossary.items(), key=lambda x: x[0].lower()))

page = (Path(__file__).parent / "diagram_template.html").read_text(encoding="utf-8")
page = (page.replace("{{STEPS}}", steps).replace("{{MERMAID}}", e(MERMAID))
            .replace("{{RUN}}", runs).replace("{{HEUR}}", heur).replace("{{GLOSS}}", gloss)
            .replace("{{NSTEPS}}", str(len(STEPS))).replace("{{NTERMS}}", str(len(glossary))))
OUT.write_text(page, encoding="utf-8")
print("ok", OUT, len(page), "bytes;", len(STEPS), "pasos;", len(glossary), "términos")

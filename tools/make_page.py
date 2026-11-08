"""Genera index.html (página completa para GitHub Pages) a partir del código real del proyecto.

Uso, desde la carpeta triage-nubbix-diagrama:
    python tools/make_page.py ../pi-m1-ia-engineer

Pasos:
  1. tools/build_diagram.py lee el código del proyecto y arma artifact.html (formato de Artifact de
     claude.ai: sin <!doctype>, <html> ni <body>, porque claude.ai los agrega al publicar).
  2. Este script envuelve ese contenido en una página HTML completa y agrega Mermaid, la librería que
     dibuja el mapa de flechas (en claude.ai viene incluida; en GitHub Pages hay que cargarla).
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MERMAID_URL = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python tools/make_page.py <ruta al repo pi-m1-ia-engineer>", file=sys.stderr)
        return 1
    repo = Path(sys.argv[1]).resolve()
    artifact = ROOT / "artifact.html"
    subprocess.run([sys.executable, "-I", str(HERE / "build_diagram.py"), str(repo), str(artifact)], check=True)

    content = artifact.read_text(encoding="utf-8")
    split = content.index('<div class="wrap">')
    head, body = content[:split].strip(), content[split:].strip()
    # La meta de Artifact no aplica fuera de claude.ai.
    head = head.replace('<meta name="claude:viewport-fit-sides" content="cover">\n', "")

    page = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="description" content="Recorrido pedagógico del triage de soporte con LLMs: cada paso explicado en simple, con riesgos de la IA, controles humanos y el código real.">
{head}
</head>
<body>
{body}
<script src="{MERMAID_URL}"></script>
<script>
  // Mermaid dibuja el mapa. El tema sigue el modo claro u oscuro del sistema.
  const dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  mermaid.initialize({{ startOnLoad: true, securityLevel: "strict", theme: dark ? "dark" : "neutral" }});
</script>
</body>
</html>
"""
    (ROOT / "index.html").write_text(page, encoding="utf-8")
    print("ok: index.html", len(page), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

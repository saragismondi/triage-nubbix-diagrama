# Triage Nubbix por dentro

Diagrama interactivo y pedagógico del proyecto
[saragismondi/pi-m1-ia-engineer](https://github.com/saragismondi/pi-m1-ia-engineer) (Proyecto Integrador M1,
Henry). Muestra el recorrido de un ticket de soporte paso a paso. Cada paso trae:

- qué hace, en simple;
- las palabras técnicas, explicadas;
- qué puede salir mal con la IA;
- quién lo controla;
- un dato medido;
- **el código real**, extraído del repositorio.

## Archivos

| Archivo | Qué es |
|---|---|
| `index.html` | La página completa. Es la que publica GitHub Pages. |
| `artifact.html` | La misma página en formato Artifact de claude.ai (sin `<!doctype>` ni `<body>`). |
| `tools/build_diagram.py` | Lee el código de `pi-m1-ia-engineer` y arma los pasos con los fragmentos reales. |
| `tools/diagram_template.html` | Diseño de la página: estilos y estructura. |
| `tools/make_page.py` | Genera `index.html` a partir de los dos anteriores. |
| `.nojekyll` | Le indica a GitHub Pages que publique los archivos tal cual, sin procesarlos. |

## Regenerar la página

Si cambia el código del proyecto, los fragmentos se actualizan solos (no hay código copiado a mano):

```bash
python tools/make_page.py ../pi-m1-ia-engineer
```

Requiere Python 3.10 o superior, sin dependencias extra.

## Publicar en GitHub Pages

1. Crear un repositorio público en GitHub (por ejemplo, `triage-nubbix-diagrama`) y subir esta carpeta a la rama `main`.
2. En el repositorio: **Settings → Pages → Build and deployment → Source: Deploy from a branch**.
3. Elegir **Branch: `main`** y carpeta **`/ (root)`**, y guardar.
4. A los pocos minutos queda en `https://saragismondi.github.io/triage-nubbix-diagrama/`.

La página carga dos cosas de internet: las fuentes de Google Fonts y Mermaid (la librería que dibuja el mapa)
desde jsDelivr, versión fija 11.4.1.

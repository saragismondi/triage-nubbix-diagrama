# Triage Nubbix por dentro

**Página publicada:** https://saragismondi.github.io/triage-nubbix-diagrama/

Explicación interactiva y pedagógica del proyecto
[saragismondi/pi-m1-ia-engineer](https://github.com/saragismondi/pi-m1-ia-engineer) (Proyecto Integrador M1
de AI Engineering, Henry): un servicio que recibe un ticket de soporte de Nubbix, lo clasifica con un LLM y le
propone una respuesta a un agente humano, con varias capas de seguridad.

El objetivo no es mostrar código, sino **entender el proceso** para poder vigilar lo que una IA hace sola:
dónde decide código fijo y dónde decide un modelo, qué puede salir mal en cada paso y quién lo controla.

## Qué tiene la página

| Sección | Qué muestra |
|---|---|
| **El mapa** | Diagrama de flujo con todos los desvíos: bloqueos, alcance, reintentos, reemplazos y errores. |
| **Seguí un ticket** | 14 paradas del recorrido. Elegís uno de 7 tickets reales (un reclamo normal, un ataque disfrazado, un pedido ajeno, una inyección escondida, datos personales, ingeniería social…) y la página marca por dónde pasa y dónde sale. |
| **Cada parada** | Qué hace en simple, palabras técnicas, qué puede salir mal, quién lo controla, el dato medido, qué test lo prueba y el código real. |
| **Qué frena cada capa** | Tabla con lo que frenó cada defensa en las pruebas, y cuánto cuesta. |
| **Lo que aprendimos rompiendo cosas** | 8 errores reales del proyecto: qué pasó, cómo se notó, qué se hizo y la lección. |
| **Cómo se prueba** | De los tests gratis en cada push a la revisión independiente. |
| **Cómo vigilar a la IA** | Las heurísticas que atraviesan el proyecto. |
| **Glosario** | 66 términos en 5 temas, cada uno con un ejemplo de este proyecto. |

## De dónde sale el contenido

- **El código** de cada parada se extrae automáticamente del repositorio del proyecto (con `ast`). No hay código
  copiado a mano, y los links a GitHub quedan fijados al commit del que se extrajo.
- **Los recorridos** calculan sus pasos deterministas llamando a las funciones reales del proyecto
  (`check_input`, `check_scope`, `redact`, `required_verification`). Lo que decidió una IA se cita de pruebas
  reales con Haiku, con la fuente al pie.
- **Los números** salen de `data/metrics.jsonl` y `evals/results/` del proyecto.

## Archivos

| Archivo | Qué es |
|---|---|
| `index.html` | La página completa. Es la que publica GitHub Pages. |
| `artifact.html` | La misma página en formato Artifact de claude.ai (sin `<!doctype>` ni `<body>`). |
| `tools/build_diagram.py` | El contenido pedagógico (pasos, recorridos, lecciones, glosario) y la extracción del código real. |
| `tools/diagram_template.html` | El diseño: estilos, estructura y el script de "Seguí un ticket". |
| `tools/make_page.py` | Genera `index.html` y agrega Mermaid, la librería que dibuja el mapa. |
| `.nojekyll` | Le indica a GitHub Pages que publique los archivos tal cual. |

## Regenerar la página

Con el repositorio del proyecto clonado al lado y su entorno virtual:

```bash
python tools/make_page.py ../pi-m1-ia-engineer
```

Requiere Python 3.10 o superior. Usa solo la biblioteca estándar y el código del proyecto (que no necesita
claves de API para esto: no llama a ninguna IA).

La página carga dos cosas de internet: las fuentes de Google Fonts y Mermaid desde jsDelivr, versión fija 11.4.1.

---
bloque: velociraptor-linux
nombre: Velociraptor "virgen" sobre Linux — diseño de V0 (laboratorio) y V1 (medida)
version: 1
status: pending_human
fecha: 2026-11-15
autor: claude
rama: bloque/velociraptor-linux-diseno
depende_de: >-
  `_fases/reencuadre/plan.md` §8 (plan de Velociraptor) · `Soporte/Metrica/metrica_hids.md` §10
  (comparabilidad) · `Soporte/Metrica/boveda_congelacion.md` B1/B3/B5/B6 · TFM hermano
  «Evaluación de Velociraptor como HIDS…» (J. García-Amorena, mismo tutor) · Wazuh Linux cerrado
  (`legitimo-v3`, M1b, L2) · `prestaging_material.md` de GHOSTS (convención de material fuera del repo)
no_toca: >-
  Todo lo existente. Este bloque solo añade `_fases/velociraptor-linux/` y, cuando se apruebe,
  `Soporte/Velociraptor/`. No se arranca ninguna VM ni se descarga nada hasta que el humano apruebe.
ejecuta_ahora: NADA. Documento de diseño.
---

# plan.md — Velociraptor virgen sobre Linux (V0 + V1) · diseño

> **Convención:** **[H]** hecho con fuente · **[D]** decisión propuesta (con alternativa) ·
> **[V]** cosa que **no se puede afirmar desde aquí** y se **verifica en V0** (no se inventa).

---

## 0. En fácil

1. **Velociraptor no es una alarma como Wazuh.** Es una herramienta de investigación: recoge datos
   y los devuelve. Casi todo lo que trae "de fábrica" **registra** lo que pasa; muy poco **avisa**.
2. Por eso medir "¿detecta?" como en Wazuh **no vale tal cual**: si contáramos cada fila como una
   alerta, saldría "detecta el 100 %" (y un montón de falsos positivos), y no significaría nada.
3. **Propuesta:** medir **tres cosas por separado**, igual que hizo el TFM hermano:
   **visibilidad** (¿quedó registrado el ataque?), **detección** (¿lo marca como sospechoso?) y
   **falsos positivos** (¿qué marca en lo normal?).
4. **Lo que se espera con Linux "de fábrica":** mucha visibilidad y **poca o ninguna detección**.
   Eso **no es un fallo del diseño**: es el resultado (Velociraptor es una plataforma, no un HIDS
   listo para usar). El TFM hermano ya lo concluye para Windows.
5. **Sorpresa importante:** el TFM hermano es **solo de Windows**. No hay ninguna referencia suya
   para Linux: los artifacts de Linux hay que descubrirlos nosotros en V0.
6. **Montaje propuesto:** servidor en tu PC (ligero), cliente en `victima-linux`, **sin Wazuh
   instalado** en esa víctima durante las medidas de Velociraptor, y **el mismo auditd** que usó
   Wazuh para que la telemetría de partida sea idéntica.
7. **Se guarda todo** (cada fila que devuelva cualquier artifact, con hash), para poder reevaluar
   después sin repetir.
8. **Coste:** V0 ≈ 1–2 días; V1 (55 ataques × 2) ≈ 2–3 días; ventana legítima 72 h aparte.
   **Nada empieza hasta que el humano lo apruebe** (y no durante el ensayo/ventana de Windows).

---

## 1. Qué sabemos y qué no

### 1.1 Del TFM hermano (resumen leído; páginas impresas)

| Dato | Valor |
|---|---|
| Sistema | **Windows 10** en una sola VM; **no aparece la palabra «Linux»** en todo el documento (pp. 25, 103) |
| Casos | **9 técnicas** (TEC-001…009), una de ellas agrupa tres (p. 24) |
| Definición de detección | seis niveles: visibilidad, detección, alerta en tiempo real, salida externa, evidencia, ruido/FP. **Un evento visible NO es detección** (Tabla 11, p. 19) |
| Cómo se obtuvo | **Monitorización continua en el cliente** (artifacts `CLIENT_EVENT`); **no** usó hunts ni colecciones como método de detección (pp. 58-59) |
| Resultado | Velociraptor **público** 3/9 (solo Hayabusa «CH»), **custom** 9/9; Wazuh base 3/9, custom 4/9 (pp. 61, 81, 120) |
| Falsos positivos | solo para el custom: 10 pruebas benignas, 0 hits, **«no extrapolable»** (pp. 51-53, 88) |
| Perfiles | P1 Critical · P2 High/Forensic · P3 Medium/Behavioral · P4 Low/Basic; mapeo a Wazuh: P1=13–15, P2=10–12, P3=7–9, P4=3–6 (Tabla 60, p. 120) |
| Limitaciones que reconoce | una sola VM, 9 técnicas; **artifacts ajustados sobre el mismo conjunto de prueba, sin validación ciega**; comparación **asimétrica** con Wazuh; «no listo para producción» (pp. 59, 123-126) |
| Advertencia útil | **Wazuh registra la actividad del propio Velociraptor** (p. 121) ⇒ corridas **por separado** |

### 1.2 Lo que NO sabemos aún **[V]**

- Los **artifacts públicos de Linux** que existen **en la versión que fijemos** y cuáles **clasifican**
  (detección) frente a cuáles solo **recogen** (telemetría). Candidatos de la documentación
  oficial: `Linux.Events.ProcessExecutions`, `Linux.Events.TrackProcesses`, `Linux.Events.SSHLogin`,
  `Linux.Events.SSHBruteforce`, `Linux.Events.DNS`, `Linux.Events.HTTPConnections`,
  `Linux.Events.Journal`, `Linux.Events.EBPF`; de recolección: `Linux.Detection.AnomalousFiles`,
  `Linux.Detection.Yara.*` (necesita reglas Yara: **ya sería «propia»**). **No se da ninguno por
  bueno hasta listarlos en el servidor real** (`artifacts list`).
- Si `ProcessExecutions` usa **auditd** o **eBPF** (esto decide la paridad de telemetría con Wazuh).
- Cuánto **volumen** de filas genera Linux «de fábrica» (afecta a disco y a la unidad de medida).

---

## 2. Decisiones de diseño

| # | Decisión **[D]** | Por qué | Alternativa |
|---|---|---|---|
| **D1** | **Servidor en el PC anfitrión (Windows)**, **cliente en `victima-linux`** | Evita una VM más (el PC tiene 16 GB y Wazuh ya usa 2 VMs); el servidor es un ejecutable ligero | Servidor en una VM Linux nueva (más fiel a producción, más RAM) |
| **D2** | **Versión fijada en el pre-staging** (hoy la documentación oficial anuncia la **0.77.3**, 2026-10-05, y pide actualizar «para corregir varias vulnerabilidades (CVE)»; la 0.77.2 ya corregía fallos de autorización; el TFM hermano usó 0.75.6) | Reproducibilidad (B1) y seguridad. Se confirma en la página de *releases* al descargar | 0.75.6 para coincidir con el hermano (menos seguro; no recomendado) |
| **D3** | **Sin Wazuh en la víctima durante las corridas de VR** (snapshot nuevo `lab-listo-vr` desde `base-limpia`) | Decisión ya tomada («corridas por separado») y respaldada por el hermano (p. 121) | Ambos a la vez (ahorra 72 h, pero se ensucian mutuamente: requiere OK del tutor) |
| **D4** | **Misma telemetría de partida: el mismo auditd** (`auditd_tfg.rules`, B3) | «Virgen» = reglas de fábrica; **auditd es fuente, no regla** (B6). Así la diferencia entre HIDS es la **lógica de detección**, no los datos | Dejar auditd por defecto (menos comparable) |
| **D5** | **Tres niveles de resultado** (visibilidad · detección · FP), iguales que el TFM hermano | Evita el absurdo «100 % de TPR» y es comparable con Wazuh (ver §3) | Solo «detección» (hundiría a VR sin justicia) |
| **D6** | **Detección continua en el cliente** (artifacts `CLIENT_EVENT`), no hunts a posteriori | Es lo equivalente a un HIDS que vigila; es lo que hizo el hermano | Añadir hunts como segunda vía (se declara aparte) |
| **D7** | **Los 55 casos de Linux, con doble iteración** (iter1 canónica, iter2 control), **la misma «ventana de ataque»** que en Wazuh | Misma unidad por técnica ⇒ comparable | Subconjunto piloto (solo para el piloto) |
| **D8** | **Un único modo de lanzar los ataques para todos los HIDS** (decisión del humano, ver Q2) | Evita el efecto «envoltorio SSH» que ya vimos en Windows (plan de la ventana, M-22/M-23) | Mantener SSH como en Wazuh (comparable, con el artefacto declarado) |
| **D9** | **Se guarda todo**: cada fila de **cada** artifact (también los de telemetría), logs del cliente y definiciones exactas, con `sha256` y fuera del repo | Prioridad del humano; permite reevaluar sin repetir | — |
| **D10** | **Diseñar custom (V2) con validación ciega**: un subconjunto para **crear** artifacts y el resto para **evaluarlos** | Es la **limitación que el propio hermano reconoce** (ajustó y midió sobre lo mismo) | Todo sobre todo (resultado inflado) |

---

## 3. Qué se mide y cómo se compara con Wazuh

### 3.1 Los tres niveles (por caso `ATA<NNN>`)

| Nivel | Pregunta | Wazuh | Velociraptor |
|---|---|---|---|
| **Visibilidad** | ¿Quedó **registrado** el ataque? | `archives` contiene las **anclas** del caso (exe/línea de comandos) | alguna fila de **cualquier** artifact público contiene las **mismas anclas** en la ventana |
| **Detección** | ¿Lo **marca** como sospechoso sin que nadie lo investigue? | alerta de severidad ≥ N **no ruido** en la ventana (como hoy) | fila de un artifact **de detección** (clasifica) en la ventana, **asociable al caso** |
| **FP** | ¿Qué marca en lo normal? | `FP_uni` y `FPR` (per-HIDS) | filas de artifacts **de detección** en la ventana legítima |

- **Reutiliza lo que ya tenemos:** las **anclas** de cada caso (`*_esperado`), la ventana canónica y la
  doble iteración. La visibilidad de Wazuh se medirá con `archives` **cuando se repitan los ataques
  con `logall_json=yes`** (hoy no hay `archives` de ataques).
- **Unidad común entre HIDS** (ya fijada en `metrica_hids.md` §10): **por técnica** (SÍ/NO), y
  **`FP/acción` y `FP/hora`** en lo legítimo. **Nunca** «eventos» en crudo (no son comparables).
- **Puente de severidad** (solo para la fase `+custom`, V2): P1–P4 ↔ niveles de Wazuh con la Tabla 60
  del hermano (declarada como **aproximada**, como hace él).

### 3.2 Qué es «artifact de detección» **[V]**

Se decide **en V0, mirando el servidor real**, con una regla escrita **antes** de ver resultados:
un artifact público cuenta como «de detección» si su definición (descripción/etiquetas) dice que
**clasifica o alerta**, y como «de telemetría» si solo **recoge**. La lista queda en
`inventario_artifacts_linux.csv` (con `sha256` de cada definición) y **se congela** antes de medir
(B1/B5). Lo dudoso se anota como `dudoso` y **no se cuenta** como detección.

### 3.3 Qué esperamos (para no sorprendernos)

- Visibilidad **alta** (los artifacts de procesos/red/SSH ven casi todo lo que se ejecuta).
- Detección **muy baja** de fábrica en Linux (en Windows el hermano solo llegó a 3/9 y **gracias a
  Hayabusa**, que es de Windows; en Linux no hay equivalente).
- FP **no comparable en crudo** (los artifacts de telemetría emiten una fila por evento).
- Todo esto se **declara como hallazgo**, no como defecto del montaje.

---

## 4. Bloques

| Bloque | Qué hace | Criterio de aceptación | Estimación |
|---|---|---|---|
| **V0a — pre-staging** | Descargar el binario (con NAT del host encendido, como GHOSTS), calcular `sha256`, guardarlo **fuera del repo** en `D:\TFG-VMs\material-velociraptor\`; sidecar `prestaging_material.md` (URL, tamaño, `sha256`, versión). **La configuración del servidor (`server.config.yaml`) contiene claves privadas: NUNCA al repo** (solo su `sha256`) | binario y sidecar con hash; versión anotada en B1 | 1 h |
| **V0b — laboratorio** | Servidor en el host; cliente en `victima-linux` (servicio); snapshot **`lab-listo-vr`** desde `base-limpia` + auditd (B3) + GHOSTS (para el legítimo) + cliente VR; **sin Wazuh**; red aislada | cliente inscrito; se recoge 1 artifact de prueba; `ip route` sin salida; snapshot creado y revertible | 0,5–1 día |
| **V0c — inventario** | Listar los artifacts de Linux **reales** (`artifacts list`), clasificarlos (detección / telemetría / dudoso), medir su volumen en reposo 1 h, y **comprobar de dónde leen** (auditd/eBPF/journal) | `inventario_artifacts_linux.csv` con `sha256` de cada definición; criterio de clasificación escrito **antes** | 0,5 día |
| **V0d — piloto** | 6 casos (2 por cada táctica del alcance: Impact, Exfiltration, Collection) × 2 iteraciones: ver que las anclas aparecen, que la extracción es determinista y fijar el formato de salida | extracción reproducible; formato congelado; **se descartan estos casos como «de desarrollo» para V2** | 0,5 día |
| **V1 — medida** | Los **55 casos × 2** con la configuración congelada; extracción determinista de filas por ventana; tres niveles por caso | T2/T4-VR (Linux); `sha256` por fichero; crudo íntegro guardado | 2–3 días |
| **V1-L — legítimo** | Ventana **72 h** con la **misma receta Linux** (504 acciones) y solo el cliente VR | FP por **acción y hora**; crudo íntegro | 3 días de reloj |
| **V2 — custom (contingente)** | Artifacts propios P1–P4 con **validación ciega** (D10) | eje `+custom`, medido solo sobre los casos **no** usados para diseñar | gate |

> **Orden:** V0a → V0b → V0c → V0d → (congelar) → V1 → V1-L → análisis. **No** se solapa con la
> ventana de Windows (RAM) ni con el ensayo.

---

## 5. Qué se guarda (todo)

| Qué | Dónde | Cómo se verifica |
|---|---|---|
| **Todas las filas de todos los artifacts** (por día y por cliente), en bruto | `D:\TFG-VMs\crudo-velociraptor\` | `sha256` por fichero + `MANIFEST.tsv` |
| **Definiciones exactas de los artifacts** usados (texto completo) | idem | `sha256` por definición |
| Logs del servidor y del cliente; versión del binario | idem | `sha256` |
| Ground truth de cada caso (anclas, ventana UTC, comandos) | repo (`Dataset/Ataques/…`, ya existe) | huella existente |
| `server.config.yaml` y claves | **fuera del repo**; solo `sha256` | — |

**Regla dura (ya vigente):** el crudo se copia **antes** de revertir cualquier snapshot.

---

## 6. Riesgos

| # | Riesgo | Mitigación |
|---|---|---|
| R1 | **Pocos artifacts de detección en Linux** ⇒ resultado «casi nada» | Es el hallazgo esperado; se declara y se acompaña de la visibilidad |
| R2 | **Comparación asimétrica** (paradigma distinto) | Tres niveles + comparación **por técnica** + declararlo (lo hace el hermano, p. 126) |
| R3 | **Telemetría distinta** entre HIDS | D4 (mismo auditd) y declarar lo que no se pueda igualar |
| R4 | **Ajustar los custom sobre los mismos casos** que se evalúan | D10 (validación ciega) |
| R5 | **El modo de lanzar el ataque ensucia** (efecto SSH) | D8/Q2: decidir **una vez** para todos |
| R6 | **Claves del servidor en el repo** | `.gitignore` + comprobación en el cierre del bloque; **0 secretos** |
| R7 | **Vulnerabilidades del servidor** (hay avisos de seguridad en versiones anteriores) | Versión reciente (D2); servidor solo en la red aislada y en `localhost` |
| R8 | **RAM** si coinciden con otra ventana | No se solapan; servidor en el host (D1) |
| R9 | **El volumen de filas satura disco** | Medirlo en V0c antes de V1; guardar comprimido |

---

## 7. Preguntas (cortas)

| # | Pregunta | Recomendación |
|---|---|---|
| **Q1** | ¿Servidor en el PC (D1) o en una VM? | **En el PC** |
| **Q2** | **¿Cómo se lanzan los ataques** en las repeticiones (Wazuh con `logall` y Velociraptor)? Una sola forma para todos | Una orden local en la víctima disparada por `systemd-run` (el SSH solo la inicia), para que el «padre» sea el mismo en todos los HIDS |
| **Q3** | ¿Ventanas legítimas separadas (Wazuh / VR) o **una sola con ambos**? | **Separadas** (ya decidido); preguntar al tutor si bastaría una |
| **Q4** | ¿Se aprueba medir **tres niveles** (visibilidad / detección / FP)? | **Sí** |
| **Q5** | ¿Se aprueba la versión **más reciente** (0.77.x) en vez de la del hermano? | **Sí** (seguridad) |

---

## 8. Fuentes

- TFM hermano «Evaluación de Velociraptor como HIDS…» (`_recursos/reuniones/03/`): resumen con páginas impresas citadas arriba.
- Documentación oficial de Velociraptor (consultada 2026-11-15): <https://docs.velociraptor.app/> ·
  notas de versión 0.77 <https://docs.velociraptor.app/blog/2026/2026-05-31-release-notes-0.77/> ·
  aviso 0.77.2 <https://docs.velociraptor.app/announcements/advisories/v0-77-2/> ·
  monitorización de clientes <https://docs.velociraptor.app/docs/clients/monitoring/> ·
  artifacts de evento <https://docs.velociraptor.app/tags/client-event-artifact> ·
  artifacts de cliente <https://docs.velociraptor.app/tags/client-artifact>.
- Nombres de artifacts: **candidatos de la documentación**, a verificar en V0c con el servidor real.

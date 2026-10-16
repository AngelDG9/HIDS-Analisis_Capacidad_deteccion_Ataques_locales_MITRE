---
bloque: reencuadre
nombre: Reencuadre del TFG tras la 2ª reunión con el profesor (REVISIÓN A FONDO · v2)
version: 2
status: approved_by_human
fecha: 2026-10-16
fecha_aprobacion: 2026-10-16
aprobado_por: humano
autor: tfg-planner
gate: |
  **APROBADO (2026-10-16).** Respuestas del humano al gate:
  · Q1 marco → **SÍ**. · Q2 unidad → **evento** (titular) + **acción/hora** (comparación entre HIDS). · Q3 reglas/artifacts propios → **virgen primero; decidir después**.
  · Q4 GHOSTS + 72 h → **SÍ** (+ plan B). · Q5 internet → **lab aislado + internet local**. · Q6 Windows → **después de Linux, paso a paso**.
  · Q7 InfoStealer → **fuera** ("a decidir"). · Q8 Tabla 1 (v17) + 3 discrepancias → **SÍ**. · Q9 orden (legítimo 72 h primero; M1b re-recorte) → **SÍ**.
  · **Q10 (nueva)**: las corridas de legítimo son **POR SEPARADO** (un HIDS a la vez, sin el otro instalado) — como los hermanos.
  · **Q11 (nueva)**: **orden = Linux Wazuh → Windows Wazuh → Velociraptor (Linux y Windows)**; **no mezclar HIDS**.
---

# plan.md — Bloque `reencuadre` (v2)

> **Qué es este documento.** No es la ejecución: es el **plan** (arquitectura, métrica,
> estructura de tablas, secuencia de bloques y criterios de aceptación) del **reencuadre del
> TFG** tras la 2ª reunión con el profesor. Este bloque **no modifica el laboratorio ni el
> corpus**: produce este plan y (en ejecución, tras el gate) la reescritura de los documentos
> base y la especificación congelada de la métrica y las tablas.
>
> **Regla dura:** ningún bloque del programa mide nada hasta que la **métrica y las tablas**
> estén **congeladas** (bloque `reencuadre-metrica`). Medir antes de congelar invalida el
> resultado.

> ## ⚠️ v2 — qué cambia respecto a v1 (resumen para el revisor)
>
> Material nuevo y encargos nuevos desde v1:
> 1. **Rutas movidas:** el material de la reunión ya **no** está en
>    `C:\Users\angel\Desktop\reunion tfg 2\` sino en **`_recursos/reuniones/03/`** (solo lectura).
>    Corregidas todas las citas de v1.
> 2. **Nueva `Tabla 1 - Matriz MITRE Enterprise v17.xlsx`** (la pidió el humano al profesor).
>    Estudiada **hoja a hoja** e incorporada: es **“la clasificación”** (**Tabla 1 del modelo**).
>    Se **declara su equivalencia** con nuestro corpus v19.1 y **3 discrepancias** (§1.3).
> 3. **Repo hermano NIDS** (`ignmercam/mitre-attack-ids-detection-optimization`, TFG de
>    **Ignacio Merchán**, **mismo tutor**, 2026): estudiado a fondo; su **pipeline de *pruning*
>    con G-Mean = nuestra Tabla 5** (§1.4, §5.5).
> 4. **Los 7 flecos** de las notas: resueltos uno a uno (§2.3).
> 5. **Nota metodológica del humano** sobre el **orden** (¿recalcular ataques antes del nuevo
>    legítimo?): **resuelta** (§10.4).
> 6. **Guía del profesor desactualizada**: reflejada en una tabla “antes/ahora” (§3.4 y §14).
> 7. **Lecciones de los 2 TFMs hermanos** (Jorge Linares — malware Windows con escenario de
>    usuario normal; José M. Peña — ransomware con Velociraptor): extraídas (§1.5).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Contexto, fuentes estudiadas y hallazgos](#1-contexto-fuentes-estudiadas-y-hallazgos)
2. [Objetivo del bloque, alcance y los 7 flecos](#2-objetivo-del-bloque-alcance-y-los-7-flecos)
3. [Objetivos redefinidos del TFG](#3-objetivos-redefinidos-del-tfg)
4. [La métrica nueva, definida con precisión](#4-la-métrica-nueva-definida-con-precisión)
5. [Estructura de las tablas (adaptación de T1–T5)](#5-estructura-de-las-tablas-adaptación-de-t15)
6. [Dimensiones a medir](#6-dimensiones-a-medir)
7. [Plan del legítimo (GHOSTS + 72 h + internet local)](#7-plan-del-legítimo-ghosts--72-h--internet-local)
8. [Plan de Velociraptor](#8-plan-de-velociraptor)
9. [Internet: decisión y alternativa](#9-internet-decisión-y-alternativa)
10. [Secuencia de bloques (orden razonado)](#10-secuencia-de-bloques-orden-razonado)
11. [Riesgos, decisiones abiertas y casos límite](#11-riesgos-decisiones-abiertas-y-casos-límite)
12. [Criterios de aceptación](#12-criterios-de-aceptación)
13. [Gate humano (lenguaje sencillo)](#13-gate-humano-lenguaje-sencillo)
14. [Qué NO entra (fuera de alcance)](#14-qué-no-entra-fuera-de-alcance)
15. [Ficheros que se tocarán](#15-ficheros-que-se-tocarán)
16. [Trazabilidad (fuentes)](#16-trazabilidad-fuentes)

---

## 0. Resumen ejecutivo

El TFG **no se reinicia: se reencuadra**. Lo que ya está hecho (55 ataques P1 en Linux,
laboratorio Wazuh + Windows, metodología de ataque, doble iteración, métrica congelada) **se
reaprovecha**; lo que cambia es **el enfoque del análisis**:

1. **Solo P1** (Impact / Exfiltration / Collection = ransomware / exfiltración / sabotaje).
2. **Solo Wazuh y Velociraptor** (fuera el tercer HIDS).
3. **Virgen primero** en ambos HIDS (sin reglas/artifacts propios); después se **decide** si se
   añaden (pasa a ser un **eje de configuración**, no un "extra si sobra tiempo").
4. **Estructura**: Clasificación → Ataques → Análisis de resultados.
5. **Reaprovechar las 5 tablas del profesor** (T1–T5) + "Requisitos de estudios" + "Leyenda",
   **ahora con la estructura real leída del Excel del profesor** (§5).
6. **La parte legítima cambia de objetivo**: no es "línea base", es **cuánto se equivoca** el
   HIDS en legítimo (**FP/TN y su impacto**). Generada con **acciones reales (GHOSTS)** y **72 h**.
7. **Medir a varios niveles/configuraciones** (`rule.level` en Wazuh; perfiles P1–P4 en VR).
8. **Internet**: se simula en local (**entorno aislado + "internet local" declarada**); la
   alternativa híbrida queda **documentada**, no descartada.
9. **(v2) Tabla 1 (v17) incorporada** como **clasificación** del modelo, con **equivalencia
   declarada** al corpus host v19.1 (§1.3).
10. **(v2) Repo hermano NIDS como referencia metodológica directa**: sus 4 niveles de severidad,
    su GM = √(TPR·TNR), su **pipeline de *pruning*** (Pruning 500/1000, Conservative,
    Generalized Conservative, Aggressive G-Mean) y su doble métrica de alertas
    (**Raw** vs **Flow-correlated**) → **nuestra Tabla 5** (§1.4, §5.5).

**Decisión central del plan (sin cambios):** aprovechar que **el corpus actual YA es una medida
"virgen" de Wazuh** (RS3 y RS4 vacías; cada fila de alerta guarda `rule_level` y `rs_origen`)
para obtener **toda la rejilla virgen × umbral × RS con un recorte determinista** (sin
re-atacar), y reservar la **re-ejecución** solo para las configuraciones `+propias`/`+externas`
(contingentes) y para Velociraptor. El **cuello de botella real** es la **captura legítima de
72 h** (reloj de pared), que debe **arrancarse cuanto antes** tras congelar la métrica.

> **(v2) Matiz de orden (§10.4):** el **recorte de ataques** no depende del legítimo (puede ir
> pronto), pero **el juicio del ruido y las métricas finales SÍ** dependen del **nuevo legítimo
> de 72 h** → los baselines actuales quedan como **"histórico"** y, **tras el legítimo, el
> recorte se RE-EJECUTA** (es determinista y barato).

---

## 1. Contexto, fuentes estudiadas y hallazgos

### 1.1 Fuentes estudiadas (todas verificadas)

**Material de la 2ª/3ª reunión** — **`_recursos/reuniones/03/`** (solo lectura; **corregida** la
ruta de v1, que apuntaba a `C:\Users\angel\Desktop\reunion tfg 2\`, ya inexistente):
- `notas reunion TFG.txt` (notas del humano — 50 líneas) · `ghost.txt` · `tfg interesante.txt`.
- **`Tabla 1 - Matriz MITRE Enterprise v17.xlsx`** *(nueva)* — la clasificación de red de v17
  (10 hojas; ver §1.3).
- `Tablas 2, 3, 4, 5 (con FG-PA).xlsx` — **el modelo de presentación del profesor**. Volcado a
  texto y leído **entero** (21 hojas: `RuleSets`, `Tabla 3 (Legítimo)`, `T2 (At) …`, `T4 (Rend) …`,
  `T5 (Pru) …` en **5 configuraciones** de severidad, `Tabla 2 - Ataques detec (Imple)`,
  `Techniques`, `(A) Ataques`, `(B) Legitimo`). Estructura real transcrita en §5.
- `TFM - Velociraptor como HIDS.pdf` (216 pág., **mismo tutor**) — perfiles P1–P4, artifacts
  públicos vs custom, las **9 técnicas** y la **comparación con Wazuh** (base 3/9, custom 4/9 =
  7/9; Hayabusa 3/9; mapeo de severidad VR↔Wazuh, Tabla 60). Volcado leído.
- `TFM_JORGE_LINARES.pdf` (malware Windows, escenario de **usuario normal**) y
  `TFM_Jose_Manuel_Peña_Ramírez.pdf` (ransomware + Velociraptor). Lecciones en §1.5.
- `Detección_de_Ataques_en_Red_v7.pdf` (246 pág., trabajo NIDS de referencia).

> **Volcados a texto** (válidos, en `C:\Users\angel\AppData\Local\Temp\opencode\`):
> `xlsx_dump.txt`, `tabla1_dump.txt` (nuevo, generado en esta revisión), `ref_dump.txt`, y los
> `.txt` de los PDFs. **No** son artefactos del repo.

**Repo hermano NIDS (GitHub, público)** — **`ignmercam/mitre-attack-ids-detection-optimization`**
(*la URL de las notas, `ignmerca`, da 404; la correcta la trajo el humano*). Es el **TFG de
Ignacio Merchán Cámara**, **mismo tutor** (F. J. Muñoz Calle), **2026**. Estudiado por su README,
su **árbol completo de ficheros** (API de GitHub, 1.223 blobs) y sus **scripts Python** (§1.4).

**Material del profesor en el repo** (`_recursos/`, solo lectura):
- `reuniones/02/guia_profesor.txt` (guía rectora) y `reuniones/02/notas_reunion.txt`.
  *(La reunión `01` está marcada obsoleta.)*
- `recursos_profesor/documentacion-y-scripts-profesor/`: `Detecciones Red (Ref).xlsx`
  (hojas `(A.1) Snort Reglas`, `(A.2) Configuración`, `(B) Ataques`, `Técnicas Detectables Red`,
  `Subtécnicas Implementadas`, `(C) Tráfico Legítimo`, `(D) Referencias`, `(E) Leyenda`,
  `Requisitos Estudios`) y los scripts de extracción MITRE; `01_TFG4-HIDS … (obsoleto)` (la
  versión antigua de la guía, que cita `ait-aecid` y `kyoushi-environment`).
- `recursos_profesor/repos-similares/Snort-FG-PA-…/`: **estándar de facto** (carpetas `BBDD/`,
  `Dataset/`, `Estudio-FG/`, `Estudio-PA/`, `Hojas/`, `Soporte/`, `VerificacionFG/`).
- `recursos_profesor/tfgs-similares/`: 3 TFGs hermanos en PDF.

**Lo nuestro** (repo): `state.md`, `context.md`, `requirements.md`, `roadmap.md`, `Hojas/`
(`ATA_index.csv`, `corpus_host.csv`, `cobertura_p1_linux.csv`, `inventario_p1_windows.csv`,
`auditoria_origen.csv`, `cobertura_atomic.csv`, `repeticiones.csv`, `lista_tecnicas_validas.md`),
`Dataset/Ataques/` (55 ATA), `Dataset/Legitimo/` (Linux + `windows/`), `Bitacora/` (55 JSON),
`Soporte/Wazuh/` (`rulesets_diseno.md`, `active_ruleset.txt`, `politica_filtrado_ruido.md`),
`Soporte/Ataques/` (`plantilla_esperado.md`, `criterio_ataques.md`, `c0/`),
`Soporte/Laboratorio/windows/` (telemetría, runbooks), `_artefactos/scripts/`.

### 1.2 Hallazgos que cambian el plan (verificados)

1. **Nuestro corpus ya es "virgen" y ya trae la rejilla.** Verificado en `active_ruleset.txt`:
   `RS3 = 0` reglas y `RS4 = 0` reglas (vacías). Y verificado en las `-Audited.csv` reales
   (**160 ficheros**, los 160 con `rule_level` + `rs_origen` en cabecera, según la revisión del
   orquestador). ⇒ La rejilla **virgen × umbral × {RS1, RS1+RS2}** se obtiene con un **recorte
   determinista** de lo ya medido, **sin re-atacar**. Cambia el coste del reencuadre de semanas a
   días.
2. **El modelo del profesor ya "asocia TP/FP por regla"** (`Requisitos Estudios`:
   *"Asociación Manual (a TP/FP) de SIDs Snort (en cada RSx)"*). Nuestro filtro ya hace esa
   asociación (`deteccion` / `artefacto_ataque` / `ruido_conocido` / `auto_ruido`). **Ventaja
   metodológica ya construida.**
3. **La unidad del NIDS es el "flujo" y su FPR es "% de flujos legítimos con alerta"; el TPR es
   por "pcap".** Confirmado en el Excel del profesor: `T4 (Rend)` con filas `#pcaps TP/FN`
   (TPR por **pcaps**) y `#Flows FP/TN` (FPR por **flujos**); `#Flows = 78.694.206`. Es una
   **métrica a dos resoluciones**. Nuestro HIDS reproduces esa estructura (caso ↔ evento/acción).
4. **El TFM de Velociraptor es directamente reaprovechable**: mismas 9 técnicas, perfiles
   **P1–P4**, distinción **público vs custom**, **Hayabusa**, y una **tabla de mapeo de severidad
   VR↔Wazuh** (Tabla 60) que sirve de puente para el eje "umbral".
5. **Velociraptor no es un motor de reglas como Wazuh**: su "detección" = un *artifact* de
   monitorización que **emite filas** (con perfiles P1–P4). Definir su "unidad" (= fila/evento de
   artifact) es un **riesgo metodológico explícito** (§8, §11).
6. **GHOSTS es infraestructura en sí misma** (servidor **API** + **clientes** Windows/Linux y
   actividad tipo navegador/descarga) ⇒ con lab aislado **exige la "internet local"** que ya
   necesitábamos para C2/nubes. **No es un script: es un bloque.**
7. **`92600` (nivel 0) suprime la alerta** de `python3` ⇒ en Wazuh **el umbral arranca en "hay
   alerta o no la hay"**; el nivel 0 no emite alerta. El eje "umbral" es `rule.level ≥ N` sobre
   **alertas ya emitidas**, no sobre todos los eventos.
8. **(v2) La Tabla 1 del profesor es de RED; es un espejo invertido del nuestro.** Verificado: la
   `Summary` da **Tactics 14 · Techniques 211 (red 77, solo-red 17) · Subtechniques 468 (red 91,
   solo-red 34)**. Nuestro filtro host v19.1 produce **625 host-eligible / 72 no**. La relación
   de diseño es: **`host_eligible ≈ NOT(Only Network Detection)`** — con **discrepancias
   declaradas** (§1.3).
9. **(v2) El repo hermano NIDS es la referencia metodológica directa** (§1.4): su *pipeline* de
   *pruning* es **exactamente nuestro Tabla 5** y su **G-Mean = √(TPR·TNR)** es **exactamente**
   la fórmula del profesor. Nos da la **plantilla de cálculo** ya validada por el grupo.
10. **(v2) Los TFMs hermanos usan unidades de FP que ya intuíamos** (§1.5): Linares cuenta
    **FP absolutos en el escenario normal** con **dos umbrales** (85,5 % con 13,9 FP vs 51 % con
    3,1 FP); Peña usa **control benigno** y **control de malware no-ransomware** para medir FP, y
    avisa de que **una misma acción genera varias señales a la vez** (doble conteo) — el mismo
    principio que nuestra distinción **alertas vs `rule.id` distintos**.
11. **(v2) La guía del profesor está desactualizada** en 5 puntos (§3.4) pero **siguen vigentes**
    el **filtro inverso host** y la **prioridad R/E/S**.

### 1.3 La `Tabla 1 - Matriz MITRE Enterprise v17.xlsx` (la clasificación) — estudio hoja a hoja

**Qué es.** La tabla de **clasificación** de las técnicas ATT&CK **Enterprise v17** desde el punto
de vista de **red** (para el NIDS hermano). Fecha de actualización: **22/06/2025**; versión **v17**.

**Hojas y contenido (verificado por volcado completo):**

| Hoja | Filas×Cols | Contenido |
|---|---|---|
| `Tabla 1` | 16×8 | Resumen **por táctica**: `Tactic · #Techniques · #Network · #Network-only · #Subtechniques · #Network · #Network-only` + **TOTAL**. |
| `Summary` | 9×5 | Cifras globales: **Tactics 14/14/0** · **Techniques 211 (red 77, solo-red 17)** · **Subtechniques 468 (red 91, solo-red 34)**. |
| `Summary_Techniques (ordenado)` / `Summary_Techniques` | 19/22×13 | Por táctica, con **"SIN repetición"** (necesario porque una técnica puede estar en varias tácticas: **245 con repetición → 211 sin repetición**). |
| `Tactics` | 16×6 | 14 tácticas con `ID · Nombre · #Techniques · Network Detection · Only Network Detection`. |
| `Techniques` | 213×8 | **211 técnicas**: `ID · Name · Tactic IDs · Tactic Names · #Subtechniques · Network Detection · Only Network Detection`. |
| `Subtechniques` | 470×7 | **468 subtécnicas**: `ID · Name · Technique ID · Technique Name · Network Detection · Only Network Detection`. |
| `Subtech_Tact` | 470×16 | Matriz subtécnica × táctica (X = pertenece). |
| `Tech_Tact` | 213×16 | Matriz técnica × táctica. |
| `Summary_Subtechniques` | 214×6 | Por técnica: `#Subtécnicas · #red · #solo-red`. |
| `Separador` | 1×1 | vacía. |

**El criterio (clave para nosotros).** Las columnas `Network Detection` (la detecta un NIDS) y
`Only Network Detection` (SOLO la detecta un NIDS) son el **espejo** de nuestro **filtro inverso
host**. Para un **HIDS** nos interesan las **NO-solo-red** (host-eligibles o híbridas).

**Verificación: P1 en la Tabla 1 (v17).** Técnicas que tocan **Collection / Exfiltration /
Impact** = **41**; de ellas **3 son solo-red**: **`T1029`, `T1030`, `T1602`**. Subtécnicas P1 =
**51**; **6 solo-red**: `T1020.001, T1557.002, T1557.004, T1567.003, T1602.001, T1602.002`.

**Equivalencia declarada con nuestro corpus (v19.1).** Nuestro `host_eligible` (filtro inverso
por Data Components endpoint, `Hojas/corpus_host.csv`, 625/697) **coincide en diseño** con
`NOT(Only Network Detection=YES)`. **Discrepancias declaradas** (por **versión** v17↔v19.1 y por
**granularidad**):

| Item | Tabla 1 (v17) | Nosotros (v19.1) | Estado |
|---|---|---|---|
| `T1029` (Scheduled Transfer) | **solo-red** | **host_eligible** y **medida** (ATA021) | ⚠️ discrepancia (v19.1 le da DCs host: Process Creation, Scheduled Job Metadata) |
| `T1602.001` / `.002` (Configuration Repository) | **solo-red** | **host_eligible** (v19.1 con DCs host); en `inventario_p1_windows.csv` = **no factible** (Network Devices) | ⚠️ discrepancia **de criterio**, **no entra** en la medida. *(El padre `T1602` es `solo_red` también en v19.1 ⇒ **sin discrepancia**; mismo patrón que `T1557.004`.)* |
| `T1567.003` (Text Storage Sites) | **subt. solo-red** | **host_eligible** y **medida** (ATA050) | ⚠️ discrepancia |
| `T1030` (Data Transfer Size Limits) | **solo-red** | **no** está en nuestro P1 | coherente |
| `T1557.004` | **subt. solo-red** | fuera de alcance (Network Devices) | coherente |

**Conteo de coherencia (padres):** Tabla 1 P1 con técnicas host-detectables = **41 − 3 = 38**;
nuestros **padres P1 host-eligible = 39**; la única diferencia es **`T1029`**. La equivalencia es
**buena** y las diferencias quedan **trazadas**.

**Consecuencias para el plan:**
- **Nuestra adaptación de Tabla 1** (§5.1) será una **hoja conjunta** que muestre **ambos
  criterios lado a lado** (`Only Network Detection (v17)` **y** `host_eligible (v19.1)`), para
  que la equivalencia sea **auditable** y las 3 discrepancias queden **visibles**, no ocultas.
- **Se declara el desfase de versión** (v17 vs v19.1) y de **nombres de táctica** (v17
  *Defense Evasion* → v19.1 *Stealth*; v17 *Defense Evasion* → v19.1 incluye
  *Defense Impairment*): **no se puede unir por nombre de táctica**, hay que **mapear por ID**.

### 1.4 El repo hermano NIDS — estudio a fondo (referencia metodológica directa)

**Repo:** `https://github.com/ignmercam/mitre-attack-ids-detection-optimization` (TFG de
**Ignacio Merchán Cámara**, tutor **F. J. Muñoz Calle**, US/ETSI, **2026**). Título: *"Análisis de
la capacidad de detección de ataques en red bajo las matrices MITRE ATT&CK Enterprise e ICS
mediante Snort, FortiGate y Palo Alto Networks"*. Es el **"hermano" NIDS** del mismo tutor.

**Estructura verificada** (árbol completo por API; 1.223 ficheros):
```
Enterprise/  Tables - Enterprise.xlsx  ·  manual labeling/{csv,xlsx} (224 ficheros, uno por técnica/ataque)
             snort/{conf,reglas}  ·  analysis/{02-CSV_RS, 03-SID-Alerts, 04-Pruning, 05-CSV_Pruning}
ICS/         (espejo: 9 RS de Snort, incl. Quickdraw)
Scripts/     procesa_*.py · optimo_*_GM_v*.py · tablas_*_GM_v2.py · genera_csv_pruning.py
```
- **`manual labeling/`**: **1 CSV+XLSX por técnica/ataque** (p. ej. `T1029-Scheduled_transfer`,
  `T1498.001-UDP_flood-Manual`, `T1567.002-Exfiltration_To_Cloud_Storage`) ⇒ **la etiqueta manual
  por ataque**. Nuestra analogía: **el `ATA<NNN>_esperado.csv` + la bitácora + el `-Audited.csv`**
  (los “manual labelings” de nuestro trabajo).

**Metodología (leída en los scripts; cifras verificadas):**

| Pieza | Valor real (código/README) | Nuestra adaptación |
|---|---|---|
| Universo ataques | `TOTAL_ATK_PCAPS = 110` (Enterprise) | **55 casos** `ATA<NNN>` (**128 ventanas**; la repetición `_rev` es la medida canónica en 9) |
| Universo legítimo | `TOTAL_LEG_FLOWS = 78.694.206` (**78 M** flujos) | **N** unidades de actividad legítima (72 h) — **se instrumenta** |
| **TPR** | `tp = Σ pcaps con ≥1 SID del ruleset`; `TPR = tp / total_atk_pcaps` | **por caso** (ATA) |
| **TNR/FPR** | `fp = Σ flujos con ≥1 SID`; `TNR = tn / total_leg_flows` | **por unidad legítima** |
| **G-Mean** | `gm = √(tpr·tnr)` = **√(TPR·(1−FPR))** | **idéntico** (`Tabla 4`) |
| **Usabilidad** | `usab = FP_alertas / TP_alertas` (FTTAR) | **idéntico** |
| Doble métrica de alertas | **`Raw Alerts`** y **`Diff Alerts/Flow`** (= Σ SIDs únicos por flujo) | **`#Alertas`** y **`#Flow-correlated Alerts`** (= Σ `rule.id` distintos por unidad) |
| Niveles | **Snort `[Priority: ≤4..≤1]` + "Any"** (4 niveles); **FG/PA `severity ≥ 1..5`** (5 niveles) | **`rule.level ≥ N`** (Wazuh), **`P4≤…≤P1`** (VR) |

**Pruning (Python, `optimo_*_GM_v*.py`) — es exactamente nuestra Tabla 5.** Variantes:
1. **Pruning 500**: quita SIDs con **`Diff Alerts/Flow` FP > 500** (y variante **1000**).
2. **Conservative Pruning**: quita **SIDs que son FP y nunca TP** (`sids_legitimo − sids_ataque`).
3. **Generalized Conservative**: quita **todos** los SIDs FP **aunque sean TP**.
4. **Aggressive Pruning (G-Mean)**: **eliminación hacia atrás** ordenando las reglas mixtas por
   impacto en legítimo (desc) y **quitando solo si el GM mejora** (`if m_gm > current_gm`).

Salidas por escenario: `1a/1b/1c/1d_*_Removed.csv`, `2_GM_Optimization_Steps.csv`,
`3_Optimization_Summary.txt`, `4_Detailed_Execution_Log.txt`; globales:
`Global_G-Mean_Snort_Summary.xlsx` y `Global_G-Mean_FG-PA_Summary.xlsx`.
**Nuestra Tabla 5 reproduce esto** con `rule.id` en lugar de SID (§5.5).

### 1.5 Lecciones de los 2 TFMs hermanos (y del TFM de Velociraptor)

**Jorge Linares — *"Monitoring of Malware Behaviour in Microsoft Systems"*** (ETW-TI, GNN de
grafos de procedencia; **solo Windows**; **escenario de usuario normal**):
- Dataset: **7 escenarios normales** + **84 ejecuciones** (12 muestras × 7 escenarios). El malware
  **se ejecuta SOBRE el escenario normal** (no aparte) ⇒ escenario realista.
- El detector se entrena **solo con actividad normal** (el objetivo del TFG **no** es lograr un
  detector, sino **demostrar viabilidad**).
- **Resultado clave (umbral ↔ FP):** **85,5 %** de detección con el **umbral menos estricto**
  (**13,9 FP** en el escenario normal) frente a **51 %** con el **más estricto** (**3,1 FP**).
- Red aislada con **INetSim** (HTTP/HTTPS/SMTP/POP3/FTP) — **el hermano también simula
  internet en local** (refuerza nuestra §9).
- **Lecciones para nosotros:** (a) el **umbral es un eje obligatorio** (no un extra); (b) los FP
  **dependen de la actividad de fondo** ⇒ el legítimo debe ser **realista y largo**; (c) medir
  **FP absolutos** por escenario es válido y comparable.

**José Manuel Peña Ramírez — *ransomware + Velociraptor/ThreatTrace*** (análisis dinámico +
búsqueda de IoC con Velociraptor, representación STIX):
- **300 muestras** de ransomware Windows; **controles**: **20 cargas benignas** (su **negativo de
  FP**) y **5 muestras de malware no-ransomware** (su **negativo de familia**).
- Resultado del control benigno: **32 colecciones**, solo **3 devolvieron 26 filas**
  (LOLBins y tareas programadas) — “**algunos mecanismos recogen acciones legítimas**” ⇒
  interpretar **junto con el CONTEXTO**, no por el nombre del proceso.
- **Aviso metodológico explícito:** *"una misma acción puede generar a la vez una señal de
  proceso y otra de impacto"* ⇒ el recuento por “categorías” **no** implica orígenes
  independientes.
- **Lecciones para nosotros:** (a) el **control benigno** (= nuestro legítimo) y el **control de
  otra familia** son el patrón correcto para medir FP; (b) **ruido = regla que dispara en
  legítimo** ⇒ **mismo principio que nuestra distinción `alertas` vs `rule.id` distintos**
  (evitar el doble conteo).

**TFM Velociraptor (mismo tutor)** — confirma que las **9 técnicas** y los **perfiles P1–P4**
permiten **puentear severidades** VR↔Wazuh (Tabla 60) y que **público vs custom** es un eje real
(base 3/9; custom 4/9 = 7/9; VR custom 9/9; Hayabusa 3/9).

---

## 2. Objetivo del bloque, alcance y los 7 flecos

### 2.1 Objetivo del bloque `reencuadre`

Fijar, de forma **defendible y congelable**, el **nuevo marco del TFG**: objetivo, alcance,
**métrica** (definida sin ambigüedad), **estructura de tablas**, **dimensiones de medida**,
plan del legítimo, plan de Velociraptor y la **secuencia de bloques** que lo ejecuta.

**Producto del bloque:** `plan.md` (este fichero). El humano lo revisa (ataque al plan) y lo
aprueba; entonces el resto del programa se ejecuta por bloques.

### 2.2 Alcance de este bloque

**Entra:** reencuadre de **objetivo/alcance** (§3), **métrica** (§4), **tablas** (§5),
**dimensiones** (§6), **legítimo** (§7), **Velociraptor** (§8), **internet** (§9), **secuencia**
(§10), **riesgos/decisiones** (§11), **CA** (§12) y **gate** (§13).

**No entra en este bloque:** no se toca el laboratorio, ni el corpus, ni `_recursos/`; no se
reescriben aún `context.md`/`requirements.md`/`roadmap.md` (lo hace `reencuadre-docs`); no se mide
nada (empieza tras `reencuadre-metrica`).

### 2.3 Los 7 flecos de las notas — resolución

| # | Fleco (notas) | Resolución en este plan |
|---|---|---|
| 1 | **`Tabla 1 - Matriz MITRE v17.xlsx`** | **Disponible** ahora; estudiada **hoja a hoja** (§1.3) e **incorporada como Tabla 1 del modelo** (§5.1), con **equivalencia** al corpus host y **3 discrepancias declaradas**. |
| 2 | **Repo "pináculo de NIDS"** | **URL correcta** `ignmercam/…` (la de las notas, `ignmerca`, da 404). Estudiado a fondo (§1.4); su *pipeline* de *pruning* = **nuestra Tabla 5**; su G-Mean = la del profesor. |
| 3 | **"Tamaño ~ nº acciones, TIEMPOS…"** | El profesor dijo **"algo equivalente"**, no esa columna exacta. **Decisión:** en T2 añadimos **`nº de acciones (k/m)`** (ya existe: `acciones cubiertas`) **y** una dimensión nueva de **TIEMPOS** (`duración de la ventana` + **`t hasta la 1ª detección`**) (§5.2, §6). |
| 4 | **Coste computacional** | **Fuera** del alcance, pero **anotado como experimento opcional** (§14): el profesor añadió *"sería interesante ver por qué al medir afecta a la detección y cómo, con hechos; se podría usar para TP/FP"*. |
| 5 | **Leer A FONDO los 2 TFMs hermanos** | **Hecho** (§1.5): extraídas sus **lecciones de FP/TP** (Linares: umbral ↔ FP; Peña: control benigno + doble conteo). |
| 6 | **Criterio de ART ↔ "equivalente a pcap"** | **Declarado**: el "paquete" sigue el **criterio de ART** (plataforma + **inputs/contexto** + **comandos/acciones** + limpieza) **+ nuestra telemetría**. Ya tenemos `ataque.sh` + `esperado.csv` + `README` + bitácora + evidencias; **falta consolidarlo homogéneo** por ataque (§5.2). |
| 7 | **`ait-aecid` (guía del profesor)** | Es **AECID** del **AIT austríaco**: HIDS **basado en anomalías** (aprende lo normal; motor libre = **AMiner**). **Fuera de alcance** (solo Wazuh + VR) pero **se cita en el estado del arte** como **otro paradigma** (junto a `kyoushi-environment`, que la guía también cita). No confundir con el **AECID español** (cooperación). |

---

## 3. Objetivos redefinidos del TFG

> Redacción de referencia para reescribir `context.md` / `requirements.md` / `roadmap.md`.

### 3.1 Objetivo general (nuevo)

> **Analizar la capacidad de detección de ataques locales de la matriz MITRE ATT&CK
> Enterprise (subconjunto P1: Impact / Exfiltration / Collection) mediante dos HIDS
> open-source —Wazuh y Velociraptor— en su configuración "de fábrica" (virgen), y cuantificar
> tanto la detección (TPR) como el error sobre la actividad legítima (FP), a varios niveles de
> severidad/configuración y en las plataformas Linux y Windows, produciendo un conjunto de
> tablas homogéneas con los trabajos hermanos del grupo.**

### 3.2 Objetivos específicos (redefinidos)

| # | Objetivo | Cómo se ve |
|---|---|---|
| O1 | **Clasificar** las técnicas P1 host-eligible (matriz MITRE, filtro inverso host) **≡ Tabla 1 del profesor invertida** | **Tabla 1** (adaptada; §5.1) |
| O2 | **Ejecutar** los ataques P1 y caracterizarlos como **"paquete equivalente a pcap"** (criterio ART + telemetría) | **Tabla 2** |
| O3 | **Medir el error en legítimo** (FP/TN con acciones reales, GHOSTS) | **Tabla 3** |
| O4 | **Calcular métricas** (TPR, FPR, Precisión, F1, GM, usabilidad) por nivel/config | **Tabla 4** |
| O5 | **Medir el efecto del "pruning"** (variantes 500/1000, Conservative, Generalized, Aggressive) | **Tabla 5** |
| O6 | **Evaluar Velociraptor** con el mismo corpus y **compararlo con Wazuh** | T2/T4 (ambos HIDS) |
| O7 | **Homogeneidad** con los TFGs hermanos (plantillas, excels, nomenclatura) | Requisitos + Leyenda |
| O8 | Redactar la **memoria** siguiendo el esqueleto de los hermanos. | Fase memoria |

### 3.3 Reencuadres de decisión (respecto al `context.md` actual)

| Tema | Antes | Ahora |
|---|---|---|
| Alcance | "12-15 técnicas", varias tácticas | **Solo P1** (89 host-eligible; 72 Linux, 17 no-Linux) |
| HIDS | Wazuh núcleo; VR y un tercero "si sobra tiempo" | **Wazuh + Velociraptor** (fuera tercero) |
| VR | Extra | **Fase propia**, virgen primero, custom después |
| Reglas propias | RS3 "crece en Fase 3" | **Eje de configuración** (virgen / +propias / +externas) |
| Legítimo | "línea base"; script sintético 2×4 h | **Medir FP**: GHOSTS + 72 h + internet local |
| Métrica | η = √(CD·(1−FP)) | **Métrica del profesor** (TPR/FPR/Precisión/F1/GM/usabilidad) |
| Resultados | Tabla libre | **T1–T5 + Requisitos + Leyenda** del profesor (estructura real §5) |
| Umbral | — | **`rule.level ≥ N` × `RS` × HIDS × SO** |
| Clasificación | `corpus_host.csv` (v19.1) | **Tabla 1 (v17) como espejo + corpus v19.1** (equivalencia declarada) |
| Snort/pcaps/coste CPU | Fase 4 | **Fuera** (coste: solo experimento opcional, §14) |

### 3.4 La guía del profesor está desactualizada (reflejado)

| Punto de la guía (`guia_profesor.txt`) | Estado | Ahora |
|---|---|---|
| "12-15 técnicas" | **obsoleto** | **Solo P1** (89 host-eligible) |
| Tercer HIDS (OSSEC/Sagan/Splunk/Samhain) | **obsoleto** | **Fuera** (solo Wazuh + VR) |
| Snort / pcaps / "convertir logs en pcap" | **obsoleto** | **Fuera** |
| `ait-aecid` / `kyoushi-environment` | **obsoleto** como herramienta | **Solo cita** en el estado del arte (otro paradigma: HIDS *basado en anomalías*) |
| Baseline corto | **obsoleto** | **72 h + GHOSTS** |
| FortiEDR (comercial) | — | **Fuera** (solo open-source) |
| **Filtro inverso host** | **VIGENTE** | Se conserva (`corpus_host.csv`) |
| **Prioridad R/E/S** | **VIGENTE** | Se conserva (columna `priority`) |

---

## 4. La métrica nueva, definida con precisión

> **La parte más delicada.** Se define **sin ambigüedad**, se **congela** en `reencuadre-metrica`
> y **no se vuelve a tocar** (política "métrica congelada" ya vigente). Cualquier cambio posterior
> se declara y obliga a re-calcular.

### 4.1 Principio: dos planos, como el NIDS (verificado en el Excel del profesor)

El trabajo de referencia mide en **dos planos** y una **resolución de alerta**:
- **Plano ATAQUE** → por **caso** (en el NIDS, *pcap*): `TPR`.
- **Plano LEGÍTIMO** → por **unidad de actividad** (en el NIDS, *flujo*): `FPR`.
- **Plano ALERTA** → para `Precisión` y `Usabilidad`.

Replicamos esa estructura **explícitamente**, porque es lo comparable con los hermanos.

### 4.2 Las tres unidades (definidas)

| Plano | Unidad (HIDS) | Equivalente NIDS | Se usa para |
|---|---|---|---|
| **Ataque** | **Caso = una ventana de ataque `ATA<NNN>` (una ejecución)** | pcap | TPR, FN |
| **Legítimo** | **Unidad de actividad legítima = un evento/registro de telemetría del endpoint** | flujo | FPR, TN |
| **Alerta** | **Alerta = un `rule.id` que Wazuh emite (un match)** / **un evento que un artifact de Velociraptor emite** | alerta | Precisión, Usabilidad |

**Decisión sobre la unidad legítima (la más discutida):**
- **Primaria = evento/registro de telemetría legítimo** (el "flujo" del HIDS). El **denominador**
  (= nº total de eventos legítimos evaluados) **se instrumenta**: en Wazuh con `<logall_json>`
  (archivos de todos los eventos, **no cambia el ruleset → sigue virgen**) o contando en el origen
  (auditd/Sysmon/FIM). Es la definición que **más se parece al NIDS** y la que evita sesgos.
- **Complementos declarados** (no una unidad alternativa en silencio): (i) **acción legítima de
  GHOSTS** (unidad discreta, análoga a un flujo "de aplicación"), y (ii) **hora de actividad**
  (FP/hora). Los tres se reportan; el **titular es el primario**.
- **Si la instrumentación del denominador no fuese viable** (volumen de 72 h), el **fallback
  declarado** es: FPR por **acción GHOSTS** + **FP/hora**, y se documenta como limitación.

> ⚠️ **Punto #1 de confirmación con el tutor**: la unidad legítima. Se lleva **esta propuesta
> decidida** (evento, con complementos), no una pregunta abierta.

### 4.3 Matriz de confusión (por plano)

**Plano ATAQUE (caso):**
```
               | detectado | no detectado
  ataque real  |  TP_ata    |   FN_ata
```
- `TP_ata = nº de casos con ≥1 alerta clasificada 'deteccion'` (regla del ataque, con la
  **pertenencia** de la métrica congelada).
- `FN_ata = N − TP_ata`, con `N = nº de casos medidos`.
- **TPR (Recall / Sensibilidad / CD) = TP_ata / (TP_ata + FN_ata) = TP_ata / N.**

**Plano LEGÍTIMO (unidad):**
```
                  | con alerta | sin alerta
  actividad legít.|  FP_uni    |   TN_uni
```
- `FP_uni = nº de unidades legítimas con ≥1 alerta` (bajo la config y umbral dados).
- `TN_uni = M − FP_uni`, con `M = nº total de unidades legítimas`.
- **FPR = FP_uni / (FP_uni + TN_uni) = FP_uni / M.** · **TNR = 1 − FPR.**

**Plano ALERTA (conteo de alertas) — dos variantes, como el profesor:**
- `A_TP = nº de alertas del ataque` (`deteccion`).
- `A_FP = nº de alertas sobre actividad legítima` (todas las alertas en legítimo — incluida la
  auto-alerta del propio HIDS; **es ruido para el operador**).
- **Alertas brutas (`Raw`)** vs **Alertas correlacionadas por unidad (`Flow-correlated`)**:
  `A_TP^c = Σ_unidades_del_ataque (rule.id distintos que dispararon)` y
  `A_FP^c = Σ_unidades_legítimas (rule.id distintos que dispararon)`.
  *(Es el `#Flow-correlated Alerts` del profesor / `Diff Alerts/Flow` del repo hermano.)*
- **Precisión = A_TP / (A_TP + A_FP)** (versión bruta; análoga con `^c`).
- **Usabilidad operacional (FTTAR) = A_FP / A_TP** *(nº de alertas FP por cada TP; interesa ≈0)*.

### 4.4 Métricas derivadas

| Métrica | Fórmula | Óptimo | Nota |
|---|---|---|---|
| **TPR / Recall / CD** | `TP_ata / N` | →1 | por **caso** |
| **FPR** | `FP_uni / M` | →0 | por **unidad legítima** |
| **TNR / Especificidad** | `1 − FPR` | →1 | |
| **Precisión** | `A_TP / (A_TP + A_FP)` | →1 | por **alerta** (y variante `^c`) |
| **F1** | `2·P·R / (P + R)` | →1 | combina Precisión (alertas) y Recall (casos) |
| **GM** | `√(TPR · (1 − FPR))` | →1 | equilibrio detección/ruido (**= fórmula del profesor y del repo hermano**) |
| **Usabilidad (FTTAR)** | `A_FP / A_TP` | →0 | carga operativa (y variante `^c`) |

> **Nota metodológica honesta (declarada, como en el NIDS):** Precisión y Recall viven en
> **planos distintos** (alertas vs casos); F1 y GM **mezclan** esas resoluciones. **Es
> exactamente** la convención del profesor (su `GM = √(TPR·(1−FPR))` con TPR por pcap y FPR por
> flujo; verificado en el Excel). Se **adopta para ser comparable** y se **declara** la limitación
> en la memoria. Si el tutor lo pide, se añade una variante todo-a-casos y todo-a-unidades.

### 4.5 Reglas de conteo (anti-sesgo)

1. **Métrica congelada** para la pertenencia (`deteccion` = es la técnica) — ya existe; se
   **reutiliza tal cual**.
2. **Un umbral no borra un caso**: si el ataque se detectó a nivel 3 y se sube a 7, el caso pasa a
   `FN` **solo si ninguna alerta del ataque supera el umbral**.
3. **La auto-alerta del HIDS cuenta como FP** (es ruido; así lo hace el profesor).
4. **Nada se descarta en silencio**: si una fila no se puede atribuir, va a `dudosa` (métrica
   congelada) y se declara.
5. **Reproducibilidad**: cada cifra se regenera con un **script determinista** y una **huella**
   (`sha256`), como en el resto del repo.

### 4.6 Comparabilidad ENTRE HIDS (nota del orquestador, resuelta)

> La revisión del orquestador avisó: la **unidad legítima = evento** **no es comparable** entre
> Wazuh (registros de log) y Velociraptor (filas de artifact): sus "eventos" son cosas distintas.

**Resolución (se congela así):**
- **El titular de FPR de Wazuh** es por **evento/registro** (más parecido al "flujo" del NIDS).
- **La comparación VR↔Wazuh se hace con una unidad COMÚN explícita**: la **acción de GHOSTS**
  (unidad discreta y contable en ambos) **y/o la hora** (FP/hora). Las **tres** se reportan.
- **La comparación principal VR↔Wazuh es POR TÉCNICA** (como el TFM del mismo tutor), **no** por
  "eventos" (que no son homogéneos). Se **declara** que son paradigmas distintos (alarmas vs
  recolección) y **no se fuerza** una igualdad artificial.
- **Riesgo declarado** (§11): el "denominador" de VR es **el número de filas emitidas** por sus
  artifacts, no un censo total de eventos del host ⇒ su FPR **no** es estrictamente el mismo
  concepto. Se documenta.

---

## 5. Estructura de las tablas (adaptación de T1–T5)

> Fuente: **`Tablas 2, 3, 4, 5 (con FG-PA).xlsx`** y **`Tabla 1 …v17.xlsx`** (estructura real
> transcrita) + `Detecciones Red (Ref).xlsx`. Se **mantienen nombres, columnas y semántica**; se
> **cambia** lo que en un HIDS es distinto (unidad, ejes).

### 5.1 Tabla 1 — Clasificación (matriz MITRE, espejo red↔host)

Adaptación de la hoja **`Techniques`** de **`Tabla 1 (v17)`** + nuestro `corpus_host.csv` (v19.1).
**Columnas:**
`Táctica | Otras tácticas | ID táctica | Técnica | ID técnica | Subtécnica | ID subtécnica |
Plataformas | P1 (R/E/S) | **Only Network Detection (v17)** | **Network Detection (v17)** |
**host_eligible (v19.1)** | DC host | DC red | Cubierta en corpus (ATA<NNN>) | Estado de cobertura`.

- Las **dos columnas de red (v17)** y la de **host (v19.1)** van **juntas**, para que la
  **equivalencia** sea auditable y las **3 discrepancias** (`T1029`, `T1602(.001/.002)`,
  `T1567.003`) queden **visibles**.
- **Mapa de táctica por ID** (no por nombre): v17 *Defense Evasion* ↔ v19.1 *Stealth*;
  v19.1 añade *Defense Impairment*.
- Fuente: `Tabla 1 …v17.xlsx` + `Hojas/corpus_host.csv` + `cobertura_p1_linux.csv` +
  `inventario_p1_windows.csv`.

### 5.2 Tabla 2 — Ataques y detecciones (por caso × configuración × umbral)

Adaptación de **`T2 (At)`** / **`Tabla 2 - Ataques detec (Imple)`**. Estructura real del profesor:
`Nº | Nº Technique | pcapng (SubTechnique-Attack) | Technique | #Flows |` + por configuración:
`#Alerts | #Flow-correlated Alerts | #SID | #Attack_Flows | Detection`.

**Adaptación HIDS:**
- **Meta (por caso/ATA):** `Nº | ATA | ID técnica | Subtécnica | Táctica | Plataforma |
  "paquete pcap" (ruta de la carpeta: **contexto + acciones + telemetría**, criterio ART) |
  Herramienta | **nº de acciones (k/m)** | **TIEMPO de la ventana (t0→t1)** |
  Análisis manual (cómo se verificó) | ¿Detectado?`.
- **Bloques por (config × umbral):** `#Alertas | #Alertas correlacionadas (por unidad) |
  #rule.id (≈ #SID) | #acciones cubiertas | **t hasta la 1ª detección** | Primera evidencia
  (rule.id) | Detection (SÍ/NO)`.
- **Fleco 3 (v2):** el "tamaño ~ nº acciones, **tiempos**" se concreta en **`nº de acciones (k/m)`**
  **+** **`TIEMPO de la ventana`** **+** **`t hasta la 1ª detección`** (§6).
- **Fleco 6 (v2):** el **"paquete equivalente a pcap"** = carpeta por ataque que reúne **contexto
  (artefacto/plataforma/inputs) + acciones (guion/comando) + telemetría (alertas/evidencias)**,
  siguiendo el **criterio de ART**; se **consolida homogéneo** (§7 del bloque `reencuadre-docs` /
  bloque de consolidación).
- **Homogeneidad:** misma cabecera que el hermano, con `rule.id` en lugar de `SID`; la columna
  `pcapng` → `ATA<NNN>` (la carpeta-paquete).

### 5.3 Tabla 3 — Legítimo (por configuración × umbral)

Adaptación de **`Tabla 3 (Legítimo)`** / **`(C) Tráfico Legítimo`**. Estructura real del profesor:
por configuración, `#Flows | #Alerts | #Flow-correlated Alerts | #SIDs | #Flows_FP | #Flows_TN |
%Flows_FP | %Flows_TN`.

**Adaptación HIDS:**
- **Meta:** `Corrida | Tipo de tráfico | Tamaño (eventos) | #Unidades | #rule.id | Duración`.
- **Bloques por (config × umbral):** `#Unidades | #Alertas | #Alertas correlacionadas |
  #rule.id | #Unidades_FP | #Unidades_TN | %Unidades_FP | %Unidades_TN | #Alertas_FP`.
- **Detalle por regla:** `rule.id | #alertas legítimas | ¿es TP en algún ataque? | veredicto`.

### 5.4 Tabla 4 — Rendimiento (métricas)

Adaptación de **`T4 (Rend)`**. Filas reales del profesor:
`#Attack flows | #Clear flows | #Total Flows | #pcaps TP | #pcaps FN | #Alerts TP |
#Flow-correlated Alerts TP | #Flows FP | #Flows TN | #Alerts FP | #Flow-correlated Alerts FP |
TPR | FPR | GM | Operational Usability | Operational Usability (correlated alerts)` + bloque de
**fórmulas** (TPR = TP/(TP+FN); FPR = FP/(TN+FP); P = TP/(TP+FP); F1 = 2PR/(P+R);
GM = √(TPR·(1−FPR)); TNR = 1−FPR; Usability = #Alertas_FP/#Alertas_TP).

**Adaptación HIDS:** filas `#Casos | #Casos TP | #Casos FN | #Alertas TP | #Unidades FP |
#Unidades TN | #Alertas FP | TPR | FPR | TNR | Precisión | F1 | GM | Usabilidad` (+ variantes `^c`).
Columnas: **(config × umbral × HIDS)**. Incluye el **bloque de fórmulas/leyenda** idéntico al
profesor.

### 5.5 Tabla 5 — Pruning (mejora del rendimiento)

Adaptación de **`T5 (Pru)`** — **exactamente** el *pipeline* del repo hermano (§1.4). Variantes
del profesor: `No Pruning` · `Pruning 500` · `Pruning 1000` · `Conservative Pruning` ·
`Generalized Conservative Pruning` · `Aggressive Pruning (G-Mean)`.

**Adaptación HIDS (con `rule.id`):**
- **Pruning N**: quitar `rule.id` con **`#alertas correlacionadas FP > N`** (N ∈ {500, 1000};
  escala a adaptar al volumen de nuestro legítimo — **decisión abierta**, §11).
- **Conservative**: quitar `rule.id` que son **FP y nunca TP**.
- **Conservative generalizado**: quitar **todos** los FP **aunque sean TP**.
- **Agresivo (G-Mean)**: **eliminación hacia atrás** ordenando las reglas mixtas por impacto en
  legítimo (desc) y quitando **solo si el GM mejora**.
- **Columnas:** `GM | %Detección (por caso) | #reglas quitadas | lista de rule.id quitados |
  Alertas (total) | #Alertas TP | #Alertas FP | Usabilidad`.

### 5.6 Hoja "Requisitos de estudios" y "Leyenda"

- **Requisitos de estudios** (analogía exacta del `Requisitos Estudios` del profesor):
  `(1) Técnica detectable por host`, `(2) Marcado manual de acciones/instancias`,
  `(3) Asociación manual TP/FP por rule.id`, `(4) Detectable por patrones/reglas`,
  `(5) Cubre todas las técnicas del corpus`, `(6) "Paquete pcap" completo
  (contexto + acciones + telemetría)`. Cada uno con **"¿cumple? / nº que no lo cumple"**.
- **Leyenda** (analogía del `(E) Leyenda`): documenta **columna a columna** cada tabla, el
  **glosario de unidades** (§4.2) y **la equivalencia pcap↔paquete** y **red↔host** (§5.1).

---

## 6. Dimensiones a medir

Rejilla = **producto cartesiano** de los ejes; se reporta en T2/T3/T4/T5.

| Eje | Valores | Coste |
|---|---|---|
| **HIDS** | Wazuh · Velociraptor | VR = fase propia |
| **Config (Wazuh)** | `C0 = RS1` (base) · `C1 = RS1+RS2` (de fábrica = **virgen**) · `C2 = +RS3` (propias) · `C3 = +RS4` (externas) | C0/C1 = **recorte** (gratis); C2/C3 = **re-ejecutar** |
| **Config (VR)** | `virgen` (artifacts públicos/nativos) · `+custom` (artifacts propios) | fase propia |
| **Umbral (Wazuh)** | `rule.level ≥ N`, N ∈ {0*, 3, 7, 10, 12} (*nivel 0 no emite alerta; se documenta) | **recorte** (gratis) |
| **Umbral (VR)** | perfiles **P4 ≤ P3 ≤ P2 ≤ P1** (Low→Critical), con el mapeo VR↔Wazuh del TFM | recorte |
| **Plataforma** | Linux · Windows | Windows = `fase-03b` |
| **Unidad** | caso (ataque) · unidad legítima (evento) · alerta | — |
| **(v2) TIEMPOS** | `duración de la ventana (t0→t1)` · `t hasta la 1ª detección` | recorte |

**Nota sobre el orden de severidad:** en **Wazuh el nivel NO está invertido** (mayor = más
severo); **Snort sí** lo invierte (`N=1` = máximo). El profesor lo advierte en su hoja `RuleSets`.
Al puentear VR↔Wazuh, **respetar el orden** (Tabla 60 del TFM).

**Definición de "virgen" (declarada):** **teléfono de detección de fábrica** = ruleset por defecto
del HIDS **sin reglas propias ni de terceros**; **la telemetría estándar SÍ se activa** (auditd en
Linux, Sysmon en Windows son **fuentes de telemetría**, no "reglas"). Para VR: **artifacts
públicos/nativos**, sin artifacts propios. Se declara para que la comparación sea justa.

**Bóveda de congelación:** antes de medir, se fija (a) ruleset por defecto (versión), (b)
telemetría, (c) versión del HIDS, (d) umbrales, (e) definición de "virgen". Se congela y se
repite la medida si algo cambia.

---

## 7. Plan del legítimo (GHOSTS + 72 h + internet local)

### 7.1 Qué cambia y por qué

- **Objetivo redefinido:** no es "línea base"; es **cuantificar el error**: **cuántos FP** (y
  cuántos TN) genera el HIDS sobre actividad **real**.
- **Generador:** **GHOSTS** (CMU-SEI): *"simulador de usuarios humanos ficticios (NPCs)"*.
  **Se retira el script determinista** como generador (queda como dato histórico).
- **Duración:** **72 h** (ampliable), cubriendo **noche + día** (reutilizar las franjas ya
  validadas: `00:45–04:45Z` y `12:00–16:00Z`, ahora de forma continua).
- **Realismo:** acciones **reales** (navegación, descargas, ficheros), no un guion sintético.

### 7.2 GHOSTS: alcance e infraestructura

- **Componentes:** **servidor API central** + **clientes** (Universal/.NET o Lite). Soporta
  **Windows y Linux**.
- **Necesidad:** actividad tipo **navegador/descarga** ⇒ requiere **"internet local"** (§9).
- **Es infraestructura**: bloque propio (`legitimo-infra`) con **decisión go/no-go** (si GHOSTS no
  es viable en el tiempo, **plan B declarado**: acciones reales por script —pero con
  navegador/apps reales— no un guion plano).
- **Nota del orquestador (v2):** con el cliente **Lite** GHOSTS quizá necesite **menos
  "internet local"** (genera tráfico sin apps reales) → lo decidirá el **go/no-go** de `L0`.

### 7.3 Qué se mide

- **T3**: por (config × umbral) → `#alertas legítimas`, `#rule.id`, `#unidades_FP`,
  `#unidades_TN`, `%FP`, `#alertas_FP`.
- **T4**: `FPR`, `TNR`, `Precisión`, `GM`, `Usabilidad` (plano legítimo + alerta; ± variantes `^c`).
- **Detalle por `rule.id`**: qué reglas de fábrica son "solo FP" (candidatas a T5/pruning).
- **Acelerable?** El reloj de pared **no**; sí son paralelizables los *NPCs* y la **corrida
  simultánea de los dos HIDS** si el *tester* confirma que la convivencia es inocua (§11).

### 7.4 Instrumentación del denominador

- Activar `<logall_json>` (o contar en el origen) **solo durante la ventana legítima** para tener
  `M` = nº de eventos legítimos ⇒ permite la **FPR por evento** (§4.2). **No cambia el ruleset**
  (virgen preservada); se declara.

---

## 8. Plan de Velociraptor

### 8.1 Reaprovechamiento del TFM del mismo tutor

- **9 técnicas**, perfil **P1–P4**, **artifacts públicos vs custom**, **Hayabusa**, y
  **comparación con Wazuh** ya hecha (base 3/9, custom 4/9; VR custom 9/9; Hayabusa 3/9).
- **Puente de umbrales:** mapeo **VR P1–P4 ↔ niveles Wazuh** (Tabla 60 del TFM).
- **Importante (nota del humano en las notas):** el TFM evaluó **con y sin plugins** y **hay
  cambios**; el humano propone **evaluar todo VIRGEN primero** (Wazuh y VR) ⇒ coincide con el
  eje de configuración.
- **Se reutiliza** la **metodología**; **no** se copian resultados ajenos.

### 8.2 Bloques de Velociraptor

- `velociraptor-lab`: desplegar **servidor + cliente** en el lab (Linux + Windows).
- `velociraptor-virgen`: **artifacts públicos/nativos** (sin custom) sobre los **55 ataques** +
  legítimo ⇒ T2/T4 VR virgen. **Define la unidad de VR** (fila de artifact = "alerta").
- `velociraptor-propias` (contingente): **artifacts custom P1–P4** ⇒ eje `+custom`.

### 8.3 Riesgo metodológico (explícito)

Velociraptor **no es un motor de reglas**: su salida son **filas de artifacts**. Equivalencias a
declarar: *artifact ≈ regla*, *fila emitida ≈ alerta*, *perfil P1–P4 ≈ nivel*. La **comparación
VR↔Wazuh** se hace **por técnica** (como el TFM) y con la tabla de mapeo, **declarando** que son
paradigmas distintos (alarmas vs recolección), y con la **unidad común** (acción GHOSTS / hora,
§4.6). **No se fuerza** una igualdad artificial.

---

## 9. Internet: decisión y alternativa

- **Decisión (recomendada):** **laboratorio aislado + "internet local" simulada + declarada**.
  Se levantan servicios locales que representan navegación/descarga/nube/C2 (los mismos que ya usa
  el corpus para T1567.002/.003/.004, T1102, T1071, T1090…).
- **Argumento (para el tutor):** un **HIDS mira el host**; detectar un C2 = detectar el
  **proceso/conexión**, y eso **funciona igual** con un C2 local que con uno real. Además, el
  **trabajo NIDS de referencia usó datasets, no internet en vivo**; y el hermano **Jorge Linares**
  aisló la red con **INetSim** (§1.5).
- **Alternativa híbrida (documentada, no descartada):** añadir NAT temporal **solo** para una
  prueba representativa de C2 real (declarando IPs/dominios y fechas), como sub-experimento
  acotado si el tutor lo exige.
- **Sin secretos en el repo** (regla vigente).

---

## 10. Secuencia de bloques (orden razonado)

### 10.1 Principios de orden

1. **Congelar antes de medir.** La métrica y las tablas se cierran **antes** de la primera medida
   nueva.
2. **Virgen primero.** Wazuh virgen y VR virgen **antes** de `+propias`/`+externas`/`+custom`.
3. **Lo gratis, primero.** El recorte de lo ya medido se hace **ya**.
4. **Lo largo, pronto.** La **captura legítima de 72 h** se **arranca cuanto antes** (reloj).
5. **El lab no se comparte mal.** No medir dos cosas a la vez que se ensucien (decisión *tester*).
6. **Trazabilidad.** Cada bloque cierra con huella (`sha256`) y verificación del *tester*.

### 10.2 Bloques (orden propuesto)

**Programa `reencuadre` (documentación — no toca el lab):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| **R0** | **`reencuadre`** *(este plan)* | Congela objetivo, alcance, métrica, tablas, secuencia. Gate humano. | — |
| **R1** | **`reencuadre-docs`** | Reescribe `context.md` / `requirements.md` / `roadmap.md` (+ glosario, nomenclatura, **Tabla 1**). | R0 |
| **R2** | **`reencuadre-metrica`** | **Especifica y congela** la métrica + **plantillas T1–T5 + Requisitos + Leyenda** (excels equivalentes) + scripts deterministas + tests. | R0 |

**Fase de medida VIRGEN (aprovecha lo hecho):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| **M1a** | **`virgen-wazuh-ataques` (histórico)** | **Recorte determinista** de los 55 ATA por `rule_level` × `rs_origen` → **T2/T4 (virgen × umbral × {RS1, RS1+RS2})** con el **baseline viejo**. Verifica el "paquete pcap". | R2 |
| **L0** | **`legitimo-infra`** | **GHOSTS** + **"internet local"** (construcción). Go/no-go. | R2 |
| **L1** | **`legitimo-72h`** | Captura legítima **72 h** (Wazuh virgen) + instrumentación del denominador. **Cuello de botella (3 días).** | L0 |
| **M1b** | **`virgen-wazuh-ataques` (RE-EJECUCIÓN)** | **Re-corre el recorte** con el **legítimo NUEVO** como catálogo de ruido (§10.4). | L1, M1a |
| **L2** | **`legitimo-analisis`** | **T3/T4 (legítimo virgen)** → cierra **T4 virgen**. | L1, M1b |

**Velociraptor VIRGEN:**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| **V0** | **`velociraptor-lab`** | Servidor + cliente VR (Linux + Windows). | R2 |
| **V1** | **`velociraptor-virgen`** | Artifacts públicos sobre los 55 ATA + legítimo → **T2/T4 VR virgen**. | V0, (L1 idealmente el mismo dataset legítimo) |

**Punto de decisión (gate): ¿añadimos reglas/artifacts propios?**

| # | Bloque (contingente) | Qué hace | Depende de |
|---|---|---|---|
| **W2** | **`wazuh-propias`** | RS3 (propias) + **preflight anti-enmascaramiento** + **re-medir** ⇒ config `+propias`. | gate, M1b, L2 |
| **W3** | **`wazuh-externas`** | RS4 curado (Sigma/community) + re-medir ⇒ `+externas`. | gate, W2 |
| **V2** | **`velociraptor-propias`** | Artifacts custom P1–P4 + re-medir ⇒ `+custom`. | gate, V1 |

**Windows (segunda plataforma):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| **B1** | **`fase-03b` (Windows ataques)** | Ataques P1 en Windows (continúa desde `ATA055`) + T2/T4 Windows. | R2, (lab Windows ya hecho) |

**Cierre:**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| **A1** | **`analisis-final`** | **T5 (pruning)** + métricas finales + gráficas + conclusiones + comparativa VR↔Wazuh. | M1b, L2, V1, (contingentes), (B1) |
| **A2** | **`memoria`** | Memoria + anexos (esqueleto de los hermanos). | A1 |

### 10.3 Crítica de caminos y paralelismo

- **Camino crítico:** R0 → R2 → **L0 → L1 (72 h)** → M1b → L2 → A1 → A2. La **captura legítima**
  es el **cuello de botella real** (días de reloj) ⇒ **arrancarla antes** que el resto.
- **Paralelizable:** M1a (recorte), V0/V1 y B1 pueden solaparse con la captura **si el *tester*
  confirma** que no ensucian el legítimo (VMs distintas / la corrida en la VM "legit" aislada).
- **Ventaja clave:** M1a/M1b son **recorte** (días → horas) porque el corpus ya está medido y
  etiquetado con `rule_level` + `rs_origen`.
- **(v2 · decisión del humano, 2026-10-16)** **No se mezclan HIDS**: orden = **Linux Wazuh →
  Windows Wazuh → Velociraptor (Linux y Windows)**. Y las **corridas de legítimo son POR SEPARADO**
  (un HIDS a la vez, **sin el otro instalado**), como en los TFGs hermanos. Sustituye a la opción
  de "corrida simultánea de los 2 HIDS" (§11.2, decisión abierta 4 → **resuelta: por separado**).
- **`W2`/`W3`/`V2` (propias)** NO se abren en el camino crítico: son **contingentes al gate**.

### 10.4 ⚠️ (v2) Nota de orden — ¿se recalculan los ataques antes del nuevo legítimo?

> **Pregunta del humano:** *"¿se recalculan los ataques ANTES del nuevo legítimo? ¿no habría que
> medirlo sobre el nuevo legítimo?"* → **Tiene razón.** Resolución (congelada así):

1. El **recorte de ataques** (T2: **qué se detecta**, con qué `rule.id`, a qué `rule.level`)
   **NO depende del legítimo** ⇒ puede ir **pronto** (`M1a`, histórico).
2. Pero **el juicio del ruido** (qué alertas de las ventanas de ataque son FP) y **las métricas
   finales** (Precisión / F1 / GM / Usabilidad) **SÍ dependen del NUEVO legítimo** (el catálogo de
   ruido válido es el de **las 72 h**).
3. ⇒ Los **baselines actuales (2×4 h, Linux y Windows) quedan como `histórico`**; el catálogo de
   ruido **autoritativo** es el de **las 72 h**.
4. ⇒ **Tras el legítimo, el recorte se RE-EJECUTA** (`M1b`): es **determinista y barato**, y así
   **todo se juzga con el mismo legítimo**.
5. ⇒ **Orden resultante:** **lanzar el legítimo (72 h) cuanto antes**; el **recorte (`M1a`) en
   paralelo**; y **`M1b` (re-recorte) justo tras `L1`**.

---

## 11. Riesgos, decisiones abiertas y casos límite

### 11.1 Riesgos (con mitigación)

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **Unidad legítima mal definida** | Métrica no defendible | **Decidida** (§4.2) con complementos; **validar con el tutor** antes de congelar |
| **Comparación entre HIDS** (unidades no homogéneas) | Comparativa injusta | **Unidad común** (acción GHOSTS / hora) + **comparación por técnica** (§4.6) |
| **GHOSTS no viable en el tiempo** | Bloque L1 se cae | Go/no-go en `L0`; **plan B**: acciones reales (navegador/apps) por guion, declarado |
| **72 h de reloj** | Bloquea el cierre | Arrancar pronto; paralelizar; 72 h **ampliable**, no reducible |
| **`+propias`/`+externas` = escribir muchas reglas** | Alcance desbocado | **Contingente al gate**; alcance acotado a P1; reutilizar Sigma/community curado |
| **Velociraptor no es rule-based** | Comparación injusta | Unidad VR definida; mapeo P1–P4↔nivel; **comparación por técnica** |
| **(v2) Desfase v17↔v19.1** | Tabla 1 no cuadra con el corpus | **Equivalencia + 3 discrepancias declaradas** (§1.3) |
| **Congelar mal la config** | Medidas inválidas | Bóveda de congelación (§6) + huella + repetición |
| **Windows (segunda plataforma)** | Tiempo | Fase propia; reutilizar lab; nunca Linux y Windows a la vez (RAM) |
| **CRLF / cadena de huellas** | Reproducibilidad | Deuda existente declarada; **no** `checkout/stash` sobre `esperado`/`Audited` |
| **Fuga de secreto** | Seguridad | **Regla dura**: nunca escribir la contraseña del lab en ficheros del repo |

### 11.2 Decisiones abiertas (para el humano / tutor)

1. **Unidad legítima** (evento vs acción vs hora) → se propone **evento** con complementos (§4.2).
2. **¿Se añaden reglas/artifacts propios?** → **gate tras virgen**.
3. **¿Windows entra en la medida virgen** o después? (tiempo).
4. **Corrida simultánea de los 2 HIDS** en el legítimo (¿inocuo?) → decisión del *tester*.
5. **Denominador legítimo**: ¿`logall_json` los 72 h, o conteo en origen, o fallback?
6. **GHOSTS go/no-go** y plan B.
7. **InfoStealer**: **fuera por ahora** ("a decidir" a futuro).
8. **Internet**: híbrido (C2 real acotado) → ¿lo pide el tutor?
9. **(v2) Umbral de "Pruning N"**: ¿500/1000 (escala del NIDS) o adaptado al volumen de nuestro
   legítimo? (§5.5).
10. **(v2) Fleco 3 — "tamaño/tiempos"**: confirmar que `nº acciones (k/m)` + `tiempo de ventana`
    + `t hasta 1ª detección` es el "algo equivalente" que quería el profesor.

### 11.3 Casos límite declarados

- **Nivel 0 no emite alerta** (`92600`): el umbral "≥0" se documenta como "hay/no hay alerta".
- **Auto-alerta del HIDS** domina el ruido de Linux (~54 %): es FP operativo (se cuenta y se
  declara); con umbral alto puede desaparecer → **T5** lo mide.
- **Reglas de doble uso** (TP en un ataque, FP en legítimo): no se borran a ciegas; **T5** con
  variante **conservadora** y **conservadora generalizada**.
- **`RS2` (auditd) es del paquete**, se cuenta como **parte de "virgen"** y también como config
  `C0 = RS1` (recorte) para ver su aporte.
- **(v2) Doble conteo de señales**: una misma acción puede generar **varias** señales a la vez
  (lección de Peña) ⇒ siempre se reportan **`#Alertas`** y **`#rule.id` distintos** (correlacionadas)
  por separado.

---

## 12. Criterios de aceptación

### 12.1 CA del bloque `reencuadre` (este)

| # | Criterio | Verificación |
|---|---|---|
| CA-R1 | `plan.md` existe y tiene las secciones obligatorias (objetivo, pasos, ficheros, CA, verificación, fuera de alcance). | Revisión del fichero |
| CA-R2 | Los 55 ATA **tocan P1** y la afirmación se verifica en `ATA_index.csv`. | `grep` sobre tácticas (**nota**: ATA055 = `Credential Access; Collection`; ATA035 = `Collection` en el CSV, y su técnica T1056.004 ∈ *Collection + Credential Access* ⇒ P1 = *toca* {Collection, Exfiltration, Impact}) |
| CA-R3 | Se confirma que **RS3 = RS4 = 0** y que `-Audited.csv` trae `rule_level` + `rs_origen`. | Citas a `active_ruleset.txt` + una `-Audited.csv` |
| CA-R4 | La **métrica** está definida sin ambigüedad (unidades, fórmulas, reglas de conteo). | §4 |
| CA-R5 | Las **5 tablas + Requisitos + Leyenda** tienen estructura definida **según el Excel real**. | §5 |
| CA-R6 | La **secuencia de bloques** está ordenada con dependencias, cuello de botella y la **nota de orden (§10.4)**. | §10 |
| CA-R7 | Hay **gate humano** con preguntas claras. | §13 |
| CA-R8 | **No** se ha escrito la contraseña del lab ni secretos. | Auditoría de texto |
| **CA-R9** | **(v2)** La **equivalencia Tabla 1 (v17) ↔ corpus host (v19.1)** está declarada con las **3 discrepancias** trazadas. | §1.3, §5.1 |
| **CA-R10** | **(v2)** El **repo hermano** se cita como referencia y su *pruning* se refleja en **T5**. | §1.4, §5.5 |

### 12.2 CA del programa (por hito)

| # | Criterio | Verificación |
|---|---|---|
| CA-P1 | `context.md`/`requirements.md`/`roadmap.md` reescritos y coherentes con §3. | Revisión + coherencia cruzada |
| CA-P2 | **Métrica y tablas congeladas** con versión y fecha. | Doc + huella |
| CA-P3 | **T2/T4 virgen × umbral × RS** regenerables por script determinista. | Re-ejecución byte a byte |
| CA-P4 | Los 55 **"paquetes pcap"** (contexto+acciones+telemetría, criterio ART) existen, **consolidados** y se listan. | Listado por ATA |
| CA-P5 | **72 h de legítimo** con GHOSTS + internet local, instrumentado el denominador. | Logs + `M` |
| CA-P6 | **T3/T4 legítimo** con FP/TN por unidad y por alerta (± correlacionadas). | Hojas + script |
| CA-P7 | **VR virgen** evaluado sobre el mismo corpus + mapeo P1–P4. | T2/T4 VR |
| CA-P8 | **T5 (pruning)** calculado con **todas las variantes** (500/1000, Conservative, Generalized, Aggressive). | Hoja T5 |
| CA-P9 | Cada cifra con **huella** y **verificación del *tester*** (PASA). | Cadena de huellas |
| CA-P10 | **Comparativa VR↔Wazuh** por técnica con limitaciones declaradas y unidad común. | Tabla final |
| **CA-P11** | **(v2)** El recorte (**M1b**) se **re-ejecuta** con el legítimo de 72 h y los baselines aparecen como `histórico`. | Doc + huellas |

---

## 13. Gate humano (lenguaje sencillo)

> Preguntas claras para aprobar el reencuadre **antes** de tocar nada.

1. **¿Te vale este marco?** Solo P1, solo Wazuh + Velociraptor, virgen primero, estructura
   Clasificación → Ataques → Análisis, y las **5 tablas del profesor** adaptadas **según su Excel
   real**.
2. **La unidad del legítimo** (lo más delicado): propongo **contar eventos legítimos** (como el
   NIDS contaba *flujos*) y usar **FP = % de eventos que disparan alerta**, **más** dos
   complementos (acciones de GHOSTS y FP/hora). Para **comparar Wazuh y Velociraptor**, la unidad
   **común** es la **acción de GHOSTS / la hora** (sus "eventos" no son homogéneos). ¿De acuerdo?
3. **¿Añadimos reglas/artifacts propios** (Wazuh RS3/RS4, VR custom) o **nos quedamos solo en
   virgen**? (Mi propuesta: medir **virgen** completo y **decidir después**.)
4. **GHOSTS + 72 h**: ¿ok invertir en montar GHOSTS (infraestructura) y 3 días de reloj? Si GHOSTS
   no sale, ¿aceptas el **plan B** (acciones reales por guion, declarado)?
5. **Internet**: ¿te vale **lab aislado + internet local** (argumento: el HIDS ve el host), con la
   **alternativa híbrida** documentada, o quieres el sub-experimento de C2 real?
6. **Windows**: ¿lo hacemos en paralelo con Linux o después? (recomiendo: **después de la virgen
   de Linux**).
7. **InfoStealer**: ¿lo dejamos fuera y "a decidir"?
8. **(v2) Tabla 1**: ¿te vale usar la **Tabla 1 (v17)** como clasificación y **declarar** las 3
   diferencias con nuestro corpus v19.1 (`T1029`, `T1602`, `T1567.003`)?
9. **(v2) Orden**: confirmo que **lanzo el legítimo de 72 h cuanto antes** y que el **recorte de
   ataques se re-ejecuta** sobre el legítimo nuevo antes de las métricas finales (§10.4). ¿OK?

---

## 14. Qué NO entra (fuera de alcance)

- **Tercer HIDS** (OSSEC / Sagan / Splunk / Samhain): fuera.
- **Snort / pcaps / análisis de red pura**: fuera.
- **Coste computacional** (Fase 4 antigua): fuera, **salvo experimento opcional declarado** (§14.1).
- **InfoStealer** como exfiltración: fuera **por ahora** ("a decidir").
- **Técnicas P2/P3**: fuera (otro trabajo).
- **Modo bloqueo** del HIDS: fuera (detección-only).
- **Comparativa cuantitativa** con los TFGs hermanos: solo **cualitativa**.
- **(v2) `ait-aecid` / AECID / `kyoushi-environment`**: fuera (solo **cita** en el estado del arte).
- **(v2) FortiEDR** (comercial de la guía): fuera.

### 14.1 (v2) Experimento opcional declarado — coste computacional

> El profesor: *"sería interesante ver por qué al medir afecta a la detección y cómo, con hechos;
> se podría usar para TP/FP"*.

**Declarado como opcional, "si sobra tiempo"** (NO entra en el camino crítico): medir
CPU/memoria/IO mientras corre el HIDS y **ver si (y cómo) la propia medición afecta a la
detección**, con hechos; explorar si el coste sirve como señal para **TP/FP**. Si se hace, va como
**anexo**, nunca como resultado principal.

---

## 15. Ficheros que se tocarán

**Este bloque (`reencuadre`):**
- `plan.md` (este fichero). **Único.**

**El programa (estimado; cada bloque lo confirmará en su plan):**
- `context.md`, `requirements.md`, `roadmap.md` (R1).
- `Hojas/` → nuevas hojas/excels equivalentes a **T1–T5 + Requisitos + Leyenda** (R2, M1a/M1b, L2…).
- `_artefactos/scripts/` → scripts de recuento deterministas + *pruning* (R2, A1).
- `Soporte/Laboratorio/` → GHOSTS + "internet local" (L0).
- `Soporte/Wazuh/Reglas/` → RS3/RS4 **solo si** el gate los aprueba (W2/W3).
- `Soporte/Velociraptor/` (nuevo) → lab + artifacts (V0/V1/V2).
- `Dataset/Legitimo/` → nueva corrida 72 h (L1); los baselines actuales se **etiquetan como
  `histórico`** (no se borran).
- `Dataset/Ataques/…` → **consolidación del "paquete"** por ataque (contexto+acciones+telemetría).
- `_fases/<bloque>/` → plan/change-doc por bloque.

**`_recursos/`: solo lectura. Nunca se modifica.** (Material de la reunión en
`_recursos/reuniones/03/`.)

---

## 16. Trazabilidad (fuentes)

- **Reunión (material nuevo, ruta corregida):** `_recursos/reuniones/03/notas reunion TFG.txt`,
  `ghost.txt`, `tfg interesante.txt`, **`Tabla 1 - Matriz MITRE Enterprise v17.xlsx`**,
  `Tablas 2, 3, 4, 5 (con FG-PA).xlsx`, `TFM - Velociraptor como HIDS.pdf`,
  `TFM_JORGE_LINARES.pdf`, `TFM_Jose_Manuel_Peña_Ramírez.pdf`,
  `Detección_de_Ataques_en_Red_v7.pdf`.
- **Repo hermano NIDS (GitHub, público):**
  `https://github.com/ignmercam/mitre-attack-ids-detection-optimization` (README + árbol completo
  + `Scripts/optimo_Snort_GM_v4.py`, `tablas_Snort_GM_v2.py`, `procesa_prioridades_snort_v2.py`).
- **Profesor (repo):** `_recursos/reuniones/02/guia_profesor.txt` (y `notas_reunion.txt`),
  `recursos_profesor/documentacion-y-scripts-profesor/Detecciones Red (Ref).xlsx`,
  `…/01_TFG4-HIDS … (obsoleto)`, `recursos_profesor/repos-similares/Snort-FG-PA-…/`.
- **Nuestro repo:** `state.md`, `context.md`, `requirements.md`, `roadmap.md`,
  `Hojas/ATA_index.csv`, `Hojas/corpus_host.csv`, `Hojas/cobertura_p1_linux.csv`,
  `Hojas/inventario_p1_windows.csv`, `Hojas/lista_tecnicas_validas.md`,
  `Soporte/Wazuh/Configuracion/active_ruleset.txt`, `rulesets_diseno.md`,
  `politica_filtrado_ruido.md`, `Soporte/Ataques/plantilla_esperado.md`,
  `Soporte/Laboratorio/windows/telemetria_windows.md`, `Bitacora/ATA001.json`,
  `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/README.md`.

**Afirmaciones verificadas con cita directa (para el revisor):**

| Afirmación | Cita verificable |
|---|---|
| **Tabla 1 v17**: Tactics 14/14/0; Techniques 211 (red 77, solo-red 17); Subtechniques 468 (red 91, solo-red 34) | `Tabla 1 …v17.xlsx`, hoja `Summary` (fecha 22/06/2025; versión v17) |
| P1 en Tabla 1 = **41 técnicas**, **3 solo-red** (`T1029`, `T1030`, `T1602`) | Cross-check de la hoja `Techniques` (script propio, esta revisión) |
| Nuestro corpus **625/697** host-eligible; **P1 = 89** | `Hojas/corpus_host.csv`, `Hojas/lista_tecnicas_validas.md` |
| **3 discrepancias** (`T1029`, `T1602.001/.002`, `T1567.003`) entre Tabla 1 y el corpus | Cross-check `Tabla 1 …v17.xlsx` ↔ `inventario_p1_windows.csv` |
| **Corpus P1-Linux** = 72 filas (48 medida · 6 cubierta_por_ata · 8 cubierta_madre · 2 parcial · 8 no factible) | `Hojas/cobertura_p1_linux.csv` |
| **55 ATA** `ATA001`..`ATA055`; ATA055 = `Credential Access; Collection` | `Hojas/ATA_index.csv` |
| **RS3/RS4 vacías** | `active_ruleset.txt` (RS3 0, RS4 0) — y la revisión del orquestador (160/160 con `rule_level`+`rs_origen`) |
| **Modelo del profesor**: T4 → TPR por **pcaps**, FPR por **Flows** (`#Flows=78.694.206`); GM = √(TPR·(1−FPR)); Usabilidad = #Alertas_FP/#Alertas_TP | `xlsx_dump.txt` (hojas `T4 (Rend)`, bloque de fórmulas) |
| **T5** = Pruning 500/1000, Conservative, Generalized Conservative, Aggressive | `xlsx_dump.txt` (hojas `T5 (Pru)`) |
| **Repo hermano**: `TOTAL_ATK_PCAPS=110`, `TOTAL_LEG_FLOWS=78.694.206`, `gm=√(tpr·tnr)`, `usab=a_fp/a_tp`, *pruning* 500/1000/Conservative/Aggressive G-Mean; `Raw` vs `Diff Alerts/Flow` | `Scripts/optimo_Snort_GM_v4.py`; README del repo |
| **Repo hermano**: TFG de **Ignacio Merchán Cámara**, tutor **F. J. Muñoz Calle**, 2026 | README del repo |
| **La guía cita** OSSEC/Sagan/Splunk/Samhain, Snort-por-logs, `ait-aecid`, `kyoushi-environment` | `_recursos/reuniones/02/guia_profesor.txt` líneas 3, 17, 29, 30–32 |
| **Linares**: 85,5 % (13,9 FP) vs 51 % (3,1 FP); INetSim | `TFM_JORGE_LINARES.txt` (abstract, §7) |
| **Peña**: control benigno (32 colecciones, 3 con 26 filas) + control no-ransomware (5 muestras, 0 filas); doble conteo de categorías | `TFM_Jose_Manuel_Peña_Ramírez.txt` §5.5, §5.7 |
| **VR**: 9 técnicas, P1–P4, Wazuh base 3/9, custom 4/9, VR custom 9/9, Hayabusa 3/9; Tabla 60 (mapeo severidad) | `TFM - Velociraptor como HIDS.txt` |

---

### Declarado — cosas que NO cuadran (para el revisor)

1. **La guía del profesor cita herramientas que ya no entran** (tercer HIDS, Snort, `ait-aecid`):
   la guía es **rectora pero desactualizada** (§3.4). **No se aplica tal cual.**
2. **Desfase de versión ATT&CK**: Tabla 1 = **v17**; nuestro corpus = **v19.1** ⇒ **3
   discrepancias** de criterio/versión (`T1029`, `T1602`, `T1567.003`). Se **declaran**, no se
   ocultan.
3. **Nombres de táctica cambiados**: v17 *Defense Evasion* ↔ v19.1 *Stealth* (+ *Defense
   Impairment*) ⇒ **no se puede unir por nombre**; hay que mapear por **ID**.
4. **"4 niveles de prioridad" del hermano**: en realidad **Snort = 4 niveles** (`Priority ≤1..≤4`)
   + `Any`; **FG/PA = 5 niveles** (`severity ≥1..≥5`). Se declara la asimetría.
5. **ATA055 / ATA035** no son P1 "puros": su táctica incluye *Credential Access*. La afirmación
   "100% P1" se sostiene **solo** bajo "toca {Collection, Exfiltration, Impact}".
6. **Nuestro corpus tiene 55 casos pero 128 ventanas** (doble iteración + 9 repeticiones `_rev`):
   la métrica (TPR por caso) debe **declarar** qué ventana es la canónica (la repetición lo es en
   las 9).
7. **El "paquete pcap" hoy está disperso** (carpeta del comando + bitácora + resultados + `c0/`):
   hay que **consolidarlo homogéneo** por ataque (criterio ART).

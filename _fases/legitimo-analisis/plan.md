---
bloque: legitimo-analisis
nombre: L2 (análisis del legítimo 72 h) + M1b (re-corte de los ataques con el legítimo nuevo)
version: 1
status: approved_by_human
fecha: 2026-11-07
fecha_aprobacion: 2026-11-08
aprobado_por: humano
autor: tfg-planner
depende_de: _fases/legitimo-v3/change-doc.md · Soporte/Metrica/metrica_hids.md (v1) · Soporte/Metrica/boveda_congelacion.md (v2) · Hojas/T2_ataques.csv (M1a, histórico)
gate: humano
nota_gate: |
  **APROBADO (2026-11-08).** Luz verde del humano al plan con las 3 decisiones (§12): unidad de `FP_uni` = linea de `archives`; catalogo M1b = 72 h + 4 reglas historicas del operador; completar T3/T5 sin tocar formulas. **Decision expresa: NO se anade** la comprobacion adicional «ningun ataque depende solo de una regla de ruido» (riesgo declarado y aceptado).
---

# plan.md — bloque `legitimo-analisis` (L2 + M1b)

> **Resumen en 6 líneas.** Este bloque **no mide nada nuevo en el laboratorio**: convierte los
> datos ya sellados de la ventana legítima de 72 h en **T3/T4/T5** y **re-juzga** las 128
> ventanas de ataque con el catálogo de ruido nuevo (**M1b**). La pieza crítica es **`FP_uni`**:
> las alertas **no llevan id de evento**, así que la unidad se toma de la **línea de
> `archives.json`** (el evento decodificado), **no** del `timestamp` (que pierde un 15 % de
> unidades). El resultado esperado es **FPR(C1,N=0) = 85,7963 %**, **FPR(C0,N=0) = 0,0146 %**,
> **TPR = 53/55** y **0 cambios** en T2 respecto de M1a; los 2 `FN` siguen siendo
> **ATA013/ATA034**. La decisión metodológica que necesita tu OK es el **catálogo M1b** (72 h + 4
> reglas históricas del operador); la unidad de `FP_uni` no es una opción libre: es la única que
> no pierde eventos. Se explica en §3.1/§6.1 y se lleva al gate.

---

## 0. Resumen ejecutivo (qué sale y qué decide)

| # | Resultado | Valor esperado | Dónde |
|---|---|---|---|
| 1 | `M` (endpoint `001`) | **342.966** eventos | `denominador_M.csv`; recuento propio |
| 2 | `FP_uni` C1×N0 (y N3) | **294.252** unidades | T3; índice de eventos |
| 3 | `FPR` C1×N0 / `TNR` | **0,857963** / **0,142037** | T3/T4 |
| 4 | `FP_uni` C0×N0 / `FPR` | **50** / **0,000146** | T3/T4 |
| 5 | `FP_uni` C1×N7/N10 / N12 | **2** / **0** | T3/T4 |
| 6 | Variante **sin `auto_ruido`** | **227.967** unidades; FPR **0,664693** | T3 |
| 7 | `auto_ruido` en 72 h | **66.285** alertas-evento (**22,5266 %**) | §3.2 / catálogo |
| 8 | Reglas de **doble uso** | **4**: `80781`, `80790`, `80791`, `80792` | T5 |
| 9 | `80792` en ataques | **1.988** detecciones canónicas; **53/55** casos | T5 |
| 10 | M1b | **128/128** ventanas re-juzgadas; **0** cambios de fila; **53/55**; FN = {ATA013, ATA034} | T2/T4 |
| 11 | Sensibilidad catálogo 72 h **puro** | **54/55** (flipa solo ATA034; ATA013 sigue FN por `dudosa`) → **NO canónica** | §6.4 |
| 12 | `pytest` | **≥ 342 + nuevos**, todo verde | §9 |

**Lectura:** el ruido del legítimo es **estructural** (`auditd`: `80792` = 80 %, `80791` = 19 %)
y **no se puede separar** de la detección con pruning ingenuo: la regla más ruidosa (`80792`) es
también la que detecta **53/55** ataques. El `Aggressive (G-Mean)` bien hecho quita 3 reglas de
doble uso **redundantes** (`80781/80790/80791`) y **conserva `80792`**: GM sube de **0,369963**
a **0,547509** sin perder TPR.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

1. **L2 — analizar el legítimo**: producir **T3** (plano legítimo: `FP_uni`, `TN_uni`, `FPR`,
   `TNR`, complementos `FP/acción`, `FP/hora`, variante sin `auto_ruido`), **T4** (las 7
   fórmulas) y **T5** (reglas de doble uso + pruning), con la **rejilla** `C0/C1 × N ∈
   {0,3,7,10,12}` y el **catálogo de ruido autoritativo** de las 72 h.
2. **M1b — re-cortar los ataques**: **re-juzgar** las **128 ventanas** con ese catálogo, sin
   re-ejecutar ningún ataque, y recalcular **T2/T4** comparando con **M1a** (histórico).
3. Dejar **trazabilidad** completa (fuente:línea, `sha256`, decisiones) y **declarar** lo que no
   se pueda calcular con rigor.

### 1.2 Alcance (dos tandas, un solo plan)

- **Tanda L2** (§5): insumos → índice de eventos → catálogo → T3/T4 → estabilidad → T5.
- **Tanda M1b** (§6): catálogo M1b → re-ejecución de las 128 ventanas → T2/T4 → comparación →
  invariantes y sensibilidad.

### 1.3 Qué NO entra (fuera de alcance)

- **No se toca el laboratorio**: **0 VMs**, sin SSH, sin Wazuh, sin `vmrun`. No hay ventana que
  armar ni reloj que esperar.
- **No se re-ejecutan ataques**: M1b es **recorte determinista** sobre `-Detalle.csv` ya
  existentes. No se re-ataca ni se re-mide el corpus.
- **No se modifica la métrica ni la bóveda**: `Soporte/Metrica/metrica_hids.md`,
  `metrica_hids.py` y `boveda_congelacion.md` se **leen**, no se editan. Las fórmulas y `M` no
  cambian.
- **No se modifica el corpus**: `Hojas/ATA_index.csv`, `Hojas/repeticiones.csv`,
  `Dataset/Ataques/.../Auditado/*` y `Bitacora/` **no se tocan**. El re-corte se **añade** en
  `Dataset/Ataques/.../M1b/`.
- **No se toca `Dataset/Legitimo/legitimo_72h/`** promovido (8 ficheros): es **entrada de solo
  lectura**. Los productos nuevos van a `.../legitimo_72h/analisis/`.
- **No se toca `_recursos/`**.
- **No C2/C3**: `RS3 = RS4 = 0`; sus bloques se **declaran vacíos** (L8).
- **No Windows (B1), no Velociraptor (V0/V1), no evasión, no InfoStealer, no P2**.
- **No se re-etiqueta a mano** ninguna fila; el re-corte es determinista y se audita con `diff`.
- **No commits ni `git push`**; sin secretos.

---

## 2. Estado de partida verificado (hechos, no supuestos)

| # | Hecho | Valor | Fuente |
|---|---|---|---|
| 1 | Ventana legítima | `2026-11-02T00:00:00Z .. 2026-11-05T00:00:00Z` (72 h) | `ventana_meta.md:16-18` |
| 2 | `M` endpoint `001` | **342.966** (total con manager: 394.739) | `denominador_M.csv:5-6` |
| 3 | Alertas del endpoint | **294.253**; **11** `rule_id` | `ruleids_legitimos.csv:2-13`; `ventana_meta.md:77-94` |
| 4 | Concentración del ruido | `80792` 236.277; `80791` 55.649; `80780` 1.871 | `ruleids_legitimos.csv:5-12` |
| 5 | Acciones GHOSTS | **504** (163/178/163) | `ghosts_acciones.csv:3-4`; `ventana_meta.md:107-109` |
| 6 | Campaña FP | **11/11 `SI`**; **1.793** alertas; **0** a `N≥7` | `campana_fp.csv:4-14` |
| 7 | Catálogo viejo (M1a) | **12** reglas (`5402/5501/5502/5715` incluidas) | `Dataset/Legitimo/ruleids_legitimos.csv:2-13` |
| 8 | Catálogo nuevo (72 h) | **11** reglas (`11, 554, 591, 80711, 80730, 80780, 80781, 80782, 80790, 80791, 80792`) | `Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv:2-13` |
| 9 | T2 viejo (M1a) | **53/55**; FN = `ATA013`, `ATA034`; C1×N0 `A_TP` = 2.004 | `Hojas/T2_ataques.csv` (cabecera); `Hojas/T4_rendimiento.csv` |
| 10 | `-Audited.csv` | **128** ventanas; `rule_level` + `rs_origen` + `categoria` | `Dataset/Ataques/.../Auditado/` |
| 11 | Repeticiones canónicas | **9** (`_rev1`) | `Hojas/repeticiones.csv:4-12` |
| 12 | `archives.json` retenido | 4 ficheros en `D:\TFG-VMs\legitimo-2026-11-02\denominador\`; `sha256` **idénticos** a `denominador_M.csv` | verificado 2026-11-07 |
| 13 | Enlace alerta↔evento | multiconjunto `(timestamp, rule_id)` **exactamente igual** entre eventos de `archives` con nivel ≥3 (294.252) y alertas sin `rule 11` (294.252) | verificado 2026-11-07 |
| 14 | `id` de Wazuh | **NO único**: 213.748 distintos para 342.966 líneas (129.218 colisiones) | verificado 2026-11-07 |
| 15 | `timestamp` como proxy | **249.761** distintos para 294.253 alertas (**-15,1 %**) | verificado 2026-11-07 |
| 16 | Regla `1002` | nivel **2** (72 eventos `snapd`) en `archives` pero **no** en alertas | verificado 2026-11-07 |
| 17 | Regla `11` | **1** alerta `stats` sin evento en `archives` | `ruleids_legitimos.csv:2`; `ventana_meta.md:94` |
| 18 | `auto_ruido` 72 h | **66.285** alertas-evento (**22,5266 %**) | verificado 2026-11-07 (predicado de `filtrar_ruido.py:322-346`) |
| 19 | Doble uso | **4** reglas: `80781`, `80790`, `80791`, `80792` | verificado 2026-11-07 (T3 × T2) |
| 20 | Reglas viejas no ejercitadas | `5402/5501/5502/5715`: **22** filas `ruido_conocido` en ATA013/ATA034 (**16** de `5501/5502` + **6** de `5715`) | verificado 2026-11-07 |
| 21 | Estabilidad diaria | FPR **0,859312 / 0,856924 / 0,857657** | verificado 2026-11-07 |
| 22 | Estabilidad horaria | FPR **0,828336 … 0,889727** (72/72 horas con FP) | verificado 2026-11-07 |
| 23 | Índice de eventos | **294.252** filas; **1,35 MB** `.gz` (16,0 MB crudo) | verificado 2026-11-07 |
| 24 | Bóveda | `version: 2`; `B10` sellado 2026-11-05 | `boveda_congelacion.md:4-8` |

> **Nota de honestidad:** los puntos 12–23 se han comprobado **hoy** con scripts de solo lectura
> sobre los ficheros retenidos. El ejecutor debe **repetir** las comprobaciones y **parar** si
> alguna no cuadra (§9). No se aceptan cifras “de memoria”.

---

## 3. Definiciones que fija este plan (sin cambiar la métrica)

### 3.1 Unidad legítima y `FP_uni` (la decisión clave)

- **Unidad** = **una línea de `archives.json`** = **un evento decodificado** por Wazuh
  (`metrica_hids.md:45-54`). `M` = líneas del agente `001` en `[t0,t1]` = **342.966**.
- **Clave de unidad** = **`(fichero, nº de línea)`** (p. ej. `02:12345`). Es **única por
  construcción** y determinista. **No** se usa el `id` de Wazuh (colisiona: 213.748 distintos
  para 342.966 líneas) **ni** `timestamp+agent` (249.761 distintos; pierde 44.491 unidades,
  15,1 %). Ambos proxies se **rechazan** y se cuantifican en §14.
- **`FP_uni`** = nº de **unidades distintas** con **≥1 alerta emitida** que pase
  `rs_origen ∈ config` y `rule_level ≥ N` (`metrica_hids.md:53, 93-96`).
- **`TN_uni` = `M − FP_uni`**; **`FPR = FP_uni / M`**; **`TNR = 1 − FPR`**.
- **Alerta emitida** = línea de `archives` con bloque `rule` y **nivel ≥ 3** (hecho observado:
  el log de alertas de esta instalación no contiene niveles < 3; causa probable
  `log_alert_level=3`, no verificable con el manager cerrado; ver §14.3). Los **72** eventos de
  nivel 2 (regla `1002`) **no** son alertas y **no** cuentan como FP.
- **`A_FP`** = nº de **alertas** (filas) que pasan el filtro. En este dataset **`A_FP = FP_uni`**
  porque **un evento emite como máximo una alerta** (1 `rule` por línea). La única excepción es
  la alerta `rule 11` (`stats`), que **no tiene unidad** y queda fuera de `C1` por
  `rs_origen=UNKNOWN`; se declara (§14.2).

### 3.2 `auto_ruido` (qué es **aquí**, con evidencia)

**Definición (congelada en `filtrar_ruido.py:322-346` y `politica_filtrado_ruido.md:86-108`)**:
una alerta es `auto_ruido` si **el origen es el propio Wazuh**, por **campos**, en este orden:

1. `audit_exe` (nombre base) ∈ `{wazuh-agentd, wazuh-syscheckd, wazuh-logcollector,
   wazuh-modulesd, wazuh-execd, wazuh-db, wazuh-analysisd}`;
2. `audit_cwd == /var/ossec`;
3. `audit_file` / `audit_dir` / `syscheck_path` bajo `/var/ossec/var/run/*`;
4. `rule_id == 11` **y** grupo `stats` (recuento interno).

**En la ventana de 72 h** (aplicando el predicado a los eventos de `archives`):

| `rule_id` | alertas | `auto_ruido` | motivo dominante | lectura |
|---|---|---|---|---|
| `80791` | 55.649 | **51.812** | `audit_exe=/var/ossec/bin/wazuh-agentd` (51.806) | el agente reescribe su estado |
| `80792` | 236.277 | **13.584** | `audit_cwd=/var/ossec` (9.752) + exe Wazuh (3.832) | hijos del HIDS, no la actividad GHOSTS |
| `80780` | 1.871 | **813** | exe Wazuh | `wazuh-modulesd` |
| `80781` | 93 | **74** | exe Wazuh | `wazuh-modulesd` |
| `80782` | 227 | **2** | exe Wazuh | residual |
| **Total** | **294.252** | **66.285** | | **22,5266 %** |

> **Cuadre con `alertas_detalle.csv`:** el CSV tiene **294.253** filas porque incluye la alerta
> `rule 11` (`stats`), que es `auto_ruido` pero **no tiene unidad** (no está en `archives`).
> Contando esa fila, las **alertas** auto son **66.286**; las **unidades** auto son **66.285**.
> T3 usa las unidades (66.285); el catálogo/`auto_ruido_evidencia.csv` declara ambas cifras.

- **No es una lista de reglas**: `80791` es `auto_ruido` en el **93 %** de sus alertas, pero el
  **7 %** restante son borrados legítimos de `udevadm`, `snapd`, `systemd`, etc. (evidencia:
  `audit_exe` de esas filas). Por eso el predicado es **por campos**, no por `rule_id`.
- **La cifra “≈54 %” de la métrica/baseline viejo NO es la de las 72 h**: el 54 % era el
  **baseline sintético de 2×4 h** (`state.md:96`; `politica_filtrado_ruido.md:106`). En 72 h es
  **22,5266 %**. Se declara; **no se cambia la métrica** (§14.1).
- **Variante sin `auto_ruido`** (complemento obligatorio): `FP_uni = 227.967`;
  `FPR = 0,664693` (66,4691 %). Se publica **junto** al titular, nunca en su lugar.

### 3.3 `ruido_conocido` y `dudosa` en el legítimo

- En una ventana **sin ataque**, toda alerta no-`auto_ruido` es, por definición, **ruido
  conocido** (no hay señales de ataque que evaluar). T3 las cuenta como **FP**.
- **`dudosa` = 0** en el legítimo: no hay `esperado` ni pertenencia al ataque. Se declara.
- En M1b (ataques), la `dudosa` **sí** existe y se resuelve con las `-Revision.csv` originales
  (veredictos humanos ya firmados); **no se re-etiqueta**.

### 3.4 Regla de **doble uso**

Una `rule.id` es de **doble uso** si:

1. aparece en el **catálogo de ruido** de las 72 h (es FP en legítimo), **y**
2. es `categoria=deteccion` en **≥1 caso canónico** de ataque.

**Resultado (verificado):** `80781`, `80790`, `80791`, `80792`.
`80792` es la regla **principal** de detección (**1.988** alertas canónicas; **53/55** casos);
las otras tres son señales declaradas en **ATA002** (`80781`, `80790`) y **ATA008** (`80791`).
No se borran a ciegas (L3, `metrica_hids.md:242`): **solo T5 las evalúa**.

### 3.5 Catálogo autoritativo y catálogo M1b

- **Catálogo autoritativo** = las **11** reglas **observadas** en las 72 h
  (`Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv`). Es la fuente de T3/T5.
- **Catálogo M1b (decisión de este plan)** = **72 h ∪ {5402, 5501, 5502, 5715}** (15 reglas),
  con una columna `origen_catalogo ∈ {72h, baseline_historico}`. **Motivo:** las 4 reglas del
  operador **no se ejercitaron** en las 72 h porque la ventana **no tuvo sesiones del operador
  en el endpoint** (`ventana_meta.md:170-171`: 0 `srcip`/`srcuser`; sin `sudo`), **no** porque
  sean ataques. La ausencia en 72 h **no es evidencia de detección**; el baseline histórico es
  la única evidencia disponible para esas 4 reglas. Se **declara** y se lleva al gate.
- **Sensibilidad** (no canónica): catálogo **72 h puro** (11 reglas). Se publica para demostrar
  por qué **no** se usa: flipa **ATA013/ATA034** a `TP` por ruido del operador (§6.4).

### 3.6 Umbral efectivo

`N=0` ≡ “cualquier alerta emitida” (`metrica_hids.md:170-172`). En esta instalación **no se
emiten alertas de nivel < 3** (regla `1002`, nivel 2, 72 eventos en `archives` y 0 en alertas)
⇒ **`N=0` y `N=3` coinciden** en T3 y T2. Se declara; no se cambia el conjunto de umbrales.

### 3.7 Ventana canónica y configs

- **Caso** = ventana canónica: **`_rev1`** si el ATA está en `Hojas/repeticiones.csv` (9);
  si no, **`_iter1`** (`metrica_hids.md:204-213`). **No cambia.**
- **Configs**: `C0={RS1}`, `C1={RS1,RS2}` (virgen). **`C2`/`C3` vacías** (RS3=RS4=0, L8).
- **Umbrales**: `N ∈ {0,3,7,10,12}`. **No cambia.**

---

## 4. Fórmulas literales (se aplican, no se redefinen)

Fuente: `metrica_hids.md:124-138`; implementación única: `metrica_hids.py:91-138`.

| # | Métrica | Fórmula | Redondeo |
|---|---|---|---|
| 1 | **TPR** | `TP_ata / N`, `N = 55` | 6 dec |
| 2 | **FPR** | `FP_uni / M` | 6 dec |
| 3 | **TNR** | `1 − FPR` | 6 dec |
| 4 | **Precisión** | `A_TP / (A_TP + A_FP)` | 6 dec |
| 5 | **F1** | `2·P·R / (P + R)`, `R = TPR` | 6 dec |
| 6 | **GM** | `√(TPR · (1 − FPR))` | 6 dec |
| 7 | **Usabilidad (FTTAR)** | `A_FP / A_TP` | 4 dec |
| 7c | **Usabilidad `^c`** | `A_FP^c / A_TP^c` | 4 dec |

**Doble conteo** (`metrica_hids.md:108-121`): se publican **siempre** `#Alertas` y
`#rule.id` distintos; en legítimo, como **1 evento → 1 alerta**, `A_FP = FP_uni` y
`A_FP^c = FP_uni` (se declara la degeneración). En ataque, `A_TP^c` = `Σ` por caso de
`rule.id` distintos (columna de T2).

---

## 5. Tanda L2 — análisis del legítimo

### 5.1 L2-1 · Verificar insumos y procedencia (antes de calcular)

**Pasos**

1. Comprobar que existen los **4** ficheros de `archives` en
   `D:\TFG-VMs\legitimo-2026-11-02\denominador\` y que sus `sha256` son
   `0adf47b8…`, `ed39daf0…`, `78f504ae…`, `ae53465c…` (los de `denominador_M.csv:2`).
   **Si no coinciden → PARAR** (no aproximar).
2. Copiar `MANIFEST.tsv` a `Dataset/Legitimo/legitimo_72h/analisis/MANIFEST_archives.tsv`
   (producto pequeño, con `sha256`).
3. Verificar los `sha256` de `alertas_detalle.csv`, `ruleids_legitimos.csv`,
   `denominador_M.csv`, `campana_fp.csv`, `ghosts_acciones.csv` contra `PROMOCION.md:11-19`.
4. **No** modificar ningún fichero promovido.

**Producto:** `MANIFEST_archives.tsv` + nota de verificación en el `change-doc`.

### 5.2 L2-2 · Índice de eventos (la unidad exacta)

**Qué se construye:** `Dataset/Legitimo/legitimo_72h/analisis/eventos_alerta_72h.csv.gz`, una fila
por **evento decodificado del endpoint con alerta emitida** en `[t0,t1]`, con:

```
unidad,timestamp_utc,rule_id,rule_level,rs_origen,auto_ruido
```

- `unidad` = `"<fichero>:<nº línea>"` (p. ej. `02:12345`), **único**.
- El `id` de Wazuh **no** se incluye en el índice (no es clave y colisiona); queda en el
  `archives` original y, si se necesita para auditar una fila, se busca por `unidad`.
- `rs_origen` = mapa `rule_id → RS` del catálogo de 72 h (`554/591` → RS1; `807xx` → RS2;
  `11` → UNKNOWN).
- `auto_ruido` = 0/1 aplicando el predicado de `filtrar_ruido.py:322-346` a los campos
  `data.audit.*` / `rule_id`+`stats` de la línea.
- **Solo se incluyen eventos con alerta emitida** (`rule` presente y `level ≥ 3`). Los **48.642**
  eventos sin `rule` **más** los **72** de nivel 2 **no** son unidades FP (no alertan) pero **sí
  cuentan en `M`**; el índice es el subconjunto alertante (294.252 filas). `M` se toma de
  `denominador_M.csv` y se **re-cuenta** en el paso 1.
- Tamaño esperado: **294.252 filas**, **≈1,35 MB `.gz`** (16,0 MB crudo).

**Verificación obligatoria (CA-L2-01/02):**

- `M` recalculado = **342.966**.
- nº de líneas del índice = **294.252**.
- multiconjunto `(timestamp, rule_id)` del índice == multiconjunto de
  `alertas_detalle.csv` **sin** `rule 11` (294.252). Si no: **PARAR**.
- `auto_ruido` total = **66.285**; por regla: `80791` 51.812, `80792` 13.584, `80780` 813,
  `80781` 74, `80782` 2.

**Por qué no se usa `timestamp`:** 294.253 alertas → **249.761** timestamps distintos
(-15,1 %); agrupar por timestamp **fusionaría** eventos distintos y **subestimaría** `FP_uni`
(la diferencia es de hasta 44.491 unidades; FPR 72,8 % vs 85,8 %). Se **declara** en §14.4.
**Por qué no se usa `id`:** 213.748 distintos (-27,4 %), por colisiones del `id` de Wazuh.

### 5.3 L2-3 · Catálogo de ruido autoritativo

**Producto:** `Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv` con **11** filas:

```
rule_id,rule_level,rule_description,groups,rs_origen,count,first_seen,last_seen,
alertas_auto,alertas_no_auto,pct_auto,origen_catalogo
```

- `count` = nº de alertas de la regla en `[t0,t1]` (suma **294.253**, incluida `rule 11`).
- `first_seen`/`last_seen` de `ruleids_legitimos.csv`.
- `alertas_auto`/`pct_auto` del índice (predicado §3.2).
- `origen_catalogo = 72h` para las 11.
- **Declaración**: `rule 11` (`UNKNOWN`, `stats`, 1 alerta) **no** pertenece a `C0` ni a `C1`;
  se lista para que la suma cuadre, pero no entra en T3.
- **Declaración**: `rule 1002` (nivel 2, 72 eventos) **no** está en el catálogo porque **no
  emite alerta**; se documenta en `auto_ruido_evidencia.csv`/`change-doc` y se excluye de T3.

**Producto secundario:** `auto_ruido_evidencia.csv` (por regla y motivo: `exe`, `cwd`, `ruta`,
`stats`; con el valor de evidencia y el conteo). Es la prueba de §3.2.

### 5.4 L2-4 · T3 y T4 (la rejilla)

**T3** — `Hojas/T3_legitimo.csv` (formato largo, plantilla existente):

- Se alimenta `tabla3_legitimo.py` con el **detalle** `T3_detalle.csv` generado desde el índice
  (una fila por evento alertante, con `unidad`, `rule_id`, `rule_level`, `rs_origen`,
  `categoria ∈ {auto_ruido, ruido_conocido}`, `rule_groups` unido del catálogo).
- `--unidades-count 342966`, `--inicio-utc 2026-11-02T00:00:00Z`,
  `--fin-utc 2026-11-05T00:00:00Z`, `--duracion-h 72`, `--n-acciones-ghosts 504`,
  `--tamano` = tamaño de `archives` (43,6 MB comprimido; declarar).
- `--config C0 C1 --umbral 0 3 7 10 12`.
- **C2/C3**: no se generan; se declaran vacías en la cabecera/`change-doc` (L8).

**Valores esperados (CA-L2-03/04):**

| config | N | `#Unidades` M | `#Unidades_FP` | `#Unidades_TN` | `%Unidades_FP` (FPR) | `%Unidades_TN` (TNR) | `#Alertas` = A_FP | `#Alertas_FP_sin_auto` | `#rule.id` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| C0 | 0 | 342.966 | **50** | 342.916 | **0,0146** | 99,9854 | 50 | 50 | 2 |
| C0 | 3 | 342.966 | **50** | 342.916 | **0,0146** | 99,9854 | 50 | 50 | 2 |
| C0 | 7 | 342.966 | **0** | 342.966 | 0,0000 | 100,0000 | 0 | 0 | 0 |
| C0 | 10 | 342.966 | **0** | 342.966 | 0,0000 | 100,0000 | 0 | 0 | 0 |
| C0 | 12 | 342.966 | **0** | 342.966 | 0,0000 | 100,0000 | 0 | 0 | 0 |
| C1 | 0 | 342.966 | **294.252** | 48.714 | **85,7963** | 14,2037 | 294.252 | **227.967** | 10 |
| C1 | 3 | 342.966 | **294.252** | 48.714 | **85,7963** | 14,2037 | 294.252 | **227.967** | 10 |
| C1 | 7 | 342.966 | **2** | 342.964 | **0,0006** | 99,9994 | 2 | 2 | 1 |
| C1 | 10 | 342.966 | **2** | 342.964 | **0,0006** | 99,9994 | 2 | 2 | 1 |
| C1 | 12 | 342.966 | **0** | 342.966 | 0,0000 | 100,0000 | 0 | 0 | 0 |

- **Complementos**: `FP/acción = A_FP/504`; `FP/hora = A_FP/72`. C1×N0: **583,8333** y
  **4.086,8333**; C0×N0: **0,0992** y **0,6944**. (Se usa `A_FP`, como la plantilla T3; se
  declara.)
- **Variante sin `auto_ruido`** (C1×N0/N3): `FP_uni = 227.967`; `FPR = 0,664693`.
- **`#Alertas_correlacionadas`** = `#Unidades_FP` (1 evento → 1 alerta); se declara.

**T4** — `Hojas/T4_rendimiento.csv` (ancho, 10 columnas C0/C1 × N):

- Se ejecuta `tabla4_rendimiento.py --t2 Hojas/T2_ataques.csv --t3 Hojas/T3_legitimo.csv`.
- **Valores esperados** (CA-L2-05; 6/4 decimales): ver **Anexo A**. Cabecera destacada:
  - **C1×N0/N3**: TPR **0,963636**, FPR **0,857963**, TNR **0,142037**, Precisión **0,006764**,
    F1 **0,013435**, GM **0,369963**, Usab **146,8323**, Usab`^c` **4.746,0000**.
  - **C0×N0/N3**: TPR **0,036364**, FPR **0,000146**, TNR **0,999854**, Precisión **0,206349**,
    F1 **0,061831**, GM **0,190679**, Usab **3,8462**, Usab`^c` **8,3333**.
  - **C1×N7**: TPR **0,036364**, FPR **0,000005831**, Precisión **0,818182**, GM **0,190692**.
  - **C1×N10/N12**: columnas degeneradas (A_TP=0); se publican con **0** y se declaran.

**Nota de honestidad (T4):** `Precisión` y `F1` mezclan planos (alerta y caso); es la
convención del profesor (`metrica_hids.md:154-157`). No se “arregla”: se **declara**.

### 5.5 L2-5 · Estabilidad (día, hora y campaña)

**Productos:**

1. `Dataset/Legitimo/legitimo_72h/analisis/estabilidad_dia.csv` (3 filas):
   `dia,M,FP_uni_C0_N0,FP_uni_C1_N0,FP_uni_C1_N7,FPR_C0,FPR_C1_N0,FPR_C1_N7,A_FP,auto`.
   - Esperado: M **114.118 / 114.659 / 114.189**; FPR C1×N0 **0,859312 / 0,856924 /
     0,857657**. (El ±1 respecto de la ficha se declara: frontera de rotación diaria; el total
     es idéntico, §14.5.)
2. `Dataset/Legitimo/legitimo_72h/analisis/estabilidad_hora.csv` (72 filas):
   `hora_utc,M,FP_uni_C1_N0,FPR_C1_N0,A_FP,auto`.
   - Esperado: 72/72 horas con FP; FPR entre **0,828336** y **0,889727**; M entre 3.952 y 6.476.
3. `Dataset/Legitimo/legitimo_72h/analisis/campana_estabilidad.csv` (11 filas):
   `caso,ini,fin,duracion_s,alertas,rule_ids,nivel_max,esperado_cumplido`.
   - Esperado: **1.793** alertas; **11/11 `SI`**; nivel máximo **3**; **0** alertas `N≥7`.
   - **La campaña está dentro de `M`**: no se fabrica un FPR alternativo
     (`ventana_meta.md:193-194`). `FP/acción` de campaña = **1.793/63 = 28,4603** (63 acciones
     del conjunto, `ventana_meta.md:44-45`); `n_acciones` por caso **no existe** y se declara
     (§14.6).

**Lectura esperada:** el ruido es **estructural** (reglas `80791/80792`), no de actividad; la
variación horaria es pequeña y no hay “hora del café” que dispare FP. Es un **resultado**, no
un defecto.

### 5.6 L2-6 · T5: doble uso y pruning

**Producto 1 — `Hojas/T5_doble_uso.csv` (nuevo, tabla de cruce):**

```
rule_id,rule_level,rs_origen,groups,legit_alertas,legit_unidades,legit_auto,pct_auto,
attack_detecciones,attack_casos,attack_casos_lista,doble_uso,nota
```

- **11** filas (las del catálogo de 72 h; `rule 11` incluida con `attack=0`).
- `attack_detecciones`/`attack_casos` de las **55** ventanas canónicas, `categoria=deteccion`,
  `rs_origen ∈ C1`, `N=0`.
- **Esperado:** `doble_uso=SÍ` en **4**: `80781` (1 detección, ATA002), `80790` (1, ATA002),
  `80791` (1, ATA008), `80792` (**1.988**, **53** casos). El resto `NO`.
- **Regla `11`**: `UNKNOWN`, no entra en C1; `doble_uso=NO`; se declara.

**Producto 2 — `Hojas/T5_pruning.csv` + `Hojas/T5_steps.csv` (plantillas existentes):**

- Se ejecuta `tabla5_pruning.py` con `--t2` (M1b), `--t3` (T3) y `--auditado` (M1b).
- **Parche mínimo necesario** (declarado; no toca fórmulas): el script actual deja
  `GM`, `#Alertas_FP`, `Usabilidad` y `TNR/FP/TN` de `T5_steps` **vacíos** (“requieren L1”,
  `tabla5_pruning.py:177-184, 203-210`) y define `Aggressive (G-Mean)` **igual que
  Conservative** (`:163-165`). Ahora que L1 existe, se **completa**:
  - `FP_uni(variante) = Σ` de `#unidades_con_la_regla` de las reglas activas (1:1);
  - `A_FP(variante) = Σ` de `#alertas_legitimas` de las reglas activas;
  - `TNR = 1 − FP_uni/M`; `GM = √(TPR·TNR)`; `Usabilidad = A_FP/A_TP` (correlacionada, como la
    plantilla);
  - **`Aggressive (G-Mean)` real** (`formula_plantillas.md:78`): partir de **Conservative**,
    ordenar las reglas **mixtas** por impacto en legítimo **desc**, y quitar **solo si GM
    mejora** (empate → conservar). Determinista; sin heurísticas ocultas.
- **Valores esperados (CA-L2-06):**

| variante | reglas quitadas | TPR | A_TP`^c` | A_FP | FP_uni | TNR | GM | Usab`^c` |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| No Pruning | 0 | 0,963636 | 62 | 294.252 | 294.252 | 0,142037 | 0,369963 | 4.746,0000 |
| Pruning 500 | `80780,80791,80792` | 0,054545 | 8 | 455 | 455 | 0,998673 | 0,233395 | 56,8750 |
| Pruning 1000 | `80780,80791,80792` | 0,054545 | 8 | 455 | 455 | 0,998673 | 0,233395 | 56,8750 |
| Conservative | `554,591,80711,80730,80780,80782` | 0,963636 | 62 | 292.030 | 292.030 | 0,148516 | 0,378306 | 4.710,1613 |
| Generalized Conservative | las 10 reglas del legítimo | 0,036364 | 6 | 0 | 0 | 1,000000 | 0,190693 | 0,0000 |
| Aggressive (G-Mean) | las 6 FP-only + `80781,80790,80791` | 0,963636 | 59 | 236.277 | 236.277 | 0,311077 | **0,547509** | 4.004,6949 |

- **Hallazgo T5:** `Pruning 500/1000` (escala NIDS) es **degenerado** en nuestra escala: quita
  `80792` y **hunde** el TPR a 3/55. `Conservative` apenas mejora (GM 0,3783). El **Aggressive**
  bien hecho encuentra el óptimo: quita las 3 reglas de doble uso **redundantes** (porque
  `80792` ya cubre ATA002/ATA008) y **conserva `80792`**; GM **0,5475** sin perder TPR.
- **Limitación declarada:** la `Usabilidad` de T5 es la **correlacionada** (`A_TP^c`), no la
  bruta; la bruta está en T4. Se documenta en la cabecera/`change-doc`.
- **Matiz de evidencia:** quitar `80781/80790/80791` **no baja el TPR** porque `80792` cubre
  ATA002/ATA008, pero **cambia la primera evidencia** de esos dos casos (pasa a `80792`). T5 mide
  **rendimiento**, no calidad de la evidencia; se declara en `T5_doble_uso.csv`/`change-doc`.

### 5.7 Productos de L2 (resumen)

Ver §7. Todos con cabecera `metrica_version=1`, `boveda_version=2`, `sha256` de entradas y
`layout`; sin reloj (determinismo).

---

## 6. Tanda M1b — re-corte de los ataques

### 6.1 La decisión: catálogo M1b = 72 h ∪ 4 reglas históricas del operador

**Hecho comprobado:** el catálogo de 72 h **no contiene** `5402`, `5501`, `5502`, `5715`
(reglas de `sudo`/PAM/SSH). En las 128 ventanas de ataque hay **22** filas de esas reglas
clasificadas `ruido_conocido` en **ATA013** (8+3) y **ATA034** (1+10): **16** son
`5501/5502` (`baseline`) y **6** son `5715` (`operador`).

- **Si se re-juzga con el catálogo 72 h puro**, solo **8** de las **16** filas de `5501/5502` (las de ATA034) pasan a
  `novel → deteccion` (paso 4-5 de `filtrar_ruido.py:685-693`); las **6** de `5715` siguen
  como `operador:5715` (paso 1.5, no depende del catálogo). Aun así, **ATA013/ATA034 se
  convierten en TP**: TPR **54/55 = 98,2 %**. Eso sería un **falso positivo de método**: son
  sesiones del **operador** (PAM/sudo), no del ataque; el ataque de ATA013 sigue siendo el
  punto ciego de `python3`/`92600` y ATA034 sigue sin telemetría.
- **Decisión:** catálogo M1b = **72 h ∪ {5402,5501,5502,5715}**, con `origen_catalogo` y
  justificación por fila. Las 4 reglas se mantienen como **ruido histórico declarado**, no como
  “detección”. Es coherente con la métrica: `metrica_hids.md:228-229` (punto 3 de §9) dice que el catálogo autoritativo son las 72 h
  **para lo que las 72 h observaron**; para lo **no observado**, la ausencia no es evidencia
  (misma lógica que `dudosa`, regla 6). Se lleva al **gate** (§12).
- **Sensibilidad obligatoria:** ejecutar también el catálogo **72 h puro** y publicar
  `Hojas/T2_sensibilidad_catalogo72h.csv` con TPR **54/55** y la lista de las **8** filas (las de ATA034; las de ATA013 quedan `dudosa`->ruido); diff total: **462** lineas en **42** de las 128 ventanas (**109** en **13** canonicas)
  flipadas (`5501/5502`; las 6 de `5715` no cambian). **No es canónica**; sirve para demostrar
  que el catálogo puro **no** es defendible.

**Producto:** `Dataset/Legitimo/legitimo_72h/analisis/catalogo_M1b.csv` (15 filas:
`rule_id,rule_level,rs_origen,groups,count_72h,origen_catalogo,justificacion`).

### 6.2 Re-ejecución de las 128 ventanas (determinista, sin re-atacar)

**Entrada por ventana:** `Dataset/Ataques/Resultados/Wazuh/linux/CSV/<ATA>_<iter>-Detalle.csv`
(128 ficheros). **Salida:** `Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado/` (nuevos
`-Audited.csv` + `-Revision.csv`).

**Pasos**

1. Para cada `-Audited.csv` original, **parsear la cabecera** y extraer las rutas y `sha256`
   de `alerta`, `esperado` y `revision` (si existe). **Verificar** que el `sha256` coincide con
   el fichero actual. Si no → **PARAR**.
2. Ejecutar `filtrar_ruido.py` con:
   `--alerta <Detalle> --ata <ATA> --iter <n> --catalogo catalogo_M1b.csv
   --esperado <original> --revision <original> --out M1b/...-Audited.csv
   --rev-out M1b/...-Revision.csv`.
3. **No** tocar los originales; el `--revision` es **solo lectura**.
4. **Diff** de datos (sin líneas `#`) entre el `-Audited.csv` original y el nuevo:
   - **Esperado: 0 filas distintas** en total (**130.017** filas repartidas en 128 ficheros).
     La única diferencia es la cabecera (`catalogo=...` con `sha256` nuevo; `boveda_version=2`).
   - Si hay **cualquier** diferencia: listarla en `M1b/diff.csv` y **no** aceptar el resultado
     sin revisión humana.
5. Repetir con el catálogo **72 h puro** en `M1b/sensibilidad_72h/` (solo para §6.4; **no**
   canónico).

**Invariantes que se comprueban al final:** 55 casos, 128 ventanas, **53 TP**, **2 FN** =
`{ATA013, ATA034}`, 9 repeticiones canónicas, 0 `dudosa` sin resolver.

### 6.3 T2/T4 nuevos y comparación con M1a (histórico)

1. **Conservar el viejo:** copiar `Hojas/T2_ataques.csv` →
   `Hojas/historico/T2_ataques_M1a.csv` (y `Hojas/T4_rendimiento.csv` →
   `Hojas/historico/T4_rendimiento_M1a.csv`). El original **no se pierde**.
2. **T2 nuevo (canónico):** `tabla2_ataques.py --auditado .../M1b/Auditado
   --out Hojas/T2_ataques.csv` (550 filas: 55 × 2 × 5).
3. **T4 nuevo (completo):** `tabla4_rendimiento.py --t2 Hojas/T2_ataques.csv
   --t3 Hojas/T3_legitimo.csv --out Hojas/T4_rendimiento.csv`.
4. **Comparación:** `Hojas/T2_M1b_vs_M1a.csv` con una fila por
   `(ata_id, config, umbral)` y columnas `Detection_M1a, Detection_M1b, #Alertas_M1a,
   #Alertas_M1b, primera_M1a, primera_M1b, delta, cambiada`.
   - **Esperado: 0 cambiadas; 550/550 idénticas** en **todas las columnas de datos**
     (`Detection`, `#Alertas`, `#rule.id_distintos`, `#Alertas_correlacionadas`,
     `t_hasta_1a_deteccion_s`, `primera_evidencia_rule_id`, `%Deteccion`).
   - Resumen en la cabecera: `C0_N0: TP=2/FN=53 … C1_N0: TP=53/FN=2` (idéntico a M1a).
5. **Declaración:** M1a usó el **baseline viejo de 2×4 h** (12 reglas) y es **histórico**; M1b
   usa el **legítimo de 72 h** (autoritativo) + 4 reglas históricas del operador. La
   comparación se publica aunque el resultado sea idéntico: **es una prueba de estabilidad del
   recorte**, no un “no cambio” silencioso.

### 6.4 Sensibilidad: catálogo 72 h puro (no canónica)

- Ejecutar T2 con `M1b/sensibilidad_72h/` y el catálogo de **11** reglas.
- **Esperado:** `solo `ATA034` pasa a **TP**; TPR **54/55 = 98,2 %**; **8** filas (las de ATA034)
  `5501/5502` → `deteccion` (PAM del operador); las **6** de `5715` siguen
  `ruido_conocido`/`operador:5715`. **Se declara como artefacto** y se **rechaza** como medida.
- Producto: `Hojas/T2_sensibilidad_catalogo72h.csv` + nota en el `change-doc`. **No** se usa en
  T4.

### 6.5 Productos de M1b (resumen)

Ver §7. Todos con `sha256` de entradas y `diff` reproducible.

---

## 7. Ficheros que se escriben (y los que NO)

### 7.1 Nuevos / modificados

| Ruta | Tipo | ¿Se versiona? | Nota |
|---|---|---|---|
| `plan.md` | plan | sí | este fichero (raíz) |
| `_artefactos/scripts/analizar_legitimo_72h.py` | script nuevo | sí | índice + catálogo + auto + estabilidad + `T3_detalle` |
| `_artefactos/scripts/cruzar_doble_uso.py` | script nuevo | sí | T5 doble uso |
| `_artefactos/scripts/recortar_ataques_m1b.py` | script nuevo | sí | orquesta 128 re-ejecuciones + diff |
| `_artefactos/scripts/tabla3_legitimo.py` | parche mínimo | sí | `--doble-uso`; `veredicto` desde `categoria` (no toca fórmulas) |
| `_artefactos/scripts/tabla5_pruning.py` | parche | sí | completa columnas L1 + `Aggressive` real (no toca fórmulas) |
| `_artefactos/scripts/tests/test_legitimo_analisis.py` | tests nuevos | sí | determinismo, 1:1, auto, T5 |
| `_artefactos/scripts/tests/test_tabla5_pruning.py` | tests | sí | GM, aggressive, empates |
| `Dataset/Legitimo/legitimo_72h/analisis/eventos_alerta_72h.csv.gz` | producto | sí | 294.252 filas; ≈1,35 MB |
| `Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv` | producto | sí | 11 reglas |
| `Dataset/Legitimo/legitimo_72h/analisis/catalogo_M1b.csv` | producto | sí | 15 reglas (unión declarada) |
| `Dataset/Legitimo/legitimo_72h/analisis/auto_ruido_evidencia.csv` | producto | sí | prueba del predicado |
| `Dataset/Legitimo/legitimo_72h/analisis/estabilidad_dia.csv` | producto | sí | 3 filas |
| `Dataset/Legitimo/legitimo_72h/analisis/estabilidad_hora.csv` | producto | sí | 72 filas |
| `Dataset/Legitimo/legitimo_72h/analisis/campana_estabilidad.csv` | producto | sí | 11 filas |
| `Dataset/Legitimo/legitimo_72h/analisis/MANIFEST_archives.tsv` | producto | sí | `sha256` de los 4 archivos |
| `Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado/*` | producto | sí | 128 `-Audited` (+ `-Revision` donde haya `dudosa`) |
| `Dataset/Ataques/Resultados/Wazuh/linux/M1b/README.md` | producto | sí | comando, entradas, `sha256`, diff |
| `Hojas/T3_legitimo.csv` | tabla final | sí | plantilla rellenada |
| `Hojas/T4_rendimiento.csv` | tabla final | sí | plantilla rellenada |
| `Hojas/T5_pruning.csv` | tabla final | sí | plantilla completada |
| `Hojas/T5_steps.csv` | tabla final | sí | pasos del aggressive |
| `Hojas/T5_doble_uso.csv` | tabla nueva | sí | cruce 11 reglas |
| `Hojas/T2_ataques.csv` | tabla final | sí | **canónica M1b** |
| `Hojas/T2_M1b_vs_M1a.csv` | comparación | sí | 550 filas |
| `Hojas/T2_sensibilidad_catalogo72h.csv` | sensibilidad | sí | **no canónica** |
| `Hojas/historico/T2_ataques_M1a.csv` | copia | sí | original M1a |
| `Hojas/historico/T4_rendimiento_M1a.csv` | copia | sí | original M1a |
| `Hojas/historico/T5_pruning_M1a.csv` | copia | sí | original M1a |
| `Soporte/Laboratorio/legitimo_72h/analisis/T3_detalle.csv` | intermedio | **no** (declarado) | ≈35 MB; regenerable del índice |
| `_fases/legitimo-analisis/{plan,reviews,change-doc}.md` | cierre | sí | los archiva el orquestador |

### 7.2 NO se tocan

`Soporte/Metrica/*` · `Hojas/ATA_index.csv` · `Hojas/repeticiones.csv` · `Hojas/leyenda.csv` ·
`Hojas/requisitos_estudio.csv` · `Dataset/Legitimo/legitimo_72h/{alertas_detalle.csv,
ruleids_legitimos.csv,denominador_M.csv,ghosts_acciones.csv,campana_fp.csv,campana_ventanas.tsv,
ventana_meta.md,PROMOCION.md}` · `Dataset/Ataques/.../Auditado/*` (originales) ·
`Dataset/Ataques/Comandos/*` · `Bitacora/*` · `_recursos/*`.

> **Nota sobre `Hojas/T2_ataques.csv`:** se **reemplaza** por la versión M1b (canónica) y el
> original M1a se **copia** a `Hojas/historico/`. No se destruye nada. Si el humano prefiere lo
> contrario, se cambia en el gate.

---

## 8. Criterios de aceptación (numéricos)

### 8.1 L2

| CA | Criterio | Comprobación |
|---|---|---|
| **CA-L2-01** | `M` recalculado = **342.966** exacto | recuento sobre `archives` |
| **CA-L2-02** | Índice = **294.252** filas; multiconjunto `(timestamp,rule_id)` == alertas sin `rule 11` | comparación exacta; 0 diferencias |
| **CA-L2-03** | `FP_uni(C1,N0)=294.252`; `FPR=0,857963`; `TNR=0,142037` | T3 |
| **CA-L2-04** | `FP_uni(C0,N0)=50`; `FPR=0,000146`; `FP_uni(C1,N7)=2`; `FP_uni(C1,N12)=0` | T3 |
| **CA-L2-05** | `FP_uni` sin `auto_ruido` = **227.967**; `FPR=0,664693`; auto = **66.285** | T3 |
| **CA-L2-06** | T3 tiene **10** filas agregadas (C0/C1 × 5 umbrales); C2/C3 declaradas vacías | T3 |
| **CA-L2-07** | T4 completo: **10** columnas, **0** celdas vacías salvo las degeneradas declaradas; valores = Anexo A (±0,000001) | T4 |
| **CA-L2-08** | Catálogo 72 h: **11** reglas; suma `count` = **294.253**; `auto` = **66.285** | catálogo |
| **CA-L2-09** | Doble uso = **4** (`80781,80790,80791,80792`); `80792` = **53/55** casos | T5_doble_uso |
| **CA-L2-10** | Estabilidad: 3 días; FPR C1×N0 ∈ [0,856924, 0,859312]; 72 horas; FPR ∈ [0,828336, 0,889727]; campaña **11/11**, **1.793** alertas, 0 `N≥7` | `estabilidad_*`/`campana_*` |
| **CA-L2-11** | T5: `No Pruning` GM **0,369963**; `Conservative` **0,378306**; `Aggressive` **0,547509**; `Pruning 500/1000` TPR **3/55** | T5 |
| **CA-L2-12** | `Aggressive` quita `80781/80790/80791` y **conserva `80792`** | T5 |
| **CA-L2-13** | `pytest` ≥ 342 + nuevos, todo verde | `pytest` |
| **CA-L2-14** | 0 ficheros de `Soporte/Metrica/`, `Dataset/Legitimo/legitimo_72h/` (promovidos), `_recursos/` modificados | `git status` |

### 8.2 M1b

| CA | Criterio | Comprobación |
|---|---|---|
| **CA-M1b-01** | **128/128** ventanas re-ejecutadas; 0 errores; `sha256` de `alerta`/`esperado`/`revision` = originales | orquestador |
| **CA-M1b-02** | **0** filas de datos distintas entre `-Audited` original y M1b (130.017 filas × 128); solo cambia la cabecera | `diff` |
| **CA-M1b-03** | T2 M1b == T2 M1a en **550/550** filas (**todas las columnas de datos**: `Detection`, `#Alertas`, `#rule.id_distintos`, `#Alertas_correlacionadas`, `t_hasta_1a_deteccion_s`, `primera_evidencia_rule_id`, `%Deteccion`) | `T2_M1b_vs_M1a.csv` |
| **CA-M1b-04** | Invariantes: **55** casos, **128** ventanas, **53 TP**, **2 FN** = `{ATA013, ATA034}`, **9** repeticiones | T2 + `repeticiones.csv` |
| **CA-M1b-05** | Sensibilidad 72 h puro: TPR **54/55**; **8** filas `5501/5502` flipadas (las de ATA034; ATA013 queda `dudosa`->ruido); **no** canónica | `T2_sensibilidad` |
| **CA-M1b-06** | T4 M1b: C1×N0 TPR **0,963636**, FPR **0,857963**, P **0,006764**, F1 **0,013435**, GM **0,369963**, Usab **146,8323** | T4 |
| **CA-M1b-07** | 0 originales de ataque modificados; `sha256` de los 128 `-Audited` originales sin cambios | `sha256sum` + `git status` |
| **CA-M1b-08** | 0 VMs / 0 SSH / 0 cambios de laboratorio | checklist |
| **CA-M1b-09** | `pytest` verde | `pytest` |

---

## 9. Cómo se verifica (comandos y comprobaciones)

> Los comandos son **orientativos**; el ejecutor puede ajustar nombres, pero **no** la lógica.

1. **Integridad de entradas**
   - `sha256` de los 4 `archives` == `denominador_M.csv:2`.
   - `sha256` de los 5 CSV promovidos == `PROMOCION.md:11-19`.
2. **Recuento `M`**: `contar_denominador.py --desde … --hasta … --agent-id 001
   --agent-name victima-linux` → **342.966**.
3. **Índice**: `analizar_legitimo_72h.py --archives ... --out-dir ...` → 294.252 filas;
   `sha256` del `.gz` registrado.
4. **T3**: `tabla3_legitimo.py --detalle ... --unidades-count 342966 ...` → valores de §5.4.
5. **T4**: `tabla4_rendimiento.py --t2 Hojas/T2_ataques.csv --t3 Hojas/T3_legitimo.csv` →
   Anexo A.
6. **T5**: `tabla5_pruning.py ...` + `cruzar_doble_uso.py ...` → §5.6.
7. **M1b**: `recortar_ataques_m1b.py --catalogo ... --out-dir .../M1b --diff ...` →
   128/128, 0 cambios.
8. **T2**: `tabla2_ataques.py --auditado .../M1b/Auditado` → 550 filas; comparación.
9. **Tests**: `python -m pytest _artefactos/scripts/tests -q` (≥342 + nuevos).
10. **No-regresión**: `git status --porcelain` solo muestra las rutas de §7.1; **ningún**
    original de ataque/legítimo/metrica.

**Criterio de parada:** si cualquiera de los pasos 1–4 no da el valor exacto, **no se sigue**;
se documenta en `lo que no cuadra` y se pregunta.

---

## 10. Riesgos y mitigaciones

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| R1 | `archives` está **fuera del repo** (`D:\TFG-VMs\…`) y puede perderse | T3 no reproducible | `MANIFEST` con `sha256` + índice compacto **dentro** del repo (1,35 MB) |
| R2 | El catálogo **72 h puro** flipa los 2 FN a TP | Resultado inflado (100 %) | Catálogo M1b = unión declarada; sensibilidad publicada; gate |
| R3 | `timestamp`/`id` como unidad | `FP_uni` subestimado 15–27 % | Unidad = línea de `archives`; proxies cuantificados y rechazados |
| R4 | Parches a `tabla3`/`tabla5` | Romper una tabla congelada | Parches **aditivos**, tests, no tocar `metrica_hids.py` |
| R5 | Re-ejecución M1b no idéntica | Pérdida de confianza | `diff` fila a fila; si ≠0, **parar** y revisar |
| R6 | `rule 11` / `rule 1002` | 1 alerta / 72 eventos fuera de T3 | Declarados y excluidos con criterio; suma reconciliada |
| R7 | Frontera diaria ±1 evento | Cifra por día no coincide con la ficha | Declarado; total idéntico; se usan los recuentos propios |
| R8 | `n_acciones` de campaña vacío | No hay FP/acción por caso | Se usa el total 63 y se declara |
| R9 | `Aggressive` mal implementado | T5 engañoso | Algoritmo escrito, tests de GM y de empate |
| R10 | 72 h sintéticas (GHOSTS), 3 días | No cubre ciclos semanales | Limitación ya declarada en L1; no se extrapola |
| R11 | Sin sesiones del operador en 72 h | Catálogo no cubre PAM/sudo | Unión declarada + sensibilidad |
| R12 | CRLF / huellas | `sha256` de CSV | No `checkout`/`stash`; leer en binario; declarar |

---

## 11. Calendario propuesto (sin dependencia de reloj)

| Sesión | Fecha propuesta | Trabajo | Salida |
|---|---|---|---|
| **D0** | 2026-11-09 (lun) | Gate del plan | `status: approved_by_human` |
| **D1** | 2026-11-10 (mar) | L2-1…L2-5: verificación, índice, catálogo, T3/T4, estabilidad | T3/T4 + productos de estabilidad |
| **D2** | 2026-11-11 (mié) | L2-6 (T5) + M1b completo + T2/T4 + sensibilidad | T5, M1b, T2/T4 |
| **D3** | 2026-11-12 (jue) | Verificación (`tfg-tester`), correcciones, cierre | `change-doc`, `state`, `roadmap` |

> **No hay reloj de pared**: si una sesión se cae, se retoma sin perder la ventana. La fecha la
> fija el humano; la propuesta es solo eso.

---

## 12. Gate humano (lenguaje sencillo)

**Para ejecutar este bloque necesito que confirmes 3 cosas:**

1. **La unidad de `FP_uni` se toma de la línea de `archives.json`** (el evento decodificado),
   **no** del `timestamp` de la alerta. Con `timestamp` se pierden **44.491** unidades (15,1 %)
   y el FPR saldría **72,8 %** en vez de **85,8 %**. ¿Lo apruebas?
2. **El catálogo para re-juzgar los ataques es el de las 72 h + las 4 reglas del operador**
   (`5402/5501/5502/5715`) que las 72 h no ejercitaron. Si uso solo las 72 h, **ATA013 y ATA034
   pasan de NO a SÍ** por ruido del operador: sería un falso positivo de método. ¿Lo apruebas?
   (La versión “solo 72 h” se publica aparte como sensibilidad, **no** como resultado.)
3. **Autorizas completar T3/T5** (columnas que estaban vacías “hasta L1”) y el `Aggressive`
   real de T5, **sin tocar** las fórmulas, la métrica, la bóveda ni los originales. ¿Lo apruebas?

**Si alguna respuesta es “no”, dime cuál y el plan se ajusta antes de ejecutar.**

---

## 13. Trazabilidad (fuente:línea)

| Afirmación | Cita |
|---|---|
| Unidad = evento decodificado; `FP_uni`; `TN_uni` | `Soporte/Metrica/metrica_hids.md:45-54`, `:93-96` |
| `FPR`, `TNR`, fórmulas | `metrica_hids.md:124-138`; `metrica_hids.py:91-138` |
| Reglas de conteo (auto = FP; variante sin auto; doble uso; `dudosa`) | `metrica_hids.md:165-181`, `:242` |
| Catálogo autoritativo = 72 h; baseline histórico no sirve | `metrica_hids.md:228-229` |
| Ventana canónica | `metrica_hids.md:204-213`; `Hojas/repeticiones.csv:4-12` |
| `auto_ruido` por campos | `_artefactos/scripts/filtrar_ruido.py:119-140`, `:322-346`; `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md:86-108` |
| Orden de decisión (auto → señales → artefacto → catálogo → novel) | `filtrar_ruido.py:594-697` |
| Catálogo viejo (12 reglas) | `Dataset/Legitimo/ruleids_legitimos.csv:2-13`; `politica_filtrado_ruido.md:42` |
| `M` = 342.966; total 394.739 | `Dataset/Legitimo/legitimo_72h/denominador_M.csv:5-6` |
| 294.253 alertas; 11 reglas; concentración | `Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv:2-13`; `ventana_meta.md:77-94` |
| 504 acciones; 163/178/163 | `Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv:3-4` |
| Campaña 11/11; 1.793 alertas | `Dataset/Legitimo/legitimo_72h/campana_fp.csv:4-14`; `ventana_meta.md:120-142` |
| `archives` 4 ficheros y `sha256` | `denominador_M.csv:2`; `MANIFEST.tsv` (copia) |
| `rule 11` UNKNOWN; `rule 1002` nivel 2 | `ruleids_legitimos.csv:2`; `ventana_meta.md:94,100-101`; verificación propia |
| T2 viejo (M1a) | `Hojas/T2_ataques.csv` (cabecera); `Hojas/T4_rendimiento.csv` |
| T3/T4/T5 plantillas y columnas | `_artefactos/scripts/tabla3_legitimo.py:35-76`; `tabla4_rendimiento.py:34-58`; `tabla5_pruning.py:37-64` |
| `Aggressive (G-Mean)` definición | `Soporte/Metrica/formula_plantillas.md:69-78` |
| `Aggressive` actual = Conservative | `tabla5_pruning.py:163-165` |
| Bóveda v2 / B10 | `Soporte/Metrica/boveda_congelacion.md:4-8`, `:29-34` |
| Cierre L1 y siguiente L2/M1b | `_fases/legitimo-v3/change-doc.md:86-90`; `state.md:10`; `roadmap.md:72-76` |

---

## 14. Lo que no cuadra / decisiones abiertas (declarado, no escondido)

1. **`auto_ruido` “≈54 %” no es la cifra de 72 h.** El 54 % es del baseline sintético 2×4 h
   (`state.md:96`; `politica_filtrado_ruido.md:106`). En 72 h es **22,5266 %** (66.285/294.252).
   La métrica no cambia; se **declara** y se usa el valor medido.
2. **`rule 11` (stats) no tiene evento.** 294.253 alertas = 294.252 eventos + 1 alerta interna.
   Queda fuera de `C1` por `rs_origen=UNKNOWN`; se lista en el catálogo para que la suma cuadre.
3. **Nivel 2 no emite.** 72 eventos de `rule 1002` (`snapd`, nivel 2) están en `archives` y no
   en alertas. **`N=0` ≡ `N=3`** en esta instalación. La causa probable es `log_alert_level=3`
   (por defecto); **no** se ha podido leer `ossec.conf` con el manager cerrado. Se declara; no se
   añade un umbral nuevo.
4. **El `timestamp` de la alerta no identifica el evento.** 249.761 timestamps distintos para
   294.253 alertas; agrupar por timestamp **subestima** `FP_uni` (FPR 72,8 % vs 85,8 %). Se
   rechaza y se usa la línea de `archives`.
5. **El `id` de Wazuh tampoco es único.** 213.748 distintos para 342.966 líneas (colisiones).
   Se usa solo como referencia.
6. **Frontera diaria ±1.** Los recuentos por día propios (114.118 / 114.659 / 114.189) difieren
   en **1** evento de la ficha (114.118 / 114.660 / 114.188); el **total es 342.966**. Es la
   rotación diaria; se declara y se usan los recuentos propios.
7. **`n_acciones` de campaña vacío.** No hay FP/acción por caso; solo el total **63** acciones
   de la ficha. `FP/acción` de campaña = **28,4603** (1.793/63), declarado.
8. **`Pruning 500/1000` es degenerado a nuestra escala.** Quita `80792` y deja TPR **3/55**;
   no es un fallo, es la escala NIDS (500/1000) aplicada a 294.252 eventos. Se publica y se
   declara.
9. **`Aggressive (G-Mean)` estaba implementado como Conservative.** El plan lo **corrige** con
   el algoritmo congelado (`formula_plantillas.md:78`) y tests; no cambia la métrica.
10. **T5 `Usabilidad` es correlacionada.** La columna `#Alertas_TP` de T5 es `A_TP^c` (Σ por caso
    de `rule.id` distintos); por eso su Usabilidad (4.746,0) **no** es la bruta de T4 (146,83).
    Se documenta; no se mezclan.
11. **El catálogo 72 h no cubre PAM/sudo** porque la ventana no tuvo sesiones del operador en el
    endpoint (V4). La unión con las 4 reglas históricas es una **decisión** (gate), no un hecho.
    La sensibilidad 72 h puro (54/55) se publica para que se vea el efecto.
12. **La ventana es sintética (GHOSTS) y de 3 días.** No cubre ciclos semanales/mensuales ni
    actividad humana real; ya declarado en L1. No se extrapola.
13. **`archives` está fuera del repo.** El índice compacto (1,35 MB) lo mitiga, pero la
    reproducibilidad “desde cero” exige los 4 ficheros originales. Se declara.
14. **C2/C3 vacías.** `RS3=RS4=0`; no se inventan columnas. Se declaran (L8).

---

## Anexo A · Valores esperados de T4 (para verificación)

> `M = 342.966`; `N = 55`; `A_TP`/`A_TP^c` de T2 (M1b, idéntico a M1a); `FP_uni` de T3.
> Redondeo: ratios 6 dec; Usabilidad 4 dec. Las columnas C1×N10/N12 y C0×N10/N12 son
> degeneradas (A_TP=0) y se publican con 0.

| Columna | TPR | FPR | TNR | Precisión | F1 | GM | Usab | Usab`^c` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `C0_N0` | 0,036364 | 0,000146 | 0,999854 | 0,206349 | 0,061831 | 0,190679 | 3,8462 | 8,3333 |
| `C0_N3` | 0,036364 | 0,000146 | 0,999854 | 0,206349 | 0,061831 | 0,190679 | 3,8462 | 8,3333 |
| `C0_N7` | 0,036364 | 0,000000 | 1,000000 | 1,000000 | 0,070175 | 0,190693 | 0,0000 | 0,0000 |
| `C0_N10` | 0,000000 | 0,000000 | 1,000000 | 0,000000 | 0,000000 | 0,000000 | 0,0000 | 0,0000 |
| `C0_N12` | 0,000000 | 0,000000 | 1,000000 | 0,000000 | 0,000000 | 0,000000 | 0,0000 | 0,0000 |
| `C1_N0` | 0,963636 | 0,857963 | 0,142037 | 0,006764 | 0,013435 | 0,369963 | 146,8323 | 4.746,0000 |
| `C1_N3` | 0,963636 | 0,857963 | 0,142037 | 0,006764 | 0,013435 | 0,369963 | 146,8323 | 4.746,0000 |
| `C1_N7` | 0,036364 | 0,000006 | 0,999994 | 0,818182 | 0,069632 | 0,190692 | 0,2222 | 1,0000 |
| `C1_N10` | 0,000000 | 0,000006 | 0,999994 | 0,000000 | 0,000000 | 0,000000 | 0,0000 | 0,0000 |
| `C1_N12` | 0,000000 | 0,000000 | 1,000000 | 0,000000 | 0,000000 | 0,000000 | 0,0000 | 0,0000 |

**Nota:** `C1_N10` tiene `FP_uni=2` (regla `80711`, nivel 10) pero `A_TP=0`; por eso
`Precisión=0` y `GM=0`. No es un error: es la definición.

---

## Anexo B · Pseudocódigo de `Aggressive (G-Mean)` (T5)

```
activas = (reglas_ataque ∪ reglas_legitimo) − (reglas_legitimo − reglas_ataque)   # = Conservative
cur = metricas(activas)
para r en mixed ordenadas por legit_alertas DESC (empate: rule_id ASC):
    cand = activas − {r}
    m = metricas(cand)
    si m.GM > cur.GM + 1e-12:
        activas = cand; cur = m
# metricas: TPR = casos con (reglas_caso ∩ activas) ≠ ∅ / 55
#           FP_uni = Σ legit_unidades(r) para r ∈ activas
#           TNR = 1 − FP_uni/M; GM = sqrt(TPR·TNR)
```

**Resultado esperado:** `activas` conserva `80792` y quita `80781/80790/80791` (+ las 6 FP-only
de la base); GM **0,547509**; TPR **53/55**.

---

*Fin del plan v1 (draft). Pendiente de gate humano.*

> **Correccion factual (2026-11-08, cierre del bloque).** Tras ejecutar M1b se corrigen dos errores del plan:
> (1) `FPR` sin `auto_ruido` = **0,664693** (el plan decia 0,664691; usaba `M=342.967`);
> (2) la sensibilidad con catalogo 72 h puro da **54/55** (no 55/55): solo **ATA034** pasa a TP;
> **ATA013 sigue FN** porque sus filas `5501/5502` quedan `dudosa`->ruido (paso 3 antes del 4).
> Flipan **8** filas (las de ATA034); el diff total es **462** lineas en **42** de las 128 ventanas (**109** en **13** canonicas).
> El producto y el veredicto **no cambian**.

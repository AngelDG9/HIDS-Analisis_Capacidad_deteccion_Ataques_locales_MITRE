---
fase: 1
nombre: Corpus MITRE (F-01)
version: 3
status: approved_by_human
fecha: 2026-09-19
fecha_aprobacion: 2026-09-19
aprobado_por: humano
autor: tfg-planner
---

# Plan — Fase 1: Corpus MITRE (F-01)

## 1. Objetivo y alcance

**Objetivo:** obtener de forma **reproducible** la lista de técnicas/subtécnicas de
**MITRE ATT&CK Enterprise v19.1** que tienen telemetría **endpoint** (filtro inverso host,
R-03) y dejar lista una **lista priorizada R/E/S** (R-04) para que el humano elija el corpus
de **12-15 técnicas** (Ransomware / Exfiltración / Sabotaje).

**Entra (In scope):**
- T-01: descargar el STIX/JSON de Enterprise v19.1.
- T-02: script `extraer_tecnicas_host.py` + tests sobre técnicas conocidas.
- T-03: `corpus_host.csv` (con `host_eligible` y `priority`), `lista_tecnicas_validas.md`
  priorizada y `ATA_index.csv` inicial (cabecera + filas del corpus elegido).
- Gate humano 1.5 (elegir las 12-15 técnicas).

**NO entra (Fuera de alcance):**
- Implementar ataques, laboratorio, Wazuh, baseline (Fases 2-3).
- HIDS distintos de Wazuh (Velociraptor/Snort/otro) — extras (R-05).
- Dominios Mobile/ICS/Cloud; solo Enterprise.
- `Hojas/Mapeos.xlsx`: se **difiere** a Fase 3/5 (fichero binario, poco diffeable; el mapeo
  ataque↔técnica se cubre aquí con CSV + MD). Si el humano lo exige en el gate, se añade un
  export mínimo.
- Descargar xlsx de versiones previas: no hay plantilla v19.1; se usa el STIX oficial.

---

## 2. Diseño técnico

### 2.1 T-01 — Descarga del STIX v19.1

- **Fuente oficial (elegida):** `mitre-attack/attack-stix-data` (repositorio oficial de
  versiones congeladas de ATT&CK), fichero versionado:
  `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json`
  (alternativa: repo `mitre/cti`, `enterprise-attack/enterprise-attack.json`, que apunta a
  la versión "current"; se prefiere `attack-stix-data` por estar **pinneada** a v19.1).
- **Salida:** `_artefactos/mitre/enterprise-attack-v19.1.json`.
- **Verificación de versión:** el bundle contiene un objeto `x-mitre-collection` con
  `x_mitre_version`. Se exige `== "19.1"`; si no coincide, **abortar** (no generar corpus).
- **Verificación de integridad:** calcular `sha256` del fichero y guardarlo en
  `_artefactos/mitre/enterprise-attack-v19.1.sha256`. Se registra URL + fecha de descarga en
  el propio sidecar (o cabecera del CSV de T-02).
- **Versionado:** el `.json` (~decenas de MB) puede superar el umbral cómodo de git → se
  propone **gitignore del JSON** y commitear el `.sha256` + URL; el script lo regenera.
  Decisión final en el gate (ver Riesgos).

### 2.2 T-02 — Script `extraer_tecnicas_host.py`

**Ubicación:** `_artefactos/scripts/extraer_tecnicas_host.py`.
**Entrada:** ruta al STIX (por defecto `_artefactos/mitre/enterprise-attack-v19.1.json`).
**Salida:** `Hojas/corpus_host.csv` (UTF-8), con cabecera que indica `version=19.1` y fecha.

**Algoritmo (lógica del filtro inverso, paso a paso):**

1. Cargar JSON y volcar `bundle["objects"]` en un índice `id → objeto`.
2. Indexar `x-mitre-data-component` → resolver su `name`. Si tiene
   `x_mitre_data_source_ref`, resolver también el **nombre del Data Source** (para
   desambiguar; en v18+ los Data Sources están deprecados, así que es *best-effort*).
3. Recoger todos los `attack-pattern` (técnicas y subtécnicas). Marcar
   `x_mitre_is_subtechnique`.
4. **Excluir deprecated/revoked** a nivel de objeto (`x_mitre_deprecated == true` o
   `revoked == true`). No se incluyen en el CSV (o se incluyen con `host_eligible=NO` y
   `motivo=deprecated`; ver decisión abajo).
5. **Camino principal en v19 — cadena de detección.** En v19 el mapeo **ya no** es
   `Data Component --detects--> technique`. La cadena real es:
   `technique ←detects— Detection Strategy (x-mitre-detection-strategy) → Analytics
   (x_mitre_analytics) → Data Components`. Para cada `attack-pattern`:
   1. Localizar relaciones `relationship_type == "detects"` que lo toquen (con el
      `attack-pattern` en cualquiera de los dos extremos) → obtener sus
      `x-mitre-detection-strategy`.
   2. Para cada Detection Strategy, recorrer sus **Analytics** (`x_mitre_analytics`,
      objetos `AN....`), que en v19 cuelgan de la estrategia por relación o por referencia
      interna.
   3. De cada Analytic obtener sus **Data Components** (`DC....`, tipo
      `x-mitre-data-component`), resolviendo tanto relaciones explícitas como referencias
      internas del objeto si las hubiera.
   **Ancla verificada:** **T1039 — Data from Network Shared Drive** → Detection Strategy
   **DET0410** → Analytics **AN1145 (Windows) / AN1146 (Linux) / AN1147 (macOS)** →
   Data Components **DC0102 Network Share Access, DC0039 File Creation, DC0055 File Access,
   DC0054 Drive Access**.
   5b. **Fallback robusto.** Si el bundle expone (o vuelve a exponer) el camino directo
   `data-component --detects--> attack-pattern`, recorrerlo también y **unir** ambos
   conjuntos de Data Components (sin duplicados). El resultado no debe depender de cuál de
   los dos caminos esté presente.
   5c. **Ajuste en 1.4.** El executor **inspeccionará el esquema real del bundle** descargado
   (cómo se referencian los Analytics desde la Detection Strategy y los Data Components desde
   el Analytic: relaciones u otros campos internos) y ajustará el parser si el formato
   difiere. Si un Analytic no expone claramente sus Data Components por relación, usar el
   **campo/referencia interna** del objeto y documentarlo en el propio script.
6. **Clasificar cada Data Component** en tres cubos:
   - `RED_PURA` = {`Network Connection Creation`, `Network Traffic Content`,
     `Network Traffic Flow`}.
   - `RED_DESCARTADA` = {`Network Share Access`, `Response Content`, `Response Metadata`}
     (Network Share + Internet Scan; "descartadas del todo").
   - `HOST` = cualquier otro Data Component (p. ej. `Process Creation`,
     `File Modification`, `Command Execution`, `Registry Key Modification`, ...).
     Para `Response Content`/`Response Metadata`, si existe Data Source, exigir además que el
     Data Source sea `Internet Scan` para evitar colisiones de nombre genérico.
7. **Regla de decisión (interpretación amplia, fijada):** `host_eligible = YES` **si y solo
   si** existe ≥1 Data Component ∈ `HOST`, con independencia de que la técnica tenga además
   DC de red (pura o descartada). Solo es `NO` si **todos** sus DC son de red
   (`RED_PURA ∪ RED_DESCARTADA`). Los DC de red descartados **nunca otorgan elegibilidad pero
   no anulan** una técnica con telemetría endpoint. Si **no hay ningún** Data Component →
   `NO`, `motivo = sin_datacomponents` (conservador).
8. **Subtécnicas sin relaciones propias:** heredar los Data Components de la técnica padre y
   marcar `heredado_padre = true` (regla explícita, no silenciosa).
9. **Plataformas:** de `x_mitre_platforms`; aplanar a texto separado por `;`. Añadir
   `endpoint_lw = si` si incluye `Linux` o `Windows` (dato de apoyo para priorizar; **no**
   altera `host_eligible`).
10. **Tácticas:** de `kill_chain_phases` con `kill_chain_name == "mitre-attack"`, mapeando
    `phase_name` al nombre de la táctica (`x-mitre-tactic.shortname → name`), separadas por `;`.
11. **Prioridad R/E/S (R-04):** score determinista y documentado en el propio script:
    - **P1** — táctica ∈ {Impact, Exfiltration, Collection} **o** técnica de la lista curada
      R/E/S (p. ej. T1486 ransomware, T1485, T1490, T1489, T1567, T1041, T1048, T1074,
      T1560, T1119...).
    - **P2** — habilitadora directa de R/E/S (p. ej. Defense Evasion/Execution con
      telemetría de fichero/proceso relevante).
    - **P3** — resto de técnicas host-eligible.
    La prioridad se calcula en T-02; la **selección final** es humana (paso 1.5).
12. Escribir el CSV ordenado por `priority`, `host_eligible`, `tecnica_id`.

**Esquema de columnas de `Hojas/corpus_host.csv`:**

| Columna | Descripción |
|---|---|
| `tecnica_id` | `T1486` / `T1486.001` |
| `nombre` | Nombre human-legible |
| `es_subtecnica` | `si`/`no` |
| `padre_id` | Vacío o `T1486` |
| `tacticas` | Tácticas separadas por `;` |
| `plataformas` | `x_mitre_platforms` separadas por `;` |
| `endpoint_lw` | `si` si Linux/Windows |
| `data_components` | Data Components separados por `;` |
| `num_dc` | Nº de Data Components |
| `dc_host` | Nº de DC con telemetría endpoint |
| `dc_red` | Nº de DC de red (pura o descartada) |
| `host_eligible` | `YES`/`NO` |
| `priority` | `P1`/`P2`/`P3` |
| `heredado_padre` | `si`/`no` |
| `motivo` | `ok`, `solo_red`, `sin_datacomponents`, `deprecated` |
| `stix_version` | `19.1` |
| `fecha_generacion` | `YYYY-MM-DD` |

**Decisión fijada — interpretación amplia del filtro inverso.** Los Data Components de red
descartados (`Network Share Access`, `Internet Scan: Response Content/Metadata`) se suman al
cubo de red: **nunca otorgan elegibilidad**, pero **no anulan** una técnica que tenga al menos
un Data Component de host. Una técnica es `host_eligible=NO` solo si **todos** sus Data
Components son de red (pura o descartada).

> **Decisión humana (2026-09-19):** se adopta la interpretación **amplia** del filtro inverso;
> los Data Components de red descartados (`Network Share Access`, `Internet Scan`) no otorgan
> elegibilidad pero no anulan una técnica con telemetría endpoint. Fundamento: **T1039**
> (DET0410) → DC0102 (red) + DC0039/DC0055/DC0054 (host) → **`host_eligible=YES`**.

> **Decisión humana (2026-09-19) — T1046 se ratifica como híbrida:** el borrador asumía
> `T1046=NO` (red pura), pero el STIX real v19.1 muestra que su cadena
> **DET0376 → AN1057/1058/1059/1060** incluye **DC0032 Process Creation** además de DC de red.
> Aplicando la interpretación amplia, **T1046 => `host_eligible=YES` (híbrida)**. El caso de
> negativa "red pura => NO" queda cubierto por **T1595**. `requirements.md` (R-03) se alinea.

### 2.3 T-03 — Salidas human-legibles y corpus

- `Hojas/lista_tecnicas_validas.md`: tabla priorizada (P1→P3) de las técnicas
  `host_eligible=YES`, con ID, nombre, táctica(s), plataformas, DC endpoint y por qué encaja
  en R/E/S. Incluye la **candidata corta para el corpus** (top ~20) y la recomendación de
  las 12-15 con cobertura ≥1 por táctica relevante.
- `Hojas/ATA_index.csv`: cabecera `ata_id,tactica,tecnica,descripcion,artefacto,estado`.
  - Antes del gate 1.5: cabecera + candidatas con `estado=propuesto` (sin comprometer).
  - Tras la selección humana: reescrito con las 12-15 elegidas, `ATA001...`, `estado=pendiente`,
    `artefacto` vacío (se rellena en Fase 3).

---

## 3. Ubicación de script y tests

```
_artefactos/
  mitre/enterprise-attack-v19.1.json          (T-01, gitignore probable)
  mitre/enterprise-attack-v19.1.sha256        (T-01)
  scripts/extraer_tecnicas_host.py            (T-02)
  scripts/tests/test_extraer_tecnicas_host.py (tests unitarios, fixture sintético)
  scripts/tests/fixtures/stix_mini.json       (bundle mínimo con cadena DET→AN→DC)
  scripts/tests/test_real_stix.py             (integración, se salta si falta el STIX)
Hojas/
  corpus_host.csv
  lista_tecnicas_validas.md
  ATA_index.csv
```

**Tests con pytest** (sin dependencia del STIX grande para los unitarios):

| Test | Técnica (R-03) | Esperado |
|---|---|---|
| `test_ransomware_T1486_yes` | T1486 Data Encrypted for Impact | `host_eligible=YES`, `priority=P1` |
| `test_network_discovery_T1046_hybrid_yes` | T1046 Network Service Discovery | `host_eligible=YES` (híbrida: tiene DC de host y de red) |
| `test_command_interpreter_T1059_yes` | T1059 Command and Scripting Interpreter | `YES` |
| `test_scan_T1595_no` | T1595 Active Scanning (Internet Scan) | `NO` |
| `test_deprecated_excluded` | patrón con `x_mitre_deprecated=true` | no incluido / `NO` |
| `test_subtechnique_inherits_parent` | sub sin `detects` propio | `heredado_padre=si`, misma decisión que el padre |
| `test_T1039_detection_strategy_chain` | T1039 (DET0410 → AN1145/6/7 → DC0102, DC0039, DC0055, DC0054) | `host_eligible=YES` pese a tener DC de red |
| `test_relationship_direction` | `detects` directo DC↔pattern (fallback) | mismo resultado que el camino por Detection Strategy |
| `test_collection_header` | bundle | versión `19.1` en cabecera del CSV |

**Nota (T1046):** el borrador inicial esperaba `T1046=NO` (red pura). Los datos reales de
v19.1 muestran que es **híbrida** (DET0376 → AN1057/1058/1059/1060, con `DC0032 Process
Creation`), por lo que se ratifica `host_eligible=YES` (decisión humana 2026-09-19). La
negativa "red pura => NO" se testea con **T1595**.

Los tests de integración (`test_real_stix.py`) reutilizan las aserciones R-03
(T1486=YES, T1046=YES híbrida, T1595=NO) sobre el STIX descargado; se marcan `skip` si el
fichero no existe. Comando: `pytest _artefactos/scripts/tests -q`.

---

## 4. Tareas atómicas (orden F-01: T-01 → T-02 → T-03)

| # | Tarea | Modo | Salida verificable |
|---|---|---|---|
| 1.1 | **T-01** descargar STIX v19.1 + verificar `x_mitre_version==19.1` + sha256 | [AUTO] | `_artefactos/mitre/enterprise-attack-v19.1.json` + `.sha256` |
| 1.2 | **T-02** escribir `extraer_tecnicas_host.py` (filtro inverso + prioridad) | [AUTO] | script en `_artefactos/scripts/` |
| 1.3 | **T-02/tests** fixture sintético + tests R-03 (paso 3) | [AUTO] | `pytest ... -q` en verde |
| 1.4 | **T-03** inspeccionar esquema real del STIX, ajustar parser (paso 5c) y ejecutar → CSV + `lista_tecnicas_validas.md` priorizada | [AUTO] | `Hojas/corpus_host.csv`, `Hojas/lista_tecnicas_validas.md` |
| 1.5 | Revisar lista, elegir las **12-15 técnicas** del corpus | **[HUMANO]** | decisión (ver §8) |
| 1.6 | Materializar `Hojas/ATA_index.csv` con las elegidas (`ATA001...`, `pendiente`) | [AUTO] | `Hojas/ATA_index.csv` |
| 1.7 | Verificación final de fase (`tfg-tester`) y actualizar `state.md`/`roadmap.md` | [AUTO] | informe de verificación + estado |

Cada paso produce un fichero concreto y es reversible (los CSV se regeneran desde el script).

---

## 5. Definition of Done (roadmap Fase 1)

- Script reproducible + lista priorizada + corpus elegido en `Hojas/ATA_index.csv`.
- En concreto:
  - [ ] `_artefactos/mitre/enterprise-attack-v19.1.json` con versión 19.1 verificada + sha256.
  - [ ] `_artefactos/scripts/extraer_tecnicas_host.py` versionado en git.
  - [ ] Tests R-03 en verde (T1486=YES, T1046=YES híbrida, T1595=NO entre otros).
  - [ ] `Hojas/corpus_host.csv` con `host_eligible` y `priority`.
  - [ ] `Hojas/lista_tecnicas_validas.md` priorizada R/E/S.
  - [ ] `Hojas/ATA_index.csv` con las 12-15 técnicas elegidas por el humano.

---

## 6. Cómo se verifica

1. **Reproducibilidad (R-02):** borrar `Hojas/corpus_host.csv`, re-ejecutar el script y
   comprobar que el CSV se regenera idéntico (mismo hash, salvo columna fecha).
2. **Versión (R-01):** cabecera del CSV y del MD indica `v19.1` + fecha; el bundle valida
   `x_mitre_version`.
3. **Filtro inverso (R-03):** `pytest` pasa; además comprobación manual de 3 casos conocidos
   (**T1486=YES**, **T1595=NO** red pura, **T1039=YES** con cadena DET0410). T1046 se verifica
   como **YES híbrida** (DET0376 con DC0032 Process Creation).
4. **Prioridad (R-04):** la columna `priority` existe y T1486 aparece en P1.
5. **Coherencia del corpus:** cada fila de `ATA_index.csv` existe en `corpus_host.csv` con
   `host_eligible=YES`; IDs `ATA<NNN>` únicos y correlativos.
6. **DoD:** checklist de §5 completo.

---

## 7. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| URL/fichero v19.1 no existe o difiere | Probar `attack-stix-data` y `mitre/cti`; verificar `x_mitre_version`; si no existe, parar y consultar al humano. |
| Fichero STIX demasiado grande para git | Gitignore del JSON + commit del `.sha256` y URL; el script re-descarga. Decisión en el gate. |
| Esquema real de v19 (Detection Strategy/Analytics/DC) distinto al esperado | Cadena principal + fallback directo + inspección del bundle en 1.4 (paso 5c). |
| Dirección de las relaciones `detects` distinta a la esperada | El parser acepta ambas direcciones y une ambos caminos (test `test_relationship_direction`). |
| Colisión de nombres de Data Components genéricos (`Response Content`) | Desambiguar por Data Source `Internet Scan`; si no está, coincidencia exacta y se documenta. |
| Subtécnicas sin telemetría propia | Herencia explícita del padre con `heredado_padre=si`; nunca silenciosa. |
| Ambigüedad de "descartar del todo" — **RESUELTO (2026-09-19)** | Interpretación amplia fijada: DC de red no otorgan elegibilidad pero no anulan host; T1039=YES (§2.2). |
| Sesgo de la heurística R/E/S | La prioridad es apoyo; la selección final es **[HUMANO]** (1.5). |
| Técnica sin Data Components en v19.1 | Marcada `NO`/`sin_datacomponents` (conservador, evita falsos positivos de elegibilidad). |

---

## 8. Validación humana (paso 1.5) — [HUMANO]

**Punto de parada obligatorio.** Tras 1.4, el orquestador presenta al humano:

1. `Hojas/lista_tecnicas_validas.md` (lista priorizada P1→P3 con justificación R/E/S).
2. Resumen de cobertura por táctica y por familia R/E/S.

El humano **elige las 12-15 técnicas** del corpus (foco Ransomware, Exfiltración y Sabotaje).
Solo entonces se ejecuta 1.6 (materializar `ATA_index.csv`) y se cierra la fase.

Este punto corresponde al hito **H1** del roadmap (lista de técnicas válidas + criterio del
filtro inverso). Hasta que el humano apruebe, `status` permanece en
`pending_human_approval`.

### 8.1 Corpus final elegido — decisión humana (2026-09-19)

El humano ratifica el **corpus de 13 técnicas** con dos cambios respecto a la recomendación
automática: **entra T1041 en lugar de T1052** y **entra T1560 en lugar de T1114**.

- **T1486, T1485, T1490, T1489, T1561, T1565, T1491** (7 Impact)
- **T1048, T1567, T1041** (3 Exfiltration)
- **T1074, T1119, T1560** (3 Collection)

Reparto: **7 Impact / 3 Exfiltration / 3 Collection**. La variedad "1 técnica por táctica"
(ampliación de cobertura) se tratará con el tutor como **ciclo siguiente**. Estas 13 técnicas
se materializan en `Hojas/ATA_index.csv` (`ATA001...ATA013`, `estado=pendiente`) en la tarea 1.6.

---

## 9. Trazabilidad

| Requisito | Dónde se cumple |
|---|---|
| R-01 (v19.1) | T-01 + cabecera CSV/MD |
| R-02 (script reproducible) | `extraer_tecnicas_host.py` versionado |
| R-03 (filtro inverso host) | T-02 §2.2 (cadena DET→AN→DC + fallback directo) + tests §3 |
| R-04 (prioridad R/E/S) | columna `priority` |
| R-07 (`ATA<NNN>`) | `Hojas/ATA_index.csv` (1.6) |
| F-01 | secuencia 1.1 → 1.6 |

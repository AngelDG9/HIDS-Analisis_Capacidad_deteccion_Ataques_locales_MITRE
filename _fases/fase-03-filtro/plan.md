---
fase: 3
bloque: fase-03-filtro
tarea: A2.1 (T-11 · R-09/R-13)
nombre: Filtro de ruido y etiquetado auditado de alertas (herramienta)
version: 1
status: approved_by_human
fecha: 2026-09-24
fecha_aprobacion: 2026-09-25
aprobado_por: humano
autor: tfg-planner
gate: humano (aprobación de este plan antes de implementar)
---

# Plan — Bloque `fase-03-filtro` (A2.1): filtro de ruido y etiquetado auditado

> Primera herramienta de preparación de la Fase 3. **No detecta ataques: organiza y
> etiqueta la evidencia** de una ventana de alertas, con un criterio **explícito,
> determinista y reproducible**. De ella dependen la tabla R-09, la métrica η (R-10) y
> la doble iteración (R-11). KISS: 8/10 hecho > 10/10 sin hacer.

## 0. Objetivo y alcance

**Objetivo:** construir `filtrar_ruido.py`, que dada la **ventana de alertas de un ataque**
(una fila por alerta) y el **catálogo baseline** (`Dataset/Legitimo/ruleids_legitimos.csv`)
produce `ATA<NNN>_iter{N}-Audited.csv`: cada alerta **clasificada por capa** (`RS1..RS4`) y
**etiquetada** como `deteccion`, `ruido_conocido`, `auto_ruido` o `dudosa`, con `motivo` y
evidencia trazables.

**Entra:** la herramienta, su política escrita, tests offline, un ejemplo de salida y el
formato del fichero de señales esperadas del ataque.
**NO entra:** pre-flight anti-enmascaramiento (A2.2), Atomic Red Team (A2.3), cronómetro
t0/t1 (A2.4), ejecutar ataques, escribir reglas RS3, tocar el laboratorio, η (Fase 4).

## 1. Datos que faltan → **Paso 0** (primera tarea del ejecutor, con VMs encendidas)

No conocemos los **nombres exactos** de los campos JSON de audit/FIM (no están en el repo).
No se inventan: el paso 0 los fija y los deja en el repo (reproducibilidad + fixtures).

1. Ampliar `extraer_alertas.py` con **`--muestra`**: vuelca líneas JSON **crudas** de una
   ventana → `Dataset/Muestras/baseline_muestra.jsonl` (muestra representativa de `80791`
   auto-ruido, `80792` auto-ruido y del script, `8078x`, reglas RS1 de auth). **Revisar que
   no haya secretos** antes de commitear.
2. Ampliar `extraer_alertas.py` con **`--detail`**: una **fila por alerta** (mismos filtros de
   ventana y resolución de `rs_origen` que ya usa) → `Dataset/Legitimo/baseline_detalle_v1.csv`
   y `_v2.csv`. Sirven de fixture y hacen el test (a) **offline para siempre**.
3. Con esa muestra, cerrar la lista de **columnas del detalle** (candidatas, a confirmar en
   el paso 0): `timestamp_utc, agent_name, rule_id, rule_level, rule_description, rule_groups,
   rs_origen, audit_exe, audit_cwd, audit_key, audit_type, syscheck_path`.

## 2. Criterio de clasificación (la decisión central)

Una alerta recibe **una** categoría aplicando este orden (gana el primero que casa):

```
1. auto_ruido       si su ORIGEN es el propio Wazuh (por campos, no por rule.id):
                    audit.exe ∈ {wazuh-agentd, wazuh-syscheckd, wazuh-logcollector,
                                 wazuh-modulesd, wazuh-execd, wazuh-db, wazuh-analysisd}
                    OR audit.cwd == /var/ossec  OR ruta ~ /var/ossec/var/run/*
2. deteccion        si casa una SEÑAL ESPERADA de tipo `deteccion` del ataque
3. dudosa           si casa una SEÑAL ESPERADA de tipo `ambigua` (o falta el campo para evaluar)
4. deteccion        si rule.id NO está en el catálogo (motivo `novel`)
5. ruido_conocido   si rule.id SÍ está en el catálogo
```

**Cómo se atribuye una alerta a la técnica (clave):** con el **fichero de señales esperadas**
del artefacto del ataque, `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv`,
derivado del **Data Component** de la técnica (`Hojas/corpus_host.csv`) + el ruleset Wazuh.
Se redacta **antes** de ejecutar el ataque (T-09, [MIXTO]: el agente propone, el humano valida).
Columnas: `senal_id, tipo, campo, patron, dato_componente, tecnica, nota`, con
`tipo ∈ {deteccion, ambigua}` y `campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key,
syscheck_path}` (`patron` literal o glob `*`). Así se atribuye **por ruta** (watch key /
syscheck path), **por proceso** (`audit_exe`/`audit_cwd`) y **por grupo/regla**.

Por qué así: "ya salía en el baseline" **no** equivale a "es ruido". El catálogo **acota** el
ruido (`baseline_meta.md` §9), y una señal esperada que casa **gana al catálogo** → un ataque
que dispare una alerta conocida (p. ej. "fichero creado", `80790`) se cuenta como **detección**,
no como ruido. Sin fichero de señales, la herramienta **falla ruidosamente** (no resuelve en
silencio); solo hay un modo explícito `--modo baseline` para pasar una ventana sin ataque.

## 3. Auto-ruido (§ decisión 2) — categoría propia

`auto_ruido` es **categoría propia**, detectada **por campos** (proceso/cwd/ruta), no por
`rule.id`: `80791` de `wazuh-agentd` y `80792` con `cwd=/var/ossec` (hijos de
`wazuh-syscheckd`/`wazuh-logcollector`) son el **~54 %** del ruido. **No se mezcla** con
`ruido_conocido` (así el 54 % queda visible) y **nunca** cuenta como detección. Se cuenta y se
reporta **aparte** en el resumen. Si una señal `deteccion` apuntara a un proceso de Wazuh,
se emite **conflicto** en el log (no se resuelve en silencio).

## 4. Dudosas y revisión humana (§ decisión 3)

`dudosa` = señal declarada **ambigua** (regla que para esa técnica puede ser ruido o ataque,
p. ej. `80790` "Created:") o alerta **sin los campos** necesarios para evaluar la atribución.
La herramienta marca `revision=pendiente` y emite `ATA<NNN>_iter{N}-Revision.csv` (las filas
dudosas + columna `veredicto`). El humano escribe `veredicto ∈ {deteccion, ruido}` + `nota`.
Al re-ejecutar con `--revision <fichero>`, los veredictos se **pliegan** en el audited
(`revision=resuelta`, `veredicto_humano`, `revisor`, `fecha`) y queda **trazable y versionado**.

## 5. Salida (§ decisión 4)

- **Fichero:** `Dataset/Ataques/Resultados/Wazuh/Auditado/ATA<NNN>_iter{N}-Audited.csv`
  (una **fila por alerta**; cumple la nomenclatura `-Audited.csv` de T-11 y la doble iteración
  de R-11). La vista agregada por `rule.id`/capa para la tabla R-09 es Fase 3/4.
- **Columnas exactas:** `ata_id, iter, timestamp_utc, agent_name, rule_id, rule_level,
  rule_groups, rs_origen, rule_description, categoria, motivo, atribucion, revision,
  veredicto_humano, evidencia`.
  - `categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa}`.
  - `motivo`: `senal:<senal_id>`, `novel`, `baseline`, `auto_ruido:<proceso>`, `ambigua:<senal_id>`, `sin_campos`.
  - `atribucion`: `tecnica` + `dato_componente` de la señal que casó (vacío si no hay).
  - `evidencia`: campo(s) que decidieron (p. ej. `audit_key=/home/angel/lab-attack/x`).
- **Cabecera `#`** (convención del repo) con rutas y `sha256` de entradas + conteos. **Sin reloj**:
  misma entrada → salida **byte a byte** idéntica (R-13). Orden estable por `(timestamp, rule_id, evidencia)`.

## 6. Casos límite (§ decisión 5)

- **(a) Catálogo superconjunto:** el script del baseline no correrá en Fase 3, así que parte del
  catálogo sobrestima el ruido. **No hace el filtro demasiado agresivo** porque las señales del
  propio artefacto (p. ej. `audit_key=/home/angel/lab-attack/*`) **ganan al catálogo**; y lo no
  atribuible y ambiguo cae en `dudosa`, no en `ruido`. Si tras el piloto el filtro resulta
  agresivo, se **afina el fichero de señales**, no el código.
- **(b) RS3/RS4 hoy vacías:** la herramienta **no** tiene lógica de RS: copia `rs_origen` del
  extractor (por fichero de origen). Cuando RS3/RS4 se pueblen, funcionan **sin cambios**;
  además, un `rule.id` de RS3/RS4 **no** está en el catálogo → `novel` → `deteccion`.

## 7. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/extraer_alertas.py` | **añadir** `--detail` y `--muestra` (modo agregado y `--test` intactos) |
| `_artefactos/scripts/filtrar_ruido.py` | **nuevo** (la herramienta) |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` + `tests/fixtures/filtro_*` | **nuevos** (tests offline) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | **nuevo** (política: categorías, orden, señales, revisión) |
| `Dataset/Muestras/baseline_muestra.jsonl` | **nuevo** (paso 0, fixture cruda) |
| `Dataset/Legitimo/baseline_detalle_{v1,v2}.csv` | **nuevos** (paso 0, fixture del test a) |
| `Dataset/Ataques/Resultados/Wazuh/Auditado/EJEMPLO_ATA000_iter1-Audited.csv` | **nuevo** (ejemplo de salida) |
| `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv` | **formato** + 1 ejemplo (real por ataque en T-09) |

## 8. Criterios de aceptación y casos de prueba

| # | Caso | Resultado esperado |
|---|---|---|
| **a** | `filtrar_ruido.py --modo baseline` sobre `baseline_detalle_v1.csv` (y v2) | **0 `deteccion`**; toda fila ∈ {`auto_ruido`, `ruido_conocido`} |
| **b** | Fila con `rule.id=999999` (no en catálogo) | `categoria=deteccion`, `motivo=novel` |
| **c** | Filas `80791`/`wazuh-agentd` y `80792`/`cwd=/var/ossec` | `categoria=auto_ruido`; **no** cuentan como detección |
| **d** | Ejecutar dos veces con la misma entrada | salida **byte a byte** idéntica (mismo `sha256`) |
| **e** | Señal `deteccion` que casa sobre regla **conocida** (p. ej. `80790` en la ruta del ataque) | `deteccion` (el baseline **no** lo absorbe) |
| **f** | Señal `ambigua` → emitir revisión → veredicto → `--revision` | `revision=resuelta` + `veredicto_humano` trazable |
| **g** | Filas con `rs_origen = RS1/RS2/RS3/RS4/UNKNOWN` | se copian **sin alterar** (compatibilidad RS3/RS4) |
| **h** | Ataque sin `ATA<NNN>_esperado.csv` (y sin `--modo baseline`) | **exit ≠ 0** con mensaje claro (no resuelve en silencio) |

## 9. Cómo se verifica (`tfg-tester`)

1. Ejecuta `pytest _artefactos/scripts/tests/test_filtrar_ruido.py` → **todo PASA**.
2. Reproduce **a, b, c** con los ficheros del repo y comprueba categorías y conteos.
3. Comprueba **d** (dos ejecuciones, `sha256` igual) y **g/h**.
4. Verifica columnas/orden exactos de §5 contra el ejemplo de salida y el CSV real.
5. Comprueba que `extraer_alertas.py --test` y el modo agregado **siguen funcionando** (no regresión).
6. Lee `politica_filtrado_ruido.md`: categorías y orden coinciden con el código. **PASA/FALLA** con evidencia.

## 10. Qué tiene que aprobar el humano (gate)

1. Las **4 categorías** y el **orden de decisión** de §2 (con la atribución por señales esperadas).
2. Que el **auto-ruido** sea **categoría propia** y no cuente como detección (§3).
3. Que **`novel` (rule.id no en catálogo) cuente como `deteccion`**; alternativa: marcarla `dudosa`.
4. El **fichero de señales esperadas** obligatorio por ataque (con artefacto) y su formato (§2).
5. El **nombre/columnas** de la salida (§5) y la ubicación de la **política** (§7).

---

> **Resumen del paso 0 — lo que necesito:** las **VMs encendidas** para volcar una **muestra
> cruda** real de `alerts.json` del manager (`Dataset/Muestras/baseline_muestra.jsonl`) y
> confirmar los **nombres exactos de campo** de audit/FIM. Sin ese dato, los predicados de
> auto-ruido y de atribución quedarían a ciegas; no se inventan.

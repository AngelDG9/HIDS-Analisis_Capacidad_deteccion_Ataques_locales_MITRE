---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA007
tecnica: T1491
tactica: Impact
version: 4
status: cerrado
fecha: 2026-09-28
---

# Ficha — ATA007 · T1491 Defacement (Linux / `victima-linux`)

> Bloque `fase-03-piloto-custom` (camino **ataque escrito por nosotros**). Generada por
> `tfg-executor`. **Sin secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** →
> **`iguales`** (detección idéntica entre iteraciones; sin `dudosa` sin resolver).
>
> **Revisión (`fase-03-senales`, 2026-09-28):** recuento **re-generado** con el **ancla implícita
> + evento de ejecución** (`filtrar_ruido.py`); `deteccion` **4→2** (las escrituras watch → `dudosa`
> → `ruido`; **`CA13` cerrado**); `Hojas/ATA_index.csv` **intacto** (sigue `cerrado`). Detalle en
> §8/§8.1/§9/§10.
>
> **Ratificación humana (`fase-03-senales-ratificacion`, 2026-09-28):** el humano **ratifica** las
> **4 escrituras del defacement** (`80790`/`80781`, 2 por iteración) **como `deteccion`** (son el
> ataque; el doble conteo del mismo evento se evita **al contar**, no al clasificar). `deteccion`
> **2→4** por ventana; las **13** dudosas de **procesos ajenos** (ATA004/ATA012) siguen **`ruido`**.
> Detalle en §8.1.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA007** |
| Técnica / subtécnica | **T1491** Defacement |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual** (custom; Atomic Red Team **no** tiene pruebas Linux para T1491) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG; **no** copia de ART) |
| Herramienta | `cp` (coreutils, `/usr/bin/cp`) |
| Objetivo | `/home/angel/lab-legit/public_site/index.html` (**dir VIGILADO** por `auditd`, mock web) |
| Elevación | **no** (usuario `angel`) |

Artefacto: `Dataset/Ataques/Comandos/T1491-Defacement/ATA007_ataque.sh`
(`sha256=6918a2a8e0553ad2ef618c99ca4007e96c31ab818828108b880415a9b871ff4b`, idéntico en repo y víctima).
Señales esperadas: `.../ATA007_esperado.csv`
(`sha256=c9ee94d5fc0ea3dc399f32ddb13fe12e3f336757ed9c92a9f3219e7db230f8b9`).
Validación humana del `esperado` (CA5): **2026-09-26** (frontmatter de `plan.md`, gate).
C0: `Soporte/Ataques/c0/ATA007_logtest.txt` (`sha256=6e08fbd4ed4100602fe6ce2d00250c37c2b8752ea5ed50827f11ccd0abe617d1`)
→ pre-flight **PASA** (C0 ejecutado, `n=1` evento, **sin silenciadores de fábrica**).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada en la víctima.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA007_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-26T12:05:06Z` | `2026-09-26T12:05:42Z` | 36 s | 737 | `6918a2a8…1ff4b` |
| 2 | `2026-09-26T12:16:20Z` | `2026-09-26T12:16:55Z` | 35 s | 748 | `6918a2a8…1ff4b` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager < 1 s. `t0` sellado **tras
≥ 60–90 s de asentamiento** (H2).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA007
bash ATA007_ataque.sh          # cp del defacement sobre la página "pública" simulada
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA007_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`.

> **Nota (`fase-03-cabos`, 2026-09-28):** este bloque **no** generó `sha256_artefacto.txt` (el fichero
> no existe en ninguno de los 6 directorios de `Logs/`; solo lo generó el piloto). El `sha256` del
> script consta en §2 y en `Bitacora/ATA007.json` (`ataque_sha256`) — **idéntico repo↔víctima**; no se
> reconstruye evidencia post-hoc.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-26.json` (extracción con
  `extraer_alertas.py` **H3**, con `srcip/srcuser/dstuser`; desplegado en el manager el 2026-09-26, ver §10).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 744 | 737 | 7 | **737** | 6 | **0** |
| 2 | 756 | 748 | 8 | **748** | 6 | **0** |

## 8. Resultado (conteos por categoría y capa, con veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 737 | **4** | 609 | 124 | **0** | 4 | 733 | 0 | 0 |
| 2 | 748 | **4** | 620 | 124 | **0** | 4 | 744 | 0 | 0 |

### 8.1 Detecciones — **dos cifras** y desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | **4** | **3** · `{80792, 80790, 80781}` | **4 / 0** | 2 (`T1491-S1`) + 2 (`A1/A2` ratificadas) | 0 |
| 2 | **4** | **3** · `{80792, 80790, 80781}` | **4 / 0** | 2 (`T1491-S1`) + 2 (`A1/A2` ratificadas) | 0 |

- **Dos cifras (ratificación 2026-09-28):** cada ventana tiene **4 alertas** de detección con
  **3 `rule_id` distintos** (`80792`, `80790`, `80781`). Desglose: **2 alertas / 1 `rule_id`**
  (`80792`, el **`execve` del `cp`** — `audit_command`, `cwd=/home/angel/lab-attack/ATA007`,
  ancladas por `T1491-S1` (`audit_exe=cp`) + el ancla `T1491-S2` (`audit_cwd`)) **+ 2 alertas /
  2 `rule_id`** (`80790` *Created: index.html*, `80781` *Write access: index.html* — las
  **escrituras watch del defacement**, **ratificadas por el humano como `deteccion`**).
- **El doble conteo se evita al contar:** las **2 escrituras** (`80790`/`80781`) son **el mismo
  evento** del `cp` que ya cuenta su `execve` (`80792`); por eso la ficha reporta **siempre las dos
  cifras** (*alertas* y *`rule_id` distintos*) y **no** deben sumarse como acciones independientes.
  El incremento de esta ratificación es **+4 alertas / +2 `rule_id`** (`{80790, 80781}`); el total de
  la ventana es **4 alertas / 3 `rule_id`** (`{80792, 80790, 80781}`).
- **`fase-03-senales` (2026-09-28) — `CA13` cerrado:** las escrituras watch (`80790`/`80781`) que
  antes se **promovían a `deteccion`** por la señal `S1` ancha ahora caen a
  **`dudosa`/`ambigua:T1491-A1`/`A2`** (el evento `watch` **no** es `audit_command` → la señal
  `audit_exe` no ancla). El humano las **ratificó a `deteccion`** por su **naturaleza** (el efecto
  del ataque), **no** por la señal ancha.
- **`dudosa` (3/iter) resueltas:** `80790` *Created: public_site.* (el `mkdir -p` del **setup**,
  A1) → **`ruido`** (no es la técnica); las **2 escrituras del `cp`** (A1/A2) → **`deteccion`**
  *(ratificación humana 2026-09-28: "es el ataque (la escritura del defacement); es el mismo evento
  ya contado por el `execve` del `cp` — se reporta con las dos cifras"; firma
  `revisor=humano (ratificacion 2026-09-28)`).*

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792, 80790, 80781}` == `{80792, 80790, 80781}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|4−4\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 609 vs 620 → Δ=11 |
| Sanidad `ruido_conocido` (aviso) | ✅ 124 vs 124 → Δ=0 |

> **Nota (`fase-03-senales`, 2026-09-28):** cifras recalculadas con el **ancla implícita + evento
> de ejecución**; `deteccion` pasa de **4/4** a **2/2** (las 2 escrituras watch → `dudosa` →
> `ruido`). Veredicto v2 sigue **`iguales`**.
>
> **Nota (`fase-03-senales-ratificacion`, 2026-09-28):** el humano **ratifica** las 4 escrituras a
> **`deteccion`** → `deteccion` **2/2 → 4/4**, con el **mismo conjunto de `rule_id`**
> (`{80792, 80790, 80781}`) en ambas iteraciones. Veredicto v2 sigue **`iguales`**.

## 10. Limitaciones y hallazgos (para la memoria)

1. **Señal `audit_exe` ancha — ✅ RESUELTO (`fase-03-senales`, 2026-09-28):** el filtro ya **no**
   promueve a `deteccion` las **escrituras** del propio proceso: una señal `audit_exe` solo ancla si
   la fila es un **evento de ejecución** (`audit_command`) y su `cwd` casa el ancla `audit_cwd`.
   `CA13` queda **cerrado en el artefacto**. Ver política §4 y runbook §8.2.
2. **Baseline que "tapa" la escritura (§3.1 del plan):** la ruta `lab-legit` es la que trabaja la
   actividad legítima; por eso A1/A2 se declararon **`ambigua`** en el `esperado` (revisión humana),
   nunca señal `deteccion`. La **ratificación humana (2026-09-28)** elevó el **veredicto** de esas
   filas a `deteccion` (son el ataque), pero la **señal** sigue siendo `ambigua`: el filtro **no**
   las promueve por sí solo.
3. **Gap de despliegue (runbook §8.1):** el `extraer_alertas.py` del manager estaba obsoleto (sin
   `srcip`); se **desplegó** la versión del repo y se **re-extrajo** esta ventana.
4. `lab-listo` prístino: no se instaló nada; el `public_site/` creado desaparece al revertir.

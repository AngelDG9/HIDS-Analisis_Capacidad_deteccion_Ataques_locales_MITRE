---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA007
tecnica: T1491
tactica: Impact
version: 7
status: cerrado
fecha: 2026-09-29
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
>
> **Revisión (`fase-03-metrica`, 2026-09-28):** se añade la **métrica O1+O2** (§8.2) y la categoría
> **`artefacto_ataque`**: las huellas del propio ataque **salen de `ruido_conocido`** (`124→117` y
> `124→119`). **El veredicto no cambia** (`deteccion=4/4`) y **ninguna detección genuina se pierde**.
> `Hojas/ATA_index.csv` **intacto** (sigue `cerrado`).
>
> **Corrección (`fase-03-metrica`, ciclo 2, 2026-09-28):** el `mkdir -p` del **setup** (`80790`
> *Created: public_site.*, 1/iter) **pasa de `ruido` a `artefacto`** (regla **D2/D5**): es del ataque
> (demostrable en `ATA007_ataque.sh` y en §8.1) pero está **fuera** de `ATTACK_ROOT` → no lo cubre la
> regla de pertenencia; es una **pista floja** → `artefacto`, **nunca `ruido`**. `artefacto_ataque`
> **7/5 → 8/6**; `ruido_conocido` **117/119 → 116/118**; `deteccion=4/4` (sin cambios).
>
> **Corrección (`fase-03-escalado`, criterio único, 2026-09-29):** las **4 escrituras del
> defacement** (`80790`/`80781`, 2 por iteración) **pasan de `deteccion` a `artefacto`**: son
> **EFECTO** del ataque (la escritura del `cp`), **no** una detección independiente; **la detección
> es el `execve` del `cp`** (`80792`). Criterio **único** del bloque: la **escritura bajo `watch`**
> se clasifica como **`artefacto_ataque`** (efecto), **nunca `deteccion`**. `deteccion` **4→2** por
> ventana; `artefacto_ataque` **8/6 → 10/8**; `ruido_conocido`/`auto_ruido` sin cambios. **El
> veredicto del ataque NO cambia** (sigue **DETECTADO** por el `execve`). Detalle en §8/§8.1/§9.

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

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 737 | **2** | 609 | 116 | **0** | **10** | 4 | 733 | 0 | 0 |
| 2 | 748 | **2** | 620 | 118 | **0** | **8** | 4 | 744 | 0 | 0 |

### 8.1 Detecciones — desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | **2** | **1** · `{80792}` | **2 / 0** | 2 (`T1491-S1`) | 0 |
| 2 | **2** | **1** · `{80792}` | **2 / 0** | 2 (`T1491-S1`) | 0 |

- **La detección es el `execve` del `cp` (`80792`):** **2 alertas/ventana** de `80792`
  (`audit_command`, `cwd=/home/angel/lab-attack/ATA007`), **ancladas** por `T1491-S1`
  (`audit_exe=cp`) + el ancla `T1491-S2` (`audit_cwd`). **El ataque está DETECTADO** (O1 = sí).
- **Las escrituras `watch` (`80790`/`80781`) NO son detección** — son el **EFECTO** del mismo `cp`
  (criterio **único** `fase-03-escalado`, 2026-09-29): el evento `watch` **no** es `audit_command`,
  así que la señal `audit_exe` no ancla; se clasifican como **`artefacto_ataque`** (efecto), **nunca
  `deteccion` ni `ruido`**. (`fase-03-senales`, 2026-09-28, ya cerró `CA13` en ese sentido.)
- **`dudosa` (3/iter) resueltas → `artefacto` (6/6):** el `mkdir -p` del **setup** (`80790`
  *Created: public_site.*, **fuera** de `lab-attack` → no lo cubre la regla de pertenencia; **pista
  floja → `artefacto`, nunca `ruido`**; regla D2/D5, 2026-09-28) **y** las **2 escrituras del `cp`**
  (`80790` *Created: index.html*, `80781` *Write access: index.html*; criterio único 2026-09-29).
  Firma de estas últimas: `revisor=humano (criterio unico 2026-09-29)`.

### 8.2 Métrica de detección — **O1 + O2** (`fase-03-metrica`, decisión D1)

> **Definición:** **O1** = *detectado sí/no* + `rule_id` + primera evidencia; **O2** = *acciones
> cubiertas `k/m`* (señales `deteccion` ancladas ≥1 vez / total de señales `deteccion` no-ancla).
> El **nº bruto de alertas** y los `rule_id` distintos son **anexo**, nunca el resultado.

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo: alertas / `rule_id` distintos |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-26T12:05:07.066Z` `audit_exe=/usr/bin/cp` | **1/1** (`T1491-S1`) | **2 / 10 / 116** | 2 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-26T12:16:21.407Z` `audit_exe=/usr/bin/cp` | **1/1** (`T1491-S1`) | **2 / 8 / 118** | 2 / `{80792}` |

- **O2 = 1/1:** la única acción declarada es el `execve` del `cp` (`T1491-S1`), anclado por `S2`. Las
  alertas `watch` (`80790`/`80781`) son el **mismo evento** (el `cp`) y se cuentan como
  **`artefacto_ataque`** (efecto), **no** como detección. Las filas `artefacto_ataque`/iter son la
  huella del árbol del ataque (`execve` no declarados) **más** esas escrituras del `cp`.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|2−2\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 609 vs 620 → Δ=11 |
| Sanidad `ruido_conocido` (aviso) | ✅ 116 vs 118 → Δ=2 |

> **Nota (`fase-03-senales`, 2026-09-28):** cifras recalculadas con el **ancla implícita + evento
> de ejecución**; `deteccion` pasa de **4/4** a **2/2** (las 2 escrituras watch → `dudosa` →
> `ruido`). Veredicto v2 sigue **`iguales`**.
>
> **Nota (`fase-03-senales-ratificacion`, 2026-09-28):** el humano **ratifica** las 4 escrituras a
> **`deteccion`** → `deteccion` **2/2 → 4/4**, con el **mismo conjunto de `rule_id`**
> (`{80792, 80790, 80781}`) en ambas iteraciones. Veredicto v2 sigue **`iguales`**.
>
> **Nota (`fase-03-escalado`, criterio único, 2026-09-29):** ⚠️ **reemplaza** la ratificación de
> 2026-09-28. Las 4 escrituras `watch` pasan a **`artefacto_ataque`** (efecto, no detección) →
> `deteccion=2/2`, **mismo conjunto de `rule_id`** (`{80792}`) en ambas iteraciones. **El ataque
> sigue DETECTADO**; veredicto v2 sigue **`iguales`**.

## 10. Limitaciones y hallazgos (para la memoria)

1. **Señal `audit_exe` ancha — ✅ RESUELTO (`fase-03-senales`, 2026-09-28):** el filtro ya **no**
   promueve a `deteccion` las **escrituras** del propio proceso: una señal `audit_exe` solo ancla si
   la fila es un **evento de ejecución** (`audit_command`) y su `cwd` casa el ancla `audit_cwd`.
   `CA13` queda **cerrado en el artefacto**. Ver política §4 y runbook §8.2.
2. **Baseline que "tapa" la escritura (§3.1 del plan):** la ruta `lab-legit` es la que trabaja la
   actividad legítima; por eso A1/A2 se declararon **`ambigua`** en el `esperado` (revisión humana),
   nunca señal `deteccion`. La **corrección del 2026-09-29 (criterio único `fase-03-escalado`)**
   mantiene esas filas como **`artefacto_ataque`** (efecto del ataque, **no** detección): la **señal**
   sigue siendo `ambigua` y el filtro **no** las promueve por sí solo; la detección del ataque es el
   `execve` del `cp` (`80792`).
3. **Gap de despliegue (runbook §8.1):** el `extraer_alertas.py` del manager estaba obsoleto (sin
   `srcip`); se **desplegó** la versión del repo y se **re-extrajo** esta ventana.
4. `lab-listo` prístino: no se instaló nada; el `public_site/` creado desaparece al revertir.

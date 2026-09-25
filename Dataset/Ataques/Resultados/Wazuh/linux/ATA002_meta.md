---
fase: 3
bloque: fase-03-piloto
ata_id: ATA002
tecnica: T1485
tactica: Impact
version: 2
status: review
fecha: 2026-09-25
---

# Ficha — ATA002 · T1485 Data Destruction (Linux / `victima-linux`)

> Piloto `fase-03-piloto`. Generada por `tfg-executor`. **Sin secretos.**
> Estado **`review`**: las 177 `dudosa` quedaron **resueltas** por veredicto humano (2026-09-25,
> `ruido`), pero el **chequeo de sanidad** del criterio de doble iteración (§6 del plan) **falla**
> por el `ruido_conocido` (iter1 capturó un arranque de máquina con mucho más churn que iter2).
> **Hallazgo declarado** (ver §9), no un fallo de la maquinaria.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA002** |
| Técnica / subtécnica | **T1485** Data Destruction |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Prioridad | n/d (no definida en el corpus; ATA002 es de la primera tanda de 13) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Prueba ART | *FreeBSD/macOS/Linux — Overwrite file with DD* |
| GUID | `38deee99-fd65-4031-bec8-bfa4f9f26146` |
| Path en el clon | `atomics/T1485/T1485.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Herramienta | `dd` (coreutils 9.4, `/usr/bin/dd`) |
| Dependencias | ninguna nueva — `which dd python3 wget curl` OK |
| Elevación | **no** (usuario `angel`) |
| Desviación D1 | destino `/home/angel/lab-legit/ATA002_scratch_dd.txt` (no `/etc`, no escribible sin `sudo`); aceptada por el humano. Se pierde la señal FIM; la detección va por `execve`/`watch` de `dd`. |

Artefacto: `Dataset/Ataques/Comandos/T1485-Data_Destruction/ATA002_ataque.sh`
(`sha256=0a838e9732544b994aac16ecccf6dceda145e5a061d3ec73bcc9cf5bf3e27f16`, idéntico en repo y en la víctima).
Señales esperadas: `.../T1485-Data_Destruction/ATA002_esperado.csv`
(`sha256=970c5dfcc6c845e7e60fdfc4d5d010b17f6570d606514372abfbaf2aad1f17c7`).
Validación humana (CA5): **2026-09-25**, registrada en `plan.md` (frontmatter `gate`) y en el
comentario de cabecera del propio `ATA002_esperado.csv` (reescrito de «PENDIENTE» a «validado»).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración (revert iter1 `2026-09-25T20:29:59Z`,
  iter2 `2026-09-25T20:35:18Z`). Entre iteraciones el revert es obligatorio.
- **Manager NO revertido** (conserva las alertas de ambas ventanas).
- **NAT desconectado** (no reconectado). No se instaló nada en la víctima.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | sha256 `ATA002_ataque.sh` |
|---|---|---|---|---|
| 1 | `2026-09-25T20:31:17Z` | `2026-09-25T20:32:01Z` | 44 s | `0a838e97…e27f16` |
| 2 | `2026-09-25T20:36:17Z` | `2026-09-25T20:36:48Z` | 31 s | `0a838e97…e27f16` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager < 1 s.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA002
bash ATA002_ataque.sh
```

Cuerpo (parametrizado, sin elevación): `dd if=/dev/zero of=$HOME/lab-legit/ATA002_scratch_dd.txt bs=1M count=1`
y después el cuerpo de la atómica `dd of=<target> if=/dev/zero count=$(ls -l …) iflag=count_bytes`.
`stdout`+`stderr` en `ejecucion.out` (rc=0 en ambas).

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA002_iter{1,2}/`:
`times.log`, `ejecucion.out`, `ps_antes.txt`, `ps_despues.txt`, `deps.txt`, `sha256_artefacto.txt`.
(ATA002 no usa receptor → sin `sink.log`.)

## 7. Ventana extraída

- Fichero diario (NO `alerts.json`): `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-25.json`.
- **Aislamiento por agente:** extracción `--detail` → `_raw` y filtro a `agent_name == victima-linux`.
  El `_raw` conserva filas de otros agentes (manager) para verificar el filtro.

| Iter | Filas en ventana (`_raw`) | victima-linux | wazuh-server (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 1022 | 1014 | 8 | **1014** | 9 | **0** |
| 2 | 777 | 770 | 7 | **770** | 8 | **0** |

Reparto por capa RS (Detalle): iter1 `RS2=1000, RS1=14`; iter2 `RS2=766, RS1=4`. RS3/RS4 vacías (no se escribieron reglas). **0 filas de otro agente** (CA11 ✔).

## 8. Resultado (conteos por categoría, con veredicto humano ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa |
|---|---|---|---|---|---|
| 1 | 1014 | **4** | 606 | 404 | **0** |
| 2 | 770 | **4** | 641 | 125 | **0** |

**`deteccion` (idénticas en ambas, todas `audit_exe=/usr/bin/dd`):** `80792`×2 (execve de `dd`),
`80790`×1 (Created bajo watch), `80781`×1 (Watch-Write bajo watch). → **Wazuh detecta el ataque**
por las reglas de auditd de fábrica (RS2).

**`dudosa` resueltas (177):** iter1 128 (`80791`×120, `80780`×6, `80782`×2), iter2 49 (`80791`×48,
`80780`×1). Señal ambigua `T1485-A2` (`rule_group=audit_watch_write`) **demasiado amplia**: ninguna
fila toca `/home/angel/lab-legit` (0 con `lab-legit` en la ruta); eran eventos watch-write genéricos
(`/run/systemd`, `/run/user`, sockets gnupg…). **Veredicto humano (bloque, 2026-09-25): `ruido`**
(aprobado; sus reglas ya están en el catálogo del baseline) → `revision=resuelta`,
`veredicto_humano=ruido` en los `-Audited.csv`.

## 9. Doble iteración (§6) — veredicto `review`

| Criterio | Resultado |
|---|---|
| 1) Mismo conjunto de `rule_id` con `deteccion` | ✅ `{80781,80790,80792}` == `{80781,80790,80792}` |
| 2) `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|4−4\| = 0 ≤ 2` |
| 3) Sin `dudosa` sin resolver | ✅ 0 y 0 (177 resueltas por el humano) |
| **Sanidad** `auto_ruido` (≤ 10 %) | ✅ 606 vs 641 → `Δ=35 ≤ 60,6` |
| **Sanidad** `ruido_conocido` (≤ 10 %) | ❌ **404 vs 125 → `Δ=279` (≫ 40,4)** |

Los **3 criterios formales** pasan, pero el **chequeo de sanidad de `ruido_conocido` falla de forma
clara** → por §6 **`review`** (no se cierra en silencio).

**Por qué, con números (hallazgo):** la diferencia **no** viene del ataque, viene del **arranque de
la máquina**. Los `ruido_conocido` se concentran en un **pico en el primer segundo** de cada ventana
(iter1: 266 eventos a `20:31:17` + 96 a `20:31:18`; iter2: 81 a `20:36:18` + 43 a `20:36:28`), y son
`execve` de utilidades de sistema (`dash` 88 vs 22, `cat` 20 vs 6, `env` 16 vs 5, `uname` 12 vs 4,
`find` 12 vs 3, `systemd-executor` 11 vs 3) bajo `80792`, más `watch` `80791`/`80780`. **Iter1
capturó un arranque de máquina con más churn que iter2** (tras el revert, el `lab-listo` rearranca
servicios por temporizadores/`systemd` con un pico mayor en esa ventana). Es **variabilidad del
churn de arranque**, no del ataque (`deteccion` **idéntica**: 4 y 4, mismo conjunto de reglas).

→ **Traslado al escalado:** las ventanas tras un revert son **cortas** y muy sensibles al churn de
arranque; conviene (a) **esperar a que el arranque se asiente** antes de `t0`, y/o (b) cubrir con la
sanidad un margen mayor para `ruido_conocido` (o comparar solo el **rango temporal de régimen**).
Queda como **hallazgo del piloto**, no como fallo.

## 10. Limitaciones y cabos descubiertos

1. **Señal A2 demasiado genérica** (ambigua `rule_group=audit_watch_write`): no discrimina por ruta
   → 177 `dudosa` (resueltas a `ruido`). Para el escalado, hacer las señales **más específicas**
   (p. ej. la **carpeta del ataque** como señal).
2. **Glitch del runbook (filtro por agente):** el snippet canónico conservaba la línea de comentario
   `#` como cabecera y **descartaba la cabecera real** (porque `extraer_alertas.py --detail` antepone
   un `#`). **✅ Corregido el 2026-09-25 en `Soporte/Ataques/piloto_procedimiento.md` §2 paso 9**
   (ahora salta las líneas `#` y conserva la cabecera real); verificado re-ejecutándolo sobre
   `ATA002_iter1-Detalle_raw.csv` → salida **idéntica** al `Detalle.csv` (1014 filas).
3. **Sanidad de `ruido_conocido` sensible al arranque** (§9): ver hallazgo.
4. **Sin señal FIM** por la desviación D1 (target en `lab-legit`, no vigilado por syscheck); la
   detección se apoya en auditd (`execve`/`watch`). La atómica sin `sudo` no permite otra cosa.
5. `lab-listo` se mantiene prístino: no se instaló nada y el fichero creado desaparece al revertir.

---
fase: 3
bloque: fase-03-ampliacion
tanda: C
ata_id: ATA026
tecnica: T1565.002
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA026 · T1565.002 Transmitted Data Manipulation (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda C**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Proxy local** (`nc | sed | nc`) + **receptor del HOST**; el cuerpo llega **alterado**.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA026** |
| Técnica | **T1565.002 — Data Manipulation: Transmitted Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) — el HIDS de host no ve la red |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `nc` (proxy + emisor) + `sed` (reescritura **en tránsito**) |
| Efecto | el receptor recibe un cuerpo **con `sha256` distinto** del enviado (`importe=100`→`9999`) |
| Elevación | **no** |
| Guardarraíl | proxy **solo** en `127.0.0.1`; destino **solo** `192.168.65.1:9091`; `timeout`; `sed` fijo |

Artefacto: `.../T1565.002-Transmitted_Data_Manipulation/ATA026_ataque.sh`
(`sha256=19a23f6e620aa526725a1459ab356b6bd5b9b555a34ee86924f1c5604c6388fa`).
Señales: `.../ATA026_esperado.csv` (`sha256=c1ffde8d138c1c2672f27e974c7a77ff28ccafbcebe87c132bcfb9cbf7bb5072`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA026_logtest.txt` (`sha256=bac6447dc34909532cf29b5a122e55657079bbeff9de3a39e801aa3a5dbf2421`)
→ `ATA026_preflight.md` (`sha256=e3470aa57abcdd3db946353bdb9a0bb14179e2db2ec3720a5b6e96493f85b822`) **PASA**
(2 eventos `nc`/`sed` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras 90 s. **Receptor del HOST**
(`sink_http.py --bind 192.168.65.1 --port 9090 --tcp-port 9091`) levantado **antes de `t0`** y parado
**tras `t1`**. Firewall: **no** hizo falta (puerto alcanzable; `TCP_OK`).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T03:50:53Z` | `2026-09-29T03:51:31Z` | 38 s | 1214 | `19a23f6e…88fa` |
| 2 | `2026-09-29T03:54:38Z` | `2026-09-29T03:55:16Z` | 38 s | 1127 | `19a23f6e…88fa` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA026
bash ATA026_ataque.sh    # nc -l 127.0.0.1:8082 | sed 's/importe=100/importe=9999/' | nc -q1 192.168.65.1 9091
```

## 6. Evidencia

`Logs/ATA026_iter{1,2}/`: `times.log`, `ejecucion.out`, `original.txt`, **`sink.log`**.

**Prueba de éxito — el dato llegó ALTERADO (sha del receptor ≠ sha enviado):**

| Iter | `sha256` original | `sha256` manipulado esperado | `sha256` en `sink.log` | ¿coincide con el manipulado? |
|---|---|---|---|---|
| 1 | `c100612f…dd89` | `b3fd1e3c…0023` | `b3fd1e3c…0023` | **SÍ** ✅ (≠ original) |
| 2 | `c100612f…dd89` | `b3fd1e3c…0023` | `b3fd1e3c…0023` | **SÍ** ✅ (≠ original) |

`MANIP_TRANSITO=OK` en ambas. (El `sink.log` también registra una conexión `len=0` de la prueba de
conectividad `nc -z`, **antes de `t0`**.)

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1223 | 1215 | 1214 |
| 2 | 1136 | 1128 | 1127 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1214 | **1** | 657 | 534 | **0** | 22 | 10 | 1204 | 0 | 0 |
| 2 | 1127 | **1** | 609 | 498 | **0** | 19 | 16 | 1111 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 (`S2`: `sed`) | 0 |
| 2 | 1 | 1 · `{80792}` | 1 (`S2`: `sed`) | 0 |

- `sed` (`/usr/bin/sed`) **anclado** al `cwd` del ataque (la reescritura **en tránsito**).
- **`dudosa` resueltas:** iter1 → 1 `80792` `sin_ancla` → `artefacto`; 7 `PAM` → `ruido`.
  iter2 → 1 `80792` `sin_ancla` → `artefacto`; 11 `PAM` → `ruido`. **Ninguna** fila del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `03:50:55.913Z` `audit_exe=/usr/bin/sed` | **1/2** (`S2`) | 1 / 22 / 534 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `03:54:39.941Z` `audit_exe=/usr/bin/sed` | **1/2** (`S2`) | 1 / 19 / 498 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|1−1|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA026.json`.

## 10. Limitaciones y hallazgos

1. **⭐⭐ La manipulación en tránsito es (casi) invisible al HIDS de host:** el HIDS **no ve la red** y
   **no** distingue el sha enviado del recibido; sólo ve los **procesos** (`nc`, `sed`). El efecto se
   prueba con el **`sink.log`** (sha recibido = sha manipulado ≠ sha original). **La de mayor
   dificultad de la tanda** (como anticipaba el plan).
2. **⭐ HALLAZGO (mismo sistema que ATA028):** el `esperado` declara `audit_exe=nc`, pero audit
   registra `/usr/bin/nc.openbsd` → `nc` **no casa** (**O2 = 1/2**). La detección la sostiene `sed`.
3. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
4. **Huella de la sesión/ejecución del ataque declarada** (no es detección): 1 fila `80792`
   `nc.openbsd` sin `cwd`. Ver **§10.1**.

### 10.1 Huellas del ataque declaradas — **NO son detección**

> Añadido en `fase-03-ampliacion` (cabos de documentación, 2026-09-29). **No** se recalcula nada
> (métrica **congelada** y `esperado` **firmado**).

- **Qué fila:** **1** en **iter2**: `80792` con `audit_exe=/usr/bin/nc.openbsd` y **`audit_cwd`
  vacío** (ts `2026-09-29T03:54:39.954Z`).
- **Dónde cae:** en **`ruido_conocido`/`baseline`** (el `80792` está en el catálogo base y, sin
  `cwd`, la pertenencia por carpeta **no** puede anclarla). No reclasificable sin editar el
  `esperado` firmado.
- **Por qué NO es detección:** es una ejecución de `nc` del **propio ataque** que el `esperado` **no**
  puede casar por el nombre del binario (`nc` vs `nc.openbsd`, ya declarado como **hallazgo** en el
  punto 2 de arriba). Nada del ataque **se pierde**: la técnica sigue **DETECTADA** por **`80792` de `sed`**
  (reescritura en tránsito, anclada al `cwd`) — ver §8.2.
- **Nota de alcance:** en iter1 las 3 filas de `nc.openbsd` **sí** llevan `cwd` del ataque (se
  anclan bien); la asimetría es que en iter2 **una** de ellas salió sin `cwd`.

### 10.2 Alcance del invariante «0 filas del ataque en `ruido`»

- El invariante **«0 filas del ataque en `ruido_conocido`/`auto_ruido`»** se cumple **bajo la
  pertenencia por carpeta**: una fila con **`audit_cwd`** o **ruta** bajo **`lab-attack/ATA<NNN>`** →
  paso 3.5 → **`artefacto_ataque`**, **nunca** `ruido`.
- Quedan **fuera** de ese mecanismo las filas **sin `cwd`** ni ruta de la carpeta (p. ej. esta
  `nc.openbsd`): el filtro no puede **demostrar** que son del ataque → se **declaran** (§10.1) y
  **no** cuentan como detección. Limitación **declarada** del mecanismo.

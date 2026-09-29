---
fase: 3
bloque: fase-03-ampliacion
tanda: B
ata_id: ATA023
tecnica: T1496.002
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA023 · T1496.002 Bandwidth Hijacking (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda B**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Acotado:** 32 MiB y `--max-time 15 s`; transferencia de **~1,2 s**; **no satura** nada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA023** |
| Técnica | **T1496.002 — Resource Hijacking: Bandwidth** |
| Táctica | **Impact** |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) — **sin reglas de red/recursos** ⇒ probable solo-`execve` |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramientas | **`head -c 33554432 /dev/zero`** (flujo) + **`curl`** (volcado al receptor) |
| Efecto | `POST /api/bw/hog` de **32 MiB** al receptor del HOST |
| Elevación | **no** |
| Guardarraíl | topes duros: `MAX_BYTES=32 MiB`, `MAX_TIME=15 s` (aborta si se suben > 64 MiB / 30 s) |

Artefacto: `.../T1496.002-Bandwidth_Hijacking/ATA023_ataque.sh`
(`sha256=db76ac459df61774fd2c4d70451787ee2aa56ce931e75f24f8ac3f54574cb310`; la **ejecución** usó
`035cdc84…2ae2` —un **endurecimiento posterior** del guion cambió el fichero, ver `correccion` en
`Bitacora/ATA023.json`). `HOG=OK` es **condicional**: se comprueba el `curl` (rc=0, HTTP 2xx, `enviado==MAX_BYTES`);
si no cuadra → `HOG=FALLO` + `exit 1`.
Señales: `.../ATA023_esperado.csv` (`sha256=41142efb43a2be4ecafba64cc8618a6d316715bf734201c5a09b0ae804583cfb`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA023_logtest.txt` (`sha256=2f44cc57dce5036c9b69495bcb995c34afa4c1d4367e41117c0b6b0b76518092`)
→ `ATA023_preflight.md` (`sha256=646fe995d568a0743095ee50ed6c6a212245bcfdf16b8223a818f4b4f067899d`) **PASA**
(2 eventos: `head` y `curl` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **Receptor** HTTP 9090 (+TCP 9091) levantado **antes de `t0`** y parado tras `t1`; **sin regla
de firewall** (puerto alcanzable).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T02:02:46Z` | `2026-09-29T02:03:20Z` | 34 s | 886 | `035cdc84…2ae2` |
| 2 | `2026-09-29T02:06:31Z` | `2026-09-29T02:07:04Z` | 33 s | 884 | `035cdc84…2ae2` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA023
bash ATA023_ataque.sh     # head -c 32MiB /dev/zero | curl POST al receptor (acotado)
```

## 6. Evidencia

`Logs/ATA023_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito — la transferencia masiva ocurrió (bytes recibidos):**

| Iter | `sink.log` del HOST | tiempo cliente |
|---|---|---|
| 1 | `POST /api/bw/hog from=192.168.65.129 len=33554432 sha256=83ee4724…` | `HTTP=200 enviado=33554432B tiempo=1.23s` |
| 2 | `POST /api/bw/hog from=192.168.65.129 len=33554432 sha256=83ee4724…` | `HTTP=200 enviado=33554432B tiempo=1.19s` |

`HOG=OK` en ambas (32 554 432 B = 32 MiB). El `sha256` es el de un flujo de ceros (constante).

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 893 | 886 | 886 |
| 2 | 891 | 884 | 884 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 886 | **2** | 622 | 257 | **0** | 5 | 10 | 876 | 0 | 0 |
| 2 | 884 | **2** | 620 | 257 | **0** | 5 | 9 | 875 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 2 | 1 · `{80792}` | 2 (`S1` curl, `S2` head) | 0 |
| 2 | 2 | 1 · `{80792}` | 2 | 0 |

- `head` (flujo) y `curl` (transferencia) → `80792`, anclados al `cwd` del ataque.
- `dudosa` resueltas (10/iter1, 9/iter2): **`head` con `cwd=/`** (churn del login, `sin_ancla`) +
  **PAM del operador** (`sin_campos`) → **`ruido`**. **Ninguna** fila del ataque en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `02:02:48.665Z` `audit_exe=/usr/bin/head` | **2/2** (`S1`,`S2`) | 2 / 5 / 257 | 2 / `{80792}` |
| 2 | **sí** | `{80792}` | `02:06:33.084Z` `audit_exe=/usr/bin/head` | **2/2** | 2 / 5 / 257 | 2 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|2−2|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA023.json`.

## 10. Limitaciones y hallazgos ⭐

1. **R9 confirmado (hallazgo del bloque):** Wazuh **no tiene reglas de red ni de recursos** ⇒ el
   «ancho de banda» **no se ve**; la única detección es el **`execve`** (`head`/`curl`). Si el consumo
   se hiciera con *builtins* (p. ej. `dd` no… aquí `head`), sería un **punto ciego**.
2. **Acotación declarada:** 32 MiB en ~1,2 s; **no satura** la VM ni el host.
3. **C0 sin punto ciego** (`head`/`curl`→`80792`). **Realismo acotado** declarado (README §11).

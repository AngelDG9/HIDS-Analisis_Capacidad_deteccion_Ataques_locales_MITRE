---
fase: 3
bloque: fase-03-ampliacion
tanda: B
ata_id: ATA020
tecnica: T1020
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA020 · T1020 Automated Exfiltration (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda B**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA020** |
| Técnica | **T1020 — Automated Exfiltration** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) — la red no es visible |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`curl`** en **bucle** (automatización) |
| Efecto | 4 `POST` a `http://192.168.65.1:9090/api/exfil/<fichero>` (receptor del HOST) |
| Elevación | **no** |
| Guardarraíl | endpoint **DEBE** ser `192.168.65.1:9090` y el *staging* bajo `ATA020` (aborta si no) |

Artefacto: `.../T1020-Automated_Exfiltration/ATA020_ataque.sh`
(`sha256=fe171ff167630763de4708f01b3b4fe5730394bca5c2b2ed1aa405da635b536e`).
Señales: `.../ATA020_esperado.csv` (`sha256=eed2ede1203ed684243337f574254b8d88cc7cf826ea1bf9451151e8345ee218`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA020_logtest.txt` (`sha256=7ed74bfcddc22ece22ab06092b097fd7f423094550f0ed6f1449fd624cbacc43`)
→ `ATA020_preflight.md` (`sha256=aa550c64b613c1d53e8f5268cc00934105858b98248be8573c698ccecfb0ec0f`) **PASA**
(1 evento `curl` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **Receptor** HTTP 9090 (+TCP 9091) levantado **antes de `t0`** y parado tras `t1`; puerto ya
alcanzable ⇒ **sin regla de firewall**.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T01:55:28Z` | `2026-09-29T01:56:00Z` | 32 s | 875 | `fe171ff1…536e` |
| 2 | `2026-09-29T01:59:08Z` | `2026-09-29T01:59:40Z` | 32 s | 894 | `fe171ff1…536e` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA020
bash ATA020_ataque.sh     # bucle: curl POST por cada fichero del staging (4/4)
```

## 6. Evidencia

`Logs/ATA020_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito — el dato SALIÓ de la víctima (4/4 en cada iteración):**

| fichero | `sha256` local | `sha256` en `sink.log` | ¿coincide? |
|---|---|---|---|
| `clientes.csv` | `2ad637b8…d9e6` | `2ad637b8…d9e6` | **SÍ** ✅ |
| `facturas.csv` | `1011daaa…e115` | `1011daaa…e115` | **SÍ** ✅ |
| `nominas.csv` | `b5c25b1a…a810` | `b5c25b1a…a810` | **SÍ** ✅ |
| `contratos.csv` | `279a24d6…1d3f` | `279a24d6…1d3f` | **SÍ** ✅ |

`AUTOMATIZADO=OK (4/4 ficheros exfiltrados sin intervencion)` ⇒ la **automatización** (el fenómeno de
T1020) ocurrió de verdad. `sha256` de los 4 ficheros **idéntico** al enviado.

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 883 | 875 | 875 |
| 2 | 902 | 894 | 894 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 875 | **4** | 607 | 257 | **0** | 7 | 9 | 866 | 0 | 0 |
| 2 | 894 | **4** | 626 | 257 | **0** | 7 | 9 | 885 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 4 | 1 · `{80792}` | 4 (`S1`×4) | 0 |
| 2 | 4 | 1 · `{80792}` | 4 | 0 |

- **una `execve` de `curl` por fichero** (4), `80792`, ancladas al `cwd` del ataque.
- `dudosa` resueltas (6/iter): **PAM `5501/5502`** del operador (`sin_campos`) → **`ruido`**.
  **Ninguna** fila del ataque en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `01:55:29.719Z` `audit_exe=/usr/bin/curl` | **1/1** (`S1`) | 4 / 7 / 257 | 4 / `{80792}` |
| 2 | **sí** | `{80792}` | `01:59:09.085Z` `audit_exe=/usr/bin/curl` | **1/1** | 4 / 7 / 257 | 4 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|4−4|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA020.json`.

## 10. Limitaciones y hallazgos

1. **El HIDS detecta la automatización por el conteo de `execve`** (4 `curl`), no por ver la red.
2. **Distinta de ATA009** (un fichero) y **ATA010** (un canal): aquí el fenómeno es el **bucle**.
3. **C0 sin punto ciego** (`curl`→`80792`). **Realismo acotado** declarado (README §11).

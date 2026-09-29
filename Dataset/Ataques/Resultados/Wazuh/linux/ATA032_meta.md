---
fase: 3
bloque: fase-03-ampliacion-2
tanda: A
ata_id: ATA032
tecnica: T1565.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA032 · T1565.001 Stored Data Manipulation (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda A**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> Objeto: un **ledger simulado** en `lab-legit` (activo en reposo); **no** destructivo.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA032** |
| Técnica | **T1565.001 — Stored Data Manipulation** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) + **`watch`** del ledger (`80790/80781/80791`, efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `sed -i` (replace de un asiento + append de un asiento falso) |
| Efecto | el `sha256` del ledger **antes ≠ después**; marcadores presentes |
| Elevación | **no** |
| Guardarraíl | el objetivo es **exactamente** `lab-legit/finanzas/ledger_2026.csv` |

Artefacto: `.../T1565.001-Stored_Data_Manipulation/ATA032_ataque.sh`
(`sha256=bd5640562e60c36540631cb814efd462c83249f534681bc9a0d6f5ac3a621723`).
Señales: `.../ATA032_esperado.csv` (`sha256=9565e51046b70ba378b0cf03eacf763cddc18ba9eae76538f960161473afa0e6`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA032_logtest.txt` (`sha256=2615829b8d14a5d23a1a161824de857be8186d34fe5ab1b0aab06752e175f962`)
→ `ATA032_preflight.md` (`sha256=4ebb1c417788b2e2755c19976f84c599c93c7dfd68390539d36b13ab7151c9b6`) **PASA**
(1 evento `sed` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T09:25:48Z` | `2026-09-29T09:26:21Z` | 33 s | 1006 | `bd564056…723` |
| 2 | `2026-09-29T09:29:49Z` | `2026-09-29T09:30:21Z` | 32 s | 1009 | `bd564056…723` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA032
bash ATA032_ataque.sh   # 2x sed -i sobre lab-legit/finanzas/ledger_2026.csv
```

## 6. Evidencia

`Logs/ATA032_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el ledger se manipuló de verdad:**

| Iter | sha256 antes | sha256 después | marcadores | `MANIPULACION` |
|---|---|---|---|---|
| 1 | `6888bf39…233a` | `1d2f79b0…5b03d` | presentes | **OK** ✅ |
| 2 | `6888bf39…233a` | `1d2f79b0…5b03d` | presentes | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1012 | 1007 | 1006 |
| 2 | 1015 | 1010 | 1009 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1006 | **2** | 617 | 358 | **0** | 29 | 14 | 992 | 0 | 0 |
| 2 | 1009 | **2** | 617 | 362 | **0** | 28 | 14 | 995 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 2 | 1 · `{80792}` | 2 (`S1` sed) | 0 |
| 2 | 2 | 1 · `{80792}` | 2 | 0 |

- `80792` × 2: los **2 `sed -i`**, **anclados** al `cwd` del ataque (señal `T1565.001-S1` ∧ ancla
  `S2`). **0 sorpresas** (`novel`).
- **`dudosa` resueltas (10/iter):** `80790` (creación de `finanzas` + ledger + ficheros temporales
  `sedXXXX`), `80781` (escrituras) y `80791` (borrado de los temporales `sed`; `sin_ancla`) bajo el
  **`watch`** → **`artefacto`** (efecto). **Ninguna** fila del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `09:25:50.131Z` `audit_exe=/usr/bin/sed` | **1/1** (`S1`) | 2 / 29 / 358 | 2 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `09:29:50.859Z` `audit_exe=/usr/bin/sed` | **1/1** (`S1`) | 2 / 28 / 362 | 2 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|2−2|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA032.json`.

## 10. Limitaciones y hallazgos

1. **El contenido en reposo NO se ve por FIM** (el `syscheck` del agente **no** vigila `lab-legit`):
   el cambio del ledger se ve por el **`watch` de auditd** (`80790/80781/80791`), que se declara
   **`ambigua`** → `artefacto`, **no** detección. La detección efectiva es el **`execve` de `sed`**.
2. **Solapamiento declarado con ATA006/T1565** (misma herramienta `sed -i`): aquí el **objeto** es un
   **activo concreto con integridad** (ledger de finanzas), no un fichero de datos genérico.
3. **`sed -i` deja trazas de su mecánica** (temporales `sedXXXX` creados/borrados): efecto, `artefacto`.
4. **C0 sin punto ciego.** Realismo acotado declarado (README §9).

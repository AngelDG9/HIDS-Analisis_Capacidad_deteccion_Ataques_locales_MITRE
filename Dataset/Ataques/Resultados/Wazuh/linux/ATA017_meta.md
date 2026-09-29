---
fase: 3
bloque: fase-03-ampliacion
tanda: A
ata_id: ATA017
tecnica: T1657
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA017 · T1657 Financial Theft (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda A**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA017** |
| Técnica | **T1657 — Financial Theft** |
| Táctica | Impact (sabotaje/fraude) |
| Sistema | Linux (`victima-linux`) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`; **la detección**) + **`watch`+FIM/audit-file** (efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` |
| Herramientas | **`cat`, `sed`, `cp`** |
| Destino | `/home/angel/lab-legit/libro_cuentas_2026.csv` (modificado, **VIGILADO**) + `cartera_simulada.txt` |
| Salida | `/home/angel/lab-attack/ATA017/collected/` |
| Elevación | **no** |

Artefacto: `.../T1657-Financial_Theft/ATA017_ataque.sh`
(`sha256=c938c1ee56223488d8ba44f09678c75c40e4f680f14d46718030f4bc8fbe4736`, idéntico repo↔víctima).
Señales: `.../ATA017_esperado.csv` (`sha256=d112fdc9c0ffaf4c9378ea90cb3cb90b9255d102bda2a3bb2d00e4a5db35cb02`).
Validación humana: **APROBADO 2026-09-29**.
C0: `ATA017_logtest.txt` (`sha256=5165e0d5ee48beccb91ab16096b25eec75af38f77164130faa6cdccc47f96860`)
→ pre-flight **PASA** (2 eventos, `80792` level 3; sin silenciador).

## 3. Snapshot

Víctima a **`lab-listo`** por iteración (manager **no** revertido). **NAT off**; nada instalado.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA017_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T00:53:14Z` | `2026-09-29T00:53:46Z` | 32 s | 1137 | `c938c1ee…8fbe4736` |
| 2 | `2026-09-29T00:57:43Z` | `2026-09-29T00:58:15Z` | 32 s | 1103 | `c938c1ee…8fbe4736` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA017
bash ATA017_ataque.sh     # sed -i: transf. fraudulenta + altera saldo; cp: sustrae libro y cartera
```

## 6. Evidencia

`Logs/ATA017_iter{1,2}/`. **Prueba de éxito:** `FRAUDE=OK` — aparece la transferencia fraudulenta
(**`TRF-9999`**), el `sha256` del libro cambia y la copia en `lab-attack` es **idéntica**
(`43aa89f3…7d296`); cartera sustraída.

## 7. Ventana extraída

Fichero diario `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (H3); sólo `victima-linux`.

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1137 | **4** | 540 | 567 | **0** | 26 | 1 | 1136 | 0 | 0 |
| 2 | 1103 | **4** | 538 | 536 | **0** | 25 | 1 | 1102 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id`** | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | **4** | 1 · `{80792}` | 2 `sed` (`S1`) + 2 `cp` (`S2`) | 0 |
| 2 | **4** | 1 · `{80792}` | 2 `sed` + 2 `cp` | 0 |

- Todo `80792`, **anclado** por `T1657-S3` a `cwd=/home/angel/lab-attack/ATA017`.
- **`dudosa` resueltas (10/iter) → `artefacto`:** los eventos **`watch`** de la manipulación
  (`80790` *Created*, `80781` *Write*, `80791` *Deleted` de los temporales de `sed -i`) en `lab-legit`
  — **efecto del ataque, NO detección**; **0 a `ruido`**.
- **`artefacto_ataque=26/25`**: 13/14 `execve` automáticos + 10 `watch` humanos + resto.

### 8.2 Métrica — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-29T00:53:17.179Z` `audit_exe=/usr/bin/sed` | **2/2** | **4 / 26 / 567** | 4 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-29T00:57:45.262Z` `audit_exe=/usr/bin/sed` | **2/2** | **4 / 25 / 536** | 4 / `{80792}` |

## 9. Doble iteración (**v2**) — **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ `rule_id` de `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|4−4\| = 0 ≤ 2` |
| C3′ sin `dudosa` | ✅ 0 y 0 |

## 10. Limitaciones y hallazgos

1. **El `watch` SÍ ve la manipulación del libro** (`80790/80781/80791`), pero por la **regla única**
   se cuenta como **`artefacto`** (efecto) y la detección es el **`execve`** (`sed`/`cp`). El HIDS
   **no distingue** contenido financiero: ve «escritura en ruta vigilada», no «fraude».
2. Ninguna fila del ataque en `ruido`; **0** filas ajenas resueltas en esta técnica.
3. Datos de juguete; **ninguna** cuenta financiera real.

## 11. C0

`ATA017_logtest.txt` → **PASA** (`sed`/`cp` → `80792` level 3; sin silenciador).

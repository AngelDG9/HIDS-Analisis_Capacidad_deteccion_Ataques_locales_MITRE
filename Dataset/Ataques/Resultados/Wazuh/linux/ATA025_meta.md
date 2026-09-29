---
fase: 3
bloque: fase-03-ampliacion
tanda: C
ata_id: ATA025
tecnica: T1496.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA025 · T1496.001 Compute Hijacking (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda C**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> Carga de CPU **acotada** (`timeout 10s`, 2 trabajadores); sin procesos colgados.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA025** |
| Técnica | **T1496.001 — Resource Hijacking: Compute** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `timeout` (coreutils) + `yes` |
| Efecto | CPU de la víctima al **100 %** durante la ventana; **0** procesos residuales |
| Elevación | **no** |
| Guardarraíl | `WORKERS ≤ 4`, `DURATION ≤ 15 s`, cada trabajador bajo `timeout`, `trap` que mata remanentes |

Artefacto: `.../T1496.001-Compute_Hijacking/ATA025_ataque.sh`
(`sha256=8dc97e905e50e85135324d695d3b1dfb2f4d37f49f3e9bfc598f8df4df6cdaf4`).
Señales: `.../ATA025_esperado.csv` (`sha256=c69a5dac12aa832b4689665c6f03eba85910189c15732053a3f3d768402945e3`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA025_logtest.txt` (`sha256=048569d51e66db498201590e86062345afb9fb1eb7ea0904a57422659c6f09f9`)
→ `ATA025_preflight.md` (`sha256=f7da05b7202198957d40750682b8180c7f683eb51154fef76030212a5e6b31c2`) **PASA**
(2 eventos `yes`/`timeout` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras 90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T03:35:12Z` | `2026-09-29T03:35:56Z` | 44 s | 1151 | `8dc97e90…daf4` |
| 2 | `2026-09-29T03:38:59Z` | `2026-09-29T03:39:42Z` | 43 s | 1186 | `8dc97e90…daf4` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA025
bash ATA025_ataque.sh     # 2 x (timeout 10s yes >/dev/null)
```

## 6. Evidencia

`Logs/ATA025_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — la CPU se saturó de verdad (medida de `/proc/stat`):**

| Iter | `cpu_busy_pct_durante` | `cpu_busy_pct_despues` | `loadavg` antes→después | `yes` vivos al final | `HIJACK_COMPUTE` |
|---|---|---|---|---|---|
| 1 | **100.0 %** | 88.8 % | `0.71→0.91` | **0** | **OK** ✅ |
| 2 | **100.0 %** | 88.9 % | `0.65→0.86` | **0** | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1161 | 1152 | 1151 |
| 2 | 1196 | 1187 | 1186 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1151 | **9** | 610 | 509 | **0** | 23 | 2 | 1149 | 0 | 0 |
| 2 | 1186 | **8** | 624 | 532 | **0** | 22 | 7 | 1179 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 9 | 1 · `{80792}` | 9 (`timeout` 7 + `yes` 2) | 0 |
| 2 | 8 | 1 · `{80792}` | 8 (`timeout` 7 + `yes` 1) | 0 |

- `timeout`/`yes` **anclados** al `cwd` del ataque (`audit_exe=/usr/bin/timeout`, `/usr/bin/yes`).
- **`dudosa` resueltas:** iter1 → 1 `80792` `sin_ancla` → `artefacto`; 2 `5502` → `ruido`.
  iter2 → 2 `80792` `sin_ancla` → `artefacto`; 5 `5501/5502` → `ruido`. **Ninguna** fila del ataque
  en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `03:35:15.214Z` `audit_exe=/usr/bin/timeout` | **2/2** (`S1,S2`) | 9 / 23 / 509 | 9 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `03:39:01.579Z` `audit_exe=/usr/bin/timeout` | **2/2** | 8 / 22 / 532 | 8 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|8−9|=1 ≤ 2`; sin dudosas. Ver `Bitacora/ATA025.json`.

## 10. Limitaciones y hallazgos

1. **⭐ R9 confirmado de nuevo:** Wazuh **no tiene reglas de CPU/recursos** → **el consumo no se ve**;
   la única detección es el **`execve`**. Si el "robo de cómputo" se hiciera con **builtins del
   shell** (p. ej. un bucle `while :`), **no habría `execve`** → **punto ciego total**.
2. **C0 sin punto ciego.** Carga **acotada** y **0 residuo** (verificado con `pgrep -x yes`).
3. Realismo acotado declarado (README §9).

---
fase: 3
bloque: fase-03-ampliacion-2
tanda: A
ata_id: ATA029
tecnica: T1005
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA029 · T1005 Data from Local System (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda A**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> Técnica **no destructiva** (recolección dirigida de datos de juguete en `lab-legit`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA029** |
| Técnica | **T1005 — Data from Local System** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) + **`watch`** de `lab-legit` (`80790`, efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `cp` (recolección dirigida de una **lista declarada** de 3 ficheros) |
| Efecto | los 3 ficheros de `lab-legit/srv_data/` se copian a `lab-attack/ATA029/loot/` |
| Elevación | **no** |
| Guardarraíl | origen bajo `lab-legit/srv_data`; salida bajo `lab-attack/ATA029`; solo lectura de `lab-legit` |

Artefacto: `.../T1005-Data_from_Local_System/ATA029_ataque.sh`
(`sha256=05719a168d64ef9470a5f77d21790e13c9cc4d2bc3b657db0994381bf3bfee38`).
Señales: `.../ATA029_esperado.csv` (`sha256=a4925402ed671577badd6f330db179e770f31849d8b277dc2effe65902cbcec0`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA029_logtest.txt` (`sha256=0857503711bc5a67f13b13408d29db276e32fb759fc5f2a4bedb5c2dace4b352`)
→ `ATA029_preflight.md` (`sha256=bfa74917e45da4f916ed9833fd3f972dba1cf58a27226ab864af337f1547c404`) **PASA**
(1 evento `cp` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T08:56:28Z` | `2026-09-29T08:57:05Z` | 37 s | 770 | `05719a16…ee38` |
| 2 | `2026-09-29T09:02:07Z` | `2026-09-29T09:02:40Z` | 33 s | 1013 | `05719a16…ee38` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA029
bash ATA029_ataque.sh   # cp de la lista declarada (3 ficheros) a loot/
```

## 6. Evidencia

`Logs/ATA029_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — la recolección se hizo de verdad:**

| Iter | `ficheros_recolectados` | `coincidencias_sha256` | `RECOLECCION` |
|---|---|---|---|
| 1 | 3/3 | 3/3 | **OK** ✅ |
| 2 | 3/3 | 3/3 | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 776 | 771 | 770 |
| 2 | 1020 | 1014 | 1013 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 770 | **3** | 622 | 119 | **0** | 26 | 4 | 766 | 0 | 0 |
| 2 | 1013 | **3** | 619 | 358 | **0** | 33 | 13 | 1000 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 3 | 1 · `{80792}` | 3 (`S1` cp) | 0 |
| 2 | 3 | 1 · `{80792}` | 3 | 0 |

- `80792` × 3: los **3 `cp`** de la recolección dirigida, **anclados** al `cwd` del ataque (señal
  `T1005-S1` ∧ ancla `S2`). **0 sorpresas** (`novel`).
- **`dudosa` resueltas (4/iter):** `80790` (creación de `srv_data` + los 3 ficheros) bajo el
  **`watch`** de `lab-legit` → **`artefacto`** (efecto/semilla, no detección). **Ninguna** fila del
  ataque en `ruido`.
- **`artefacto_ataque` (auto):** los `execve` **no declarados** de la propia mecánica
  (`mkdir`/`cat`/`sha256sum`/`awk`/`ls`, cwd del ataque) + las escrituras del material.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `08:56:29.062Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 3 / 26 / 119 | 3 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `09:02:08.978Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 3 / 33 / 358 | 3 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|3−3|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA029.json`.

## 10. Limitaciones y hallazgos

1. **«Leer no deja rastro» confirmado.** El `watch` de `lab-legit` es `-p wa`; **leer** no alerta.
   La técnica se detecta por el **`execve` del lector** (`cp`), **no** por el acceso a los datos.
2. **Detección solo por `execve`** (un único `rule_id`, `80792`): el HIDS de host no ve la
   «recolección» como tal, sino el proceso. Coherente con R9.
3. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
4. **Solapamiento declarado:** la detección de `cp` es la misma familia que en ATA014 (copia de
   material); aquí el valor es la **recolección dirigida por lista** y el refuerzo de la lección
   «leer no deja rastro».

---
fase: 3
bloque: fase-03-ampliacion-2
tanda: A
ata_id: ATA030
tecnica: T1560.001
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA030 · T1560.001 Archive via Utility (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda A**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Contraste científico con ATA013/T1560.002** (archivo por **librería** con `python3` → **NO
> detectado** por el punto ciego de fábrica `92600`): la **misma acción** con **utilidad** sí alerta.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA030** |
| Técnica | **T1560.001 — Archive via Utility** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** de la utilidad (`80792`: `tar` + `gzip`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `tar -czf` (invoca `gzip`) sobre el material recolectado |
| Efecto | `collected_ATA030.tar.gz` creado y con los 3 ficheros del material |
| Elevación | **no** |
| Guardarraíl | material y archivo **solo** bajo `lab-attack/ATA030` |

Artefacto: `.../T1560.001-Archive_via_Utility/ATA030_ataque.sh`
(`sha256=b47fc87deaa56274c3bbd67edf69d64cde269a361ccac27827a4ff9b21e7bcfe`).
Señales: `.../ATA030_esperado.csv` (`sha256=301791d67241b6fae8a68eb0a72a71300c4a4ceda2e384d605e80ca81b85f0f0`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA030_logtest.txt` (`sha256=cd5b9264ce7ca127e6fac58227e6c610f61fe8e40561e9fbb2cd2acb33bc08fd`)
→ `ATA030_preflight.md` (`sha256=f7c4c170cf08a5447166f5e5902a5d5a262796fc0f9bdd0a62a57f49a8d41a0b`) **PASA**
(2 eventos `tar`/`gzip` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T09:07:17Z` | `2026-09-29T09:07:49Z` | 32 s | 1018 | `b47fc87d…cfe` |
| 2 | `2026-09-29T09:12:29Z` | `2026-09-29T09:13:01Z` | 32 s | 992 | `b47fc87d…cfe` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA030
bash ATA030_ataque.sh   # tar -czf collected_ATA030.tar.gz ... + tar -tzf (verificación)
```

## 6. Evidencia

`Logs/ATA030_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el archivo se creó de verdad:**

| Iter | `miembros_de_datos` | `tar -tzf` | sha256 del `.tar.gz` | `ARCHIVADO` |
|---|---|---|---|---|
| 1 | 3 | 3 ficheros del material | `a74c798b…52e0` | **OK** ✅ |
| 2 | 3 | 3 ficheros del material | `179cec18…fd2e` | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1024 | 1019 | 1018 |
| 2 | 998 | 993 | 992 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1018 | **12** | 641 | 345 | **0** | 20 | 11 | 1007 | 0 | 0 |
| 2 | 992 | **12** | 619 | 341 | **0** | 20 | 10 | 982 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 12 | 1 · `{80792}` | 12 (9 `tar` + 3 `gzip`) | 0 |
| 2 | 12 | 1 · `{80792}` | 12 (9 `tar` + 3 `gzip`) | 0 |

- `80792` × 12/iter: **`tar`** (incluye el proceso de archivado y los hijos/re-ejecuciones de `tar`
  durante `-czf`/`-tzf`) + **`gzip`** (invocado por `tar -z`), **anclados** al `cwd` del ataque
  (señales `S1`/`S2` ∧ ancla `S3`). **0 sorpresas** (`novel`).
- **`dudosa` resueltas:** **1/iter** `80790` (creación del `.tar.gz` bajo el watch) → **`artefacto`**;
  **8/iter (iter1) y 7/iter (iter2)** de PAM `5501/5502` → **`ruido`** (login del operador).
- **`artefacto_ataque` (auto):** los `execve` no declarados de la mecánica (`mkdir`/`cat`/`rm`/
  `sha256sum`/`grep`/`echo`…) y sus escrituras.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `09:07:19.006Z` `Audit: Command: /usr/bin/tar` | **2/2** (`S1`,`S2`) | 12 / 20 / 345 | 12 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `09:12:30.865Z` `Audit: Command: /usr/bin/tar` | **2/2** (`S1`,`S2`) | 12 / 20 / 341 | 12 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|12−12|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA030.json`.

## 10. Limitaciones y hallazgos

1. **⭐ La elección de herramienta decide la detección.** El **mismo objetivo** («archivar lo
   recolectado») es:
   - **INVISIBLE** si se hace por **librería** con `python3` (**ATA013/T1560.002**, punto ciego
     de fábrica **`92600`**), y
   - **VISIBLE** si se hace con **utilidad de línea de órdenes** (`tar`/`gzip`, **ATA030**).
   Es el **contraste científico** del trío de archivo (utility / library / custom).
2. **Detección por `execve`** (un único `rule_id`, `80792`), como en el resto del corpus (R9).
3. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
4. **PAM del operador a `ruido`** (criterio ratificado): ver §11.

## 11. Filas `ruido` (para ratificación) — PAM del login del operador

- **iter1: 8 filas** `5501`/`5502`; **iter2: 7 filas** `5501`/`5502` — sesiones **PAM del login del
  operador** (las conexiones `ssh` de la ventana), **ajenas al ataque** y sin `cwd`/ruta del ataque.
  Se pliegan a **`ruido`** por el criterio **ya ratificado (2026-09-28): PAM del login = `ruido`**.
- **Ninguna** fila del ataque cae en `ruido` (verificado: `ruido_con_lab-attack=0`).

---
fase: 3
bloque: fase-03-escalado
tanda: A
ata_id: ATA005
tecnica: T1561
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-28
---

# Ficha — ATA005 · T1561 Disk Wipe (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda A**, 3.º de 4). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada.
> **Simulación segura:** nunca se toca un disco real (guardarraíles en el guion).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA005** |
| Técnica | **T1561 — Disk Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART no tiene pruebas para T1561) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramientas | **`dd`** (sobrescritura in-situ) + **`shred -n 1 -z -u`** |
| Objetivo | `/home/angel/lab-attack/ATA005/` (`backup_completo_2026-09.bin`, **NO vigilado**) |
| Elevación | **no** |
| Guardarraíles | destino **solo** bajo `lab-attack/ATA005/`; **nunca** un dispositivo (`-b`/`-c` → aborta) |

Artefacto: `Dataset/Ataques/Comandos/T1561-Disk_Wipe/ATA005_ataque.sh`
(`sha256=58a2bddb48dc8871d122869bf1a370c6aff7100880d75c1d4e9f0937059b5658`).
Señales esperadas: `.../ATA005_esperado.csv`
(`sha256=f048ecf572b568316ded3145a6f4afeba3782c13c68b80692c2042a33a063991`).
Validación humana (CA1): **APROBADO 2026-09-28**.
C0: `Soporte/Ataques/c0/ATA005_logtest.txt`
(`sha256=58ea13da1b2dacfb244ff0bfa496292ae0a117cac94202c5494be178a5bd225c`)
→ pre-flight **PASA** (2 eventos `dd`/`shred`, ambos `80792` level 3; **sin** silenciador).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras ≥ 90 s de asentamiento (H2).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA005_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T21:34:35Z` | `2026-09-28T21:35:06Z` | 31 s | 695 | `58a2bddb…9b5658` |
| 2 | `2026-09-28T21:38:34Z` | `2026-09-28T21:39:05Z` | 31 s | 712 | `58a2bddb…9b5658` |

Reloj víctima↔manager < 1 s; `t0 < t1` en ambas.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA005
bash ATA005_ataque.sh      # dd if=/dev/zero (32 MiB) ; dd if=/dev/urandom conv=notrunc ; shred -n 1 -z -u
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA005_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `ps_despues.txt`, `sha256_artefacto.txt`.

**Prueba de éxito:** `sha256` **antes ≠ después** con el **tamaño estable** (33.554.432 B) ⇒
**`WIPE=OK`** en ambas iteraciones (contenido sobrescrito, tamaño intacto).

| Iter | sha256 antes | sha256 después |
|---|---|---|
| 1 | `83ee4724…8c4302` | `b4bfb6c3…ba2c70` |
| 2 | `83ee4724…8c4302` | `a95032d5…52435d` |

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros | Detalle final |
|---|---|---|---|---|
| 1 | 701 | 695 | 6 | **695** |
| 2 | 718 | 712 | 6 | **712** |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 695 | **3** | 603 | 51 | **0** | **38** | 1 | 694 | 0 | 0 |
| 2 | 712 | **3** | 622 | 49 | **0** | **38** | 2 | 710 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **3** | 1 · `{80792}` | 3 (`T1561-S1`×2, `T1561-S2`) | 0 |
| 2 | **3** | 1 · `{80792}` | 3 (`T1561-S1`×2, `T1561-S2`) | 0 |

- Las **3 alertas** son los `execve` de **`dd` ×2** (creación + sobrescritura) y **`shred` ×1**,
  `80792` (`audit_command`), anclados a `cwd=/home/angel/lab-attack/ATA005` por `T1561-S3`.
- **`dudosa` resueltas:** 23/iter — los eventos **`watch` de `shred`** (`80791` *Deleted*, `80780`
  *Write*) sobre ficheros **dentro de la carpeta del ataque** → **`artefacto`** (son el ataque, no la
  detección declarada; **nunca `ruido`**). Más `5502` del operador (1 en iter1, 2 en iter2) → **`ruido`**.
- **`artefacto_ataque=38`/iter** = 15 automáticos + 23 humanos.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T21:34:37.165Z` `audit_exe=/usr/bin/dd` | **2/2** (`S1`/`S2`) | **3 / 38 / 51** | 3 alertas / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T21:38:34.685Z` `audit_exe=/usr/bin/dd` | **2/2** (`S1`/`S2`) | **3 / 38 / 49** | 3 alertas / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|3−3\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 603 vs 622 → Δ=19 (aviso) |
| Sanidad `ruido_conocido` (aviso) | ✅ 51 vs 49 → Δ=2 |

## 10. Limitaciones y hallazgos

1. **Simulación segura:** el wipe se aplica a un **fichero de juguete** (copia de seguridad
   simulada), **nunca** a un disco real. Guardarraíles verificados en el guion.
2. **Ruido de `shred`:** `shred` genera **muchos** `watch` (re-escrituras + `rename`), todos en la
   carpeta del ataque → `artefacto` (23/iter). No cuentan como detección.
3. **C0 sin punto ciego** (`dd`/`shred` → `80792`). **Realismo acotado** declarado (README §11).

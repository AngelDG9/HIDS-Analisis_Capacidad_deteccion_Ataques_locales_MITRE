---
fase: 3
bloque: fase-03-escalado
tanda: B
ata_id: ATA011
tecnica: T1074
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA011 · T1074 Data Staged (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda B**, 1.º de 3). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Simulación segura:** todo ocurre en el directorio **NO vigilado** `/home/angel/lab-attack/ATA011/`;
> **no** se toca `lab-legit`, ni el sistema real.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA011** |
| Técnica | **T1074 — Data Staged** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (la prueba ART de T1074 en Linux descarga de GitHub → no ejecutable sin NAT) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`audit_command`, regla `80792`, RS2) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramientas | **`mkdir`, `cp`, `sha256sum`** (coreutils) |
| Objetivo | `recoleccion/` → `staging/` (reunir + manifiesto `sha256`), todo en `/home/angel/lab-attack/ATA011/` |
| Elevación | **no** |
| Guardarraíl | el destino **DEBE** quedar bajo `lab-attack/ATA011` (aborta si no) |

Artefacto: `Dataset/Ataques/Comandos/T1074-Data_Staged/ATA011_ataque.sh`
(`sha256=57fa2e9aa497b224707e5b1e49130419435ebd3e4e8bc6084c8fa5153a4e0e58`, idéntico repo↔víctima).
Señales esperadas: `.../ATA011_esperado.csv`
(`sha256=72c83b9eef0afdfdbf46b70203f8bfd411b37590f12ae46b021f0498ec529f06`).
Validación humana (CA1): **APROBADO 2026-09-29** (firma en su cabecera).
C0: `Soporte/Ataques/c0/ATA011_logtest.txt`
(`sha256=0db202ee329fd132945c7f9040fe59c52aa576763a26ab404eada7161b290bc2`)
→ pre-flight `ATA011_preflight.md` **PASA** (2 eventos: `mkdir` y `cp` → `80792` level 3; **sin** silenciador).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. Ventana `[t0,t1]` con `t0` sellado **tras 95 s de
  asentamiento** (H2) en una **única sesión SSH** (todo el churn de login queda **antes** de `t0`).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA011_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T23:03:10Z` | `2026-09-28T23:03:52Z` | 42 s | 645 | `57fa2e9a…4e0e58` |
| 2 | `2026-09-28T23:07:57Z` | `2026-09-28T23:08:38Z` | 41 s | 634 | `57fa2e9a…4e0e58` |

`t0 < t1` en ambas; `T1_LOCAL` del guion (`…:12Z`, `…:58Z`) **≠ T0** (no degenerado). Reloj
víctima↔manager `|Δ| < 1 s`.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA011
bash ATA011_ataque.sh      # mkdir recoleccion/ + mkdir staging/ + cp ×3 + manifiesto sha256
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA011_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, `efecto.txt`.

**Prueba de éxito (independiente de la alerta):** el `staging/` contiene **3 ficheros** y el
**manifiesto `sha256`** se **revalida** (`sha256sum -c` → los 3 `OK`) ⇒ los datos quedaron **reunidos
y listos** para exfiltrar. Los `sha256` de los 3 CSV son **idénticos** entre iteraciones
(determinismo de los datos de juguete).

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final |
|---|---|---|---|---|
| 1 | 652 | 645 | 7 | **645** |
| 2 | 642 | 634 | 8 | **634** |

## 8. Resultado (conteos por categoría)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 645 | **5** | 630 | 1 | **0** | **9** | 0 | 644 | 0 | 0 |
| 2 | 634 | **5** | 618 | 1 | **0** | **10** | 0 | 634 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **5** | 1 · `{80792}` | 2 (`S1`, `S2`) | 0 |
| 2 | **5** | 1 · `{80792}` | 2 (`S1`, `S2`) | 0 |

- Las **5 alertas** de cada ventana son los **`execve` anclados** del guion: **2 `mkdir`** (`S1`:
  `recoleccion/` y `staging/`) y **3 `cp`** (`S2`), todos `80792` (`audit_command`), anclados a
  `cwd=/home/angel/lab-attack/ATA011` por `T1074-S3`. **`rule_id` distintos = 1**.
- **`artefacto_ataque`** (9/10): `execve` no declarados con `cwd` bajo la carpeta del ataque
  (`date`, `sha256sum`, `chmod`, `ls`… del propio guion). **Ninguna fila del ataque en `ruido`** (CA5).
- **`dudosa` = 0** → **no se genera `-Revision.csv`** (no hay veredictos humanos que plegar).

### 8.2 Métrica de detección — **O1 + O2** (métrica congelada)

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo: alertas / `rule_id` distintos |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T23:03:11.709Z` `audit_exe=/usr/bin/mkdir` | **2/2** (`S1`,`S2`) | **5 / 9 / 1** | 5 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T23:07:57.902Z` `audit_exe=/usr/bin/mkdir` | **2/2** (`S1`,`S2`) | **5 / 10 / 1** | 5 / `{80792}` |

> O2 = señales de **acción** (`audit_exe`) del `esperado` ancladas ≥1 vez / total: **2/2**
> (`mkdir`, `cp`). El ancla `T1074-S3` (`audit_cwd`) es el mecanismo de anclaje, **no** una acción.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|5−5\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 630 vs 618 → Δ=12 (aviso) |
| Sanidad `ruido_conocido` (aviso) | ✅ 1 vs 1 → Δ=0 |

## 10. Limitaciones y hallazgos

1. **Sin señales `ambigua`** (el ataque no escribe bajo *watch*): se evitó el efecto colateral de
   ATA003 (una `ambigua` amplia por `rule_group` capturaba *churn* ajeno). **0 `dudosa`**.
2. **Solapamiento declarado** con ATA012/T1119 (recolectar) y ATA013/T1560 (archivar): aquí la acción
   característica es **reunir** (`mkdir`+`cp`) sin `find` masivo ni compresión. Ver README §9.
3. **C0 sin punto ciego** (`mkdir`/`cp` → `80792` level 3). **Realismo acotado** declarado (README §11).
4. **Instrumentación t0/t1 (tanda B):** una **única sesión SSH** por ventana evita la rareza del lote
   anterior (`T1_LOCAL == T0` y oficial +31/+40 s): aquí `T1_LOCAL > T0` y el `t1` oficial se sella
   tras el scan FIM. **0 `dudosa`** (no reaparecen las PAM del operador dentro de la ventana).

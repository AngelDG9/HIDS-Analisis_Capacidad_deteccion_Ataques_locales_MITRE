---
fase: 3
bloque: fase-03-ampliacion
tanda: A
ata_id: ATA014
tecnica: T1114
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA014 · T1114 Email Collection (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda A**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Ejecutado con la **métrica
> congelada** (`_fases/fase-03-metrica/change-doc.md`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA014** |
| Técnica | **T1114 — Email Collection** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2; **la detección**) + `watch` (escritura en `lab-legit`; **efecto**) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG; ART no trae prueba Linux utilizable sin red) |
| Herramientas | **`cat`, `grep`, `cp`** |
| Objetivo | buzón mbox **simulado** `/home/angel/lab-legit/mailbox_angel_2026.mbox` (**VIGILADO**) |
| Salida | `/home/angel/lab-attack/ATA014/collected/` |
| Elevación | **no** |

Artefacto: `Dataset/Ataques/Comandos/T1114-Email_Collection/ATA014_ataque.sh`
(`sha256=6030024e1270018be58a207a72eba758584f9aa11b5c220b05e31e51f4fe94e9`, idéntico repo↔víctima).
Señales: `.../ATA014_esperado.csv` (`sha256=d95d63d0a8ebadabdc3f54ca2dd8d545f53cd81f9463af966acf78d8062df0d1`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `Soporte/Ataques/c0/ATA014_logtest.txt`
(`sha256=caa5adf517d52c846f0eb322a20bec9db763a65d4530e1af629112697dd13f70`) → pre-flight
`ATA014_preflight.md` **PASA** (2 eventos, ganadoras `80792` level 3; **sin** silenciador).

## 3. Snapshot

Víctima revertida a **`lab-listo`** antes de cada iteración (el **manager NO** se revierte).
**NAT desconectado**; no se instaló nada. `t0` tras ≥ 90 s de asentamiento (H2).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA014_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T00:30:17Z` | `2026-09-29T00:30:49Z` | 32 s | 949 | `6030024e…4fe94e9` |
| 2 | `2026-09-29T00:35:39Z` | `2026-09-29T00:36:11Z` | 32 s | 965 | `6030024e…4fe94e9` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA014
bash ATA014_ataque.sh     # siembra el mbox en lab-legit, lo busca (grep) y lo copia (cp)
```

## 6. Evidencia

`Logs/ATA014_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `sha256_artefacto.txt`.

**Prueba de éxito (independiente de la alerta):** `RECOLECCION=OK` en ambas iteraciones — el buzón
tiene **3 mensajes** y la copia en `lab-attack` conserva el **mismo `sha256`**
(`7108682b…a1`) que el original ⇒ los mensajes se recolectaron **de verdad**.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux` (todas las filas del Detalle).

## 8. Resultado (conteos por categoría, veredicto plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 949 | **3** | 541 | 390 | **0** | 15 | 1 | 948 | 0 | 0 |
| 2 | 965 | **3** | 540 | 407 | **0** | 15 | 1 | 964 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **3** | 1 · `{80792}` | 2 `grep` + 1 `cp` (`T1114-S1`,`T1114-S2`) | 0 |
| 2 | **3** | 1 · `{80792}` | 2 `grep` + 1 `cp` | 0 |

- Las 3 alertas son **`execve`** de `grep` (extracción) y `cp` (copia), `80792` (`audit_command`),
  **ancladas** a `cwd=/home/angel/lab-attack/ATA014` por `T1114-S3`.
- **`dudosa` resueltas (11/iter):** **10 a `ruido`** (`grep` de `update-motd.d` con `cwd=/`, disparado
  por el **login SSH del operador**; ajeno al ataque — criterio ya ratificado 2026-09-28) + **1 a
  `artefacto`** (creación del buzón bajo `watch`, `80790`, **efecto** del ataque).
- **`artefacto_ataque=15`**: árbol de `execve` no declarado en la carpeta del ataque (`bash`,
  `sha256sum`…) + la escritura `watch` del buzón. **Ninguno** en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2** (métrica congelada)

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-29T00:30:19.066Z` `audit_exe=/usr/bin/grep` | **2/2** (`S1`,`S2`) | **3 / 15 / 390** | 3 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-29T00:35:41.282Z` `audit_exe=/usr/bin/grep` | **2/2** | **3 / 15 / 407** | 3 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|3−3\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 541 vs 540 → Δ=1 |
| Sanidad `ruido_conocido` (aviso) | ⚠️ 390 vs 407 → Δ=17 (aviso; churn de login) |

## 10. Limitaciones y hallazgos

1. **La LECTURA del buzón no es visible al HIDS:** `auditd` vigila `lab-legit` con `-p wa`
   (**escritura/atributos**), **no lecturas** → la técnica se detecta por el **`execve` del lector**
   (`grep`) y del copiador (`cp`), no por «acceso a fichero». Hallazgo honesto para la memoria.
2. **`sin_ancla` sistemático del churn de login:** como `grep` es una señal declarada, los `grep`
   de `/etc/update-motd.d` que corren **al iniciar la sesión SSH del operador** (`cwd=/`) caen a
   `dudosa` y se resuelven a **`ruido`** (10/iter). Es el efecto H-A/H-B ya conocido.
3. Datos de juguete con nombres creíbles; **realismo acotado** declarado (README §9, runbook §10).
4. **C0 sin punto ciego** (`grep`/`cp` → `80792` level 3).

---

## § Repetición auditada (rev)

> Bloque `fase-03-repeticiones` (tandas R1+R2), **2026-10-01**. `esperado_rev` firmado **APROBADO 2026-10-01 (validación humana)** ANTES del primer `t0`. Añadido por `tfg-executor`. **Sin secretos.**

### Motivo

- **`motivo_repeticion` = `prestaging`.** Auditoría: ATA014 sembraba el buzón mbox DENTRO de [t0,t1] (la siembra no es la técnica) — obs. §C (`criterio_ataques.md`).

### Qué cambió respecto al original (el original NO se toca)

- **Método original:** propio: siembra del mbox + recolección (grep/cp) en la MISMA ventana.
- **Método de la repetición:** propio: siembra del mbox ANTES de t0; la ventana mide SOLO la recolección (grep/cp).
- **ART:** no aplica (motivo de pre-staging; el método es propio, sin cambio de mecanismo).
- **Material antes de `t0`:** buzón mbox simulado (`mailbox_angel_2026.mbox`, 3 mensajes) sembrado en `lab-legit` ANTES de t0.

### Iteraciones (rev)

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | auto_ruido | ruido_conocido | artefacto_ataque | dudosa |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-01T19:38:54Z` | `2026-10-01T19:39:27Z` | 835 | **3** | 603 | 218 | 11 | 0 |
| 2 | `2026-10-01T19:42:40Z` | `2026-10-01T19:43:13Z` | 845 | **3** | 613 | 218 | 11 | 0 |

### Resultado (métrica congelada O1+O2)

- **O1 (detectado):** sí — `rule_id` = `['80792']`.
- **O2 (acciones cubiertas):** iter1 = 2/2 · iter2 = 2/2.
  - iter1 primera evidencia: `2026-10-01T19:38:55.974Z` `audit_exe=/usr/bin/grep`.
  - iter2 primera evidencia: `2026-10-01T19:42:42.381Z` `audit_exe=/usr/bin/grep`.
- **Doble iteración (v2):** `iguales` (mismo `rule_id` de detección; recuento estable; sin dudosas).
- **`dudosa` resueltas:** iter1: ruido=10 · iter2: ruido=10.
- **0 filas del ataque en `ruido`** (verificado por la pertenencia por carpeta).

### Prueba de efecto (independiente de la alerta)

- iter1: RECOLECCION=OK (3 mensajes; copia sha256 idéntica).
- iter2: RECOLECCION=OK (3 mensajes; copia sha256 idéntica).

### Trazabilidad

- `esperado_rev`: `Dataset/Ataques/Comandos/T1114-Email_Collection/ATA014_esperado_rev.csv` (`sha256=a4b724b64a85938e8c96fd493d36bd027bc1624f57534dff8acf9046e34ac72c`).
- `ataque_rev`: `Dataset/Ataques/Comandos/T1114-Email_Collection/ATA014_ataque_rev.sh` (`sha256=52e4512e092d735aa1ff92e48ae68c74389b130c35aecd2d473cfe8905763adb`).
- C0: `Soporte/Ataques/c0/ATA014_rev_logtest.txt` + `ATA014_rev_preflight.md` (**PASA**, sin silenciadores).
- Detalle: `Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA014_rev1-Detalle.csv` · `Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA014_rev2-Detalle.csv`.
- Auditado: `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA014_rev1-Audited.csv` · `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA014_rev2-Audited.csv`.
- **Nuevo esperado SIN las señales `ambigua` de la siembra (ya no cae en la ventana).**


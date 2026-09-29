---
fase: 3
bloque: fase-03-ampliacion
tanda: B
ata_id: ATA021
tecnica: T1029
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA021 · T1029 Scheduled Transfer (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda B**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Cron de usuario** (`angel`), **sin `sudo`**; la entrada se **retira** al terminar la ventana.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA021** |
| Técnica | **T1029 — Scheduled Transfer** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** (crontab de usuario) |
| Capa del HIDS | **`execve`** (`80792`, RS2) + `watch` de fábrica sobre `/var/spool/cron` (80791/80782) + syslog (`2832`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramientas | **`crontab`** (instala/retira) + **`bash`/`curl`** (job ejecutado por cron) |
| Efecto | `POST /api/scheduled/dato_programado.csv` al receptor (disparado por cron **dentro** de `[t0,t1]`) |
| Elevación | **no** |
| Guardarraíl | aborta si ya existe un crontab; **solo** el crontab de `angel`; **retira** la entrada al final |

Artefacto: `.../T1029-Scheduled_Transfer/ATA021_ataque.sh`
(`sha256=06d21fec27b0ee1d4d48947046e5955fc77618398830c4ec47b71ee01e34cf54`) + `cron_job.sh`
(`sha256=d65bd1f2bc814163ac5e43a2e64bc24ded6a0efef49758eb314daf75a00b0635`).
Señales: `.../ATA021_esperado.csv` (`sha256=75499e0a7f399a44816431cde4911f67ad4915b90d5ffe54786363113efd1e08`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA021_logtest.txt` (`sha256=0a5d712ae40d77ccb6a1b206f0abf254744e3706161ae7ae4dc804ec5c1ee572`)
→ `ATA021_preflight.md` (`sha256=88127a5690c79fb4d887064660d23cf5aa94d44c43f02fbda76dd4b4634ac8e6`) **PASA**
(`crontab`/`curl`/`dash` → `80792` level 3; línea `CRON`→`1002`; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **Receptor** HTTP 9090 (+TCP 9091) levantado **antes de `t0`** y parado tras `t1`; **sin regla
de firewall**.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | disparo cron | sha256 ataque |
|---|---|---|---|---|---|---|
| 1 | `2026-09-29T02:10:12Z` | `2026-09-29T02:11:33Z` | 81 s | 959 | `2026-09-29T02:11:01Z` | `06d21fec…cf54` |
| 2 | `2026-09-29T02:15:27Z` | `2026-09-29T02:16:34Z` | 67 s | 930 | `2026-09-29T02:16:01Z` | `06d21fec…cf54` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA021
bash ATA021_ataque.sh     # instala cron -> espera el disparo -> retira la entrada
# crontab: "* * * * * cd /home/angel/lab-attack/ATA021 && /bin/bash ./cron_job.sh >/dev/null 2>&1"
```

## 6. Evidencia

`Logs/ATA021_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito — la transferencia PROGRAMADA ocurrió dentro de la ventana:**

| Iter | `sink.log` del HOST | `fired.ok` (job) | ¿en `[t0,t1]`? |
|---|---|---|---|
| 1 | `POST /api/scheduled/dato_programado.csv from=192.168.65.129 len=113 sha256=0916137c…309b` | `2026-09-29T02:11:01Z` | **SÍ** ✅ |
| 2 | `POST /api/scheduled/dato_programado.csv from=192.168.65.129 len=113 sha256=0916137c…309b` | `2026-09-29T02:16:01Z` | **SÍ** ✅ |

`TRANSFERENCIA_PROGRAMADA=OK` en ambas; `sha256` del dato **idéntico** al enviado.

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 967 | 959 | 959 |
| 2 | 938 | 930 | 930 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 959 | **6** | 628 | 259 | **0** | 66 | 11 | 948 | 0 | 0 |
| 2 | 930 | **6** | 611 | 261 | **0** | 52 | 11 | 919 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 6 | 1 · `{80792}` | 5 `crontab` (`S1`) + 1 `curl` (`S2`) | 0 |
| 2 | 6 | 1 · `{80792}` | 5 `crontab` + 1 `curl` | 0 |

- `crontab` (instalar/verificar/retirar) y `curl` (job de cron) → `80792`, **anclados** al `cwd` del ataque.
- **`dudosa` resueltas (77/iter → reparto real por iteración: `ruido` 73 + `artefacto` 4):**
  **66 `dash`** de **login/churn** → `ruido`; **1 `dash` (el lanzador de cron)** → `artefacto`;
  **7 PAM del operador (`5501`/`5502`) → `ruido` SIEMPRE** (criterio **ratificado 2026-09-28**:
  es el churn del login SSH y **no es demostrable** que sean del ataque, aunque caigan pegadas al
  disparo de cron); **2× `80791`** (borrado en `/var/spool/cron`, efecto del `crontab`) →
  `artefacto`; **1× `2832`** (*Crontab entry changed*, syslog) → `artefacto`.
  **Reparto por iteración:** **i1 = 73 `ruido` + 4 `artefacto` · i2 = 73 `ruido` + 4 `artefacto`**
  (global **`ruido` 146 / `artefacto` 8**, cuadra con `Bitacora/ATA021.json` `revision_global`).
  **Ninguna** fila del ataque en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `02:10:14.991Z` `audit_exe=/usr/bin/crontab` | **2/2** (`S1`,`S2`) | 6 / 66 / 259 | 6 / `{80792}` |
| 2 | **sí** | `{80792}` | `02:15:29.380Z` `audit_exe=/usr/bin/crontab` | **2/2** | 6 / 52 / 261 | 6 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|6−6|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA021.json`.

## 10. Limitaciones y hallazgos ⭐

1. **⭐ La capa syslog/journald de cron SÍ aporta una detección extra NO esperada:** la regla de fábrica
   **`2832`** (*Crontab entry changed*, nivel 5) alertaría sobre el mensaje `REPLACE` de `crontab -`.
   No se declaró en el `esperado` (se redactó antes) → se pliega como **`artefacto_ataque`** (es del
   ataque, no es la detección declarada). Contradice el C0 optimista: el C0 probó una *línea CMD de
   cron* (`program_name=CRON`, que **no** casa), pero el **mensaje `REPLACE`** de `crontab` sí casa.
2. **`/var/spool/cron/crontabs` SÍ genera eventos `watch`** de fábrica (`80791` *Deleted*, `80782`
   *Write*) — la capa de persistencia de cron **no está ciega** como se hipotetizó.
3. **El lanzador `/bin/sh` de cron** (`dash`, `cwd=$HOME`) se declaró **`ambigua`** → `dudosa` →
   veredicto humano (`artefacto`), para no dejarlo caer en `ruido` (guardarraíl). Coste: 66-67 `dash`
   del **login del operador** caen a `dudosa` y se resuelven a `ruido` (criterio ratificado).
4. **C0 reconfirmado** (`crontab`/`curl`/`dash` → `80792`). **Realismo acotado** declarado (README §11).

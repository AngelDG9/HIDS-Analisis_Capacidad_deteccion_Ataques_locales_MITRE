---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA004
tecnica: T1489
tactica: Impact
version: 2
status: cerrado
fecha: 2026-09-26
---

# Ficha — ATA004 · T1489 Service Stop (Linux / `victima-linux`)

> Bloque `fase-03-piloto-custom` (control **de ART**). Generada por `tfg-executor`. **Sin
> secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA004** |
| Técnica / subtécnica | **T1489** Service Stop |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **ART** (control) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Prueba ART | *Linux - Stop service using systemctl* |
| GUID | `42e3a5bd-1e45-427f-aa08-2a65fa29a820` |
| Path en el clon | `atomics/T1489/T1489.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Herramienta | `systemctl` (`/usr/bin/systemctl`) |
| Servicio | **`cron`** (activo/enabled en `lab-listo`) |
| Elevación | **sí** — el ejecutor lanza el script **ya elevado**: `echo '<contraseña del laboratorio>' \| sudo -S bash ATA004_ataque.sh` (**solo stdin**, cero secretos en el artefacto; **sin** `sudo` anidado) |

Artefacto: `Dataset/Ataques/Comandos/T1489-Service_Stop/ATA004_ataque.sh`
(`sha256=b6d8090857d26daed6817ce765dea10a0e845757cdcc47bbee95628823256755`, idéntico repo↔víctima).
Señales esperadas: `.../ATA004_esperado.csv`
(`sha256=a4a53a3c3c4032d312e26c794164d02870354c9409dcae63bcb6d62552c98341`).
Validación humana (CA5): **2026-09-26**.
C0: `Soporte/Ataques/c0/ATA004_logtest.txt` (`sha256=1176b82b922e609901be08bf1a9798c70396f1d7505efb2204539ede5732133b`)
→ pre-flight **PASA** (C0, `n=1` evento `systemctl`, **sin silenciadores de fábrica**).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | estado `cron` | sha256 `ATA004_ataque.sh` |
|---|---|---|---|---|---|---|
| 1 | `2026-09-26T12:34:39Z` | `2026-09-26T12:35:15Z` | 36 s | 751 | active → **inactive** | `b6d80908…56755` |
| 2 | `2026-09-26T12:39:50Z` | `2026-09-26T12:40:26Z` | 36 s | 738 | active → **inactive** | `b6d80908…56755` |

`t0 < t1` en ambas. Reloj víctima↔manager < 1 s. `t0` sellado tras el asentamiento (H2).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA004
echo '<contraseña del laboratorio>' | sudo -S bash ATA004_ataque.sh   # una sola elevación
# dentro: systemctl is-active cron ; systemctl stop cron ; systemctl is-active cron
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA004_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`.

> **Nota (`fase-03-cabos`, 2026-09-28):** este bloque **no** generó `sha256_artefacto.txt` (el fichero
> no existe en ninguno de los 6 directorios de `Logs/`; solo lo generó el piloto). El `sha256` del
> script consta en §2 y en `Bitacora/ATA004.json` (`ataque_sha256`) — **idéntico repo↔víctima**; no se
> reconstruye evidencia post-hoc.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-26.json` (extractor **H3**).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 758 | 751 | 7 | **751** | 6 | **0** |
| 2 | 746 | 738 | 8 | **738** | 6 | **0** |

## 8. Resultado (conteos por categoría y capa, con veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 751 | **5** | 622 | 124 | **0** | 7 | 744 | 0 | 0 |
| 2 | 738 | **5** | 604 | 129 | **0** | 7 | 731 | 0 | 0 |

### 8.1 Detecciones — **dos cifras**, genuinas/ajenas y desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | 5 | 1 · `{80792}` | **3 / 2** | 5 (`T1489-S1`) | 0 |
| 2 | 5 | 1 · `{80792}` | **3 / 2** | 5 (`T1489-S1`) | 0 |

- Las 5 alertas son `80792` (*Audit: Command: `/usr/bin/systemctl`*), todas por `T1489-S1`.
- **Genuinas del ataque** (`cwd=/home/angel/lab-attack/ATA004`): **3** — las `systemctl is-active`/`stop`/`is-active`
  del script. **Ajenas:** **2** `systemctl --user unset-environment SSH_AUTH_SOCK|GSM_SKIP_SSH_AGENT_WORKAROUND`
  (`cwd=/home/angel`) del **cierre de sesión SSH del operador** → contadas por `T1489-S1` (señal ancha).
- **Efecto `journald`/`systemd` — hallazgo (`fase-03-cabos`, 2026-09-28):** **0** detecciones por grupo
  `systemd` (`40700`): **no es un silenciado, es una detección inexistente de fábrica**. La regla
  `40700` (agrupador de `0285-systemd_rules.xml`, Wazuh v4.14.7, pin del laboratorio) es
  **`level="0"`** (no emite alerta); sus **hijas** `40701`–`40705` (level 2/5) **solo** disparan con
  patrones de **fallo** (`Stale file handle`, `entered failed state`, `status=1/FAILURE`…). Una
  **parada normal** (`systemctl stop cron`, mensajes `Stopping/Stopped`) **no casa ninguna hija** →
  gana `40700` (level 0) → **no hay alerta journald**. La hipótesis queda **resuelta** (no "sin
  probar"): la detección efectiva del ataque es el **`execve` `80792`** (audit). Ver §10.5 y runbook §8.3.
- **`dudosa` resueltas (3/iter, todas declaradas A1/A2):** `80792` (*execve* de `sudo`), `80780`
  (*Watch-Write* por `sudo`) → A1 (`audit_exe=sudo`); `5402` (*Successful sudo to ROOT*) → A2.
  → **`ruido`**, nota *"elevación (declarada ambigua en el esperado); parte del ataque pero no de la
  técnica - no infla; criterio del orquestador"*.
- **Ancla `audit_cwd` inerte:** el `sudo` corrió desde la carpeta del ataque, pero `S2`
  (`audit_cwd=/home/angel/lab-attack/ATA004/*`) **no casó** el valor real (`/home/angel/lab-attack/ATA004`,
  sin barra final) → **no** lo promovió a `deteccion` (al contrario de lo previsto en el gate); quedó
  `dudosa` por A1 y se resolvió a `ruido`.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|5−5\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 622 vs 604 → Δ=18 |
| Sanidad `ruido_conocido` (aviso) | ✅ 124 vs 129 → Δ=5 |

## 10. Limitaciones y hallazgos

1. **Señal `audit_exe` ancha (hallazgo transversal):** `systemctl --user` del cierre de sesión del
   operador se contó como detección. **Recomendación:** anclar por `audit_cwd` de la carpeta del
   ataque (patrón corregido) y/o `rule_id` del execve (runbook §8).
2. **Elevación declarada `ambigua`:** A1/A2 evitaron que el `sudo`/`5402` inflaran el recuento; se
   resolvieron a `ruido`.
3. **Gap de despliegue (runbook §8.1):** extractor H3 desplegado; `5715` del operador → `operador:5715`.
4. `lab-listo` prístino: `cron` vuelve a `active` al revertir; no se instaló nada.
5. **Punto ciego de journald (hallazgo, `fase-03-cabos`, 2026-09-28):** la vía journald/systemd del
   ruleset de fábrica **no** alerta de una **parada normal** de servicio (`40700` es el agrupador
   **`level=0`**; solo las hijas de **fallo** `40701`–`40705` alertan). Para una técnica que dependa de
   journald, la detección exige **regla propia (RS3)** o declararla por el **`rule_id` del `execve`**
   (`80792`). **Cabo del escalado** (confirmar con un C0 sobre una línea journald real y, si aplica,
   escribir la regla). Ver §8.1 y runbook §8.3.

---
fase: 2
tarea: 2.10 (T-06 · R-08)
nombre: Baseline legítimo — ventanas 1 y 2 (meta)
version: 4
status: completada (ventanas 1 y 2 extraídas y comparadas)
fecha: 2026-09-23
fecha_extraccion: 2026-09-23
autor: tfg-executor
---

# Baseline legítimo — ventanas 1 y 2 (T-06 · R-08)

> Este fichero documenta **las DOS ventanas** del baseline legítimo (T-06 · R-08), ambas
> **cerradas, extraídas y comparadas** (2026-09-23):
>
> - **Ventana 1 (noche) — CERRADA y extraída:** `t0` = **2026-09-23T00:45:00Z**,
>   `t1` = **2026-09-23T04:45:00Z** (240 min). **6.837** alertas, 12 `rule.id`, 0 `UNKNOWN`.
>   CSV individual: `Dataset/Legitimo/ruleids_legitimos_v1.csv`. Detalle en §1–§11.
> - **Ventana 2 (tarde) — CERRADA y extraída:** `t0` = **2026-09-23T12:00:01Z** (14:00:01 local),
>   `t1` = **2026-09-23T16:00:01Z** (18:00:01 local) (240 min). **6.737** alertas, 12 `rule.id`,
>   0 `UNKNOWN`. CSV individual: `Dataset/Legitimo/ruleids_legitimos_v2.csv`. Detalle en **§12–§13**.
>
> **Catálogo definitivo (entregable R-08 para la Fase 3):** `Dataset/Legitimo/ruleids_legitimos.csv`
> = **unión agregada** de las dos ventanas (12 `rule.id`, **13.574** alertas). Ver **§15**.
> **Comparación v1 vs v2 y veredicto de estabilidad: §14.**
>
> Las dos ventanas usan **el mismo script, sin cambios** y el mismo procedimiento (revert de
> la víctima a `lab-listo` + scan FIM forzado al inicio) para ser comparables.

## 1. Resumen

| Campo | Valor |
|---|---|
| Actividad | Legítima y variada, scripted (ver §5) |
| **t0 (UTC)** | **2026-09-23T00:45:00Z** |
| **t0 (local, Europe/Madrid/CEST)** | **2026-09-23 02:45:00** |
| Duración prevista | **240 min** (4 h) |
| **t1 real (UTC)** | **2026-09-23T04:45:00Z** (`END` en `baseline_log.txt`) |
| **t1 real (local)** | **2026-09-23 06:45:00** |
| **Duración real** | **240 min** (48/48 ciclos, 1 fallo de ciclo = 0) |
| Requisito | `t1 − t0 = 240 min ≥ 4 h` (R-08) ✔ |
| Víctima | `victima-linux` (192.168.65.129), snapshot `lab-listo` |
| Manager | `wazuh-server` (192.168.65.128), **no revertido** (conserva las alertas) |
| NAT | **desconectado** (`ens37` DOWN); solo `VMnet1` activa |
| Ataques | ninguno |

## 2. Snapshot y estado de partida

- **`victima-linux`:** apagado limpio → `vmrun -T ws revertToSnapshot ... lab-listo`
  (2026-09-23 02:07:50 CEST) → arranque. `lab-listo` **no** incluye los ficheros de
  la baseline: `lab-legit` parte **vacío**.
- **`wazuh-server`:** **no** se revierte (conserva alertas). Servicios
  `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` = `active`.
- **Nota de zona horaria (documentada):** el revert **deshace** el arreglo cosmético
  de `/etc/timezone`, que queda de nuevo en **`Etc/UTC`** dentro del snapshot. La
  zona **efectiva** de la VM ya era `Europe/Madrid` (`timedatectl` → CEST +0200), de
  modo que las marcas locales del script son correctas; `alerts.json` sella en **UTC**.
  Desajuste meramente cosmético (`/etc/timezone` vs `timedatectl`), no afecta a `t0/t1`.

## 3. Comprobaciones previas a `t0`

- Ping cruzado 128↔129: **OK** (0 % pérdida, ~0,3 ms).
- Agente `victima-linux` (ID **001**) en el manager: **Active**.
- **Telemetría verificada antes de `t0`:** un `sudo id` en la víctima (00:09 UTC)
  generó alertas nuevas en el manager (PAM/sudo, `5501/5502/5402`) → el pipeline
  agente→manager funciona.
- `Dataset/Legitimo/` (repo) y `/home/angel/lab-legit/` (víctima): **vacíos** antes
  del arranque.

## 4. RuleSets activos durante la ventana

Manifiesto: `Soporte/Wazuh/Configuracion/active_ruleset.txt` (Wazuh 4.14.7).

| RS | Origen | Estado en esta ventana |
|---|---|---|
| **RS1** | `/var/ossec/ruleset/rules/*.xml` (excepto auditd) | **activo** (4471 reglas, 167 ficheros) |
| **RS2** | `/var/ossec/ruleset/rules/0365-auditd_rules.xml` (+ auditd en la víctima) | **activo** (44 reglas, 80700–80794) |
| **RS3** | `/var/ossec/etc/rules/local_rules.xml` | **vacío** (0 reglas; la *smoke* `100000` se retiró el 2026-09-23) |
| **RS4** | `/var/ossec/etc/rules/external_*.xml` | **vacío** (opción A, gate G2) |

Clasificación `rule.id → RS` por **fichero de origen** (`rulesets_diseno.md` §4).

## 5. Actividad programada

Script: `Soporte/Wazuh/Scripts/baseline_actividad.sh` (desplegado en
`/home/angel/baseline_actividad.sh`; lanzado con `nohup`, sobrevive a la desconexión SSH).

- Ciclo cada **~5 min** en `/home/angel/lab-legit/`:
  crear/leer/escribir ficheros, `tar` de un directorio (backup), `cp`/`mv`/`rm` de
  temporales, `find`/`grep`/`sha256sum`, lectura de `journalctl`, `apt list --installed`.
- Log de la ventana: **`/home/angel/lab-legit/baseline_log.txt`** (timestamps **UTC**):
  `START <UTC>`, `CYCLE <n> <UTC>`, `END <UTC>`.
- Determinista, sin secretos, re-ejecutable. La **actividad natural** (systemd, cron,
  SSH, rootcheck, auditd) se suma por sí sola.
- Rango de telemetría afectado: auditd vigila `/home/angel/lab-legit` (`-w ... -p wa`),
  por lo que la actividad dispara **RS2** (80780/80781/80790/80791) y `execve` → **80792**;
  FIM (`syscheck`) vigila `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot` (no `lab-legit`).

## 6. Scan FIM forzado (dentro de la ventana)

- Comando: `sudo /var/ossec/bin/agent_control -r -u 001` (manager).
- **Hora: 2026-09-23T00:46:07Z** (local 02:46:07). Motivo: el ciclo FIM por defecto es
  de 12 h (`<frequency>43200</frequency>`); se fuerza uno al inicio de la ventana.
- Resultado: **0 alertas FIM/syscheck** en la ventana (la víctima está limpia y no se
  modificó ninguna ruta vigilada por FIM) → el scan se ejecutó pero no hubo cambios que
  reportar. Documentado como tal, sin interpretarlo como fallo.

## 7. PASO 0 — módulo vulnerability-detection del manager

- **Config:** `/var/ossec/etc/ossec.conf` → `<vulnerability-detection><enabled>yes</enabled>`
  con `<feed-update-interval>60m</feed-update-interval>`.
- **Sin NAT no puede descargar las listas de CVE.** Evidencia (log archivado del manager
  `logs/wazuh/2026/Sep/ossec-22.log.gz`, ~01:10–01:30 UTC):
  `wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed:
  Error -1 from server: Could not resolve hostname`.
- **¿Genera alertas?** **No.** `grep -c vulnerability /var/ossec/logs/alerts/alerts.json`
  = **0**; en la ventana, **0** alertas con contenido "vulnerab"; ninguna alerta de los
  `rule.id` 23501–23508 (reglas de vulnerability-detector).
- **Regla de decisión aplicada:** *solo errores de log, sin alertas* → **no se toca nada**,
  se documenta y la ventana sigue. **(No se modificó la configuración del manager.)**

## 8. Ritmo de alertas y recursos (primeros ~12 min: 00:45:00 → 00:56:53 UTC)

| Métrica | Valor |
|---|---|
| Alertas en la ventana (hasta 00:56:53Z) | **1020** |
| Media bruta | ~86/min (inflada por el pico del inicio) |
| **Ritmo en reposo** | **~12/min** |
| Picos cortos | 572 (00:46, FIM + arranque de ciclos), 62/100 (00:50/00:51), 53 (00:55) |
| ¿Sostenido > 500/min? | **No** (los picos caen al minuto siguiente a ~12/min) |
| `rule.id` distintos | 10 (parcial; **total de la ventana = 12**, ver §10.1) |
| Agentes | `victima-linux` 1005, `wazuh-server` 15 |
| Top reglas | 80792 (execve, 783), 80791 (delete var/run, 170), 80781/80790 (lab-legit), 5501/5502 (PAM), 5715 (sshd), 5402 (sudo) |
| Disco manager `/` | 48 G total, 21 G usados, **25 G libres** (46 %), estable |
| RAM manager | ~2,4 G libres / 3,3 G disponibles; swap 0 B |

Ninguna de las reglas observadas proviene del vulnerability-detector; todas son
RS1 (PAM/sshd/sudo) o RS2 (auditd).

## 9. Limitaciones

- **Actividad sintética:** la actividad scripted no reproduce al 100 % el uso humano
  real; se mitiga con actividad natural (systemd, cron, SSH, rootcheck, auditd) y con el
  scan FIM forzado. El baseline **acota** el ruido normal, no lo agota.
- **Sin usuario humano:** en ninguna de las dos ventanas hay interacción humana real; la
  actividad es scripted + natural del sistema.
- **4 h por ventana (2 ventanas):** se cubren dos franjas (noche 00:45–04:45Z y tarde
  12:00–16:00Z). No cubre fin de semana ni el resto del día; el ciclo diario queda cubierto
  solo parcialmente.
- **El catálogo es un SUPERCONJUNTO del ruido esperable durante un ataque:** el script de
  baseline **no correrá** durante las ejecuciones de la Fase 3, de modo que las reglas que
  genera (p. ej. `80780`/`80781`/`80782`/`80790` de `lab-legit` y parte de `80792`)
  **sobrestiman** el ruido normal. El catálogo **acota** el ruido (referencia para filtrar
  FP), pero una coincidencia con el baseline **no basta** para declarar FP: exige revisión
  humana en Fase 3.
- **`rule_description` de reglas genéricas:** reglas como `80792` ("Audit: Command: …")
  varían su descripción por evento; en los CSV se guarda la del **primer** evento visto
  (por eso `80791`/`80792`/`80782` muestran textos distintos entre v1 y v2 sin ser reglas
  distintas).
- La ventana **no incluye ataques** (eso es Fase 3); este baseline es el catálogo de ruido.
- `/etc/timezone` dentro del snapshot quedó `Etc/UTC` (cosmético); la zona efectiva es
  `Europe/Madrid` y las marcas UTC de `alerts.json` son las usadas para `t0/t1`.

## 10. Extracción del catálogo (ventana 1) — resultados

- **Script:** `_artefactos/scripts/extraer_alertas.py` (copia en el manager
  `/home/angel/extraer_alertas.py`; reutilizable en Fase 3).
- **Comando exacto de extracción** (ejecutado en `wazuh-server`, como `root` para poder
  leer `/var/ossec`; el parámetro `sudo` es interactivo y **no** se guarda en ningún fichero):

  ```bash
  # en wazuh-server
  sudo python3 /home/angel/extraer_alertas.py \
      --desde 2026-09-23T00:45:00Z --hasta 2026-09-23T04:45:00Z \
      --out /home/angel/ruleids_legitimos.csv
  ```
  Salida del script:
  `alertas leídas=14413 en_ventana=6837 no_json=0 rule_ids=12 unknown=0`.
- **Artefactos generados:**
  - `Dataset/Legitimo/ruleids_legitimos.csv` (catálogo, 12 filas + cabecera).
  - `Dataset/Legitimo/baseline_log_ventana1.txt` (copia del log de la víctima: 48 ciclos,
    `START 00:45:00Z` / `END 04:45:00Z`).

### 10.1 Resumen cuantitativo (ventana 1)

| Métrica | Valor |
|---|---|
| `rule.id` **distintos** (tamaño del catálogo) | **12** |
| Alertas totales en la ventana | **6837** |
| Alertas leídas en `alerts.json` (total histórico) | 14413 (0 JSON inválido) |
| **Reparto por capa** | **RS1 = 46** alertas (5 `rule.id`) · **RS2 = 6791** alertas (7 `rule.id`) |
| RS3 / RS4 | 0 alertas (vacías en Fase 2) |
| `UNKNOWN` (sin resolver a RS) | **0** ✔ |

### 10.2 Top-10 reglas por frecuencia (ventana 1)

| # | `rule_id` | `count` | RS | Descripción (primer evento) |
|---|---|---|---|---|
| 1 | 80791 | 3239 | RS2 | Audit: Deleted: /home/angel/lab-legit/work/. |
| 2 | 80792 | 2819 | RS2 | Audit: Command: /usr/bin/bash. |
| 3 | 80781 | 419 | RS2 | Audit: Watch - Write access: /home/angel/lab-legit/work/doc_1.txt. |
| 4 | 80782 | 109 | RS2 | Audit: Watch - Write access: /home/angel/lab-legit. |
| 5 | 80790 | 106 | RS2 | Audit: Created: /home/angel/lab-legit/baseline_log.txt. |
| 6 | 80780 | 95 | RS2 | Audit: Watch - Write access. |
| 7 | 5501 | 17 | RS1 | PAM: Login session opened. |
| 8 | 5502 | 15 | RS1 | PAM: Login session closed. |
| 9 | 5715 | 9 | RS1 | sshd: authentication success. |
| 10 | 5402 | 4 | RS1 | Successful sudo to ROOT executed. |

Frecuencias completas en el CSV; además aparecen `80730` (4, RS2) y `591` (1, RS1).

### 10.3 Patrones temporales observados

- **Arranque (00:45–00:58Z):** mayor pico de la ventana. `00:46` = **572** alertas
  (arranque del ciclo + scan FIM forzado 00:46:07Z), `00:58` = **247** (cierre de las
  sesiones SSH de puesta en marcha). Tras ello, **ritmo de reposo ≈ 12/min**.
- **Ciclo scripted cada 5 min:** firma estable de ~67 alertas en los minutos de ciclo
  (`80792`/`80791`/`8078x`), con `apt list --installed` (→ `dpkg`/`apt` en `80792`) y
  `journalctl`.
- **Mantenimiento diario 06:25 local (04:25:02Z):** **SÍ se ve**, pero es **pequeño**.
  Lo dispara `/etc/crontab` (`25 6 * * * root ... run-parts /etc/cron.daily`):
  `run-parts` → `apport`, `apt-compat`, `logrotate` (cada uno **1×** `80792`, execve).
  El minuto `04:25` suma **69** alertas frente a **67** de un ciclo normal (`04:20`):
  el mantenimiento **no produce un pico distintivo** ni introduce **ningún `rule.id` nuevo**.
- **`man-db.timer` (02:32:54Z ≈ 04:32 local):** `man-db.service` regenera la base de `man`
  → ráfaga de **28** eventos audit (`80791` ×26, `80792` ×1, `80780` ×1). Ruido puntual,
  **sin `rule.id` nuevos**.
- **Ráfaga horaria a las `HH:08` (~100–110 alertas/h):** `apparmor_parser`,
  `wazuh-modulesd`, `wazuh-agentd`, `systemd-detect-virt`, udev/snapd + **1×**
  `80730` (SELinux permission check). Es el patrón recurrente más marcado aparte del ciclo.

### 10.4 Observaciones para la Fase 3 (filtrado de FP)

- **El ruido dominante es auto-ruido del HIDS:** `80791`/`80792` los generan en gran parte
  el propio HIDS y el script de baseline, **no** actividad humana. La atribución es
  **distinta en cada regla**:
  - `80791` ("Deleted: var/run/."): lo genera **`wazuh-agentd`** reescribiendo su fichero de
    estado cada ~5–6 s.
  - `80792` (`execve`) de auto-ruido: procede de **hijos de `wazuh-syscheckd`** y
    **`wazuh-logcollector`** (cwd `/var/ossec`), **no** de un `execve` de `wazuh-agentd`.
    Son **dos raíces**: `wazuh-syscheckd` → hijos `dash` + `ps` (la mayoría) y
    `wazuh-logcollector` → hijos `dash` + `df`/`last`/`netstat|sed|sort` (coinciden con los
    *localfiles* de `ossec.conf`).

  Las dos primeras reglas del catálogo son, por tanto, **candidatas naturales a FP**.

  > **Nota de corrección (2026-09-23):** la redacción anterior de este punto atribuía el
  > segundo foco de auto-ruido (`80792`, `execve`) a `wazuh-agentd`. Era **impreciso**: los
  > eventos `80792` de auto-ruido provienen de **hijos de `wazuh-syscheckd`** y
  > **`wazuh-logcollector`** (cwd `/var/ossec`), verificado de forma independiente.
  > Corregido según el pendiente registrado en `state.md`.
- **Las reglas de autenticación RS1 (`5501`/`5502`/`5715`/`5402`) solo aparecen en los
  primeros ~14 min** (00:45:54–00:58:43Z; sesiones de puesta en marcha). Durante el resto
  de la ventana **no hay** actividad de login/sudo: en reposo, el ruido RS1 es ~0.
- Esta ventana **no incluye ataques** (Fase 3) y **acota** el ruido normal; el catálogo
  definitivo se consolidará con la ventana 2.

## 11. Reproducción

```powershell
# Revertir víctima (en el sobremesa)
vmrun -T ws revertToSnapshot "D:\TFG-VMs\victima-linux\victima-linux.vmx" lab-listo
vmrun -T ws start            "D:\TFG-VMs\victima-linux\victima-linux.vmx" nogui

# Desplegar y lanzar (en la víctima)
scp Soporte/Wazuh/Scripts/baseline_actividad.sh angel@192.168.65.129:/home/angel/
ssh angel@192.168.65.129 'setsid nohup bash /home/angel/baseline_actividad.sh 240 \
    </dev/null >/home/angel/baseline_nohup.out 2>&1 &'

# Scan FIM forzado (en el manager)
sudo /var/ossec/bin/agent_control -r -u 001
```

## 12. Ventana 2 (tarde) — cerrada y extraída

> **Es la ventana 2 de 2.** Mismo script y mismo procedimiento que la ventana 1
> (homogeneidad); solo cambia la **franja horaria** (tarde en vez de noche).
> **Cerrada:** 48/48 ciclos, `END 2026-09-23T16:00:01Z`.

| Campo | Valor |
|---|---|
| Actividad | Legítima y variada, **mismo script** que la ventana 1 (§5) |
| **t0 (UTC)** | **2026-09-23T12:00:01Z** (`START` en `baseline_log.txt`) |
| **t0 (local, Europe/Madrid/CEST)** | **2026-09-23 14:00:01** |
| Duración real | **240 min** (48/48 ciclos) |
| **t1 real (UTC)** | **2026-09-23T16:00:01Z** (`END` en `baseline_log.txt`) |
| **t1 real (local)** | **2026-09-23 18:00:01** |
| Requisito | `t1 − t0 = 240 min ≥ 4 h` (R-08) ✔ |
| Víctima | `victima-linux` (192.168.65.129), snapshot **`lab-listo`** (revert 2026-09-23 13:19 CEST) |
| Manager | `wazuh-server` (192.168.65.128), **no revertido** (conserva las alertas de la ventana 1) |
| NAT | **desconectado**; solo `VMnet1` activa |
| Ataques | ninguno |

### 12.1 Comprobaciones previas a `t0` (idénticas a la ventana 1)

- Ping cruzado 128↔129: **OK** (0 % pérdida).
- Servicios manager: `wazuh-manager` / `wazuh-indexer` / `wazuh-dashboard` = **active**.
- Agente `victima-linux` (ID **001**) en el manager: **Active**.
- **Telemetría verificada antes de `t0`:** un `sudo id` en la víctima (11:18 UTC) generó
  alertas nuevas (PAM/sudo) → el pipeline agente→manager funciona.
- `/home/angel/lab-legit/` (víctima): **vacío** tras el revert → **mismo punto de partida**
  que la ventana 1.
- Reloj víctima: **`Europe/Madrid` (CEST, +0200), `synchronized: yes`**. El revert vuelve a
  dejar `/etc/timezone` en `Etc/UTC` (cosmético; ver §2), sin efecto en `t0/t1` (UTC).

### 12.2 Script y lanzamiento

- **Mismo fichero, sin cambios:** `Soporte/Wazuh/Scripts/baseline_actividad.sh`
  (sha256 `44f5845f610a28b95482350f48b95469038c017cf073e0f56222c530e184542d`, idéntico en
  repo y víctima).
- Lanzamiento con `nohup` (sobrevive a la desconexión SSH):
  `setsid nohup bash /home/angel/baseline_actividad.sh 240`.
- Log de la ventana: `/home/angel/lab-legit/baseline_log.txt` (timestamps UTC).

### 12.3 Scan FIM forzado (dentro de la ventana)

- Comando: `sudo /var/ossec/bin/agent_control -r -u 001` (manager).
- **Hora: 2026-09-23T12:01:05Z** (local 14:01:05) → **t0 + 1:04** (la ventana 1 lo forzó a
  t0 + 1:07). Motivo: el ciclo FIM por defecto es de 12 h (`<frequency>43200</frequency>`).
- Resultado: **0 alertas FIM/syscheck** en la ventana (víctima limpia; ninguna ruta
  vigilada por FIM modificada) → **idéntico a la ventana 1** (que también dio 0).
  Documentado como tal, sin interpretarlo como fallo.

### 12.4 Homogeneidad con la ventana 1

| Aspecto | Ventana 1 | Ventana 2 |
|---|---|---|
| Script | `baseline_actividad.sh` (sha256 `44f5845f…`) | **idéntico** |
| Duración | 240 min | **240 min** |
| Ciclo | ~5 min | **~5 min** |
| Snapshot víctima | `lab-listo` | **`lab-listo`** |
| Manager revertido | No | **No** |
| Scan FIM | t0 + 1:07 | **t0 + 1:04** |
| Franja horaria | 02:45→06:45 local (**noche**) | **14:00→18:00 local (tarde)** |
| Config Wazuh | sin cambios | **sin cambios** |

---

## 13. Extracción del catálogo (ventana 2) — resultados

- **Script:** `_artefactos/scripts/extraer_alertas.py` (copia en el manager
  `/home/angel/extraer_alertas.py`, sha256 `33c2ec4f…` = **idéntico** al del repo;
  reutilizable en Fase 3).
- **Comando exacto** (ejecutado en `wazuh-server`, como `root` para leer `/var/ossec`;
  `sudo` interactivo, sin guardar secreto alguno):

  ```bash
  # en wazuh-server
  sudo python3 /home/angel/extraer_alertas.py \
      --desde 2026-09-23T12:00:01Z --hasta 2026-09-23T16:00:01Z \
      --out /home/angel/ruleids_legitimos_v2.csv
  ```
  Salida del script:
  `alertas leídas=27263 en_ventana=6737 no_json=0 rule_ids=12 unknown=0`.
- **Artefactos generados:**
  - `Dataset/Legitimo/ruleids_legitimos_v2.csv` (catálogo de la ventana 2, 12 filas + cabecera).
  - `Dataset/Legitimo/baseline_log_ventana2.txt` (copia del log de la víctima: 48 ciclos,
    `START 2026-09-23T12:00:01Z` / `END 2026-09-23T16:00:01Z`).

### 13.1 Resumen cuantitativo (ventana 2)

| Métrica | Valor |
|---|---|
| `rule.id` **distintos** | **12** |
| Alertas totales en la ventana | **6737** |
| Alertas leídas en `alerts.json` (total histórico) | 27263 (0 JSON inválido) |
| **Reparto por capa** | **RS1 = 35** alertas (5 `rule.id`) · **RS2 = 6702** alertas (7 `rule.id`) |
| RS3 / RS4 | 0 alertas (vacías en Fase 2) |
| `UNKNOWN` (sin resolver a RS) | **0** ✔ |

---

## 14. Comparación v1 vs v2 — estabilidad del ruido

> Comparación **honesta**, sin maquillar. Todos los `count` provienen de las dos
> extracciones (`ruleids_legitimos_v1.csv` / `_v2.csv`) y del análisis directo de
> `alerts.json` en el manager.

### 14.1 Tipos de alerta (`rule.id`)

| Conjunto | `rule.id` |
|---|---|
| **En AMBAS ventanas (12/12)** | 591, 5402, 5501, 5502, 5715, 80730, 80780, 80781, 80782, 80790, 80791, 80792 |
| **Solo en v1** | *(ninguno)* |
| **Solo en v2** | *(ninguno)* |

Los **12 `rule.id` son exactamente los mismos** en las dos ventanas: **no aparece ni
desaparece ninguna regla**.

### 14.2 Frecuencia por regla

| `rule_id` | RS | count v1 | count v2 | Δ (v2−v1) | Δ % |
|---|---|---|---|---|---|
| 591 | RS1 | 1 | 1 | 0 | 0,0 % |
| 5402 | RS1 | 4 | 2 | −2 | −50,0 % |
| 5501 | RS1 | 17 | 13 | −4 | −23,5 % |
| 5502 | RS1 | 15 | 12 | −3 | −20,0 % |
| 5715 | RS1 | 9 | 7 | −2 | −22,2 % |
| 80730 | RS2 | 4 | 4 | 0 | 0,0 % |
| 80780 | RS2 | 95 | 102 | +7 | +7,4 % |
| 80781 | RS2 | 419 | 412 | −7 | −1,7 % |
| 80782 | RS2 | 109 | 107 | −2 | −1,8 % |
| 80790 | RS2 | 106 | 105 | −1 | −0,9 % |
| 80791 | RS2 | 3239 | 3242 | +3 | +0,1 % |
| 80792 | RS2 | 2819 | 2730 | −89 | −3,2 % |
| **Total** | | **6837** | **6737** | **−100** | **−1,5 %** |

### 14.3 Ritmo

| Métrica | v1 | v2 |
|---|---|---|
| Alertas totales (240 min) | 6837 | 6737 |
| Media bruta (total/240) | 28,49/min | 28,07/min |
| **Ritmo en reposo** (sin el arranque) | **~24–25/min** | **~24–25/min** |
| Exceso del pico de arranque sobre el reposo | ~939 (minuto 00) | ~907 (minuto 12) |

Desglose horario normalizado (alertas/min; horas parciales indicadas):

| Ventana | Reparto |
|---|---|
| **v1** | 00:45–00:59 → **86,6/min** (arranque) · 01 → 24,2 · 02 → 25,2 · 03 → 24,3 · 04:00–04:45 → 25,0 |
| **v2** | 12 → **39,1/min** (incluye arranque) · 13 → 24,3 · 14 → 24,3 · 15 → 24,6 |

En **régimen** (fuera del arranque), las dos ventanas van a **~24–25 alertas/min**,
indistinguibles entre sí.

### 14.4 Reparto por capa (RS1/RS2/RS3/RS4)

| RS | v1 (alertas / `rule.id`) | v2 (alertas / `rule.id`) |
|---|---|---|
| **RS1** | 46 / 5 | 35 / 5 |
| **RS2** | 6791 / 7 | 6702 / 7 |
| **RS3** | 0 | 0 |
| **RS4** | 0 | 0 |

RS2 domina en ambas (~99,3 % en v1 y ~99,5 % en v2 del total). La diferencia de RS1
(46 → 35) son las **sesiones SSH/sudo de puesta en marcha**, presentes **solo en los
primeros ~11–14 min** de cada ventana; **no** es ruido de régimen.

### 14.5 El auto-ruido — patrón y ritmo (verificado por `audit.exe`/`audit.cwd`)

| Regla | Fuente (atribución) | v1 | v2 |
|---|---|---|---|
| **80791** | `wazuh-agentd` reescribiendo `var/run/` cada ~5 s | **2878** de 3239 (**88,9 %**) | **2876** de 3242 (**88,7 %**) |
| **80792** | hijos de `wazuh-syscheckd` y `wazuh-logcollector` (`cwd=/var/ossec`, `execve`) | **807** de 2819 (28,6 %) | **806** de 2730 (29,5 %) |

El patrón **se repite de forma casi idéntica**:
- `80791`/`wazuh-agentd`: **2878 vs 2876** (Δ = −2) → **~12/min** en ambas ventanas.
- `80792` con `cwd=/var/ossec` (auto-ruido de syscheckd/logcollector): **807 vs 806** (Δ = −1) →
  **~3,4/min** en ambas.

**Dos cifras distintas que NO deben confundirse:**

- **Cuota de las dos reglas dominantes:** `80791+80792` suman **6058** alertas = **88,6 %**
  del total en v1 y **5972** = **88,6 %** en v2. Es la **cuota de esas dos `rule.id` sobre el
  total**, e incluye **todo** su tráfico (auto-ruido **y** actividad del script de baseline),
  **no** solo auto-ruido.
- **Auto-ruido real:** solo los eventos cuyo `exe`/`cwd` es del propio Wazuh
  (`80791`/`wazuh-agentd` **2878** + `80792`/`cwd=/var/ossec` **807** ≈ **3685** alertas) =
  **~54 %** del total en v1 (coherente con `state.md`). **Ésta es la cifra válida como base
  de filtrado de FP**, no el 88,6 %.

> **Nota de corrección (2026-09-23):** la redacción anterior etiquetaba el **88,6 %** como
> "auto-ruido". Era **engañoso**: el 88,6 % es la cuota de las dos reglas dominantes sobre el
> total; el **auto-ruido real** (solo eventos originados por el propio Wazuh) es **~54 %**.
> Se distingue aquí para que la Fase 3 **no use el 88,6 %** como base para filtrar FP.

### 14.6 Veredicto sobre la estabilidad

**El ruido legítimo es ESTABLE entre las dos ventanas.** Evidencia:

1. **Mismo catálogo:** 12/12 `rule.id` idénticos; ninguna regla exclusiva de una ventana.
2. **Mismo reparto por capa:** RS1 = 5 reglas, RS2 = 7 reglas; RS3/RS4 vacías.
3. **Mismo ritmo de régimen:** ~24–25 alertas/min en ambas (total −1,5 %).
4. **Mismo auto-ruido dominante:** `80791`/`wazuh-agentd` 2878 vs 2876 y
   `80792`/`syscheckd`+`logcollector` 807 vs 806 (Δ ≤ 2).

**Divergencias detectadas (declaradas, sin maquillar):**

- **RS1 de autenticación** (`5402`, `5501`, `5502`, `5715`): 46 → 35 alertas (−24 % en
  conjunto). **Causa:** dependen del **número de sesiones SSH/sudo de puesta en marcha**, no
  del régimen; en **ambas** ventanas ocurren **solo en los primeros ~11–14 min** y luego
  **cesan** (en reposo, el ruido RS1 es ~0). Diferencia **absoluta pequeña** (11 alertas).
- **`80792`** (la regla más variable): −89 alertas (**−3,2 %**). Mezcla `execve` del **script
  de baseline**, de **systemd** y del **auto-ruido de syscheckd/logcollector**; es
  intrínsecamente la más fluctuante, pero se mantiene **< 3,5 %**.
- **`80780`**: +7 (**+7,4 %**) — la mayor variación **relativa**, pero **absoluta mínima**
  (7 alertas).
- **Descripciones de reglas genéricas** (`80782`, `80791`, `80792`): cambian porque el CSV
  guarda la descripción del **primer** evento, y ésta varía por evento (p. ej. `80791`:
  `…lab-legit/work/.` en v1 vs `…/run/user/1000/systemd/units/.` en v2). Es un **artefacto
  de documentación**, no una divergencia de reglas.
- **Mantenimiento diario:** la v1 incluyó el `cron.daily` (~04:25Z) y la v2 no; **no** produjo
  pico distintivo ni `rule.id` nuevos (confirmado: la hora 04 de v1 va a 25,0/min, igual que
  el reposo). Sin efecto en el catálogo.

**Conclusión:** no hay divergencias **estructurales**. Las diferencias son de **ritmo fino**
(≤ 3,5 % por regla; −1,5 % en el total) y de **actividad de puesta en marcha**, no del ruido
de fondo. El catálogo puede considerarse **representativo y reproducible** en franjas
horarias distintas.

> **Nota metodológica (alcance real de "estable").** La comparación v1 vs v2 se hizo entre
> **dos ejecuciones del mismo script determinista sobre el mismo snapshot**, de modo que la
> **estabilidad observada era lo esperable**. Su **validez externa es limitada**: no cubre
> **variabilidad humana** ni otras franjas horarias/semanales. Aquí "reproducible" significa
> *determinismo del script y homogeneidad del procedimiento*, **no** que el catálogo cubra
> toda la variabilidad del uso real. Para Fase 3, tratar el catálogo como **referencia de
> ruido acotada**, no como inventario exhaustivo del ruido legítimo posible.

---

## 15. Catálogo agregado (entregable R-08) y cierre de la tarea 2.10

- **Entregable R-08 para la Fase 3:** `Dataset/Legitimo/ruleids_legitimos.csv` = **unión
  agregada** de las dos ventanas. Columnas:
  `rule_id,rule_level,rule_description,groups,rs_origen,count_v1,count_v2,count_total,ventanas`
  (`ventanas` ∈ {`v1`, `v2`, `v1+v2`}; en este caso las **12 filas son `v1+v2`**). El fichero
  lleva una línea `#` de cabecera que describe qué es.
- **CSV individuales (trazabilidad):** `Dataset/Legitimo/ruleids_legitimos_v1.csv` y
  `Dataset/Legitimo/ruleids_legitimos_v2.csv`.
- **Totales del catálogo:** **12 `rule.id`**, **13.574 alertas** (6.837 + 6.737), **0 `UNKNOWN`**.
- **Tarea 2.10: COMPLETADA.** Dos ventanas de 4 h en franjas distintas (noche + tarde), mismo
  script y mismo procedimiento, extraídas y comparadas; **estabilidad verificada (§14)**.


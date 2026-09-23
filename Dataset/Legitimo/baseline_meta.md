---
fase: 2
tarea: 2.10 (T-06 · R-08)
nombre: Baseline legítimo — Ventana 1 (meta)
version: 1
status: en_curso
fecha: 2026-09-23
autor: tfg-executor
---

# Baseline legítimo — Ventana 1 (T-06 · R-08)

> Estado: **ventana EN CURSO** al redactar este documento. `t1` aún no ha ocurrido;
> la extracción de `ruleids_legitimos.csv` se hace **al terminar** (ver §10).

## 1. Resumen

| Campo | Valor |
|---|---|
| Actividad | Legítima y variada, scripted (ver §5) |
| **t0 (UTC)** | **2026-09-23T00:45:00Z** |
| **t0 (local, Europe/Madrid/CEST)** | **2026-09-23 02:45:00** |
| Duración prevista | **240 min** (4 h) |
| t1 previsto (UTC) | 2026-09-23T04:45:00Z (local 06:45:00) |
| Requisito | `t1 − t0 ≥ 4 h` (R-08) |
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
| `rule.id` distintos | 10 |
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
- **`rule_description` de reglas genéricas:** reglas como `80792` ("Audit: Command: …")
  varían su descripción por evento; en el CSV se guarda la del **primer** evento visto.
- La ventana **no incluye ataques** (eso es Fase 3); este baseline es el catálogo de ruido.
- `/etc/timezone` dentro del snapshot quedó `Etc/UTC` (cosmético); la zona efectiva es
  `Europe/Madrid` y las marcas UTC de `alerts.json` son las usadas para `t0/t1`.

## 10. Pendiente al cerrar la ventana (t1)

1. Confirmar `END <UTC>` en `/home/angel/lab-legit/baseline_log.txt` y verificar `t1 − t0 ≥ 4 h`.
2. Extraer el CSV (mismo script reutilizable en Fase 3):
   ```bash
   # en el manager (root para leer /var/ossec)
   sudo python3 extraer_alertas.py \
       --desde 2026-09-23T00:45:00Z --hasta <t1_UTC> \
       --out ruleids_legitimos.csv
   ```
3. Copiar el CSV a `Dataset/Legitimo/ruleids_legitimos.csv` y actualizar este documento
   (estado → `completado`, `t1` real, nº de `rule.id`, `UNKNOWN`).

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

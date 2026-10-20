# Diagnóstico del fallo de la ventana `legitimo-72h` (L1) — **VENTANA INVÁLIDA**

> **Fecha del diagnóstico:** 2026-10-20 (14:56–15:15 UTC) · **Solo lectura** hasta la fase de parada.
> **Ventana sellada:** `t0 = 2026-10-19T00:00:00Z` → `t1 = 2026-10-22T00:00:00Z`.
> **Fallo:** el agente `001` se desconectó a las **2026-10-19 21:59:56Z** (último keep-alive) y la
> actividad legítima se paró a las **2026-10-19 14:38:36Z**. **No se alcanzó ni el 31 % de la ventana.**
> **Decisión:** ventana **inválida**, **se repite** (no se extrae `M` ni se sella B10 con estos datos).

---

## 1. Causa raíz (con evidencia)

### **Disco de la víctima al 100 % por un log de stdout de GHOSTS sin límite (`ghasts.out`).**

| Evidencia | Valor |
|---|---|
| `df -h /` (2026-10-20 12:57Z) | `/dev/mapper/ubuntu--vg-ubuntu--lv` **9,8 G / 9,8 G / 0 libres / 100 %** |
| `df -i /` | 16 % de inodos → **no** es agotamiento de inodos |
| **Fichero culpable** | `/home/angel/ghosts-client/ghasts.out` = **4.783.345.664 B (4,78 GB ≈ 49 % del FS)** |
| Resto del FS | `/usr` 2,3 G · `/var` 1,1 G (journal 621,5 M) · `/home` 4,6 G (de ellos 4,5 G son el fichero) |
| Proceso | PID 3973 `./ghosts.client.linux`, vivo 1 d 13 h 23 min; `wchar` **9,62 GB** / `write_bytes` **9,65 GB** con tamaño fijo del fichero ⇒ **~50 % de las escrituras fallaban y reintentaban** |
| `dmesg -T` / `journalctl -k` | `systemd-journald: Failed to open system journal: No space left on device` (**ENOSPC**) |
| Top | `systemd-journald` 61 % CPU y `rsyslogd` 23 % **girando en vano** contra el disco lleno (load 2,8) |

**Mecanismo.** `client_ctl.sh start` (y `tfg_keepalive.sh`) lanzan el cliente con
`nohup ./ghosts.client.linux > ghasts.out 2>&1` y `nlog.config` tiene
**`<logger name="*" minlevel="Trace" writeTo="console" />`** → **todo el TRACE a stdout, sin rotación ni
tope**. Los targets de fichero sí están acotados (`app.log` 1 MB × 3, `clientupdates.log` 500 KB × 21);
**el de consola, no**. El fichero creció hasta llenar los ~5,5 GB libres en **~14 h**.

**Cronología (UTC, la que manda):**

| Hora (UTC) | Evidencia |
|---|---|
| 2026-10-18 **23:15** | arranque de las VMs (`uptime` 1 d 13 h 41 min a las 12:56Z) → **no hubo reinicio en el fallo** |
| 2026-10-18 **23:40:04** | arranca el cliente GHOSTS (`ghasts.out`, primera línea) → `ghasts.out` empieza a crecer |
| 2026-10-19 **14:02:33** | **primer `No space left on device`** (`logs/app.log`, `handlers.Curl.Command`) ⇒ **disco lleno** |
| 2026-10-19 **14:38:36** | **última acción legítima** (`history_timeline`, PostgreSQL del host, `createdutc`; `Curl` 14:35:02) |
| 2026-10-19 **14:39:51** | NLog: `Failed write to file '/home/angel/ghosts-client/logs/clientupdates.log' … No space left on device` |
| 2026-10-19 **14:39:52** | **última línea** de `logs/app.log` (fin de la orquestación) |
| 2026-10-19 **17:35:15** | `systemd-journald: Failed to create new user journal: No space left on device` (hora local 19:35) |
| 2026-10-19 **17:35:19** | `wazuh-agentd: WARNING: Agent buffer at 90 %` / `buffer is full: Events may be lost` (hora local 19:35) |
| 2026-10-19 **19:21:44** | `wazuh-modulesd:syscollector: ERROR: sqlite: database or disk is full` (hora local 21:21) |
| 2026-10-19 **21:59:56** | **último keep-alive del agente `001`** (`1792447196`; `agent_control` → `Disconnected`) |
| 2026-10-19 **22:00:11** | `wazuh-agentd: CRITICAL: (1107): Could not create directory 'logs/wazuh/2026' due to [(28)-(No space left on device)]` (rotación diaria, 00:00 local) |

**Prueba de que el agente murió por el disco, no por red/config:** el proceso **`wazuh-agentd` ya no
existe** (solo quedan `wazuh-execd`, `wazuh-syscheckd`, `wazuh-logcollector` y `wazuh-modulesd`, que
mantienen la unit `active`), `NRestarts=0`, `uptime` sin reinicios y **cero** cambios de paquetes
(`/var/log/apt/history.log` vacío desde el 18/10 19:40; `unattended-upgrades`: sin entradas). No hubo OOM
(`free -m`: 616 MB usados de 2,9 GB, swap 0). `wazuh-agentd` se cayó **al fallar la rotación de log de
medianoche** (22:00Z), 15 s después de su último keep-alive.

> **Nota sobre zonas horarias.** `ossec.log` del agente y la rotación diaria van en **hora local**
> (CEST, +2); `logs/app.log` del cliente GHOSTS va en **UTC** (`date:universalTime=true`); los
> `createdutc` de PostgreSQL son UTC. En esta tabla **todo está convertido a UTC**.

---

## 2. Por qué se paró también GHOSTS

**Misma causa, distinto síntoma.** El cliente **no murió**: sigue vivo (PID 3973) y su hilo de
comunicaciones mantiene el socket con el servidor (por eso la vigilancia del host lo veía `Up` y
`statusUp` se refrescaba). Lo que murió fue **la orquestación de la timeline**:

1. El handler `Curl` no pudo escribir en disco a las **14:02:33Z** (`IOException: No space left on device`).
2. NLog tampoco pudo escribir sus logs (`14:39:51Z`) y la última entrada es **14:39:52Z**, en mitad de un `du -sh`.
3. A partir de ahí **no hay una sola acción más** (PostgreSQL: máximo `createdutc` = 14:38:36).

**Por qué no corrió la franja nocturna (00:45–04:45Z del 20/10):** la timeline (`config/timeline.json`)
sí la tiene —4 handlers `Loop: true`, ventanas `12:00–16:00Z` y `00:45–04:45Z`—, pero **el bucle que
las evalúa estaba muerto** desde las 14:39Z. El keepalive no lo relanzó porque **solo relanza si el
proceso NO existe** (`if ! pgrep -f ghosts.client.linux`), y el proceso existía (zombi funcional).
**Fallo de diseño del keepalive:** vigila *vivir*, no *estar haciendo algo*.

**Consecuencia para la medida:** desde 14:39Z del 19/10 no hay actividad legítima real; el resto son
eventos de fondo (auditd/syscheck/SCA) **sin denominador válido** (el agente tampoco reportó desde las
21:59:56Z). **La ventana no sirve.**

---

## 3. `archives.json`: **sí rota** (y cómo habrá que extraerlo)

**Confirmado en el manager (`.128`):**

- `archives.json` **no** es un fichero suelto: es un **hardlink** del fichero del día en curso
  (`ossec-archive-20.json`, mismo inodo).
- **Rota a las 00:00Z (02:00 local)** al directorio **`/var/ossec/logs/archives/<AAAA>/<Mes>/`** con el
  patrón **`ossec-archive-<DD>.json.gz`** (+ `ossec-archive-<DD>.json.sum` con el sha256).
  Evidencia: `ossec-archive-19.json.gz` (27.768.540 B) con `mtime 2026-10-20 02:04` local = **00:04Z**.
- Por tanto: **el `archives.json` vivo solo contiene el día en curso**; lo anterior está en los `.gz`.

**Volumen real medido (día 19, hasta el corte):** **1.552.236** líneas, de las cuales **1.538.601**
llevan `"id":"001"` (**99,1 % del endpoint**); ≈ **70,6 k eventos/h** ⇒ **~5,1 M eventos a 72 h** y
**~90 MB comprimidos**. Disco del manager: 48 G con 22 G libres ⇒ **sin riesgo**.

**Esto cambia el procedimiento de extracción de la repetición** (el README de L1 solo copiaba
`archives.json`):

```
# 1) ANTES de logall_json off
scp  /var/ossec/logs/archives/archives.json                       -> denominador/
scp  /var/ossec/logs/archives/2026/Oct/ossec-archive-{19,20,21,22}.json{,.gz,.sum} -> denominador/
# 2) M = unión de TODOS los ficheros del rango [t0,t1]
#    (`contar_denominador.py` debe aceptar .gz y varios ficheros — verificar antes de repetir)
# 3) logall_json_ctl.sh off   (borra archives.json; los .gz del directorio NO se tocan)
```

⚠️ **Riesgo de borde:** `t1 = 00:00Z` **coincide con la rotación**. Si la copia se hace en ese instante,
el último día puede estar en `archives.json`/`ossec-archive-22.json` (plano) y no en `.gz`.
**Copiar siempre ambas formas** (plano + `.gz`) y comprobar que la suma de eventos cubre `[t0,t1]`.

---

## 4. Qué hay que cambiar/corregir **antes de repetir**

1. **[CRÍTICO] Acotar la salida de GHOSTS.**
   - `client_ctl.sh` y `tfg_keepalive.sh`: `nohup ./ghosts.client.linux >/dev/null 2>&1 &`
     (o `>> ghasts.out` con `logrotate` de 50 MB × 3).
   - `nlog.config`: la regla de consola a **`minlevel="Info"`** (o `Warn`), o eliminar el target
     `console`. Sin esto, cualquier repetición vuelve a llenar el disco (~120–390 MB/h).
2. **[CRÍTICO] Presupuesto de disco y guardarraíl en `prep`.** Exigir **≥ 4 GB libres** en `/` antes de
   `t0` y **abortar** si no se cumple; con el log acotado el consumo propio pasa a ser ~MB.
   (El LV de la víctima es de 9,8 G: **no** se puede compensar sólo con disco si el log sigue sin tope.)
3. **[CRÍTICO] Vigilancia que mida *hacer*, no *estar*.** El `watch` actual no detectó nada porque
   `statusUp` se refresca por el hilo de socket. Añadir:
   - edad de la **última acción** (`history_timeline.createdutc`) **< 1 h** dentro de franja;
   - **`df -h /` de la víctima > 1,5 GB** (se puede leer de forma pasiva con el timeline que ya ejecuta `df`);
   - `pgrep -f wazuh-agentd` (**no** `systemctl is-active`: la unit sigue `active` sin `agentd`).
4. **Keepalive con heartbeat:** si el cliente existe pero no escribe (edad de `logs/app.log` > 30 min
   dentro de franja), **relanzarlo** con `client_ctl.sh stop|start`.
5. **Alarma de "agente desconectado"** en el `watch` (comparar `last keep alive` con la hora actual):
   a 21:59:56Z el agente llevaba **más de 4 h** sin poder entregar eventos (buffer lleno desde las
   17:35Z), y el `watch` de las 18:00Z y 21:00Z lo seguía viendo `Active`.
6. **Reinicio robusto del manager** al hacer `logall_json on|off`: el `systemctl restart` de
   `logall_json_ctl.sh` **[falló en esta parada]** (ver §5). Envolverlo en:
   `wazuh-control stop` → `pkill -9 -f wazuh_apid` → `systemctl reset-failed` → `systemctl start`, con
   reintento y verificación (`systemctl is-active` + `agent_control -l`). `TimeoutSec=45` es corto
   cuando quedan procesos `wazuh_apid` huérfanos (con el arranque limpio tarda ~15 s).
7. **Extracción:** incorporar los `ossec-archive-<DD>.json.gz` al camino de `M` (§3) y verificar que
   `contar_denominador.py` los acepta (`.gz` y varios ficheros) **antes** de `t0`.
8. **Re-verificar el presupuesto de `M`** con la tasa real medida (70,6 k ev/h ≈ 90 MB gz/72 h) — sigue
   muy por debajo de 5 GB, así que **no hace falta plan B**, pero el README debe reflejar que el
   denominador **está repartido en 4 ficheros**.
9. **Timeline:** mantener las dos franjas (`12:00–16:00Z`, `00:45–04:45Z`); no hay que tocarla. El
   problema nunca fue la timeline, sino que su motor se quedó sin disco.

---

## 5. Parada y limpieza ejecutadas (orden respetado)

1. **Víctima — GHOSTS parado:** `systemctl stop/disable tfg-ghosts-legit.timer|service` + `pkill` del
   cliente y del keepalive. Verificado: **sin procesos** `ghosts.client.linux` ni `tfg_keepalive.sh`.
2. **Manager — copia ANTES de apagar** (`/tmp/legit_denominador/`):
   | Fichero | Bytes | sha256 |
   |---|---|---|
   | `archives.json` (día 20 parcial) | 4.757.038 | `931382574b03da1b64d97f5e5c522e302ea842fc75a7fb0d9f10484c2c24d9e4` |
   | `ossec-archive-19.json.gz` | 27.768.540 | `aef0a068bbed86c68b48691318ba689f2c0d889cb28d15ec3dee918682563115` |
   | `ossec-archive-20.json` | 4.801.765 | `fffbac1b027d2032b39d8c9add43283a97a884a4f5062bcfdb82761d18e692f6` |
   Copia en el host: `%TEMP%\tfg-legit-72h-fallo\` (**fuera del repo**, misma huella verificada).
   **No se versiona** (la ventana es inválida y no debe confundirse con una medida).
3. **`logall_json off`** → `valor aplicado: <logall_json>no</logall_json>` · `archives.json` **borrado**
   (esperado) · los `ossec-archive-*.json(.gz/.sum)` del **18, 19 y 20 quedan intactos** en el manager.
   *(`systemctl restart` agotó `TimeoutSec=45` por procesos `wazuh_apid` huérfanos; se recuperó con
   `wazuh-control stop` + `pkill -9 -f wazuh_apid` + `reset-failed` + `start` → `active` en ~15 s.)*
4. **Manager restaurado y verificado:** `wazuh-manager`, `wazuh-indexer` y `wazuh-dashboard` **active**;
   `diff ossec.conf.tfg-bak ossec.conf` → **CONFIG_IDENTICA**; `agent_control` responde.
   **No** se ha tocado el ruleset.
5. **Host:** GHOSTS API + PostgreSQL detenidos (`stop_ghosts.ps1`) · "internet local" detenido
   (`stop_internet_local.ps1`, puertos 8080/9090/9092 cerrados) · regla `TFG-ghosts-5000` retirada ·
   **4 tareas `TFG-Legit-*` eliminadas** (`registrar_tareas.ps1 -Eliminar`) ⇒ **la ventana ya no puede
   re-armarse sola**.
6. **VMs apagadas** (`vmrun stop … soft`, víctima y manager): `vmrun list` → **0 VMs en marcha**.
7. **Snapshots intactos:** víctima `base-limpia` · `lab-listo` · **`lab-listo-legit`**; manager
   `base-limpia` · `lab-listo`. **No se ha revertido ni creado ninguno.**
8. **`TFG_GUEST_PW` conservada** (variable de usuario; se necesitará para repetir). **Sin commits ni push.**
   No se ha tocado `_recursos/`, corpus, `Hojas/`, `Dataset/` ni `Soporte/Metrica/`.

---

## 6. Resumen en una línea

**El cliente GHOSTS escribía su TRACE a `ghasts.out` sin tope (4,78 GB); llenó el disco de la víctima
(9,8 G) a las 14:02Z del 19/10, lo que mató la orquestación de la timeline a las 14:39Z y, ocho horas
después, hizo caer `wazuh-agentd` al fallar la rotación de medianoche (último keep-alive 21:59:56Z).**
Nada de red, ni de configuración de Wazuh, ni de actualizaciones, ni OOM, ni reinicio de VM.

# `resultado.md` — evidencia operativa host-side (L1, `legitimo_72h`)

> Registro **host-side** de la preparación, el **ensayo general** y (tras `t1`) la ejecución de la
> ventana. Complementa a `legitimo_host_control.log` y `vigilancia_legitimo.log` (UTC).
> **Fecha del ensayo:** 2026-10-18 (fuera de ventana).

## 1. Ventana (sellada)

- **`t0` = 2026-10-19T00:00:00Z** (= 2026-10-19 02:00 local, Europe/Madrid CEST +02:00)
- **`t1` = 2026-10-22T00:00:00Z** (= 2026-10-22 02:00 local) · **72 h** exactas · **no cruza DST**.
- PC encendido y **sin suspensión**; **cero acceso** a la víctima en `[t0,t1]`.

## 2. Ensayo general (2026-10-18 20:08–20:53Z) — **PASA** ✅

| Paso del ensayo | Resultado |
|---|---|
| `prep`: revert `lab-listo-legit` + VMs + manager + internet local + GHOSTS + `logall_json` ON | **OK** (manager `active`, agente `001` `Active`, `<logall_json>yes</logall_json>`) |
| Aislamiento desde la víctima (NAT off) | **OK**: 8080/9090/9092 responden; `example.com` y `1.1.1.1` **fallan**; `ip route` **sin default** |
| Rotación de `archives.json` | **NO rota**: `/var/ossec/logs/archives/` tiene **1** fichero `archives.json` (+ `archives.log` a 0) |
| Entrega de `timeline_72h.json` (servidor) y persistencia en `config/timeline.json` | **OK** (persistida; `Status=Run`, `UtcTimeOn=12:00:00`, `Loop=true`) |
| **`drytest`** (timeline con ventanas abiertas, 180 s) | **OK**: **209 acciones** (`Command` 111 + `Curl` 87), **4/4 handlers** ejecutados (por `command` en `history_timeline`) |
| **Rastro en Wazuh** (marcadores en `alerts.json` del manager) | **OK**: `/usr/bin/curl` 116 · `intranet.local` 93 · `/usr/bin/gzip` 36 · `copia_noche` 33 · `nube.local` 30 · `/usr/bin/tar` 29 · `/usr/bin/md5sum` 14 · `actas/acta_reunion.txt` 6 |
| Cliente estable con la timeline de régimen (fuera de ventana) | **OK** (vivo tras el arranque; sin recarga en caliente) |
| Tarea del invitado `TFG-Ghosts-Legit` (systemd timer) | **OK**: `NEXT = 2026-10-19 01:55:00 CEST` = **2026-10-18 23:55:00Z = t0−5min** |
| Extracción ensayada: copiar `archives.json` **antes** de apagar `logall_json` | **OK**: copiado (26 844 225 B, `sha256 533f83ef…`), `M total=2474 / endpoint=2271` (ventana 20:41–20:45Z) |
| Contador de acciones GHOSTS | **OK**: 214 acciones (Command 120 + Curl 94) → `ghosts_acciones.csv` |
| `logall_json off` + restauración de `ossec.conf` | **OK**: `<logall_json>no</logall_json>`, **`CONFIG_IDENTICA`** (diff con `ossec.conf.tfg-bak`), **`archives.json` BORRADO** por el `off` (demuestra la regla de copiar antes) |
| Limpieza | **OK**: 0 VMs, 0 procesos (python/dotnet/postgres), 0 reglas `TFG-*`, VMs apagadas |

### 2.1 Hallazgos del ensayo (declarados)

1. **GHOSTS v8.3.1 — el cliente Linux muere al recargar la timeline en caliente.** Al recibir un
   `Timeline` por el servidor, reescribe `config/timeline.json`; el `FileSystemWatcher` dispara
   `Orchestrator.OnChanged` → `Thread.Interrupt()` sobre los handlers → `ThreadInterruptedException`
   **no capturada** → el proceso termina (`logs/app.log`: "All threads have been stopped" y fin).
   **Mitigación adoptada:** (a) la timeline se **coloca en disco con el cliente parado**; (b) se
   **purgan** las `machine_updates` pendientes (evita updates rezagados → recarga); (c) la entrega
   **por servidor** se mantiene como vía del plan, pero con el cliente parado después.
2. **`sudo -n` (ticket cacheado) es intermitente** en SSH sin TTY (`use_pty` en sudoers). Los
   scripts de comprobación del bloque usan **`sudo -S` por comando** (contraseña por STDIN). Los
   scripts de L0 (`logall_json_ctl.sh`, `arrancar_manager.sh`, `exportar_denominador.sh`) siguen
   funcionando en la práctica, pero se declara el riesgo (§9 del plan).
3. **Tasa de `archives.json` mayor que la estimación de L0.** Medido: **26,8 MB en 37,5 min
   ≈ 43 MB/h** con actividad intensa (dry test) — frente a los ~4,17 MB/h de fondo de L0.
   **Proyección a 72 h:** 8 h/día de actividad + 16 h/día de fondo ⇒ **≈ 1,2 GB** (≪ 5 GB ⇒ **no**
   fallback), pero **~4× menos margen** que la estimación de L0. **La vigilancia registra el tamaño
   de `archives.json`** para detectar desviaciones.
4. **`OnCalendar` con sufijo `UTC` funciona** en el systemd de la víctima (Ubuntu 24.04): el timer
   muestra `NEXT 01:55 CEST` = `23:55Z`.
5. **Ventanas nocturnas de GHOSTS:** `WorkingHours.Is` **no soporta ventanas que cruzan medianoche**
   (`timeOff < timeOn`): al estar dentro, duerme hasta el día siguiente. Por eso la franja de noche
   es `00:45–04:45Z` (sin cruzar medianoche), como en el plan.

## 3. Chequeos pre-`t0` (2026-10-18) — **PASA** ✅

- **Suspensión/hibernación:** `STANDBYIDLE` AC **0x0** · `HIBERNATEIDLE` AC **0x0** (nunca).
  *Plan de energía: **Equilibrado** (el plan pedía "alto rendimiento"); con suspensión/hibernación a 0
  el criterio V8 se cumple. Declarado.*
- **Snapshots originales intactos:** `victima-linux` = `base-limpia`, `lab-listo`, **`lab-listo-legit`**;
  `wazuh-server` = `base-limpia`, `lab-listo`.
- **Disco:** host `D:` **≈ 197 GiB libres**; manager `/` **22 G libres** (52 % usado) para ~1,2 GB de archives.
- **Limpieza:** 0 VMs encendidas · 0 procesos de prueba · 0 reglas de firewall `TFG-*` ·
  `logall_json = no` · `ossec.conf` restaurado.
- **Tareas del host `Ready`** con `NextRun` correcto (hora local): `TFG-Legit-Prep` 19/10 01:15 ·
  `TFG-Legit-Arm` 19/10 01:40 · `TFG-Legit-Watch` 19/10 05:00 (cada 3 h, 72 h) · `TFG-Legit-Stop` 22/10 02:05.

## 4. Durante la ventana (2026-10-19 → 2026-10-22)

- Log de vigilancia (`vigilancia_legitimo.log`) cada 3 h: *pendiente* (lo escribe `TFG-Legit-Watch`).
  Cada línea: GHOSTS (`statusUp`/`lastReportedUtc`), manager, agente `001`, tamaño del diario,
  tamaño de `archives.json`, `logall_json`, disco.
- Anomalías: *pendiente*.

## 5. Extracción (tras `t1`)

- **Orden:** 1) copiar `archives.json` → 2) `contar_denominador.py` → 3) `logall_json off`.
- Productos: `Dataset/Legitimo/legitimo_72h/{denominador_M.csv, ghosts_acciones.csv,
  alertas_detalle.csv, ruleids_legitimos.csv}` (+ `denominador/`).
- Validez V1–V8 y veredicto: `Dataset/Legitimo/legitimo_72h/ventana_meta.md`.

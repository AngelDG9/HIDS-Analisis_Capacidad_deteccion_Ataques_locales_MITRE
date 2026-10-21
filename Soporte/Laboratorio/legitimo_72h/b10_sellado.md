# `b10_sellado.md` — sidecar del **sellado B10** (config del legítimo) — **v2**

> **Qué es.** Los **valores reales y las huellas** con los que se sella la **bóveda B10**
> (`Soporte/Metrica/boveda_congelacion.md`, "Config del legítimo"): GHOSTS + "internet local" +
> instrumentación del denominador. `legitimo-fix` **no puede tocar `Soporte/Metrica/`**
> (protegido): este **sidecar** lo redacta el bloque y **el humano/orquestador** aplica la
> actualización a B10 y recalcula `boveda_congelacion.sha256`.
>
> Huellas completas en `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` (`sha256`, minúsculas).
> Fecha: **2026-10-21** (bloque `legitimo-fix`, v3).
>
> **Decisión del humano (gate Q8):** **bump de `boveda_version` a 2** al aplicar B10 (cambia la
> config del legítimo: log, tope, receta, keepalive y vigilancia).

## B10 — Contenido del sello (v2)

| Elemento | Valor / huella |
|---|---|
| **GHOSTS (servidor + cliente)** | `github.com/cmu-sei/GHOSTS` **v8.3.1** → commit `4d2e160860f508f699f935472b5515358f534844` → .NET 8 → PostgreSQL 16.15 (portable, `initdb -A trust`, solo `127.0.0.1`) |
| **Cliente Linux** | `src/ghosts.client.linux` (*self-contained*) en `victima-linux` (`/home/angel/ghosts-client`); `config/application.json` → `ApiRootUrl=http://192.168.65.1:5000/api` |
| **`nlog.config` (NUEVO, arreglo)** | consola **`Warn`** (`<logger name="*" minlevel="Warn" writeTo="console" />`), `app.log` **1 MB × 20**, `clientupdates.log` 500 KB × 20. Copia versionada: `Soporte/Laboratorio/ghosts/client_config/nlog.config` — `sha256` en `sha256sums.txt` |
| **Tope de stdout (NUEVO)** | `client_ctl.sh` v2: `TFG_CLIENT_OUT_MAX_MB=20` + `client.out.1` ⇒ **máximo 40 MB**; `copytruncate` acotado (se conservan los últimos 20 MB) |
| **Timeline de régimen** | **receta v1** = `recetas/d1.json` (111) · `d2.json` (117) · `d3.json` (105); activa **`d1`**; rotación diaria `d1→d2→d3` a **07:45Z** (día 1 **saltado** por `rotacion.estado`, que siembra `prep`). **Sin pipes de shell** (GHOSTS pierde su reporte). `sha256` en `sha256sums.txt` |
| **Calendario** | `recetas/calendario.json` + `recetas/bloques.env` (misma fuente para keepalive y vigilancia): B1 08:00–08:12, B2 08:12–10:00, P1 10:00–10:20, B3 10:20–13:00, P2 13:00–14:00, B4 14:00–16:15, B5 16:15–17:00 (UTC) |
| **Sesión web *browser-like*** | 8 acciones **dentro del handler `Command`**: UA fija `TFG-Legit/1.0 (Linux; x86_64; sesion-web)`, cookie jar `~/.cache/tfg-web/cookies.txt`, `Referer`, `Accept`/`Accept-Encoding`, **3 requisitos** (CSS+JS+SVG) y **descarga real del PDF**. **0** handlers `Browser*` |
| **Navegador headless** | **DESCARTADO** (`browser_eval.md`, **DT-B0 FAIL**: 12 librerías ausentes y **3,4 GB** libres < 3,5 GB). `receptor_navegador=none` |
| **Keepalive** | **v3**: heartbeat = **última acción reportada** (`lastReportedUtc` de la API de GHOSTS; `app.log` NO sirve: el hilo de updates lo refresca cada 20 s con el motor muerto), calendario, `STALE=30`, `GRACIA=15`, `CONFIRMA=5`, `MAX_RECUP=2`, `MAX_ARRANQUES=3`, `COOLDOWN=30`, `MIN_FREE_MB=1000`, `ROTACION_UTC=07:45`, `ram_free_mb` post-hoc. `guest/tfg_keepalive.sh` (`sha256` en `sha256sums.txt`) |
| **Política de rotación** | **2 reinicios** en la ventana (día 1 se salta: el sha ya coincide); estado en `rotacion.estado`; registro `accion=rotacion` en `recovery.log` |
| **Política de recuperación** | **2** como máximo; 2 confirmaciones separadas ≥ 5 min; solo dentro de bloque; nunca con < 1000 MB libres; registro `accion=recuperacion` |
| **Vigilancia** | `watch` cada **30 min**: **9 señales = 7 en vivo + 2 post-hoc** (RAM y `recovery.log`) con calendario; `watch_manager.py` lee el manager (solo lectura). **No** lee la víctima |
| **`df`: telemetría retirada / `df -h /` de usuario** | **No** hay `df` **de telemetría** añadido a la timeline (la sonda que proponía la v1 **se eliminó**): el disco lo reporta el **agente** (`<localfile><command>df -P</command><frequency>360</frequency>`) y la vigilancia lo lee por **offset incremental** (**0** cambios en Wazuh). **Sí** hay **`df -h /` de usuario**: **4** en total — 1 en **B5** de `d1`, 1 en **B5** de `d2` y **2** en `d3` (**B3** y **B5**). Es una acción legítima de usuario (mirar el disco al repasar / al cerrar), **presente y declarada** (plan §5.3), **no** telemetría |
| **"Internet local" — web estática (8080)** | `internet_local/serve_site.py` + `site/**` (index, noticias, ayuda, styles.css, portal.js, assets/logo.svg, descargas/{manual_empleado.pdf, paquete_datos.zip, plantilla_informe.csv}); `sha256` en `sha256sums.txt` |
| **"Internet local" — paste/C2 (9090)** | `Soporte/Ataques/receiver/sink_http.py` |
| **"Internet local" — nube WebDAV (9092)** | `Soporte/Ataques/receiver/sink_webdav.py` |
| **Puertos** | `5000` (GHOSTS API, `192.168.65.1`) · `8080` (web) · `9090` (paste) · `9092` (nube), firewall acotado a `192.168.65.0/24` |
| **Instrumentación `M`** | `<logall_json>yes</logall_json>` → `/var/ossec/logs/archives/archives.json`; rotación diaria a `ossec-archive-<DD>.json.gz`; `logall_json_ctl.sh` v2 con **reinicio robusto** |
| **Extracción de `M`** | `exportar_denominador.sh copiar-ventana` (`.gz` por día + vivo + `MANIFEST.tsv` + dedupe `sha256`) y `contar_denominador.py` (`--estricto`, `--manifest`, dedupe). Regla de borde `[t0,t1]` inclusivo |
| **Tarea del invitado** | `guest/tfg-ghosts-legit.{timer,service}` (fecha **parametrizada**, `Persistent=false`) + `guest/tfg_keepalive.sh`; arranca a `t0−5 min` |
| **Snapshot** | **`lab-listo-legit-v2`** (`snapshot_v2.md`); `lab-listo-legit` **se conserva**; evidencia en `fallo-2026-10-19-disco-lleno-NO-USAR` |
| **Config de la ventana** | `t0`/`t1` los firma el humano en el gate de `legitimo-72h-v2` (propuesta **26/10 00:00Z → 29/10 00:00Z**); Wazuh virgen `C1={RS1,RS2}`; `logall_json` **ON solo** en `[t0,t1]` |

## Lo que **declara** este bloque (para que B10 no maquille nada)

1. **El `M` baja**: 333 acciones frente a ~5,9 k del intento fallido ⇒ menos eventos y **FPR más
   bajo por construcción**. El TFG informará **siempre** `acciones/h` y `M` junto al FPR.
2. **2 rotaciones** (reinicios del cliente) + hasta **2 recuperaciones** + hasta **3 arranques**:
   son **actividad del banco**, declarada y acotada (~40–60 eventos, 0,002–0,004 % de `M`).
3. **`app.log` a 21 MB** (1 MB × 21) y `client.out` a **≤ 40 MB**.
4. **Los `df -P` del agente** (≈240/día, ≈7 líneas cada 6 min) **ya estaban en `M`**: no son
   instrumentación nueva, pero se declaran para que nadie los cuente como actividad del usuario.
5. **La RAM no se vigila en tiempo real** (no hay señal pasiva sin tocar la víctima): G-12 en
   `prep` y lectura **post-hoc** en `keepalive.log`.
6. **La VM tiene swap** (~1,9 GB) aunque el plan asumía 0: se **declara**; no se toca la VM
   (sería cambiar el banco antes de medir). `verificar_arreglos.sh` lo reporta como `AVISO`.
7. **El navegador no entra**: `browser_eval.md` con DT-B0 FAIL (librerías + disco).
8. **GHOSTS pierde el reporte de los comandos con `pipe`**: la receta no usa `|` (hallazgo de DT9;
   antes daba 108/111 y ahora 111/111).
9. **El cliente reescribe `config/timeline.json` al arrancar** (mismo contenido, sha distinto): la
   verificación compara **sha + huella de comandos** con el cliente parado, y la rotación se decide
   por `rotacion.estado`, no por sha.

- **`metrica_version`** = `1` → **`boveda_version`** = **`2`** (bump aprobado en Q8; lo aplica el
  humano/orquestador recalculando `boveda_congelacion.sha256`).
- **Trazabilidad:** L0 dejó montada y *pinneada* la infra; L1 falló por el stdout sin tope
  (`fallo_2026-10-19/`); `legitimo-fix` arregla la causa, rediseña la actividad y sella **v2**.

# `legitimo_72h` (L1) — captura de 72 h de actividad legítima

> **Qué es.** Utilidades de **preparación, arranque/parada, vigilancia y extracción** del bloque
> **L1** (`legitimo-72h`): **72 h continuas** de actividad legítima (GHOSTS + "internet local")
> sobre `victima-linux` con **Wazuh virgen** + `logall_json` **ON solo en la ventana**.
> Plan de referencia: **`plan.md`** (raíz, `status: approved_by_human`).
>
> **Ventana sellada (UTC):** **`t0 = 2026-10-19T00:00:00Z`** → **`t1 = 2026-10-22T00:00:00Z`**
> (72 h exactas; medianoche UTC = **02:00 local** Europe/Madrid, CEST +02:00; **no cruza el DST** del 2026-10-25).
> Ficha de la ventana: `Dataset/Legitimo/legitimo_72h/ventana_meta.md`.

---

## 1. Ficheros

| Fichero | Qué es |
|---|---|
| `legitimo_host_control.ps1` | Control **del HOST** con fases `prep` · `arm` · `watch` · `stop` · `drytest` · `cleanup` · `status` |
| `armar_legitimo.ps1` | Atajo de `-Phase arm` |
| `vigilancia_legitimo.ps1` | Atajo de `-Phase watch` (vigilancia pasiva, sin tocar la víctima) |
| `registrar_tareas.ps1` | Registra/verifica/elimina las **tareas del host** (`schtasks`) y gestiona el secreto de usuario |
| `timeline_72h.json` | **Timeline de régimen** de las 72 h (GHOSTS) — **versionada** (`sha256sums.txt`) |
| `guest/` | Tarea del **invitado** (`TFG-Ghosts-Legit`): `tfg-ghosts-legit.timer`/`.service` + `tfg_keepalive.sh` + `instalar_tarea_invitado.sh` |
| `exportar_denominador.sh` | (MANAGER) Copia `archives.json` **antes** de apagar `logall_json` + informa de la rotación |
| `exportar_acciones.sh` | (HOST) Exporta el **contador de acciones** GHOSTS (`history_timeline`) en `[t0,t1]` |
| `resultado.md` | Evidencia operativa host-side (ensayo + ventana) |
| `b10_sellado.md` | **Sidecar del sellado B10** (lo aplica el humano/orquestador en `Soporte/Metrica/`) |
| `legitimo_host_control.log` · `vigilancia_legitimo.log` | Logs (UTC) generados al ejecutar |
| `sha256sums.txt` | Huellas `sha256` de los ficheros de este directorio |

Helper nuevo del denominador: **`_artefactos/scripts/contar_denominador.py`** (+ tests).

---

## 2. Secuencia operativa (todo por tareas; **nada en segundo plano**)

| Tarea | Ámbito | Hora **local** (Madrid) | Hora UTC | Qué hace |
|---|---|---|---|---|
| **`TFG-Legit-Prep`** | host | 2026-10-19 **01:15** | `t0−45min` | revert `lab-listo-legit` · start víctima+manager · `arrancar_manager` · internet local · GHOSTS · firewall `TFG-ghosts-5000` · **`logall_json` ON** · aislamiento · reconciliar máquina GHOSTS · **entregar `timeline_72h.json`** |
| **`TFG-Legit-Arm`** | host | 2026-10-19 **01:40** | `t0−20min` | instala la **tarea del invitado** · arranca el cliente · **checklist §4.1-D** |
| **`TFG-Ghosts-Legit`** | **invitado** | 2026-10-19 **01:55** | `t0−5min` | systemd timer → arranca el cliente GHOSTS y lo **mantiene vivo** (relanza si muere) |
| **`TFG-Legit-Watch`** | host | 2026-10-19 **05:00** cada **3 h** | en `[t0,t1]` | vigilancia pasiva (GHOSTS API + manager), **sin tocar la víctima** |
| **`TFG-Legit-Stop`** | host | 2026-10-22 **02:05** | `t1+5min` | `stop víctima soft` (el **manager sigue encendido** para la extracción) |

Registro de tareas del host (re-ejecutable): `powershell -File registrar_tareas.ps1`
y verificación: `powershell -File registrar_tareas.ps1 -Verificar`.

> **⚠️ Secreto.** `TFG-Legit-Prep`/`TFG-Legit-Arm` necesitan la contraseña de las VMs
> (`TFG_GUEST_PW`, `TFG_MANAGER_PW`), que se leen **del entorno**. Para el arranque automático
> hay que dejarlas como **variable de entorno de usuario** *antes* de las 01:15 locales y borrarlas
> después (`registrar_tareas.ps1 -SetSecret` / `-ClearSecret`); alternativa: ejecutar `prep`/`arm`
> a mano con sesión delante. **La contraseña NUNCA se escribe en un fichero del repositorio.**

---

## 3. La timeline de 72 h (diseño declarado)

`timeline_72h.json` — 4 handlers, todos `Loop: true`, **ventanas UTC diarias** (franjas de
referencia del plan: **noche `00:45–04:45Z`** y **tarde `12:00–16:00Z`**):

| Handler | Ventana (UTC) | Qué hace |
|---|---|---|
| `Command` jornada | `12:00–16:00` | ficheros de oficina: `mkdir/echo/cat/cp/gzip/tar/md5sum/sha256sum/ls/find/du/wc/df` en `~/Documentos` y `~/Descargas` |
| `Curl` jornada | `12:00–16:00` | web local `:8080` (intranet/noticias/ayuda), descargas, `POST /paste` `:9090`, subida a la nube `:9092` y `PROPFIND` |
| `Command` madrugada | `00:45–04:45` | copia de seguridad nocturna + sellos + `md5sum` + `ls` |
| `Curl` madrugada | `00:45–04:45` | sincronización nocturna (noticias, subida a la nube, paste) |

- **Lanzamiento en `Loop`, ventana repetida cada día** ⇒ actividad en **día y noche** todos los días.
- **Idempotente y acotada en disco:** todos los comandos **sobrescriben** (nada de `>>`), así que no
  crece el disco ni el timeline se "agota" durante 72 h.
- **Hallazgo (declarado):** en **GHOSTS v8.3.1**, `WorkingHours.Is` **no soporta bien las ventanas
  que cruzan medianoche** (`UtcTimeOff < UtcTimeOn`): al estar dentro, calcula el siguiente
  arranque **al día siguiente** y **duerme**. Por eso la franja de noche se expresa **sin cruzar
  medianoche** (`00:45–04:45`) y no como `22:00–06:00`.
- **Cobertura declarada:** con las **dos franjas de referencia** la actividad GHOSTS ocupa
  **8 h/día** (noche + tarde); el resto del día el endpoint sigue generando **ruido de fondo**
  (auditd/syscheck/SCA) que también entra en el denominador `M`. *(Decisión: fidelidad al plan §4.2.
  Si el humano quiere más densidad, se amplían las franjas **antes de `t0`**.)*

### ⚠️ Hallazgo de GHOSTS v8.3.1 (condiciona la entrega de la timeline)

- **El cliente Linux MUERE si la timeline se recarga en caliente.** Al recibir un `Timeline` por el
  servidor, el cliente reescribe `config/timeline.json`; el `FileSystemWatcher` dispara
  `Orchestrator.OnChanged` → `StopCommon()` → `Thread.Interrupt()` sobre los handlers en ejecución →
  la `ThreadInterruptedException` **se relanza sin capturar** → **el proceso termina** (visto en
  `logs/app.log`: "All threads have been stopped" y fin del proceso).
- **Consecuencia:** entregar la timeline a un cliente **en marcha** lo mata (aunque la deja
  **escrita** en disco antes de morir). Por eso el mecanismo usado es:
  1. **cliente PARADO** → **purgar** `machine_updates` pendientes de la máquina (evita que un update
     rezagado dispare la recarga) → **colocar** `timeline_72h.json` en `config/timeline.json`
     (`scp`+`cp`, mecanismo **determinista**) → **arrancar** el cliente (lee el fichero, no hay
     recarga ⇒ **estable**);
  2. y de forma **complementaria** se usa la **entrega por el servidor**
     (`ghosts_api.py send-timeline`, vía del plan §4.1-B7) **con el cliente parado después**.
- El **keepalive** del invitado (`TFG-Ghosts-Legit`) relanza el cliente si muere; como el fichero
  ya está en disco y **no hay updates pendientes**, cada relanzamiento arranca **estable**.
- **Purga de updates:** `delete from machine_updates where machineid = '<id>'` (PostgreSQL local del
  host); el script lo hace en `prep`, `arm` y `drytest`.

### Prueba en seco de la timeline (`-Phase drytest`)

Fuera de ventana, en **minutos**: deriva `timeline_72h.dry.json` (mismos eventos con las **ventanas
abiertas** ⇒ `WorkingHours.Is` las ignora) para poder ejercitar **los 4 handlers a la vez** en
cualquier hora, entrega la timeline, deja correr ~150 s y comprueba:
**(a)** ≥ 1 acción por `handler` en `history_timeline`; **(b)** rastro visible por Wazuh
(marcadores de la actividad en el manager). Después **restaura** `timeline_72h.json` en el cliente.

---

## 4. Extracción (después de `t1`, víctima parada, manager encendido)

> **⚠️ ORDEN CRÍTICO.** `logall_json_ctl.sh off` ejecuta `rm -f archives.json` ⇒ **BORRA el
> denominador**. Por eso: **1) COPIAR `archives.json` → 2) contar `M` → 3) `logall_json off`.**

1. **Denominador `M`** (manager):
   ```powershell
   # 1) copiar (sin apagar logall_json)
   <pw> | ssh … manager "bash /tmp/exportar_denominador.sh copiar"
   scp -r angel@192.168.65.128:/tmp/legit_denominador/*  Dataset/Legitimo/legitimo_72h/denominador/
   # 2) contar
   python _artefactos/scripts/contar_denominador.py --desde 2026-10-19T00:00:00Z --hasta 2026-10-22T00:00:00Z `
       --out Dataset/Legitimo/legitimo_72h/denominador_M.csv Dataset/Legitimo/legitimo_72h/denominador/archives.json
   # 3) APAGAR (restaura ossec.conf y borra archives.json)
   <pw> | ssh … manager "bash /tmp/logall_json_ctl.sh off"
   ```
   `M` **titular** = fila `endpoint` (agente `001`); **complemento** = fila `total`.
2. **Acciones GHOSTS** (host): `bash exportar_acciones.sh 2026-10-19T00:00:00Z 2026-10-22T00:00:00Z`
   → `Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv`.
3. **Alertas** (manager, **fichero diario** — **3 días**): `ossec-alerts-<19|20|21>.json`
   con `_artefactos/scripts/extraer_alertas.py` **sin modificar** (`--detail` por día → unión →
   filtrar a `agent_name == victima-linux` y cruzar `agent.id == 001`).
4. **Ficha** `Dataset/Legitimo/legitimo_72h/ventana_meta.md` (validez V1–V8) y **sellado B10**
   (`b10_sellado.md`).

---

## 5. Disciplina en `[t0,t1]` (regla dura)

- **CERO** acceso a `victima-linux`: ni SSH, ni `vmrun … runProgramInGuest`, ni consola GUI, ni snapshots.
- El **manager** se consulta **por SSH de solo lectura** (no es la VM medida).
- **No** se cambia config (Wazuh/GHOSTS/internet local) dentro de la ventana.
- **PC encendido y sin suspensión** los 3 días (plan de energía; verificar antes de `t0`).

## 6. Higiene

- La contraseña **nunca** en un fichero del repositorio (STDIN/variables de entorno en memoria).
- `_recursos/`, corpus, `Hojas/`, `Soporte/Metrica/` **sin tocar**; en `Dataset/` **solo** la carpeta
  nueva `Dataset/Legitimo/legitimo_72h/`. **Sin `git commit`/`push`** (los hace el orquestador/humano).

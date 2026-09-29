# ATA035 · T1056.004 — Credential API Hooking (`LD_PRELOAD`, binario de laboratorio)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda B**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA035** |
| Técnica | **T1056.004 — Credential API Hooking** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG; las atómicas de ART son Windows) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS que ejercita | **ejecución de proceso** (`execve`); la **carga del módulo** no genera telemetría |

## 2. Qué hace y dónde escribe

- **Qué hace:** **hook de la API de libc** por **`LD_PRELOAD`** sobre un binario **de
  laboratorio** (`credfetch`) para **capturar credenciales simuladas**: un token por variable de
  entorno (`getenv`) y una contraseña leída de fichero (`fgets`). El hook (`hook.so`) registra lo
  interceptado en `hook_capture.log`.
- **Distinto de ATA018/T1056.001** (keylogging) y **ATA028/T1056.003** (portal falso): aquí el
  mecanismo es la **intercepción de la API** del propio proceso.
- **Destino:** todo bajo `/home/angel/lab-attack/ATA035/`.
- **Capa del HIDS que ejercita:** **`execve` del proceso de laboratorio** (`80792`). La
  **carga del `.so`** (`LD_PRELOAD`) y la **intercepción** son **invisibles** (punto ciego).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Payload | `hook.so` + `credfetch` (C propio) |
| Compilador en la víctima | **NO existe** (`gcc`/`cc`/`make`/`as`/`ld` **ausentes**) |
| **Fallback (R1)** | **payload precompilado**: se compila en la máquina con toolchain y se versiona como `.b64` (texto); la víctima lo **decodifica** (`base64 -d`) |
| Herramientas en la víctima | `base64`, `chmod`, `sha256sum`, `cat`, `grep` (de serie) |
| Elevación | **no** |
| Guardarraíl | `LD_PRELOAD` **solo** apunta al `hook.so` bajo `lab-attack/ATA035/`; **solo** se ejecuta el proceso **de laboratorio** (nunca procesos del sistema) |

> **Nota de despliegue declarada:** la víctima no tiene compilador; el payload se compila **fuera**
> (máquina con `gcc`) y se transporta como texto `.b64`. Es el **fallback previsto en el plan**
> (R1: «`.so` precompilado»). `ATA035_hook.c` / `ATA035_credfetch.c` quedan versionados para
> transparencia y reproducibilidad.

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA035` y `scp -r` del directorio de la técnica ahí
   (incluye los `.b64`).
2. `cd /home/angel/lab-attack/ATA035 && bash ATA035_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA035_esperado.csv`:

- `T1056.004-S1` (**deteccion**) `audit_exe=/home/angel/lab-attack/ATA035/credfetch` — el proceso
  de laboratorio con el hook (`80792`).
- `T1056.004-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA035/*` — ancla H4.
- `T1056.004-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — creación/escritura de los ficheros
  del payload (efecto) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` del **proceso de laboratorio** (`credfetch`, `80792`, nivel 3).
- **Punto ciego declarado:** el HIDS **no ve** la **carga del módulo** ni la **intercepción de la
  API** (audit no registra el entorno ni la carga del `.so`): ve el *proceso*, no el *hook*.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: `hook_capture.log` contiene el **token de entorno** y la **contraseña del fichero**
capturados por el hook (`capturado_token_env=1`, `capturado_password_file=1`). Evidencia en
`Logs/ATA035_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`; las credenciales son **de juguete**; no se toca ningún proceso,
  servicio ni cuenta real.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (las credenciales son
> simuladas, nunca reales); **el entorno no tiene usuarios/servicios reales** y **las rutas del
> ataque son conocidas por el analista**.

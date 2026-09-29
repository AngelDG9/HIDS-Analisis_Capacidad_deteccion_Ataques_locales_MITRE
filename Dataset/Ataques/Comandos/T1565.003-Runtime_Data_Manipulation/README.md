# ATA036 · T1565.003 — Runtime Data Manipulation (memoria de proceso, `ptrace`)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda B**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA036** |
| Técnica | **T1565.003 — Runtime Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS que ejercita | **proceso** (`execve` de la herramienta); la manipulación en memoria no genera telemetría |

## 2. Qué hace y dónde escribe

- **Qué hace:** **manipula un dato EN EJECUCIÓN (memoria)** de un proceso **de laboratorio**:
  `memedit` se **adjunta por `ptrace`** al proceso `target`, **localiza** su dato en uso en las
  regiones escribibles (`/proc/<pid>/maps` + `process_vm_readv`) y lo **sobrescribe**
  (`PTRACE_POKEDATA`): `SALDO=1000` → `SALDO=9999`, mientras el proceso sigue corriendo.
- **Contraste:** distinto de **T1565.001 Stored** (reposo, ATA032) y **T1565.002 Transmitted**
  (tránsito, ATA026). Aquí el dato se altera **en memoria**.
- **Destino:** todo bajo `/home/angel/lab-attack/ATA036/`; **solo** se toca el proceso
  **de laboratorio** `target` (guardarraíl: `/proc/<pid>/exe == $BASE/target`).
- **Capa del HIDS que ejercita:** **`execve` de la herramienta** (`80792`). El **`ptrace`** y la
  **escritura en memoria** son **invisibles** con este ruleset (punto ciego).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Payload | `memedit` (manipulador) + `target` (proceso de laboratorio) — C propio |
| Compilador en la víctima | **NO existe** (`gcc`/`cc`/`make` **ausentes**); **`gdb` tampoco** |
| **Fallback (R1)** | **payload precompilado**: se compila en la máquina con toolchain y se versiona como `.b64` (texto); la víctima lo **decodifica** (`base64 -d`) |
| Herramientas en la víctima | `base64`, `chmod`, `sha256sum`, `readlink`, `kill`, `grep`, `cat` |
| Elevación | **no** |
| Guardarraíl | **solo** el proceso de laboratorio `target` (verificado por `readlink -f /proc/<pid>/exe`); **jamás** un proceso del sistema |

> **Nota de despliegue declarada:** la víctima no tiene compilador ni `gdb`; el payload se compila
> **fuera** y se transporta como texto `.b64` (fallback R1). `ATA036_target.c` / `ATA036_memedit.c`
> quedan versionados.
>
> **Nota `yama` (declarada, paso 0/incidente):** Ubuntu trae `kernel.yama.ptrace_scope=1` → un
> proceso **no padre** no puede adjuntarse. Se detectó en un **primer intento de iter1**
> (`PTRACE_ATTACH: Operation not permitted`; ventana **descartada**). `ATA036_target.c` (proceso
> **de laboratorio**) se **declara trazable** con `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` → el
> ataque **no necesita `sudo`** ni cambiar el `sysctl` del sistema. **Cómo lo aprovecha el atacante
> en un caso real:** si el proceso objetivo **no** es trazable, el atacante necesita privilegios
> (`CAP_SYS_PTRACE`) — limitación declarada.

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA036` y `scp -r` del directorio de la técnica ahí
   (incluye los `.b64`).
2. `cd /home/angel/lab-attack/ATA036 && bash ATA036_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA036_esperado.csv`:

- `T1565.003-S1` (**deteccion**) `audit_exe=/home/angel/lab-attack/ATA036/memedit` — la herramienta
  de manipulación (`80792`).
- `T1565.003-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA036/*` — ancla H4.
- `T1565.003-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — creación/escritura del payload y del
  fichero de estado (efecto) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de la **herramienta** (`memedit`, `80792`, nivel 3).
- **Punto ciego declarado:** el HIDS **no ve** la **manipulación en memoria** (ni `ptrace` ni la
  escritura en `/proc/<pid>/mem`): ve la *herramienta*, no el *efecto sobre el dato*. Es de las
  capas **habitualmente poco cubiertas**.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: `target_state.log` muestra el dato **ANTES** (`SALDO=1000`) y **DESPUÉS**
(`SALDO=9999`) del proceso **en ejecución** (`ocurrencias_antes≥1`, `ocurrencias_despues≥1`).
Evidencia en `Logs/ATA036_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`; **no** queda ningún proceso `target`/`memedit` vivo (el guion los
  termina); no se toca ningún proceso, servicio ni cuenta real.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (el dato manipulado es
> simulado y el proceso objetivo es de laboratorio, nunca del sistema); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**.

# ATA018 · T1056.001 — Keylogging (captura de entrada, custom contenido)

> Artefacto del bloque `fase-03-ampliacion`, **tanda A**. Redactado el **2026-09-29** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Validación humana:
> **APROBADO 2026-09-29**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA018** |
| Técnica | **T1056.001 — Input Capture: Keylogging** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (adaptación **contenida** del enfoque de ART *«Logging bash history to syslog»*) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** captura la **entrada de una sesión de terminal** (comandos + una **credencial
  SIMULADA** de juguete) con un **wrapper** que registra todo lo tecleado a un fichero, y **persiste**
  el keylog en **syslog** con `logger`.
- **Destino:** captura en `/home/angel/lab-attack/ATA018/keylog_capture.log` (**NO vigilado** → sin
  FIM/`watch`); **syslog** vía `logger` (journald → regla de fábrica `40700`, `level=0`).
- **Mecanismo OCULTO (sorpresa):** el registro de la entrada es «silencioso» a nivel de host: la
  captura vive en una ruta no vigilada y el `logger` cae en `40700` (que **no alerta**, §8.3 del
  runbook). La detección declarada es el **`execve` del wrapper** (`tee`/`logger`).

## 3. ⚠️ Contención declarada (guardarraíl)

- **NO** se toca `pam_tty_audit`, ni `auditd` real, ni `/etc`, ni el historial real del usuario.
  El ataque es **contenido**: registra una **sesión simulada** de juguete.
- La «credencial» (`ClaveDemo-Fake123`) es **simbólica**; **nunca** una contraseña real.

## 4. Herramienta, dependencias y elevación

| Elemento | Valor (paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`tee`, `logger`, `bash`, `grep`, `wc`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 5. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA018/`.
2. `cd /home/angel/lab-attack/ATA018/ && bash ATA018_ataque.sh 2>&1 | tee ejecucion.out`.

## 6. Señales esperadas (convención H4)

`ATA018_esperado.csv`:

- `T1056.001-S1` (**deteccion**) `audit_exe=tee` — wrapper que captura la entrada (`80792`).
- `T1056.001-S2` (**deteccion**) `audit_exe=logger` — persistencia del keylog en syslog.
- `T1056.001-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA018/*` — ancla H4.

> **Sin señales `ambigua`:** la técnica **no escribe** en `lab-legit`; la captura queda en
> `lab-attack` (no vigilado) → sus `execve` no declarados caen en `artefacto_ataque` (auto).

## 7. Hipótesis de detección

- **DETECTADO** por el `execve` de **`tee`/`logger`** (`80792`, nivel 3) anclado al `cwd` del ataque.
- La **escritura** de la captura **no** genera `watch`/FIM (ruta no vigilada) y la persistencia en
  **syslog** cae en **`40700` (level 0)** → **no alerta** (punto conocido, declarado).

## 8. Prueba de éxito (independiente de la alerta)

El fichero de captura contiene los **comandos tecleados** y la **credencial simulada** (≥5 líneas,
incluye `ClaveDemo-Fake123` y `whoami`) ⇒ la **entrada quedó registrada**. Evidencia en
`Logs/ATA018_iter*/ejecucion.out`.

## 9. Reversión e higiene

- **Reversión:** víctima a **`lab-listo`**; el manager **no** se revierte.
- **Higiene:** sin contraseñas reales; credencial **simbólica** declarada.

## 10. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**; **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. La sesión y
> la credencial son **de juguete** con **nombres creíbles**, pero **no son datos reales**.

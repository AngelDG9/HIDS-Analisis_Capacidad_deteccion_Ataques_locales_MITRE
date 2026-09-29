# ATA015 · T1114.003 — Email Forwarding Rule (regla de reenvío, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda A**. Redactado el **2026-09-29** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Validación humana:
> **APROBADO 2026-09-29**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA015** |
| Técnica | **T1114.003 — Email Collection: Email Forwarding Rule** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (mecanismo de persistencia; sin red) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **NO roba** correo: **crea una REGLA DE REENVÍO** (persistencia) para que el correo
  futuro de la víctima se reenvíe a un buzón del atacante. Es una **escritura de fichero** de
  configuración (`.forward` + `.procmailrc`) — mecanismo **distinto** de «leer» (ATA014).
- **Destino:** `/home/angel/lab-legit/.forward` y `/home/angel/lab-legit/.procmailrc` (**VIGILADO**
  → evento `watch`); copia en `/home/angel/lab-attack/ATA015/collected/`.
- **Capa del HIDS que ejercita:** **`watch`/file-creation** (escritura en ruta vigilada) + `execve`.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`cat`, `grep`, `cp`, `mkdir`, `sha256sum`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA015/`.
2. `cd /home/angel/lab-attack/ATA015/ && bash ATA015_ataque.sh 2>&1 | tee ejecucion.out`.

## 5. Señales esperadas (convención H4)

`ATA015_esperado.csv`:

- `T1114.003-S1` (**deteccion**) `audit_exe=cat` — **creación** de la regla de reenvío (`80792`).
- `T1114.003-S2` (**deteccion**) `audit_exe=cp` — copia de la regla a la carpeta del ataque.
- `T1114.003-S3` (**deteccion**) `audit_exe=grep` — lectura/verificación de la regla.
- `T1114.003-S4` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA015/*` — ancla H4.
- `T1114.003-A1/A2/A3` (**ambigua**) `rule_id ∈ {80790, 80781, 80782}` — **creación bajo watch**
  en `lab-legit` (efecto) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de **`cat`/`cp`/`grep`** (`80792`, nivel 3) anclado al `cwd`.
- La **creación** de la regla dispara **`watch`** (`80790/80781`), declarada **`ambigua`**
  (**efecto**, no detección): el `esperado` decide qué cuenta como detección.

## 7. Prueba de éxito (independiente de la alerta)

La regla de reenvío existe, **contiene el destino del atacante** (`dropbox@exfil-lab.example`,
**simbólico**) y la copia en `lab-attack` es **idéntica** (`sha256`). Evidencia en
`Logs/ATA015_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** víctima a **`lab-listo`**; el manager **no** se revierte.
- **Higiene:** sin contraseñas reales; el dominio de reenvío es **simbólico de laboratorio**
  (no es un buzón real). No se toca el MTA ni `/etc`.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**; **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Datos **de
> juguete** con **nombres creíbles**, pero **no datos reales**.

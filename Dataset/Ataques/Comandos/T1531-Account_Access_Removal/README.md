# ATA024 · T1531 — Account Access Removal (usuario desechable, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda C**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA024** |
| Técnica | **T1531 — Account Access Removal** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **con `sudo`** (`sudo -S` por stdin) |

## 2. Qué hace y dónde escribe

- **Qué hace:** **sabotea el acceso** a una cuenta: crea un usuario **DESECHABLE**
  (`tfg-victim01`), le **bloquea** la contraseña (`passwd -l`) y lo **elimina** (`userdel -r`).
  Toca las capas **auth/PAM/syslog** y los **ficheros de cuentas**.
- **Destino:**
  - Ficheros de cuentas: `/etc/passwd`, `/etc/shadow`, `/etc/group` (vía `useradd`/`passwd`/`userdel`).
  - Home desechable `/home/tfg-victim01` (creado con `-m` y borrado con `userdel -r`).
- **Capa del HIDS que ejercita:** **`execve` de las herramientas de cuentas** + el **`watch` de
  `/etc`** (`auditd -w /etc -p wa`) que ve las **escrituras** sobre los ficheros de cuentas.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `useradd`, `userdel`, `passwd`, `id`, `grep`, `sha256sum`, `ls` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **sí**: `sudo` **solo** para `useradd`/`passwd`/`userdel` (`sudo -S` por stdin) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA024/`.
2. Pasar la contraseña de `sudo` **por el entorno** o **por stdin** (1.ª línea), nunca en el guion:

   ```bash
   cd /home/angel/lab-attack/ATA024
   SUDO_PW='<contrasena>' bash ATA024_ataque.sh 2>&1 | tee ejecucion.out
   # o:  printf '%s\n' '<contrasena>' | bash ATA024_ataque.sh 2>&1 | tee ejecucion.out
   ```

   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA024_esperado.csv`:

- `T1531-S1/S2/S3` (**deteccion**) `audit_exe ∈ {useradd, userdel, passwd}` — gestión de la cuenta
  desechable (`80792`).
- `T1531-S4` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA024/*` — ancla H4.
- `T1531-A1/A2/A3` (**ambigua**) `rule_id ∈ {80790, 80781, 80782}` — escrituras bajo el **watch**
  de `/etc` (efecto del ataque) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **Nota:** el agente **no** recolecta `/var/log/auth.log`; las reglas syslog `5902`/`5903`
> (`new user`/`delete user`) **no se declaran**. Si aparecieran, serían `novel` (no declaradas) y
> se reportarían como **anexo**.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `useradd`/`passwd`/`userdel` (`80792`, nivel 3) anclado al
  `cwd` del ataque.
- Las **escrituras** en `/etc/passwd`/`/etc/shadow` disparan el `watch` (`80790/80781/80782`),
  declarado **`ambigua`** (efecto, no detección declarada).

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: `id tfg-victim01` **falla**, su home **no existe**, `cuentas_tfg_restantes = 0` y
`/etc/passwd` **cambió** (`sha256` antes ≠ después). Evidencia en
`Logs/ATA024_iter*/ejecucion.out` + `usuario_creado.txt` / `cuenta_bloqueada.txt`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`). El manager **no** se
  revierte. El guion lleva un **`trap` de limpieza** que elimina el usuario desechable si quedara
  creado.
- **Higiene:** la contraseña de `sudo` **nunca** se escribe en el repo (entorno/stdin); no hay
  datos reales. La cuenta desechable es de **juguete**.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se sabotéan cuentas
> reales: **solo** un usuario desechable); **el entorno no tiene usuarios/servicios reales** y
> **las rutas del ataque son conocidas por el analista**.

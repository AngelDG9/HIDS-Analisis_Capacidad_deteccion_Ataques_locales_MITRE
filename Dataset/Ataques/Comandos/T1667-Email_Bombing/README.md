# ATA031 · T1667 — Email Bombing (Maildir local, custom)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda A**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA031** |
| Técnica | **T1667 — Email Bombing** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **satura un buzón local simulado** por **volumen**: entrega **N = 25** mensajes
  acotados en un **Maildir de juguete**. El mecanismo es el **volumen**, distinto de **ATA014**
  (leer buzón) y **ATA015** (regla de reenvío).
- **Destino:** `/home/angel/lab-legit/Maildir/new/` (ruta **VIGILADA** por `auditd`.
- **Capa del HIDS que ejercita:** **`execve`** de las entregas (`cp`) + **`watch`**
  (creación/escritura masiva).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `cp`, `mkdir`, `ls`, `wc`, `du` (de serie) |
| Dependencias | ninguna nueva; **no hay MTA** local (no se instala nada) |
| Elevación | **no** |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA031` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA031 && bash ATA031_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA031_esperado.csv`:

- `T1667-S1` (**deteccion**) `audit_exe=/usr/bin/cp` — entrega de cada mensaje (`80792`).
- `T1667-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA031/*` — ancla H4.
- `T1667-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — escrituras bajo el **watch** de
  `lab-legit` → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **Nota (MTA):** **no hay MTA local** instalado; el plan contemplaba «posible syslog del MTA».
> Se **declara no aplicable**: la capa disponible es `execve` + `watch`, no syslog de correo.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `cp` (`80792`) anclado al `cwd` del ataque (una alerta por
  entrega) + el **volumen** visible en el `watch`.
- La **capa de volumen** (creación masiva) se ve por el `watch`, declarado **`ambigua`** (efecto).

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: el Maildir gana **25** mensajes (`delta_mensajes=25`), el recuento pasa de `antes` a
`antes+25` y el tamaño del directorio crece. Evidencia en `Logs/ATA031_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra el Maildir de juguete). El manager
  **no** se revierte.
- **Higiene:** **cota dura `N ≤ 50`** (aborta si se supera); no hay `sudo`, ni secretos, ni correo
  real (todo de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se satura correo real:
> el buzón es simulado y el volumen está **acotado**); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**.

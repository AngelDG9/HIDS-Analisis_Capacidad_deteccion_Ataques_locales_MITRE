# ATA033 · T1491.001 — Internal Defacement (webroot interno, custom)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda A**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA033** |
| Técnica | **T1491.001 — Internal Defacement** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG; las atómicas de ART son Windows) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **defacement interno**: reescribe la **raíz web de un portal interno** simulado
  (`index.html`), sustituyendo el contenido servido. Distinto de **ATA007/T1491** (defacement
  genérico): aquí el **objeto** es el **webroot de la intranet**.
- **Destino:** `/home/angel/lab-legit/intranet_web/index.html` (ruta **VIGILADA**).
- **Capa del HIDS que ejercita:** **`execve`** (`cp`) + **`watch`** sobre el webroot.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `cp`, `mkdir`, `head`, `grep`, `sha256sum`, `awk` (de serie) |
| Dependencias | ninguna nueva; **el fichero `deface_internal.html` viaja con el artefacto** |
| Elevación | **no** |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA033` y `scp -r` del directorio de la técnica ahí
   (incluye `deface_internal.html`).
2. `cd /home/angel/lab-attack/ATA033 && bash ATA033_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA033_esperado.csv`:

- `T1491.001-S1` (**deteccion**) `audit_exe=/usr/bin/cp` — reescritura del `index.html` (`80792`).
- `T1491.001-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA033/*` — ancla H4.
- `T1491.001-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — escrituras bajo el **watch** de
  `lab-legit` → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **Nota de capa (declarada):** el plan preveía «FIM sobre el webroot»; el `syscheck` del agente
> **no** vigila `lab-legit` (solo `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`), de modo que la capa
> real disponible es el **`watch` de auditd** (`-w /home/angel/lab-legit`). Se declara con
> honestidad: el efecto va por el `watch` (declarado `ambigua`), no por FIM.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `cp` (`80792`) anclado al `cwd` del ataque.
- El cambio del webroot es visible por el **`watch`** (`80790/80781`), declarado **`ambigua`**.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: el `sha256` del `index.html` **antes ≠ después** y el marcador `COMPROMETIDA` está
presente. Evidencia en `Logs/ATA033_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`, ni secretos, ni contenido ofensivo (defacement de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se modifica un portal
> simulado, nunca un webroot real); **el entorno no tiene usuarios/servicios reales** y **las rutas
> del ataque son conocidas por el analista**.

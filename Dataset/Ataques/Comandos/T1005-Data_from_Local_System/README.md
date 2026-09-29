# ATA029 · T1005 — Data from Local System (recolección dirigida, custom)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda A**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA029** |
| Técnica | **T1005 — Data from Local System** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **recolección dirigida** (una **lista declarada**) de ficheros locales concretos:
  los datos de juguete viven en `lab-legit/srv_data/` y se **copian** a la carpeta del ataque.
  No es una búsqueda exhaustiva (eso es **T1119/ATA012**): el atacante sabe **qué** ficheros
  quiere.
- **Destino:**
  - **Lectura:** `/home/angel/lab-legit/srv_data/{empleados_2026.csv,notas_direccion.txt,config_servicio.conf}` (ruta **VIGILADA**).
  - **Copia (loot):** `/home/angel/lab-attack/ATA029/loot/`.
- **Capa del HIDS que ejercita:** **`execve` del lector** (`cp`) + confirmación de la lección
  **«leer no deja rastro»** (`-p wa` no audita lectura).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `cp`, `mkdir`, `cat`, `grep`, `sha256sum`, `awk`, `ls` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA029` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA029 && bash ATA029_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA029_esperado.csv`:

- `T1005-S1` (**deteccion**) `audit_exe=/usr/bin/cp` — el lector que recolecta (`80792`).
- `T1005-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA029/*` — ancla H4.
- `T1005-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — escrituras bajo el **watch** de
  `lab-legit` (semilla) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **Lección «leer no deja rastro»:** el `watch` es `-p wa` (write/attribute); **leer** no alerta.
> La recolección se detecta por el **`execve` del lector**, no por el acceso.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `cp` (`80792`, nivel 3) anclado al `cwd` del ataque.
- Las **escrituras** de la semilla en `lab-legit` disparan el `watch` (`80790/80781`), declarado
  **`ambigua`** (efecto, no detección declarada).

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: los **3** ficheros declarados están en `loot/` con **`sha256` idéntico** al original
(`coincidencias_sha256=3/3`). Evidencia en `Logs/ATA029_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`; `lab-legit` vuelve a
  estar vacío). El manager **no** se revierte.
- **Higiene:** no hay `sudo`, ni secretos, ni datos reales (datos de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se exfiltran datos
> reales: los datos son simulados); **el entorno no tiene usuarios/servicios reales** y **las rutas
> del ataque son conocidas por el analista**.

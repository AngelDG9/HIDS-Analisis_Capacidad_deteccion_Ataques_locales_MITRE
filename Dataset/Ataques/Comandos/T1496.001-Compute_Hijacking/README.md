# ATA025 · T1496.001 — Compute Hijacking (carga de CPU acotada, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda C**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA025** |
| Técnica | **T1496.001 — Resource Hijacking: Compute** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **roba cómputo**: lanza una **carga de CPU sostenida y acotada** (2 procesos
  `yes` a pleno rendimiento bajo `timeout 10s`), simulando minería. No escribe datos: consume
  **CPU**.
- **Destino:** CPU de la víctima. Evidencia en la carpeta del ataque (medidas de `/proc/stat`).
- **Capa del HIDS que ejercita:** **`execve`** (`timeout`, `yes`). Interés: **no hay capa de
  red/FIM**; el HIDS de host **no tiene reglas de CPU/recursos**.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `timeout` (coreutils), `yes`, `awk`, `cat`, `sleep`, `nproc` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA025/`.
2. `cd /home/angel/lab-attack/ATA025 && bash ATA025_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA025_esperado.csv`:

- `T1496.001-S1` (**deteccion**) `audit_exe=yes` — proceso de carga de CPU (`80792`).
- `T1496.001-S2` (**deteccion**) `audit_exe=timeout` — lanzador acotado (`80792`).
- `T1496.001-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA025/*` — ancla H4.

> **No hay señales `ambigua`:** no hay escritura vigilada ni fichero de datos.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `yes`/`timeout` (`80792`, nivel 3) anclado al `cwd` del ataque.
- **Punto ciego esperado:** Wazuh **no tiene reglas de CPU/recursos** → el **consumo** no se ve;
  si el consumo se hiciera con **builtins del shell** (p. ej. un bucle `while`), **no habría
  `execve`** y sería **invisible**. Se declara como hallazgo (R9).

## 7. Prueba de éxito (independiente de la alerta)

La CPU pasa de **`busy` bajo** a **`busy` alto sostenido** (calculado de `/proc/stat` durante la
ventana) y `loadavg` sube; al terminar **0 procesos `yes` vivos**. Evidencia en
`Logs/ATA025_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** sin contraseñas, claves ni datos reales. Cero red, cero NAT.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (la carga está **acotada**
> a segundos y **no** se busca tumbar nada); **el entorno no tiene usuarios/servicios reales** y
> **las rutas del ataque son conocidas por el analista**.

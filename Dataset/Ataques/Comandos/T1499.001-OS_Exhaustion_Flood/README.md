# ATA045 · T1499.001 — OS Exhaustion Flood (memoria acotada, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda A** (2.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA045** |
| Técnica | **T1499.001 — Endpoint DoS: OS Exhaustion Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1499) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **agota la memoria del SO de forma acotada**: llena `/dev/shm/ATA045_fill`
  (tmpfs RAM-backed) con `dd` hasta un **tope fijo (512 MiB)** bajo `timeout`, lo mantiene
  unos segundos y lo **libera**. Mide `MemAvailable` antes/durante/después.
- **Capa del HIDS que ejercita:** **`execve`** (`dd`/`timeout`/`free`/`rm`). **No hay** reglas
  de CPU/RAM en Wazuh → el **consumo no se ve** (hallazgo R9).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `dd`, `timeout`, `free`, `rm`, `sleep`, `awk` (de serie) |
| Dependencias | ninguna nueva · `/dev/shm` = 1.5 G tmpfs |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | `MAX_MB ≤ 768`, `HOLD ≤ 15 s`, relleno bajo `timeout`, `trap` de limpieza |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio a `/home/angel/lab-attack/ATA045/`.
2. `cd /home/angel/lab-attack/ATA045 && bash ATA045_ataque.sh 2>&1 | tee ejecucion.out`.

## 5. Señales esperadas (convención H4)

`ATA045_esperado.csv` (todas `deteccion`):

- `T1499.001-S1..S4` `audit_exe ∈ {dd, timeout, free, rm}` (`80792`).
- `T1499.001-S5` `audit_cwd=/home/angel/lab-attack/ATA045/*` — ancla H4.

> **Sin señales `ambigua`:** no hay fichero vigilado (el relleno va a tmpfs) ni red.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `dd`/`timeout` (`80792`, nivel 3) anclado al `cwd`.
- **Punto ciego esperado:** Wazuh **no tiene reglas de recursos** → el agotamiento de memoria
  **no se ve**; solo el proceso. Con *builtins* no habría `execve` → invisible (R9).

## 7. Prueba de éxito (independiente de la alerta)

`MemAvailable` cae ~`MAX_MB` **durante** el relleno y se **recupera** tras liberarlo; `0`
residuo. Evidencia en `Logs/ATA045_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** el relleno está **acotado** a segundos y a un tmpfs; **nunca** toca disco real,
  swap persistente ni el manager. `trap` borra el fichero temporal.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (agotamiento **acotado** a
> 512 MiB y ~segundos; **no** se tumba nada); **el entorno no tiene usuarios/servicios reales** y
> **las rutas del ataque son conocidas por el analista**.

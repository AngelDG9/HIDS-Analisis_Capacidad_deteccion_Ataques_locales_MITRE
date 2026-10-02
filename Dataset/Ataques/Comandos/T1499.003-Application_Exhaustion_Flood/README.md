# ATA046 · T1499.003 — Application Exhaustion Flood (app local desechable, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda A** (3.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA046** |
| Técnica | **T1499.003 — Endpoint DoS: Application Exhaustion Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1499) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Pre-staging (fuera de `[t0,t1]`):** `ATA046_prestaging.sh` levanta una **app local desechable
  mono-hilo** (`ATA046_app.py`) en **`127.0.0.1:9093`**; su endpoint `/compute` realiza un cálculo
  **caro pero acotado** (PBKDF2-HMAC-SHA256). Registra su `PID`.
- **Acción de la ventana:** `ATA046_ataque.sh` envía una **ráfaga acotada de peticiones caras**
  (`curl`, con concurrencia limitada), mide la CPU consumida por la app (`/proc/<pid>/stat`) y
  comprueba que sigue viva.
- **Destino:** SOLO `http://127.0.0.1:9093/compute` (loopback). **NUNCA** el manager ni red real.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `curl`, `xargs`, `seq`, `timeout`, `awk`, `sort`; app en `python3` (solo pre-staging) |
| Dependencias | ninguna nueva (Python stdlib) |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | `TOTAL ≤ 64`, `CONC ≤ 8`, `MAX_TIME ≤ 15 s`; destino fijado a loopback |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio a `/home/angel/lab-attack/ATA046/`.
2. **Pre-staging** (antes de `t0`): `bash ATA046_prestaging.sh`.
3. `cd /home/angel/lab-attack/ATA046 && bash ATA046_ataque.sh 2>&1 | tee ejecucion.out`.
4. Parar la app tras `t1`: `kill "$(cat app.pid)"`.

## 5. Señales esperadas (convención H4)

`ATA046_esperado.csv` (todas `deteccion`):

- `T1499.003-S1..S4` `audit_exe ∈ {curl, xargs, seq, timeout}` (`80792`).
- `T1499.003-S5` `audit_cwd=/home/angel/lab-attack/ATA046/*` — ancla H4.

> **⚠️ Punto ciego declarado:** la **app** es `python3` (regla de fábrica `92600` suprime su
> `execve`), pero arranca en el **pre-staging** (fuera de la ventana): la detección de la
> **acción** (el flood de `curl`) **no** depende de `python3`.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `curl`/`xargs` (`80792`, nivel 3) anclado al `cwd`.
- **No hay** reglas de recursos → el **grado de saturación** de la app no se ve; solo el proceso.

## 7. Prueba de éxito (independiente de la alerta)

La app registra en `app.log` las `TOTAL` peticiones `compute_s`; su **CPU** sube (delta de
`/proc/<pid>/stat`) y sigue **viva** tras la ráfaga. Evidencia en `Logs/ATA046_iter*/`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack` y mata la app). El manager **no** se revierte.
- **Higiene:** app **de juguete**, solo loopback; sin credenciales ni datos reales.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: la «aplicación» es un
> **servicio local simulado** de juguete (loopback, mono-hilo); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**.

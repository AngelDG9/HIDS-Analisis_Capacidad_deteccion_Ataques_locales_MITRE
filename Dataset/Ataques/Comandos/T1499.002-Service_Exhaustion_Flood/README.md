# ATA047 · T1499.002 — Service Exhaustion Flood (servicio local desechable, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda A** (4.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA047** |
| Técnica | **T1499.002 — Endpoint DoS: Service Exhaustion Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1499) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Pre-staging (fuera de `[t0,t1]`):** `ATA047_prestaging.sh` levanta un **servicio local
  desechable** (el receptor `sink_http.py`, propio) en **`127.0.0.1:9094`** (loopback), registra PID.
- **Acción de la ventana:** `ATA047_ataque.sh` lanza una **ráfaga acotada por VOLUMEN** de
  peticiones concurrentes (`curl`), mide el **volumen recibido** (`service.log`) y la CPU del
  servicio, y comprueba que sigue vivo.
- **Destino:** SOLO `http://127.0.0.1:9094/ping` (loopback). **NUNCA** el manager ni red real.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `curl`, `xargs`, `seq`, `timeout`, `awk`, `wc`; servicio = `sink_http.py` (Python stdlib) |
| Dependencias | ninguna nueva |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | `TOTAL ≤ 800`, `CONC ≤ 32`, `MAX_TIME ≤ 15 s`; destino fijado a loopback |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio + `sink_http.py` a `/home/angel/lab-attack/ATA047/`.
2. **Pre-staging** (antes de `t0`): `bash ATA047_prestaging.sh`.
3. `cd /home/angel/lab-attack/ATA047 && bash ATA047_ataque.sh 2>&1 | tee ejecucion.out`.
4. Parar el servicio tras `t1`: `kill "$(cat svc.pid)"`.

## 5. Señales esperadas (convención H4)

`ATA047_esperado.csv` (todas `deteccion`):

- `T1499.002-S1..S4` `audit_exe ∈ {curl, xargs, seq, timeout}` (`80792`).
- `T1499.002-S5` `audit_cwd=/home/angel/lab-attack/ATA047/*` — ancla H4.

> **⚠️ Declarado:** el **servicio** es `python3` (arranca en el pre-staging, fuera de ventana);
> la detección de la **acción** (el flood de `curl`) **no** depende de `python3`.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `curl`/`xargs` (`80792`, nivel 3) anclado al `cwd`.
- **No hay** reglas de recursos/servicio → el **volumen** no se ve; solo el proceso.

## 7. Prueba de éxito (independiente de la alerta)

El `service.log` registra un **delta ≥ TOTAL** de peticiones recibidas durante la ráfaga y la CPU
del servicio sube ⇒ el servicio absorbió el flood. Evidencia en `Logs/ATA047_iter*/`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack` y mata el servicio). El manager **no** se revierte.
- **Higiene:** servicio **de juguete**, solo loopback; sin credenciales ni datos reales.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servicio» es un
> **listener local simulado** de juguete (loopback); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**.

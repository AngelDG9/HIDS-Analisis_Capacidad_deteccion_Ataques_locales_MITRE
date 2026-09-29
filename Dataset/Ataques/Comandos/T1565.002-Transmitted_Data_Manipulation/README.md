# ATA026 · T1565.002 — Transmitted Data Manipulation (proxy local, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda C**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA026** |
| Técnica | **T1565.002 — Data Manipulation: Transmitted Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **manipula el dato EN TRÁNSITO**. Un **proxy local** (`nc | sed | nc`) reescribe
  el cuerpo (`importe=100` → `importe=9999`) **antes** de reenviarlo al receptor; el efecto es la
  **alteración**, no el robo. El emisor envía el dato **intacto**; lo que cambia es lo que **llega**.
- **Destino:** proxy `127.0.0.1:8082` → receptor del **HOST** `192.168.65.1:9091` (**VMnet1**).
- **Capa del HIDS que ejercita:** **`execve`** de `nc`/`sed`. **El HIDS de host NO ve la red** →
  la prueba del efecto es el **`sink.log`** del receptor (sha recibido).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`nc`** (OpenBSD), `sed`, `timeout`, `sha256sum` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Receptor | `Soporte/Ataques/receiver/sink_http.py --tcp-port 9091` (HOST) |
| Elevación | **no** (usuario `angel`) |

## 4. Cómo se ejecuta

1. **Receptor en el HOST** (antes de `t0`):

   ```powershell
   python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
     --tcp-port 9091 --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA026_iterN\sink.log"
   ```

2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA026/`.
3. `cd /home/angel/lab-attack/ATA026 && bash ATA026_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA026_esperado.csv`:

- `T1565.002-S1` (**deteccion**) `audit_exe=nc` — proxy local y emisor (`80792`).
- `T1565.002-S2` (**deteccion**) `audit_exe=sed` — reescritura **en tránsito** (`80792`).
- `T1565.002-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA026/*` — ancla H4.

> **No hay señales `ambigua`:** no hay escritura local vigilada.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `nc`/`sed` (`80792`, nivel 3) anclado al `cwd` del ataque.
- **Invisible al HIDS de host:** el HIDS **no ve la red** → **no** detecta que el cuerpo llegó
  alterado; lo único visible es el **proceso**. (Hallazgo: la manipulación en tránsito es de las
  técnicas que el HIDS de host **no puede** distinguir del envío legítimo por su contenido.)

## 7. Prueba de éxito (independiente de la alerta)

`sha256_original` ≠ `sha256_manipulado_esperado`, y el **`sink.log`** del receptor registra un
cuerpo con el **sha manipulado** (el dato llegó alterado). Evidencia en
`Logs/ATA026_iter*/ejecucion.out` + `sink.log`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
  **Parar el receptor** tras `t1`.
- **Higiene:** dato de juguete; sin credenciales, sin NAT, sin servicios externos. El proxy queda
  acotado por `timeout`.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (proxy y receptor **locales**;
> no se rompe la red del laboratorio); **el entorno no tiene usuarios/servicios reales** y **las
> rutas del ataque son conocidas por el analista**.

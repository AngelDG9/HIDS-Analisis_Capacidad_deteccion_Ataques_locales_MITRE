# ATA023 · T1496.002 — Bandwidth Hijacking (transferencia masiva **acotada** al receptor)

> Artefacto del bloque `fase-03-ampliacion`, **tanda B** (3.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA023** |
| Técnica | **T1496.002 — Resource Hijacking: Bandwidth** |
| Táctica | **Impact** |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

T1496.002 **sí aplica a Linux**, pero la biblioteca ART no trae una prueba Linux utilizable sin NAT.
El «hijacking de ancho de banda» se simula con una **transferencia masiva acotada** al receptor local:
demuestra el mecanismo (consumo de banda) sin salir del laboratorio ni saturar nada.

## 3. Qué hace y dónde escribe

- **Qué hace:** **consume ancho de banda** de forma **acotada**: genera un flujo de **32 MiB** de
  ceros (`head -c … /dev/zero`) y lo vuelca al receptor del HOST (`curl`).
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA023/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090`** →
  `POST /api/bw/hog`. El manager **NO** ejecuta nada (es el detector).
- **Sin artefacto persistente:** el dato son ceros; no se escribe nada en el sistema real.

## 4. ⚠️ Acotación y qué **NO** se toca (regla dura)

- **ACOTADO (aborta):** volumen **FIJO** de **32 MiB** y `--max-time 15 s`; guardarraíl en el guion
  que rechaza topes > 64 MiB / > 30 s. **Unos segundos**, no se satura nada.
- **Sin NAT**: **no** se sale a internet; el receptor es **infraestructura local** (VMnet1).
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.

## 5. Señales esperadas (convención H4)

`ATA023_esperado.csv`:

- `T1496.002-S1` (**deteccion**) `audit_exe=curl` — transferencia masiva (`80792`).
- `T1496.002-S2` (**deteccion**) `audit_exe=head` — generación del flujo acotado (`80792`).
- `T1496.002-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA023/*` — ancla H4.

> **Hipótesis honesta (R9):** Wazuh **no trae reglas de red ni de recursos** en esta configuración →
> se espera detección **solo por el `execve`** (`curl`/`head`), **no** por el consumo de banda. Si no
> hubiera proceso externo (p. ej. hecho con *builtins*), sería un **punto ciego**. La prueba del efecto
> la da el `sink.log` (32 MiB recibidos).

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`head`**, **`curl`** (`/usr/bin/curl`, 8.5.0), **`sha256sum`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `head`/`curl` no deben caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA023_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA023/`.
3. `cd /home/angel/lab-attack/ATA023/ && bash ATA023_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /api/bw/hog from=192.168.65.129 len=33554432 sha256=<H>` (32 MiB)
⇒ la transferencia **ocurrió de verdad**. Evidencia en `Logs/ATA023_iter*/sink.log` + `ejecucion.out`.

## 9. Receptor y firewall — cómo se levanta y se retira (reutiliza ATA009)

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA023_iter1\sink.log"
# Comprobar desde la víctima:
#   timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO
# Si BLOQUEADO, añadir la regla acotada:
#   netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
# Parar tras t1 y retirar la regla (si se creó):
#   netsh advfirewall firewall delete rule name="TFG-sink-9090"
#   netsh advfirewall firewall show rule name="TFG-sink-9090"   # -> "Ninguna regla coincide"
```

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servicio» es un
> **receptor local simulado** (sin NAT, sin nube, sin credenciales); la transferencia está
> **acotada a unos segundos** y **no satura** nada; **el entorno no tiene usuarios/servicios reales**
> y **las rutas del ataque son conocidas por el analista**. Los datos son **ceros** (no hay datos
> reales en juego).

# ATA020 · T1020 — Automated Exfiltration (bucle de subida al receptor del HOST)

> Artefacto del bloque `fase-03-ampliacion`, **tanda B** (2.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA020** |
| Técnica | **T1020 — Automated Exfiltration** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

El fenómeno de la técnica es la **automatización**: un proceso recorre «todo» lo recolectado y lo
exfiltra **sin intervención**. La biblioteca ART no trae una prueba Linux utilizable sin NAT para
T1020, así que se escribe a mano un guion que **itera** sobre un directorio de *staging* y sube cada
fichero. Es distinto de `ATA009` (T1567, **un** fichero) y de `ATA010` (T1041, **un** canal C2).

## 3. Qué hace y dónde escribe

- **Qué hace:** **exfiltra de forma automatizada** un **conjunto** de ficheros ya «recolectados»
  (`clientes.csv`, `facturas.csv`, `nominas.csv`, `contratos.csv`): un bucle recorre el *staging* y
  hace un `curl` POST **por fichero**, sin intervención.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA020/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090`** →
  `POST /api/exfil/<fichero>`. El manager **NO** ejecuta nada (es el detector).
- **Semilla:** los ficheros de *staging* se crean con `printf` (builtin, contenido fijo) ⇒
  **determinista** e idempotente.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el «servicio» es el **receptor local** del laboratorio
  (VMnet1). **No** se instala nada, **no** se usan claves ni cuentas.
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.
- Guardarraíles en el guion: el endpoint **DEBE** ser `http://192.168.65.1:9090/…` y el *staging*
  **DEBE** estar bajo `lab-attack/ATA020` (aborta si no).

## 5. Señales esperadas (convención H4)

`ATA020_esperado.csv`:

- `T1020-S1` (**deteccion**) `audit_exe=curl` — cliente de subida en bucle (`80792`), una por fichero.
- `T1020-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA020/*` — ancla H4.

> La **red no es visible** para el HIDS de host: la detección es el **proceso** `curl`; la **prueba**
> de la exfiltración es el `sink.log` del HOST (una línea con `sha256` por fichero). **Sin** señales
> `ambigua` (no hay escritura bajo *watch*).

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramienta | **`curl`** (`/usr/bin/curl`, 8.5.0), **`sha256sum`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `curl` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA020_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA020/`.
3. `cd /home/angel/lab-attack/ATA020/ && bash ATA020_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra **una línea por fichero** (`POST /api/exfil/<fichero> from=192.168.65.129
len=<N> sha256=<H>`); cada `<H>` **coincide** con el `sha256` del fichero correspondiente que el guion
imprime ⇒ los datos **salieron** de la víctima. Evidencia en `Logs/ATA020_iter*/sink.log` +
`ejecucion.out`.

## 9. Receptor y firewall — cómo se levanta y se retira (reutiliza ATA009)

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA020_iter1\sink.log"
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
> **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa) pero **no son datos reales**.

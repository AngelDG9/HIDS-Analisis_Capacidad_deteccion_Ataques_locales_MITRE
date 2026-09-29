# ATA019 · T1048.001 — Symmetric Encrypted Non-C2 Protocol (`openssl enc` + TCP crudo)

> Artefacto del bloque `fase-03-ampliacion`, **tanda B** (1.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos** (la «clave» es una *passphrase de juguete* de laboratorio).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA019** |
| Técnica | **T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`ATA008` (T1048.**002**, variante **asimétrica**) usó `openssl` + `wget`. Esta técnica es la
variante **simétrica** (T1048.**001**): cifra con **una sola clave simétrica** (`openssl enc
-aes-256-cbc`) y **envía por un protocolo alternativo no-HTTP** (TCP crudo al receptor del HOST).
La biblioteca ART de T1048.001 no trae una prueba Linux ejecutable **sin NAT**, así que se escribe
a mano.

## 3. Qué hace y dónde escribe

- **Qué hace:** **cifra** un extracto de clientes simulado con clave **simétrica** y lo **envía** por
  **TCP crudo** (`/dev/tcp`, puerto `9091`) al receptor del HOST. Después **descifra** el blob
  (round-trip) para demostrar que el cifrado es simétrico y reversible.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA019/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino (efecto):** el **receptor TCP del HOST** en VMnet1, **`192.168.65.1:9091`**. El manager
  **NO** ejecuta nada (es el detector).
- **Semilla:** el fichero original se crea con `printf` (builtin, contenido fijo) ⇒ **determinista**
  e idempotente. La `passphrase` simétrica es una **clave de juguete** (no es un secreto real).

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el receptor es **infraestructura local** (VMnet1). **No**
  se instala nada, **no** se usan claves ni cuentas reales.
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.
- Guardarraíl en el guion: el destino **DEBE** ser `192.168.65.1:9091` (aborta si no).

## 5. Señales esperadas (convención H4)

`ATA019_esperado.csv`:

- `T1048.001-S1` (**deteccion**) `audit_exe=openssl` — cifrado/descifrado **simétrico** (`80792`).
- `T1048.001-S2` (**deteccion**) `audit_exe=cat` — volcado del blob cifrado al socket TCP.
- `T1048.001-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA019/*` — ancla H4.

> La **red no es visible** para el HIDS de host (no hay reglas de salida en el ruleset base): la
> detección es el **proceso** (`openssl`/`cat`); la **prueba** de la exfiltración es el `sink.log`
> del HOST. **Sin** señales `ambigua` (no hay escritura bajo *watch*).

## 6. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor **con TCP** (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA019/`.
3. `cd /home/angel/lab-attack/ATA019/ && bash ATA019_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 7. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra una línea **`TCP from=192.168.65.129 len=<N> sha256=<H>`**; ese `<H>`
**coincide** con el `sha256` del blob **cifrado** (`…txt.enc`) que el guion imprime ⇒ el dato cifrado
**salió** de la víctima. Evidencia en `Logs/ATA019_iter*/sink.log` + `ejecucion.out`.

## 8. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`openssl`** (`/usr/bin/openssl`, 3.0.x), **`cat`**, **`sha256sum`**, **`awk`** |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `openssl`/`cat` no deben caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA019_logtest.txt`) |

## 9. Receptor y firewall — cómo se levanta y se retira (modo TCP)

`ATA019` usa el receptor del laboratorio (`Soporte/Ataques/receiver/sink_http.py`) con el **modo TCP**
nuevo (`--tcp-port`). **Una sola puesta en marcha por ventana** (HTTP 9090 + TCP 9091, mismo log):

**Levantar (en el HOST / sobremesa), ANTES de `t0`:**

```powershell
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 --tcp-port 9091 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA019_iter1\sink.log"
```

**Comprobar alcance de los puertos (desde la víctima, antes del ataque):**

```bash
timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo HTTP-OK || echo HTTP-BLOQUEADO
timeout 3 bash -c '</dev/tcp/192.168.65.1/9091' && echo TCP-OK  || echo TCP-BLOQUEADO
```

Si **BLOQUEADO**, añadir (una sola vez) la regla de entrada **acotada** al laboratorio:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090,9091 remoteip=192.168.65.0/24
```

**Parar y retirar (tras `t1`, al cerrar la ventana/tanda):**

```powershell
# 1) parar el receptor (Ctrl+C en su consola, o matar el proceso python de sink_http.py)
# 2) retirar la regla de firewall (si se creó)
netsh advfirewall firewall delete rule name="TFG-sink-9090"
# 3) verificar ausencia
netsh advfirewall firewall show rule name="TFG-sink-9090"   # -> "Ninguna regla coincide"
```

> El receptor y la regla se **recrean por ventana** y se **retiran al cerrar** la tanda B (CA10).
> Detalle del receptor: `Soporte/Ataques/receiver/README.md`; runbook: `piloto_procedimiento.md` §3.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** la passphrase es una **clave de juguete** (`TFG-Lab-2026-toy-key`), **no** una
  credencial real; se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servidor de exfiltración»
> es un **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa: extracto de clientes) para que la ventana
> parezca un caso realista, pero **no son datos reales**.

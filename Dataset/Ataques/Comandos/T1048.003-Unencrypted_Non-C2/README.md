# ATA042 · T1048.003 — Unencrypted Non-C2 (`nc.openbsd`, TCP crudo en claro)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda C** (4.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA042** |
| Técnica | **T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica envía el dato **sin cifrar** por un protocolo alternativo no-C2. Se ejecuta como **contraste**
de las variantes cifradas (`ATA019` simétrica, `ATA041` asimétrica): permite comprobar que **el cifrado
no cambia lo que ve el HIDS** (el HIDS ve el **proceso**, no el contenido). ART trae pruebas Linux
(HTTP/python) que requieren `python3` (punto ciego `92600`) o servicios externos → se escribe a mano con
**`nc.openbsd`** (TCP crudo), evitando el punto ciego.

## 3. Qué hace y dónde escribe

- **Qué hace:** envía un extracto de clientes simulado **en claro** por **TCP crudo** al receptor del HOST
  (`nc.openbsd … < fichero`).
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA042/`** (**NO** vigilado → detección del proceso por
  **`execve`**).
- **Destino (efecto):** el **receptor TCP del HOST** en VMnet1, **`192.168.65.1:9091`**.
- **Sin NAT**: el «servidor de exfiltración» es **infraestructura local** (VMnet1). **No** se instala nada.

## 4. ⚠️ Binario real (lección del bloque)

`nc` es un **enlace** a `/etc/alternatives/nc` → **`/usr/bin/nc.openbsd`**. El `execve` de `audit`
registra **`/usr/bin/nc.openbsd`**, no `nc` → el `esperado` declara el **nombre REAL** (`nc.openbsd`).
(Lección: *`audit_exe` con el nombre real del binario o glob*.)

## 5. Señales esperadas (convención H4)

`ATA042_esperado.csv`:

- `T1048.003-S1` (**deteccion**) `audit_exe=nc.openbsd` — envío en claro por TCP crudo (`80792`).
- `T1048.003-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA042/*` — ancla H4.

> La **red no es visible** para el HIDS de host: la detección es el **proceso** (`nc.openbsd`); la
> **prueba** es el `sink.log` del HOST. **Sin** señales `ambigua`.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`nc.openbsd`** (OpenBSD netcat 1.226), **`sha256sum`**, **`stat`**, **`awk`** |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `nc.openbsd` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA042_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor **con TCP** (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA042/`.
3. `cd /home/angel/lab-attack/ATA042/ && bash ATA042_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `TCP from=192.168.65.129 len=<N> sha256=<H>`; ese `<H>` **coincide** con
el `sha256` del fichero **en claro** que el guion imprime ⇒ el dato **salió** de la víctima. Evidencia en
`Logs/ATA042_iter*/` (`sink.log` + `ejecucion.out`).

## 9. Receptor — cómo se levanta y se retira (modo TCP)

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 --tcp-port 9091 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA042_iter1\sink.log"
# Parar tras t1: Ctrl+C / matar el proceso python de sink_http.py
```

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`). El **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servidor de exfiltración» es
> un **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa) pero **no son datos reales**.

# ATA010 · T1041 — Exfiltration Over C2 Channel (`curl` beacon al receptor-C2 del HOST)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda B**. Redactado el **2026-09-29** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA010** |
| Técnica | **T1041 — Exfiltration Over C2 Channel** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Decisión | **D4 opción A** (reutilizar el receptor HTTP del host como C2) |

## 2. Por qué es un ataque manual

`T1041` aparece en `Hojas/cobertura_atomic.csv` como **`solo_windows`** (`tests_linux=0`): Atomic Red
Team **no trae ninguna prueba Linux**. La técnica **sí aplica a Linux**, así que el ataque **se
escribe a mano**.

## 3. Qué hace y dónde escribe

- **Qué hace:** **abre un canal de mando y control (C2)** hacia el host y envía un **beacon**
  (check-in del "implante"), simulando la exfiltración **a través del canal C2**.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA010/`** (**NO** vigilado → detección del
  proceso por **`execve`** de `curl`).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090`** →
  `POST /c2/beacon`. **El manager NO ejecuta nada** (es el detector).
- **Semilla:** el beacon se crea con `printf` (builtin, contenido fijo) ⇒ determinista e idempotente.

## 4. Decisión D4 — por qué se reutiliza el receptor HTTP (opción A)

| Opción | Descripción | Elegida |
|---|---|---|
| **A (rec.)** | Reutilizar `sink_http.py` como **C2 sobre HTTP**; el `curl` que hace el POST es el `execve` visible | **SÍ** |
| B | Listener **TCP** aparte + `nc`/`bash /dev/tcp` | **NO** (no hizo falta: A es viable; curl ya está en la víctima) |
| C | Dejar ATA010 **fuera** del corpus | **NO** (la técnica es viable) |

Motivo: `curl` **existe** en la víctima (paso 0, v8.5.0), **no** se instala nada y **no** se inventa
infraestructura. La opción B (`bash /dev/tcp`) queda como **alternativa documentada** si algún día se
quisiera un mecanismo distinto (LOLBin de shell).

## 5. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el C2 es un **receptor local** del laboratorio (VMnet1).
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.
- Guardarraíl en el guion: el endpoint **DEBE** ser `http://192.168.65.1:9090/…` (aborta si no).

## 6. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramienta | **`curl`** (`/usr/bin/curl`, 8.5.0) |
| Alternativa | `bash /dev/tcp` (LOLBin) con un listener TCP aparte (D4-B) — no usada |
| Elevación | **no** |
| C0 | `curl` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA010_c0_plan.md`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor-C2 (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA010/`.
3. `cd /home/angel/lab-attack/ATA010/ && bash ATA010_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Señales esperadas (convención H4)

`ATA010_esperado.csv`:

- `T1041-S1` (**deteccion**) `audit_exe=curl` — cliente del canal C2 (beacon; `80792`).
- `T1041-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA010/*` — ancla H4 del proceso.

> La **red no es visible** para el HIDS de host (no hay reglas de salida en el ruleset base): la
> detección es el **proceso** `curl`; la **prueba** del canal es el `sink.log` del HOST. **Sin**
> señales `ambigua`.

## 9. Receptor y firewall — cómo se levanta y se retira (compartido con ATA009)

ATA010 reutiliza el **mismo receptor** que ATA009 (y que el piloto de ATA008); **una sola puesta en
marcha por ventana**. El log de esta ventana va a `…/Logs/ATA010_iter1/sink.log`.

**Levantar (en el HOST / sobremesa), ANTES de `t0`:**

```powershell
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA010_iter1\sink.log"
```

**Comprobar el puerto (desde la víctima):**
`timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO`.
Si **BLOQUEADO**, añadir (una sola vez) la regla acotada:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
```

**Parar y retirar (tras `t1`, al cerrar la ventana/tanda):** parar el proceso `sink_http.py`
(Ctrl+C) y `netsh advfirewall firewall delete rule name="TFG-sink-9090"` (verificar ausencia).
Detalle en el README de ATA009 §9 y en `Soporte/Ataques/receiver/README.md`.

## 10. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /c2/beacon` con la **IP de origen** (`192.168.65.129`), la
**longitud** y el **`sha256` del cuerpo**; ese `sha256` **coincide** con el del beacon (impreso por el
guion) ⇒ el beacon **salió** por el canal C2. Evidencia en `Logs/ATA010_iter*/sink.log` +
`ejecucion.out`.

## 11. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 12. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el C2 es un **receptor local
> simulado** (sin NAT, sin infraestructura de mando real); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**. El beacon lleva una huella de
> juguete (host/usuario/SO simulados) para que la ventana parezca un caso realista, pero **no son
> datos reales**.

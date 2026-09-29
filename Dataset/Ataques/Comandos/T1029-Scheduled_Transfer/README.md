# ATA021 · T1029 — Scheduled Transfer (cron de usuario + disparo dentro de la ventana)

> Artefacto del bloque `fase-03-ampliacion`, **tanda B** (4.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA021** |
| Técnica | **T1029 — Scheduled Transfer** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** (crontab de usuario) |

## 2. Por qué es un ataque manual

La técnica es **programar** la transferencia para que la ejecute el **planificador** (cron), no el
operador. La biblioteca ART no trae una prueba Linux ejecutable sin NAT para T1029, así que se
escribe a mano: se instala una **entrada de cron de usuario** que, cada minuto, ejecuta un job que
**exfiltra** un dato al receptor; el guion espera a que el job dispare **dentro de la ventana**.

## 3. Qué hace y dónde escribe

- **Qué hace:** **programa** (crontab de `angel`) una transferencia y **deja que cron la ejecute**
  dentro de `[t0,t1]`; al terminar **retira** la entrada (limpieza). Demuestra la **persistencia**
  (artefacto de job) y el **envío programado**.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA021/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090`** →
  `POST /api/scheduled/dato_programado.csv`. El manager **NO** ejecuta nada.
- **Persistencia:** el fichero de cron (`/var/spool/cron/crontabs/angel`) **NO** está vigilado por
  `auditd` ni por FIM/vigilancia de fábrica → **no genera evento** (hallazgo: la capa de persistencia
  de cron queda **ciega** al HIDS en esta configuración).

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el receptor es **infraestructura local** (VMnet1).
- **Solo el crontab del usuario `angel`**: guardarraíl que **aborta** si ya existe un crontab (no se
  pisa nada) y que **nunca** toca el cron de `root` ni `/etc/cron.*`. Al terminar se **retira** la
  entrada.
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua` de fichero.

## 5. Señales esperadas (convención H4)

`ATA021_esperado.csv`:

- `T1029-S1` (**deteccion**) `audit_exe=crontab` — programación del job (`80792`).
- `T1029-S2` (**deteccion**) `audit_exe=curl` — transferencia programada por cron (cwd anclado).
- `T1029-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA021/*` — ancla H4.
- `T1029-A1` (**ambigua**) `audit_exe=dash` — el lanzador `/bin/sh` de cron (cwd `$HOME`); es
  **contexto** del ataque, no la detección → `dudosa` → veredicto humano.

> **C0 (`ATA021_preflight.md`):** `crontab`/`curl`/`dash` → `80792` **nivel 3** (sin silenciador).
> La **capa syslog de cron no alerta**: las reglas `2830`–`2834` no casan `program_name=CRON` y las
> PAM del `cron:session` (`5521`/`5522`) son **nivel 0**. La **red no es visible** para el HIDS.

## 6. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA021/`.
3. `cd /home/angel/lab-attack/ATA021/ && bash ATA021_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El guion instala el cron, **espera el disparo** (≤ 100 s) y lo retira. Imprime
   `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 7. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /api/scheduled/dato_programado.csv … sha256=<H>` coincidente con
el dato local, y el job deja `fired.ok` con la hora del disparo ⇒ la transferencia **programada
ocurrió de verdad**. Evidencia en `Logs/ATA021_iter*/sink.log` + `ejecucion.out`.

## 8. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`crontab`**, **`curl`**, **`bash`**, **`sha256sum`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada); `cron` **activo** |
| Elevación | **no** (crontab de usuario) |
| C0 | `Soporte/Ataques/c0/ATA021_{c0_plan.md,logtest.txt,preflight.md}` |

## 9. Receptor y firewall — cómo se levanta y se retira (reutiliza ATA009)

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA021_iter1\sink.log"
# Comprobar desde la víctima:
#   timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO
# Si BLOQUEADO, añadir la regla acotada:
#   netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
# Parar tras t1 y retirar la regla (si se creó):
#   netsh advfirewall firewall delete rule name="TFG-sink-9090"
#   netsh advfirewall firewall show rule name="TFG-sink-9090"   # -> "Ninguna regla coincide"
```

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/` y, con ello,
  cualquier resto; el crontab se retira en el propio guion). El **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servicio» es un
> **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa) pero **no son datos reales**.

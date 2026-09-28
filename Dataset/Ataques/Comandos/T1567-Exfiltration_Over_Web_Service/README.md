# ATA009 · T1567 — Exfiltration Over Web Service (`curl` POST al receptor del HOST)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda B**. Redactado el **2026-09-29** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA009** |
| Técnica | **T1567 — Exfiltration Over Web Service** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1567` **sí trae 3 pruebas Linux** en Atomic Red Team, pero **ninguna es ejecutable en el
laboratorio sin NAT**: usan `rclone` contra un servicio en la nube o `terraform`+AWS (necesitan
salida a internet y credenciales). La técnica **sí aplica a Linux**, así que el ataque **se escribe a
mano**: se **sube** un fichero a un "servicio web" **simulado localmente** (el receptor del HOST),
sin NAT y sin claves.

## 3. Qué hace y dónde escribe

- **Qué hace:** **exfiltra** un fichero de datos simulados ("informe de ventas") mediante un cliente
  de "servicio web" (`curl` POST con `--data-binary`).
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA009/`** (**NO** vigilado → detección del
  proceso por **`execve`** de `curl`).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090`** →
  `POST /api/upload/informe_ventas_2026-Q3.csv`. **El manager NO ejecuta nada** (es el detector).
- **Semilla:** si no existe, el fichero a exfiltrar se crea con `printf` (builtin, contenido fijo)
  ⇒ **determinista** e idempotente.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el "servicio web" es el **receptor local** del laboratorio
  (VMnet1). **No** se instala nada, **no** se usan claves ni cuentas.
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.
- Guardarraíl en el guion: el endpoint **DEBE** ser `http://192.168.65.1:9090/…` (aborta si no).

## 5. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramienta | **`curl`** (`/usr/bin/curl`, 8.5.0) — presente en el paso 0 (no se instala nada) |
| Alternativa | `wget` (ya usado en ATA008) o `python3` (stdlib `urllib`) — no necesarias |
| Elevación | **no** |
| C0 | `curl` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA009_c0_plan.md`) |

## 6. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA009/`.
3. `cd /home/angel/lab-attack/ATA009/ && bash ATA009_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 7. Señales esperadas (convención H4)

`ATA009_esperado.csv`:

- `T1567-S1` (**deteccion**) `audit_exe=curl` — subida al servicio web simulado (`80792`).
- `T1567-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA009/*` — ancla H4 del proceso.

> La **red no es visible** para el HIDS de host en esta configuración (no hay reglas de salida en el
> ruleset base): la detección es el **proceso** `curl`; la **prueba** de la exfiltración es el
> `sink.log` del HOST. **Sin** señales `ambigua` (no hay escritura bajo *watch*).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /api/upload/…` con la **IP de origen** (`192.168.65.129`), la
**longitud** y el **`sha256` del cuerpo**; ese `sha256` **coincide** con el del fichero exfiltrado
(impreso por el guion) ⇒ el dato **salió** de la víctima. Evidencia en
`Logs/ATA009_iter*/sink.log` + `ejecucion.out`.

## 9. Receptor y firewall — cómo se levanta y se retira (reutiliza ATA008)

`T1567` y `T1041` (ATA009/ATA010) **comparten** el receptor del piloto de ATA008
(`Soporte/Ataques/receiver/sink_http.py`). **Una sola puesta en marcha por ventana**:

**Levantar (en el HOST / sobremesa), ANTES de `t0`:**

```powershell
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA009_iter1\sink.log"
```

**Comprobar alcance del puerto (desde la víctima, antes del ataque):**

```bash
timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO
```

Si **BLOQUEADO**, añadir (una sola vez) la regla de entrada **acotada** al laboratorio:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
```

**Parar y retirar (tras `t1`, al cerrar la ventana/tanda):**

```powershell
# 1) parar el receptor (Ctrl+C en su consola, o matar el proceso python de sink_http.py)
# 2) retirar la regla de firewall
netsh advfirewall firewall delete rule name="TFG-sink-9090"
# 3) verificar ausencia
netsh advfirewall firewall show rule name="TFG-sink-9090"   # -> "Ninguna regla coincide"
```

> El receptor y la regla se **recrean por ventana** y se **retiran al cerrar** la tanda B (CA10).
> Detalle del receptor: `Soporte/Ataques/receiver/README.md`; runbook: `piloto_procedimiento.md` §3.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el "servicio web" es un
> **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa: informe de ventas) para que la ventana
> parezca un caso realista, pero **no son datos reales**.

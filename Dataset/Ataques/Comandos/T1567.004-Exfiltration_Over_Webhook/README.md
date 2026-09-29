# ATA043 · T1567.004 — Exfiltration Over Webhook (`wget` POST JSON → `/hook`)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda C** (5.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA043** |
| Técnica | **T1567.004 — Exfiltration Over Webhook** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica publica el dato en un **webhook** (canal de servicio web, tipo Slack/Teams/Discord). Se
distingue de `ATA009/T1567` (`/api/upload`) y `ATA010/T1041` (`/c2/beacon`) por el **endpoint** y el
**formato** (JSON de evento). ART trae pruebas Windows/Linux que apuntan a servicios **cloud** (no
viables sin NAT) → guion propio con un **webhook LOCAL**.

## 3. Qué hace y dónde escribe

- **Qué hace:** construye un **payload JSON** de evento y lo **envía por POST** al endpoint webhook
  **local** del receptor del HOST (`/hook`).
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA043/`** (**NO** vigilado → detección del proceso
  por **`execve`**).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090/hook`**.
- **Sin NAT**: el «webhook» es **infraestructura local** (VMnet1). **No** se instala nada.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Guardarraíl DURO:** el webhook es **LOCAL** (nunca servicios reales/cloud). El guion **aborta** si el
  endpoint no es `http://192.168.65.1:9090/…`.
- **Sin NAT**: **no** se sale a internet. **No** se toca el sistema real → **sin** señales `ambigua`.

## 5. Señales esperadas (convención H4)

`ATA043_esperado.csv`:

- `T1567.004-S1` (**deteccion**) `audit_exe=wget` — POST del JSON al webhook (`80792`).
- `T1567.004-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA043/*` — ancla H4.

> La **red no es visible** para el HIDS de host: la detección es el **proceso** (`wget`); la **prueba**
> es el `sink.log` del HOST. **Sin** señales `ambigua`.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`wget`** 1.21.4, **`sha256sum`**, **`stat`**, **`awk`** |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `wget` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA043_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA043/`.
3. `cd /home/angel/lab-attack/ATA043/ && bash ATA043_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /hook … sha256=<H>`; ese `<H>` **coincide** con el `sha256` del
cuerpo **JSON** enviado ⇒ el dato **salió** de la víctima al **webhook**. Evidencia en
`Logs/ATA043_iter*/` (`sink.log` + `ejecucion.out`).

## 9. Receptor — cómo se levanta y se retira

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA043_iter1\sink.log"
# Parar tras t1: Ctrl+C / matar el proceso python de sink_http.py
```

> **Endpoint `/hook`:** el handler `do_POST` **genérico** del receptor ya registra **cualquier** ruta
> (método, ruta, IP, `len`, `sha256`, `Content-Type`) y responde `200`; por eso **`/hook` no requiere
> código nuevo** en `sink_http.py`. Se documenta aquí para trazabilidad (el plan preveía una
> «extensión mínima»; no fue necesaria).

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`). El **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «webhook» es un **endpoint
> local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**. Los datos de juguete llevan
> **nombres creíbles** (escena de empresa) pero **no son datos reales**.

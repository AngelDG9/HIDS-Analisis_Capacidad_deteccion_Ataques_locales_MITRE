# ATA050 · T1567.003 — Exfiltration to Text Storage Sites ("paste" local, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda B** (2.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos ni API keys reales.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA050** |
| Técnica | **T1567.003 — Exfiltration Over Web Service: Exfiltration to Text Storage Sites** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **custom** (ART solo trae la prueba Windows con `pastebin.com` + API key real) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** sube por **HTTP POST** un fichero de texto de juguete (`filtracion/notas_internas.txt`)
  a un **sitio de pegado ("paste") montado en el laboratorio** (`POST /paste` en el receptor
  `sink_http.py` del HOST, `192.168.65.1:9090`). El cliente es **`curl`** (de serie).
- **Destino:** SOLO el receptor del HOST en VMnet1. **NUNCA** el manager (`192.168.65.128`) ni
  un `pastebin` real, ni API keys de terceros.
- **Capa del HIDS que ejercita:** **`execve`** (`curl`, `80792`). La **prueba** es el `sha256`
  del cuerpo que el receptor registra en su log.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramienta | `curl` (→ `/usr/bin/curl`, de serie) |
| Dependencias | ninguna nueva |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | destino FIJO `http://192.168.65.1:9090/paste`; solo el receptor local; **cero** claves |

## 4. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§6).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA050/`; ejecutar `ATA050_prestaging.sh` (crea `filtracion/`).
3. `cd /home/angel/lab-attack/ATA050 && bash ATA050_ataque.sh 2>&1 | tee ejecucion.out`.
4. Parar el receptor tras `t1`.

## 5. Señales esperadas (convención H4)

`ATA050_esperado.csv` (todas `deteccion`):

- `T1567.003-S1` `audit_exe=curl` (`80792`).
- `T1567.003-S2` `audit_cwd=/home/angel/lab-attack/ATA050/*` — ancla H4.

> **Binario real:** `curl` → `/usr/bin/curl` (el `audit_exe` casa por basename).

## 6. Receptor ("paste") — cómo se levanta y se retira

```powershell
# Levantar (HOST), ANTES de t0 (HTTP 9090; do_POST ya registra cualquier ruta):
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA050_iter1\sink.log"
# Parar tras t1.
```

> El `do_POST` **genérico** del receptor ya registra cualquier ruta con método, IP, `len` y
> `sha256` ⇒ **no hizo falta extensión** (mismo caso que ATA043 `/hook`).

## 7. Prueba de éxito (independiente de la alerta)

El `sink.log` registra `POST /paste from=192.168.65.129 len=... sha256=<hash>`; el `sha256`
== `sha256` del fichero local. Evidencia en `Logs/ATA050_iter*/`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** receptor parado tras `t1`; **sin NAT**; **sin** API keys reales.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica (POST a un sitio de pegado) y el cliente (`curl`) son reales; el destino es un
> servicio del laboratorio.** La única prueba de ART para T1567.003 es **Windows** (POST a
> `pastebin.com` con API key real) → aquí se **sustituye por un "paste" local**. Datos de
> juguete; entorno sin usuarios/servicios reales; rutas conocidas por el analista.

> **Nota de arquitectura (servicio local).** El receptor `sink_http.py` se levanta en el **HOST**
> (`192.168.65.1`, VMnet1), **fuera de las dos VMs** — igual que en el piloto
> (`Soporte/Ataques/receiver/README.md` §1) — y de él **depende la prueba de efecto** (el `sha256`
> del `sink.log`). El endpoint `/paste` es el `do_POST` **genérico** del receptor (sin código nuevo).
> Los paquetes GUI de Tanda B (Xvfb/xclip/xdotool/xinput) se instalan **offline** (`dpkg -i`) en la
> víctima; esa copia se pierde en el revert. El estado pre-steado del HOST se limpia al cerrar la tanda.

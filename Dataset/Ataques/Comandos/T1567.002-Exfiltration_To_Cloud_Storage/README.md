# ATA049 · T1567.002 — Exfiltration to Cloud Storage (nube local WebDAV, ART adaptado)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda B** (1.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos ni claves reales.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA049** |
| Técnica | **T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **ART adaptado** (la atómica Linux de T1567.002 usa `rclone`+`terraform` → AWS S3 real) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** exfiltra un directorio de datos de juguete (`exfil/`) a un **servicio de
  almacenamiento en la nube montado en el laboratorio**: un **WebDAV local** en el HOST
  (`192.168.65.1:9090`, `Soporte/Ataques/receiver/sink_webdav.py`). El cliente es **`rclone`**
  (cliente de nube real), con un *remote* WebDAV local.
- **Destino:** SOLO el servicio WebDAV del HOST en VMnet1. **NUNCA** el manager
  (`192.168.65.128`), ni una nube/AWS/Mega reales, ni claves de terceros.
- **Capa del HIDS que ejercita:** **`execve`** (`rclone`, `80792`). El HIDS no ve la red; la
  **prueba** es el `sha256` que el servicio WebDAV registra en su log.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramienta | **`rclone` v1.75.1 (linux-amd64)**, pre-steado (URL+`sha256`, §5.1 del plan) |
| Dependencias | ninguna nueva (binario estático) |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | destino FIJO `http://192.168.65.1:9090/`; solo el servicio local; **cero** claves reales |

## 4. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el servicio WebDAV (§6).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica + el binario `rclone` a
   `/home/angel/lab-attack/ATA049/`; ejecutar `ATA049_prestaging.sh` (crea `exfil/`).
3. `cd /home/angel/lab-attack/ATA049 && bash ATA049_ataque.sh 2>&1 | tee ejecucion.out`.
4. Parar el servicio WebDAV tras `t1`.

## 5. Señales esperadas (convención H4)

`ATA049_esperado.csv` (todas `deteccion`):

- `T1567.002-S1` `audit_exe=rclone` (`80792`).
- `T1567.002-S2` `audit_cwd=/home/angel/lab-attack/ATA049/*` — ancla H4.

## 6. Servicio WebDAV local — cómo se levanta y se retira

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_webdav.py" --bind 192.168.65.1 --port 9090 `
  --root "C:\Users\angel\AppData\Local\Temp\opencode\cloud_bucket_ATA049" `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA049_iter1\sink.log"
# Parar tras t1: Ctrl+C / matar el proceso python.
```

## 7. Prueba de éxito (independiente de la alerta)

El `sink.log` del HOST registra `PUT /bucket/<fichero> ... sha256=<hash>`; el `sha256` del
fichero subido == `sha256` del fichero local (`exfil.sha256`). Evidencia en `Logs/ATA049_iter*/`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** servicio WebDAV parado tras `t1`; bucket temporal borrado; **sin NAT**; **sin**
  claves/tokens reales. El binario `rclone` (pre-steado) desaparece con el revert.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el cliente (`rclone`) son reales; el destino es un servicio del laboratorio.**
> La atómica Linux de ART (`a4b74723-5cee-4300-91c3-5e34166909b4`) usa `terraform`+AWS S3 **con
> claves reales** → aquí se **sustituye el destino** por un WebDAV local y se **retira terraform**.
> La pantalla/datos son de laboratorio; el entorno no tiene usuarios/servicios reales y las rutas
> son conocidas por el analista.

> **Nota de arquitectura (servicio local).** El receptor `sink_webdav.py` se levanta en el
> **HOST** (`192.168.65.1`, VMnet1), **fuera de las dos VMs** — igual que el `sink_http.py` del
> piloto (`Soporte/Ataques/receiver/README.md` §1) — y de él **depende la prueba de efecto**
> (el `sha256` del `sink.log`). Los paquetes GUI de Tanda B (Xvfb/xclip/xdotool/xinput) se
> instalan **offline** (`dpkg -i`) en la víctima; esa copia de paquetes se pierde en el revert,
> pero el sistema de la víctima no queda modificado. El estado pre-steado del HOST se limpia al
> cerrar la tanda.

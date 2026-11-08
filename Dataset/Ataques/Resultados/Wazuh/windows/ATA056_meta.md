---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA056
tecnica: T1020
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA056 - T1020 Automated Exfiltration (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA056** |
| Tecnica | **T1020 - Automated Exfiltration** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **ART** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART` |
| Prueba / mecanismo | T1020 IcedID Botnet HTTP PUT |
| `guid` ART | `9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0` |
| Adaptacion | input_arguments file/domain -> laboratorio local; comando ART sin cambios |
| Motivo (`criterio_ataques`) | `art_tal_cual` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1020-Automated_Exfiltration/` |
| `sha256` ataque | `2a551ec30ec2935fd14e29ae0b73ab871d0d586c1d66ed09bf755ec82eb89df1` |
| `sha256` esperado | `6aaa7af3c3e9d5027dd05d8c62a70efeaead5eb201b9b18a8328d329caafccb7` |
| C0 | `Soporte/Ataques/c0/windows/ATA056_c0.md` (`sha256=ed9e50337ffe3a053380b700eaf57fe5c36436873c6b23f6a8484e78b2d7d19c`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- Servicios del HOST **antes de `t0`** y parados tras `t1`: sink_http.py :9090 (PUT /upload/ATA056).
- Firewall acotado a `192.168.65.0/24`; NAT off; nada fuera de la red host-only.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T20:43:54Z` | `2026-11-08T20:43:56Z` | 2 s | 18 | **5** | `67027,92032,92052` | 1 |
| 2 | `2026-11-08T20:47:30Z` | `2026-11-08T20:47:31Z` | 1 s | 18 | **5** | `67027,92032,92052` | 1 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA056\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA056_iter{1,2}/efecto.txt`: PUT al sink con sha256 del fichero (36 B).

**Iter 1** (`sha256=ff1361f3a28cdbb317db89d7f726cd20ea55d7f60b1c65b74831983e731ca866`):

```text
ata=ATA056
tecnica=T1020
fuente=ART
guid=9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0
t0=2026-11-08T20:43:55Z
t1=2026-11-08T20:43:55Z
url=http://192.168.65.1:9090/upload/ATA056
file=C:\lab-attack\ATA056\T1020_exfilFile.txt
sha256=70c919c954bb6149648b26f7cfc831a32568693195f47a716de981af9608cec4
resultado=HTTP=200
sink.log (HOST):
2026-11-08T20:43:55Z PUT /upload/ATA056 from=192.168.65.130 len=36 sha256=70c919c954bb6149648b26f7cfc831a32568693195f47a716de981af9608cec4 content_type=application/octet-stream
```

**Iter 2** (`sha256=3734f4a246442fe7d33b3a25379f92aa1c7222615e4f941cf673871556783870`):

```text
ata=ATA056
tecnica=T1020
fuente=ART
guid=9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0
t0=2026-11-08T20:47:31Z
t1=2026-11-08T20:47:31Z
url=http://192.168.65.1:9090/upload/ATA056
file=C:\lab-attack\ATA056\T1020_exfilFile.txt
sha256=70c919c954bb6149648b26f7cfc831a32568693195f47a716de981af9608cec4
resultado=HTTP=200
sink.log (HOST):
2026-11-08T20:47:31Z PUT /upload/ATA056 from=192.168.65.130 len=36 sha256=70c919c954bb6149648b26f7cfc831a32568693195f47a716de981af9608cec4 content_type=application/octet-stream
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA056_iter1-Detalle.csv` | 18 | `b747317de79d8b9eafb1bb99a5999cae4d15d3a90fd6febaff609be1421ea64b` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA056_iter2-Detalle.csv` | 18 | `7453eae45fad0cf21e506a74095e0aaff37d0aa2e919112b13c41f37e013c322` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 18 | **5** | 3 | 6 | **0** | 4 | 18 | 0 | 0 | 0 |
| 2 | 18 | **5** | 3 | 6 | **0** | 4 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T20:43:56.008Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T20:47:31.856Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA056` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA056.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0` en ambas. Ver `Bitacora/ATA056.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
5. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


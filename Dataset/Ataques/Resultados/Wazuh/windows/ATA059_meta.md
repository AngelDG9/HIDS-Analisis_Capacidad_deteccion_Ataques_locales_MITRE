---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA059
tecnica: T1567.003
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA059 - T1567.003 Exfiltration to Text Storage Sites (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA059** |
| Tecnica | **T1567.003 - Exfiltration to Text Storage Sites** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **ART_adaptado** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| Prueba / mecanismo | T1567.003 pastebin POST (Windows) |
| `guid` ART | `c2e8ab6e-431e-460a-a2aa-3bc6a32022e3` |
| Adaptacion | pastebin.com -> paste.local:9090; cuerpo texto plano UTF-8 para demostrar sha256 |
| Motivo (`criterio_ataques`) | `art_requiere_red_nube` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1567.003-Exfiltration_to_Text_Storage_Sites/` |
| `sha256` ataque | `3c5efa1c0034e1bb98713b3e360c31fa93500d38e5a07d2f90743a3fc734c43f` |
| `sha256` esperado | `0dff602e402840466b4804c4dbcb73ee2818aef586f92bd372722f6d6e0ef3e9` |
| C0 | `Soporte/Ataques/c0/windows/ATA059_c0.md` (`sha256=acb049e7e5bff3748f0dbf0a523a0d8893790ed1e05cf4ae2cf8c8939416eb7b`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- Servicios del HOST **antes de `t0`** y parados tras `t1`: sink_http.py :9090 (POST /paste/ATA059).
- Firewall acotado a `192.168.65.0/24`; NAT off; nada fuera de la red host-only.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T19:39:59Z` | `2026-11-08T19:40:01Z` | 2 s | 18 | **5** | `67027,92032,92052` | 1 |
| 2 | `2026-11-08T19:43:19Z` | `2026-11-08T19:43:20Z` | 1 s | 18 | **5** | `67027,92032,92052` | 1 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA059\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA059_iter{1,2}/efecto.txt`: POST del dato al sink con sha256 del cuerpo (52 B).

**Iter 1** (`sha256=21376f0aa38596be624f26a0047d4115166a2044034aad2fab3a94183d5e29a3`):

```text
ata=ATA059
tecnica=T1567.003
fuente=ART_adaptado
guid=c2e8ab6e-431e-460a-a2aa-3bc6a32022e3
t0=2026-11-08T19:40:00Z
t1=2026-11-08T19:40:00Z
url=http://192.168.65.1:9090/paste/ATA059
sha256_body=93f8f3b7f9745840b9fa36f7f6d830cd86faaae810e251de4d3681b28f21fd40
len_body=52
resultado=HTTP=200
sink.log (HOST):
2026-11-08T19:40:00Z POST /paste/ATA059 from=192.168.65.130 len=52 sha256=93f8f3b7f9745840b9fa36f7f6d830cd86faaae810e251de4d3681b28f21fd40 content_type=text/plain
```

**Iter 2** (`sha256=54974562fb948de650276c8d7286431cdbd6b05e3ec6e63e48873200fb075d1e`):

```text
ata=ATA059
tecnica=T1567.003
fuente=ART_adaptado
guid=c2e8ab6e-431e-460a-a2aa-3bc6a32022e3
t0=2026-11-08T19:43:20Z
t1=2026-11-08T19:43:20Z
url=http://192.168.65.1:9090/paste/ATA059
sha256_body=93f8f3b7f9745840b9fa36f7f6d830cd86faaae810e251de4d3681b28f21fd40
len_body=52
resultado=HTTP=200
sink.log (HOST):
2026-11-08T19:43:20Z POST /paste/ATA059 from=192.168.65.130 len=52 sha256=93f8f3b7f9745840b9fa36f7f6d830cd86faaae810e251de4d3681b28f21fd40 content_type=text/plain
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA059_iter1-Detalle.csv` | 18 | `9b275da130b056e6b80a561050ea3fe8592ed95fba6f3067093b8bcd38127383` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA059_iter2-Detalle.csv` | 18 | `232aaf96129b248d2852e9850adf35f6917b7ba8a020e7dd7129fe1bf2b1d7be` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 18 | **5** | 3 | 6 | **0** | 4 | 18 | 0 | 0 | 0 |
| 2 | 18 | **5** | 3 | 6 | **0** | 4 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:40:00.795Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:43:20.888Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA059` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA059.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0` en ambas. Ver `Bitacora/ATA059.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
5. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


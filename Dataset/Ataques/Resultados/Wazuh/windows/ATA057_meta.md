---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA057
tecnica: T1567.004
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA057 - T1567.004 Exfiltration Over Webhook (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA057** |
| Tecnica | **T1567.004 - Exfiltration Over Webhook** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **ART** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART` |
| Prueba / mecanismo | T1567.004 Discord webhook (PowerShell) |
| `guid` ART | `f0057c81-24dc-4a2e-b658-5809c242180b` |
| Adaptacion | webhook_url/staged_file locales; cuerpo UTF-8 identico al JSON del ART |
| Motivo (`criterio_ataques`) | `art_tal_cual` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1567.004-Exfiltration_Over_Webhook/` |
| `sha256` ataque | `db472956813e0c230f66a40d3a4e114085b85bf85b6f7a25081efeddd0a32764` |
| `sha256` esperado | `2e58477ab0f1ef6e8c6feb995fae7edd743e622e7b06d1b960a11cef89b4065d` |
| C0 | `Soporte/Ataques/c0/windows/ATA057_c0.md` (`sha256=ae7bc49eccb988b4a0bb8027ca5a9f0fa0c01c98118439743da5a3c01b539cb7`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- Servicios del HOST **antes de `t0`** y parados tras `t1`: sink_http.py :9090 (POST /hook/ATA057).
- Firewall acotado a `192.168.65.0/24`; NAT off; nada fuera de la red host-only.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T20:50:50Z` | `2026-11-08T20:51:08Z` | 18 s | 23 | **5** | `67027,92032,92052` | 2 |
| 2 | `2026-11-08T20:54:33Z` | `2026-11-08T20:54:40Z` | 7 s | 20 | **5** | `67027,92032,92052` | 1 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA057\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA057_iter{1,2}/efecto.txt`: POST JSON al sink con sha256 del cuerpo (1809 B).

**Iter 1** (`sha256=53b422479617c06977f485227ec89adc684bf94089b6dda93afefde35f56a9de`):

```text
ata=ATA057
tecnica=T1567.004
fuente=ART
guid=f0057c81-24dc-4a2e-b658-5809c242180b
t0=2026-11-08T20:50:57Z
t1=2026-11-08T20:51:05Z
url=http://192.168.65.1:9090/hook/ATA057
staged=C:\lab-attack\ATA057\T1567.004_loot.txt
sha256_body=a14f54349e5ef38eb8eec5e0f3650b5b90dadf6a0a0d4fd95999dd6f5409e2f8
len_body=1809
resultado=HTTP=200
sink.log (HOST):
2026-11-08T20:51:04Z POST /hook/ATA057 from=192.168.65.130 len=1809 sha256=a14f54349e5ef38eb8eec5e0f3650b5b90dadf6a0a0d4fd95999dd6f5409e2f8 content_type=application/json
```

**Iter 2** (`sha256=6d19445445badebb4a5fc158b7ad77b6e2aa12609b35a3b0fcb659a01fc0a607`):

```text
ata=ATA057
tecnica=T1567.004
fuente=ART
guid=f0057c81-24dc-4a2e-b658-5809c242180b
t0=2026-11-08T20:54:37Z
t1=2026-11-08T20:54:39Z
url=http://192.168.65.1:9090/hook/ATA057
staged=C:\lab-attack\ATA057\T1567.004_loot.txt
sha256_body=a14f54349e5ef38eb8eec5e0f3650b5b90dadf6a0a0d4fd95999dd6f5409e2f8
len_body=1809
resultado=HTTP=200
sink.log (HOST):
2026-11-08T20:54:39Z POST /hook/ATA057 from=192.168.65.130 len=1809 sha256=a14f54349e5ef38eb8eec5e0f3650b5b90dadf6a0a0d4fd95999dd6f5409e2f8 content_type=application/json
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA057_iter1-Detalle.csv` | 23 | `223a4820660a2da71f50ddd4a854920fb770e5c1988726bc7433a40c9440e250` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA057_iter2-Detalle.csv` | 20 | `84579bea1ff7d3d3b1185ed85df50dae97b569b02c53a8f02706c386b8a09f2a` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 23 | **5** | 3 | 9 | **0** | 6 | 23 | 0 | 0 | 0 |
| 2 | 20 | **5** | 3 | 6 | **0** | 6 | 20 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T20:50:51.998Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T20:54:35.786Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA057` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA057.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0` en ambas. Ver `Bitacora/ATA057.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
5. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


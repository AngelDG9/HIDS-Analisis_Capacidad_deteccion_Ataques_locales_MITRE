---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA058
tecnica: T1567.002
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA058 - T1567.002 Exfiltration to Cloud Storage (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA058** |
| Tecnica | **T1567.002 - Exfiltration to Cloud Storage** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **ART_adaptado** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| Prueba / mecanismo | T1567.002 rclone a Mega (Windows) |
| `guid` ART | `8529ee44-279a-4a19-80bf-b846a40dda58` |
| Adaptacion | remote Mega -> WebDAV local 9092; rclone.exe pre-staged fuera del repo |
| Motivo (`criterio_ataques`) | `art_requiere_red_nube` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1567.002-Exfiltration_to_Cloud_Storage/` |
| `sha256` ataque | `4aca5ed4ffad38f973359f034ad0100fde016a6a3e8b6fa9cc7c1d3c4570e49e` |
| `sha256` esperado | `8dc73e5c88a8ab5ae223e953664fe574f4c27cf03a267e806943a041d2e923bc` |
| C0 | `Soporte/Ataques/c0/windows/ATA058_c0.md` (`sha256=3b48ee5f2860f2cd301ce5cfebd389b79cd45a9fba670edf47379fa19339052a`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- Servicios del HOST **antes de `t0`** y parados tras `t1`: sink_webdav.py :9092 (bucket ATA058).
- Firewall acotado a `192.168.65.0/24`; NAT off; nada fuera de la red host-only.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T19:33:01Z` | `2026-11-08T19:33:03Z` | 2 s | 18 | **6** | `67027,92032,92052` | 2 |
| 2 | `2026-11-08T19:36:40Z` | `2026-11-08T19:36:42Z` | 2 s | 18 | **6** | `67027,92032,92052` | 2 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA058\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA058_iter{1,2}/efecto.txt`: 4 ficheros en el bucket WebDAV con sha256 coincidente.

**Iter 1** (`sha256=ff7149b3590b275abd3a55f8f33d3fedb6aca5b5082124873bde998043e65982`):

```text
ata=ATA058
tecnica=T1567.002
fuente=ART_adaptado
guid=8529ee44-279a-4a19-80bf-b846a40dda58
t0=2026-11-08T19:33:02Z
t1=2026-11-08T19:33:03Z
remote=nube:ATA058/run_20261108T193302Z
rclone_rc=0
sha256_local_clientes.csv=cdec283f3a36b508989c68c737a7567f5504d02e94927199ce9ea1c77b0c5ace
sha256_local_contratos.csv=ded9088b4be1044de045fe76d29c5b8fbf8737778495298e7b73a2e89ffc32e6
sha256_local_facturas.csv=ac9a2a05625d5193aa4b4259fa06dfe478c34bb0da07107fb50982427ec8993a
sha256_local_nominas.csv=377bfe414b652a745779f08b44a67146240dc1df12f2e9ea0f3fec37c751c752
sink.log (HOST):
2026-11-08T19:33:03Z PUT /ATA058/run_20261108T193302Z/contratos.csv from=192.168.65.130 len=68 sha256=ded9088b4be1044de045fe76d29c5b8fbf8737778495298e7b73a2e89ffc32e6
2026-11-08T19:33:03Z PUT /ATA058/run_20261108T193302Z/facturas.csv from=192.168.65.130 len=69 sha256=ac9a2a05625d5193aa4b4259fa06dfe478c34bb0da07107fb50982427ec8993a
2026-11-08T19:33:03Z PUT /ATA058/run_20261108T193302Z/clientes.csv from=192.168.65.130 len=105 sha256=cdec283f3a36b508989c68c737a7567f5504d02e94927199ce9ea1c77b0c5ace
2026-11-08T19:33:03Z PUT /ATA058/run_20261108T193302Z/nominas.csv from=192.168.65.130 len=50 sha256=377bfe414b652a745779f08b44a67146240dc1df12f2e9ea0f3fec37c751c752
```

**Iter 2** (`sha256=ecbbf7a790d23cb3b75dca149167768da7c72605cf7c9692b9651f02b65e4ccf`):

```text
ata=ATA058
tecnica=T1567.002
fuente=ART_adaptado
guid=8529ee44-279a-4a19-80bf-b846a40dda58
t0=2026-11-08T19:36:41Z
t1=2026-11-08T19:36:42Z
remote=nube:ATA058/run_20261108T193641Z
rclone_rc=0
sha256_local_clientes.csv=cdec283f3a36b508989c68c737a7567f5504d02e94927199ce9ea1c77b0c5ace
sha256_local_contratos.csv=ded9088b4be1044de045fe76d29c5b8fbf8737778495298e7b73a2e89ffc32e6
sha256_local_facturas.csv=ac9a2a05625d5193aa4b4259fa06dfe478c34bb0da07107fb50982427ec8993a
sha256_local_nominas.csv=377bfe414b652a745779f08b44a67146240dc1df12f2e9ea0f3fec37c751c752
sink.log (HOST):
2026-11-08T19:36:42Z PUT /ATA058/run_20261108T193641Z/clientes.csv from=192.168.65.130 len=105 sha256=cdec283f3a36b508989c68c737a7567f5504d02e94927199ce9ea1c77b0c5ace
2026-11-08T19:36:42Z PUT /ATA058/run_20261108T193641Z/contratos.csv from=192.168.65.130 len=68 sha256=ded9088b4be1044de045fe76d29c5b8fbf8737778495298e7b73a2e89ffc32e6
2026-11-08T19:36:42Z PUT /ATA058/run_20261108T193641Z/facturas.csv from=192.168.65.130 len=69 sha256=ac9a2a05625d5193aa4b4259fa06dfe478c34bb0da07107fb50982427ec8993a
2026-11-08T19:36:42Z PUT /ATA058/run_20261108T193641Z/nominas.csv from=192.168.65.130 len=50 sha256=377bfe414b652a745779f08b44a67146240dc1df12f2e9ea0f3fec37c751c752
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA058_iter1-Detalle.csv` | 18 | `efd913eb6fc22879a1ef7e4ed85472fbb5b54a5c56cc542b5b6e25461e15885f` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA058_iter2-Detalle.csv` | 18 | `74990a01e55c3d575b71c0282fd817039f55138b183cbfc0455e7fc4b64fd481` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 18 | **6** | 3 | 7 | **0** | 2 | 18 | 0 | 0 | 0 |
| 2 | 18 | **6** | 3 | 7 | **0** | 2 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 3 -> `67027,92032,92052` | `2026-11-08T19:33:03.178Z` `rule_id=67027` |
| 2 | 6 | 3 -> `67027,92032,92052` | `2026-11-08T19:36:42.026Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA058` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA058.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 6 vs 6; `dudosa=0` en ambas. Ver `Bitacora/ATA058.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
4. **rclone**: el remote Mega se sustituye por WebDAV local; `rclone.exe` v1.68.1 pre-staged (60,6 MB, fuera del repo).
5. **FIM**: en estas dos ventanas no se observaron filas `554` de `rclone.conf`/`loot` dentro de `[t0,t1]`
   (la copia de `loot` es pre-`t0`; el `rclone.conf` no alerto en la ventana). Se declara; no afecta a la
   deteccion (proceso) ni al efecto (4/4 PUT).
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


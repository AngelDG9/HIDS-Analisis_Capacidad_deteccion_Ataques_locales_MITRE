---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA107
tecnica: T1074.002
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA107 - T1074.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA107** |
| Tecnica | **T1074.002** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | 20 PUTs al WebDAV del HOST 192.168.65.1:9092/staging/ |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1074.002-Remote_Data_Staging/` |
| `sha256` ataque | `6af39924d172ee6a56168f2400f507361901482a58d6352fbf9d37d1b079c8bd` |
| `sha256` esperado | `61a43d2df903c8710b74d7770cd1b7f6f2febf251fd91a58c195823974e4b8f9` |
| C0 | `Soporte/Ataques/c0/windows/ATA107_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:44:38Z` | `2026-11-09T22:44:45Z` | 7 s | 40 | **5** | `67027,92032,92052` | 26 |
| 2 | `2026-11-09T22:49:13Z` | `2026-11-09T22:49:19Z` | 6 s | 42 | **5** | `67027,92032,92052` | 26 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA107\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA107_iter{1,2}/efecto.txt`: 20 ficheros en cloud_bucket\staging; sink.log con sha256.

**Iter 1** (`sha256=b70a0159b60570b5e3f2f9440981e1d39a432752bce02f1af3ec7e880854cebf`):

```text
# ATA107 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:44:38Z t0=2026-11-09T22:44:38Z run=cmd /c C:\lab-attack\ATA107\run.cmd
2026-11-09T22:44:45Z t1=2026-11-09T22:44:45Z

evidencia_local:
  ata=ATA107
  tecnica=T1074.002
  fuente=manual
  t0=2026-11-09T22:44:42Z
  t1=2026-11-09T22:44:44Z
  sink=http://192.168.65.1:9092/staging/
  ficheros_subidos=20
  sha256=stage_01.txt=8cb837214c4d030f94e73d188532a7b2115601b0b9d1ca60c9dfb8126cad4fed;stage_02.txt=078f0e076d70895a4d3fb21ddbce7efa21cb20a680b199ad8a59d211e6dd8a7a;stage_03.txt=5f2c4d4bf80e4f1a4de1e1ca62273c7fe369a744decbe2a55c787c71486e1fef;stage_04.txt=ec66d993e518ee360106cf90b5b86980e880b1c0341b7547081a5e4cdd3bd1c0;stage_05.txt=a439100cdb5e17875aa2fa0082a7ed54c0eeb67c0a7f67e68478d2f4dd6e3337;stage_06.txt=0cda30eb5ce47152207a847d49fdc9032ac012870a7c1290a1873a30d287559c;stage_07.txt=08e77a8847e7cf8330e856a00e8a603098532589b9d6d3935f94136202496449;stage_08.txt=ba64d55fc5ac61e44d5f75aab1c464439d9e95a86f61e56fb8ea8457810312ba;stage_09.txt=78fefa2e1f0e5e227d3eeb5e07d0b22652ad0858e578b80b0de54faded1c4527;stage_10.txt=dcb2f27d9ebd3c239a617efaeb763b480849a50b57b76cba08ebee4d868ea8f6;stage_11.txt=e37fb666b70ae1e6dc89f013ce9a0be0c2aad63322a232c949775753e05efec8;stage_12.txt=e403229afc03140335d0369505fba089015db41b91e2d6f49783b7d486863e2a;stage_13.txt=8387a2822f3ce5ae35c5c70000e1243cb23b47150f24afb7e83499e932373598;stage_14.txt=3e3331c0f8d8763e7241e7363a62f170a5e22d3b688970fe56626024adc355d5;stage_15.txt=e715b337cf947e1c0d47d3e5fb8b41422dd3e03979630447c1e5229f05471b34;stage_16.txt=beeb4466efd65646bc9419548d8dde9e13f99562f25bae368a3597d3f567c681;stage_17.txt=672c29014e653c82ee0822c0de67a6ca03f081c89ed0c8e03765b5441274491b;stage_18.txt=a6e1f5534f6d0338832c517e512e534017e6e731c7e011b0cef796a281a6b6a8;stage_19.txt=8fd4c585bf8b30f4bb37a73814054420cedd71f6d57b9b3def988938b232eeb9;stage_20.txt=37ce6c82a7ca6f41854cc6a843ea0a541a95c990d14a4d1eb9463544b758d852
  staging_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_subidos=20; staging_ok=True)
```

**Iter 2** (`sha256=f4e190209456703c2902553034cf85f6d6f96e2e4c69dad5f9e33d89ddbe6e3c`):

```text
# ATA107 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:49:13Z t0=2026-11-09T22:49:13Z run=cmd /c C:\lab-attack\ATA107\run.cmd
2026-11-09T22:49:19Z t1=2026-11-09T22:49:19Z

evidencia_local:
  ata=ATA107
  tecnica=T1074.002
  fuente=manual
  t0=2026-11-09T22:49:17Z
  t1=2026-11-09T22:49:19Z
  sink=http://192.168.65.1:9092/staging/
  ficheros_subidos=20
  sha256=stage_01.txt=8cb837214c4d030f94e73d188532a7b2115601b0b9d1ca60c9dfb8126cad4fed;stage_02.txt=078f0e076d70895a4d3fb21ddbce7efa21cb20a680b199ad8a59d211e6dd8a7a;stage_03.txt=5f2c4d4bf80e4f1a4de1e1ca62273c7fe369a744decbe2a55c787c71486e1fef;stage_04.txt=ec66d993e518ee360106cf90b5b86980e880b1c0341b7547081a5e4cdd3bd1c0;stage_05.txt=a439100cdb5e17875aa2fa0082a7ed54c0eeb67c0a7f67e68478d2f4dd6e3337;stage_06.txt=0cda30eb5ce47152207a847d49fdc9032ac012870a7c1290a1873a30d287559c;stage_07.txt=08e77a8847e7cf8330e856a00e8a603098532589b9d6d3935f94136202496449;stage_08.txt=ba64d55fc5ac61e44d5f75aab1c464439d9e95a86f61e56fb8ea8457810312ba;stage_09.txt=78fefa2e1f0e5e227d3eeb5e07d0b22652ad0858e578b80b0de54faded1c4527;stage_10.txt=dcb2f27d9ebd3c239a617efaeb763b480849a50b57b76cba08ebee4d868ea8f6;stage_11.txt=e37fb666b70ae1e6dc89f013ce9a0be0c2aad63322a232c949775753e05efec8;stage_12.txt=e403229afc03140335d0369505fba089015db41b91e2d6f49783b7d486863e2a;stage_13.txt=8387a2822f3ce5ae35c5c70000e1243cb23b47150f24afb7e83499e932373598;stage_14.txt=3e3331c0f8d8763e7241e7363a62f170a5e22d3b688970fe56626024adc355d5;stage_15.txt=e715b337cf947e1c0d47d3e5fb8b41422dd3e03979630447c1e5229f05471b34;stage_16.txt=beeb4466efd65646bc9419548d8dde9e13f99562f25bae368a3597d3f567c681;stage_17.txt=672c29014e653c82ee0822c0de67a6ca03f081c89ed0c8e03765b5441274491b;stage_18.txt=a6e1f5534f6d0338832c517e512e534017e6e731c7e011b0cef796a281a6b6a8;stage_19.txt=8fd4c585bf8b30f4bb37a73814054420cedd71f6d57b9b3def988938b232eeb9;stage_20.txt=37ce6c82a7ca6f41854cc6a843ea0a541a95c990d14a4d1eb9463544b758d852
  staging_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_subidos=20; staging_ok=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA107_iter1-Detalle.csv` | 40 | `8db27d1a57cff49869dec18f467688012cab265d992a4ba63e03a86afb6ad3c9` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA107_iter2-Detalle.csv` | 42 | `52c78151f05cd4411075a9a6d82bb26e7f74ef385ec7e9aad5f2c352213ac89d` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 40 | **5** | 3 | 6 | **0** | 26 | 40 | 0 | 0 | 0 |
| 2 | 42 | **5** | 3 | 8 | **0** | 26 | 42 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:44:40.496Z` `rule_id=92032` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:49:15.294Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA107** es **manual** (no hay test ART para T1074.002). 20 PUTs al WebDAV del HOST `http://192.168.65.1:9092/staging/`; el sink guarda en `cloud_bucket\staging` y registra `PUT ... len=<N> sha256=<hash>` en `sink_webdav.log`. Pareja de **ATA040**.
2. Evidencia primaria: `sink.log` (20 lineas) y `staging_host.csv` (20 ficheros).

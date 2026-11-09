---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA078
tecnica: T1567.001
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA078 - T1567.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA078** |
| Tecnica | **T1567.001** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | git push a repo bare local (PortableGit en C:\tfg-tools) |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1567.001-Exfiltration_to_Code_Repository/` |
| `sha256` ataque | `be9bd957724e6e77c6b1992cfd6348be4a1bc3a46104c5ec74847e71010e41ea` |
| `sha256` esperado | `35c894453b20a0d6fdb30bc3a01c844ad089f710393040dbc2a9f82beb25b9d9` |
| C0 | `Soporte/Ataques/c0/windows/ATA078_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T12:44:44Z` | `2026-11-09T12:44:45Z` | 1 s | 110 | **10** | `67027,92032,92052` | 90 |
| 2 | `2026-11-09T12:50:54Z` | `2026-11-09T12:50:56Z` | 2 s | 129 | **13** | `67027,92032,92052` | 104 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA078\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA078_iter{1,2}/efecto.txt`: git log del repo bare + push main->main.

**Iter 1** (`sha256=afbb7191d093c42aa5b9fdb4a1c13e2a8ef360f658df8fd9f6552b688c63add3`):

```text
# ATA078 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T12:44:44Z t0=2026-11-09T12:44:44Z run=cmd /c C:\lab-attack\ATA078\run.cmd
2026-11-09T12:44:45Z t1=2026-11-09T12:44:45Z

evidencia_local:
  ata=ATA078
  tecnica=T1567.001
  fuente=manual
  t0=2026-11-09T12:44:45Z
  t1=2026-11-09T12:44:45Z
  repo=C:\lab-attack\ATA078\repo.git
  work=C:\lab-attack\ATA078\work
  commit=9615847 TFG exfil ATA078
  push=branch 'main' set up to track 'origin/main'.
  + $pushOut=(& $git push -u origin main 2>&1 | Out-String).Trim()
  commit_out=[master (root-commit) 9615847] TFG exfil ATA078

VEREDICTO: EFECTO DEMOSTRADO (git push; commit=9615847 TFG exfil ATA078)
```

**Iter 2** (`sha256=a91d7763805a05228f206c2d4295c38b831b4a3ef970e4d34546c2cb54e40723`):

```text
# ATA078 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T12:50:54Z t0=2026-11-09T12:50:54Z run=cmd /c C:\lab-attack\ATA078\run.cmd
2026-11-09T12:50:56Z t1=2026-11-09T12:50:56Z

evidencia_local:
  ata=ATA078
  tecnica=T1567.001
  fuente=manual
  t0=2026-11-09T12:50:55Z
  t1=2026-11-09T12:50:56Z
  repo=C:\lab-attack\ATA078\repo.git
  work=C:\lab-attack\ATA078\work
  commit=e1228f9 TFG exfil ATA078
  push=branch 'main' set up to track 'origin/main'.
  + $pushOut=(& $git push -u origin main 2>&1 | Out-String).Trim()
  commit_out=[master (root-commit) e1228f9] TFG exfil ATA078

VEREDICTO: EFECTO DEMOSTRADO (git push; commit=e1228f9 TFG exfil ATA078)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA078_iter1-Detalle.csv` | 110 | `7028f3a1d23208b7c2d252b548dbffe6e3d7a18e7095102af01f2e436efd9394` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA078_iter2-Detalle.csv` | 129 | `54ad0a3cf23e4c1500af626867831b0c8ddcbb841907fdd82911113939e10065` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 110 | **10** | 3 | 5 | **0** | 92 | 110 | 0 | 0 | 0 |
| 2 | 129 | **13** | 3 | 7 | **0** | 106 | 129 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 10 | 3 -> `67027,92032,92052` | `2026-11-09T12:44:45.847Z` `rule_id=92052` |
| 2 | 13 | 3 -> `67027,92032,92052` | `2026-11-09T12:50:56.074Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`review`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 10 vs 13;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=False`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA078** es **manual**: el clon ART `388942ad` no trae T1567.001; se implementa `git push` a un repo bare local.
2. **Pre-staging**: PortableGit se extrae en **`C:\tfg-tools\PortableGit`**, fuera del FIM `C:\lab-attack` (realtime). La extraccion en `C:\lab-attack` generaba cientos de eventos `554` de FIM que contaminaban la ventana; por eso se movio fuera. El `git.exe` y el repo siguen anclados por `*lab-attack*ATA078*`.
3. El efecto es el `git log` del repo bare (`commit=...`) y el `push` `main -> main`.

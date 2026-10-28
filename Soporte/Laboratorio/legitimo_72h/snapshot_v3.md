# `snapshot_v3.md` — contenido y verificación de `lab-listo-legit-v3`

> Snapshot de `victima-linux` del bloque **`legitimo-v3`** (plan v5, §5.3).
> **Recreado el 2026-10-28 tras cerrar H-1** (comandos sin `|`): se **borró** el `v3`
> anterior y se volvió a crear **desde `lab-listo-legit-v2`** con la **VM apagada** y el
> cliente parado (snapshot **disco-solo**, sin memoria).
> **`lab-listo-legit-v2` NO se toca**: sigue siendo la red de seguridad y el punto de
> retorno anterior. `prep` (G-1) exige que exista **`v3`**; **G-1 no detecta un revert
> manual a `v2`** (solo comprueba que el snapshot exista): `prep` vuelve a revertir a
> **`v3`** al arrancar, así que el estado de medida es siempre el de `v3`.

## Qué cambia respecto de `v2` (tabla)

| # | Elemento | En `v2` | En `v3` | Por qué |
|---|---|---|---|---|
| 1 | **Receta** (`config/timeline.d{1,2,3}.json` + `timeline.json`) | receta **v1** (111/117/105) | receta **v2**: **147/153/141** = **441** acciones + **B6** (63) | T1/T2 |
| 2 | **Pacing** | metrónomo (45-50 s) | jitter **literal** (ráfagas 1-6, intra 41-62 s, huecos ≤ 22 min, 2 pausas largas) | mejora 2 |
| 3 | **`cwd`** | `cd "$DIR"` en `client_ctl.sh` y en el keepalive | `TFG_CWD_BASE=/home/angel` en **ambos**; el ejecutable por ruta absoluta | mejora 1 / CA-05 |
| 4 | **Errores humanos** | 0/333 comandos fallidos | **10/día** con reintento y `~/Documentos/errores.log` (5 campos TAB), **sin `\|\|`** (H-1) | mejora 3 |
| 5 | **Binarios del corpus** | 11/50 | **+12** (`xargs`, `timeout`, `sed`, `ip`, `openssl`, `tee`, `free`, `logger`, `seq`, `rsync`, `shred`, `wget`) | mejora 4 |
| 6 | **Campaña `B6`** | no existe | **11 casos / 63 acciones / 22 marcas** en `17:05-17:50Z` (d1 17:06 · d2 17:17 · d3 17:11), **sin `\|`** | mejora 5 + H-1 |
| 7 | **`bloques.env` / `calendario.json`** | v1 | v2 con `B6` y `TFG_CAMPANA_*`; `TFG_MAPA_DIAS` **vacío** (se fija en T4) | T1/T2 |
| 8 | **Carpetas base del `cwd`** | no existen | `~/Documentos/{informes,actas,copias,correo}`, `~/Descargas`, `~/.cache/tfg-web` (**vacías**) | receta v2 |
| 9 | **Prerrequisito de campaña** | no existe | **`~/Documentos/campana_fp/` vacía** (solo la carpeta) | bloqueante de B6 |
| 10 | **`verificar_arreglos.sh`** | comprobaba nlog/recetas/keepalive | + `client_cwd`, `keepalive_cwd`, `carpetas_cwd`, `campana_fp`; **huella de timeline** corregida (JSON compacto) | T3 |
| 11 | **`client_ctl.sh`** | v2 | v3 (`cwd`, log `arrancado ... cwd=...`) | T3 |
| 12 | **`tfg_keepalive.sh`** | v3 (`cd $DIR`) | v3 + `cwd` (`TFG_CWD_BASE`) y huella de timeline corregida | T3 |
| 13 | **Validador de comandos** | solo prohibía `\|` simple (dejaba pasar `\|\|`) | **prohíbe cualquier `\|`** en receta y campaña (H-1) | T3-H1 |
| 14 | **Evidencia de C-09** | `RC_FALLO=7` | **`RC_FALLO=7 o 28`** (el puerto cerrado está filtrado: H-3) | T3-H1 |

> **Lo que NO cambia:** `nlog.config` (consola `Warn`, `app.log` 1 MB × 20), `client_ctl` con
> tope de 20 MB × 2, `logs/` e `instance/` sin datos de medida, timer/servicio del invitado
> **no instalados**, navegador **ausente**, agente Wazuh intacto.

## Contenido verificado (salida literal)

```
$ vmrun -T ws listSnapshots ...victima-linux.vmx
Total snapshots: 6
base-limpia
lab-listo
lab-listo-legit
fallo-2026-10-19-disco-lleno-NO-USAR
lab-listo-legit-v2          <- INTACTO
lab-listo-legit-v3          <- recreado (2026-10-28)
```

```
$ bash verificar_arreglos.sh <nlog> <d1> <d2> <d3> <keepalive>
nlog_console=Warn
nlog_sha=d8f5f1d1154601360e5d81c752ea50b034e915e10f9545625f4a5732352221fb
nlog_applog_archive=20
client_ctl_cap=20
keepalive_v3=1
recetas=e711bc93,216a747b,86057a15
recetas_sha=e711bc932c036e466fb7ad6f4ad03c2cebc39666092baa551c4e656c12dbedcd,216a747bde0f2460620a199d73c5a41d37db89fb9fbedcff8d5193fb51c59df6,86057a15a2e498de6f5cf02baa7bb4ebc0e243f84db08745fda5034ad8a11703
timeline_activa=e711bc93 (contenido = d1)
web_session=1
receptor_navegador=none
swap_mb=1915
swap_estado=AVISO (swap_mb=1915 != 0; desviación declarada)
timer=not-found
df_free_mb=4530
df_inodes_libres_pct=84
client_cwd=/home/angel
keepalive_cwd=/home/angel
carpetas_cwd=OK
campana_fp=OK
campana_fp_casos=0
RESULT=PASS
```

- **Tamaño**: snapshot **disco-solo** (sin `.vmem`); `.vmsn` = **29 473 B**.
  - **Estado de disco del snapshot**: el `.vmsd` asocia `snapshot5` (v3) con
    **`victima-linux-000004.vmdk` = 290 127 872 B** (~276,7 MiB); **ese** es el delta que
    representa el snapshot.
  - **`victima-linux-000007.vmdk` = 2 686 976 B** (~2,6 MiB) es el **delta hijo actual** del
    `.vmx` (escrituras posteriores al snapshot / estado en marcha), **no** el tamaño del
    snapshot.
- **Espacio libre dentro de la VM**: **4 530 MB** (≥ 4 GB de G-2).
- **Carpetas vacías confirmadas**: `find ~/Documentos ~/Descargas ~/.cache/tfg-web -type f` → **0**;
  `~/Documentos/campana_fp` → **0 entradas**.
- **Sin residuos**: `client.out`, `client.out.1`, `keepalive.log`, `recovery.log`,
  `rotacion.estado`, `ghasts.out` **ausentes**; `logs/` **vacío**; `instance/` solo `id.json`.
- **Recetas desplegadas** (sha256 en el invitado **en el momento de crear el snapshot**):
  `d1=e711bc93…`, `d2=216a747b…`, `d3=86057a15…`, `calendario=95ae4fef…`, `bloques=ba9b9f61…`,
  `keepalive=c1241001…`.
  **Nota de exactitud:** tras la corrección documental de T3 (`casos.md`), el `calendario.json` del
  repo pasó a **`a42cb35c…`** (solo cambia `sha256_casos_md`; **ningún comando**). `prep` lo
  **redespliega en cada arranque**, así que el estado que se mide usa **el del repo**. **E0 debe
  verificar** que el calendario desplegado coincide con el del repo.

## Cómo se creó (reproducible)

```powershell
$vmrun = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$v = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'

& $vmrun -T ws stop $v soft
& $vmrun -T ws deleteSnapshot $v 'lab-listo-legit-v3'   # recreación tras H-1
& $vmrun -T ws revertToSnapshot $v 'lab-listo-legit-v2'
& $vmrun -T ws start $v nogui
# ... deploy_client.ps1 DOS veces (idempotencia) + limpieza ...
& $vmrun -T ws stop $v soft
& $vmrun -T ws snapshot $v 'lab-listo-legit-v3'
& $vmrun -T ws start $v nogui      # verificación post-snapshot (verificar_arreglos PASS)
& $vmrun -T ws stop $v soft
& $vmrun -T ws revertToSnapshot $v 'lab-listo-legit-v3'
```

## Cómo se verifica (rápido)

1. `vmrun -T ws listSnapshots $v` → **6** snapshots y **`lab-listo-legit-v2` presente**.
2. Arrancar y ejecutar `bash ~/ghosts-client/verificar_arreglos.sh` **sin argumentos**:
   debe salir `RESULT=PASS` y `campana_fp=OK`.
3. `ls -la ~/ghosts-client/logs` → vacío; `find ~/Documentos -type f` → 0.
4. `readlink /proc/$(pgrep -f 'ghosts[.]client[.]linux' | head -1)/cwd` **tras arrancar** el
   cliente → `/home/angel` (y `logs/app.log` sigue en `~/ghosts-client/logs`).
5. `grep -c '|'` en los comandos desplegados → **0** (H-1).

## Qué NO lleva `v3`

- **No** lleva el timer/servicio del invitado (`arm` los instala 20 min antes de `t0`).
- **No** lleva logs, `client.out`, `instance/` de una ejecución ni caché de la prueba en seco.
- **No** lleva `logall_json=yes` (lo activa `prep` y lo apaga la extracción).
- **No** lleva casos de campaña (solo la carpeta vacía).

## Relación con `v2`

- **`v2` se conserva intacto** y sigue disponible como punto de retorno manual.
- `prep` ya **no** revierte a `v2`: G-1 comprueba `lab-listo-legit-v3` (script
  `legitimo_host_control.ps1`, `$Snap` y mensaje G-1).
- La diferencia de estado entre `v2` y `v3` es **solo** la del deploy + carpetas (tabla de arriba);
  `base-limpia`, `lab-listo` y `lab-listo-legit` tampoco se tocan.

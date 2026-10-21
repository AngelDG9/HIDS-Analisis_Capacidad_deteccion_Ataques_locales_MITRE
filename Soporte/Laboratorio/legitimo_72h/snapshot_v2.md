# `snapshot_v2.md` — contenido y verificación de `lab-listo-legit-v2`

> Snapshot de `victima-linux` creado al cerrar el bloque **`legitimo-fix`** (plan §9.1).
> **Se conserva `lab-listo-legit`** (v1): es la red de seguridad y la referencia de
> trazabilidad. `prep` **exige** `v2` (G-1): revertir «por inercia» a `v1` **aborta**.

## Qué contiene (y cómo se comprueba)

| Elemento | Estado esperado en `v2` | Cómo se verifica |
|---|---|---|
| Base | `lab-listo-legit` (revert) — **sin datos de la ventana fallida** | `vmrun listSnapshots` + `ls ~` |
| `nlog.config` | consola **`Warn`**, `app.log` **1 MB × 20** | `verificar_arreglos.sh` → `nlog_console=Warn`, `nlog_applog_archive=20`, `nlog_sha` == repo |
| `client_ctl.sh` | **v2** (tope 20 MB × 2, `start` idempotente, `stop` TERM→KILL) | `client_ctl_cap=20` |
| `config/timeline.json` | **`d1`** (sha == repo) | `timeline_activa` == `recetas=d1` |
| `config/timeline.d{1,2,3}.json` | presentes y con sha == repo | `recetas_sha` == repo |
| `recetas/bloques.env` + `calendario.json` | presentes | `ls ~/ghosts-client/recetas/` |
| `tfg_keepalive.sh` | **v3** | `keepalive_v3=1` |
| `logs/` | **vacío** (sin `app.log`, `clientupdates.log`) | `ls -la logs/` |
| `client.out`, `client.out.1`, `keepalive.log`, `recovery.log`, `rotacion.estado` | **ausentes** | `ls` |
| `ghasts.out` | **ausente** (el original de 4,78 GB está en `fallo-…-NO-USAR`) | `ls` |
| `~/Documentos`, `~/Descargas` | **vacíos** | `ls` |
| `~/.cache/tfg-web` | **ausente** (se recrea con la sesión web) | `ls` |
| `tfg-ghosts-legit.{timer,service}` | **NO instalados** (`not-found`) | `timer=not-found` |
| **Navegador** | **AUSENTE** (§4.8: DT-B0 FAIL) | `receptor_navegador=none` |
| Agente Wazuh | `active`, `wazuh-agentd` vivo, sin cambios | `systemctl is-active wazuh-agent` |
| Disco | ≥ 4 GB libres, inodos ≥ 20 % | `df_free_mb`, `df_inodes_libres_pct` |

> **Swap declarado**: la VM arranca con **swap habilitada (~1,9 GB)**, aunque el plan (§4.5)
> asumía `swap 0`. Se **declara** y **no** se toca (cambiar el banco antes de medir sería peor);
> `verificar_arreglos.sh` lo reporta como `swap_estado=AVISO`.

## Cómo se creó (y cómo se verifica)

```powershell
$vmrun = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$victima = 'D:\TFG-VMs\victima-linux\victima-linux.vmx'

& $vmrun -T ws stop $victima soft                  # apagado ordenado
& $vmrun -T ws snapshot $victima 'lab-listo-legit-v2'
& $vmrun -T ws listSnapshots $victima              # deben salir los 4 (+ el de evidencia)
& $vmrun -T ws start $victima nogui                # verificación post-snapshot (DT12)
# ... verificar_arreglos.sh + listado de residuos ...
& $vmrun -T ws stop $victima soft
& $vmrun -T ws revertToSnapshot $victima 'lab-listo-legit-v2'
```

- Se crea **con la VM apagada** ⇒ snapshot **disco-solo** (sin memoria).
- Después de verificarlo se **revierte a `v2`** otra vez: el estado del que arranca `prep`.

## Inventario de snapshots de `victima-linux` al cerrar el bloque

| Snapshot | Para qué |
|---|---|
| `base-limpia` | SO recién instalado (original, **intacto**) |
| `lab-listo` | laboratorio de ataques (Fase 3) — **intacto** |
| **`lab-listo-legit`** | v1 del legítimo — **se conserva** (red de seguridad / trazabilidad) |
| **`fallo-2026-10-19-disco-lleno-NO-USAR`** | **evidencia**: estado roto con `ghasts.out` de 4,78 GB (no usar) |
| **`lab-listo-legit-v2`** | **el que usa `prep`** (G-1): arreglos + receta + limpio |

## Qué NO lleva `v2`

- **No** lleva el timer/servicio del invitado (`arm` los instala 20 min antes de `t0`).
- **No** lleva logs, ficheros de trabajo ni caché de la prueba en seco.
- **No** lleva navegador ni drivers (decisión §4.8).
- **No** lleva `logall_json=yes` (lo activa `prep` y lo apaga la extracción).

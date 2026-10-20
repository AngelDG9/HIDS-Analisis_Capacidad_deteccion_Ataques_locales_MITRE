# Pausa de Windows Update en el HOST — bloque `legitimo-72h` (L1)

> **Motivo.** El humano autorizó **pausar Windows Update del sobremesa hasta después de `t1`**
> (`t1 = 2026-10-22T00:00:00Z` = 22/10 02:00 local) para que el **PC no se reinicie solo** y no
> **invalide la ventana** de 72 h (`plan.md` §3.4, §8.2 V8).
>
> **Estado:** 🔴 **PAUSADO** desde `2026-10-18T21:39:31Z` (23:39 local).
> **Reversión:** `powershell -NoProfile -ExecutionPolicy Bypass -File pausar_windows_update.ps1 restaurar`
> (ejecutar **después de `t1`**, al cerrar la ventana).
> **Registro de trazas:** `windows_update_pausa.log` (UTC).

Script: `pausar_windows_update.ps1` (`estado` | `pausar` | `restaurar`).

---

## 1. Qué se cambió exactamente (y valor previo)

| # | Elemento | Valor **previo** (2026-10-18 23:38 local) | Valor **puesto** (pausa) | Cómo se revierte |
|---|---|---|---|---|
| 1 | Clave `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` | **no existía** | creada | se borran sus 2 valores y, si quedan vacías, se borran las claves `…\AU` y `…\WindowsUpdate` |
| 2 | Valor `NoAutoUpdate` (DWORD, en `…\AU`) | (no existía) | **`1`** = desactiva la instalación automática de actualizaciones | borrar el valor |
| 3 | Valor `NoAutoRebootWithLoggedOnUsers` (DWORD, en `…\AU`) | (no existía) | **`1`** = Windows **no reinicia** con un usuario con sesión abierta | borrar el valor |
| 4 | Servicio `wuauserv` (Windows Update) — estado | **Running** | **Stopped** | `Start-Service wuauserv` |
| 5 | Servicio `wuauserv` — tipo de inicio | **Manual** (`Start`=3) | **Disabled** (`Start`=4) | `Set-Service wuauserv -StartupType Manual` (`Start`=3) |

- **`UsoSvc`** (Orquestador de actualizaciones): **NO** se toca (queda `Running`/`Automatic`). Con
  `NoAutoUpdate=1` no descarga ni instala nada. Verificado que `wuauserv` **no se reanudó** tras 5 s
  con `UsoSvc` en marcha (sigue `Stopped`/`Disabled`).
- Tareas de reinicio `\Microsoft\Windows\UpdateOrchestrator\Reboot_AC` y `Reboot_Battery`:
  **ya estaban `Disabled`** (no se tocaron); el script avisa si alguna estuviera activa.

### Reversión (comando único)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\legitimo_72h\pausar_windows_update.ps1 restaurar
```

Deja: política AU retirada, `wuauserv` `Manual` + arrancado. No hay más cambios que deshacer.

> **Nota de robustez.** En Windows 10 el servicio puede "auto-repararse" (Update Medic) y volver a
> `Manual`. La protección **duradera** es la **política `NoAutoUpdate=1` + `NoAutoRebootWithLoggedOnUsers=1`**
> (que no se auto-repara). Antes de `t0` conviene re-confirmar con `… pausar_windows_update.ps1 estado`.

---

## 2. Estado de reinicio pendiente (2026-10-18 23:39 local)

| Indicador | Valor | ¿Puede disparar un reinicio? |
|---|---|---|
| `PendingFileRenameOperations` | **True** (2 entradas de **EdgeUpdate**: `…\Microsoft\EdgeUpdate\1.3.287.9`, `…\1.3.291.9`) | **No.** Son renombrados de fichero de Edge que el SO aplica en el **próximo arranque**; **no** provocan un reinicio por sí mismos. |
| CBS `RebootPending` | False | no |
| CBS `RebootInProgress` | False | no |
| WU `RebootRequired` | False | no |
| WU `PostRebootReporting` | False | no |
| Netlogon `JoinDomain` | False | no |

**Conclusión:** **no hay ningún reinicio pendiente que pueda dispararse solo**. Las únicas entradas de
`PendingFileRenameOperations` son de **EdgeUpdate** (benignas, no reinician). Sumado a la pausa de WU y a
`NoAutoRebootWithLoggedOnUsers=1`, el riesgo de auto-reinicio durante `[t0,t1]` queda **neutralizado**.

---

## 3. Tareas del host y timer del invitado (2026-10-18 23:38–23:39 local)

### 4 tareas del host (Programador de tareas)

| Tarea | Estado | NextRun (local) | = | Correcta |
|---|---|---|---|---|
| `TFG-Legit-Prep` | **Ready** | `19/10/2026 01:15:15` | `t0−45 min` | ✅ |
| `TFG-Legit-Arm` | **Ready** | `19/10/2026 01:40:40` | `t0−20 min` | ✅ |
| `TFG-Legit-Watch` | **Ready** | `19/10/2026 05:00:00` (cada 3 h, 72 h) | en `[t0,t1]` | ✅ |
| `TFG-Legit-Stop` | **Ready** | `22/10/2026 02:05:05` | `t1+5 min` | ✅ |

- `LastResult` de `Prep`/`Arm` = **0** (última corrida: ensayo de 18/10 23:14–23:18, OK).
  `Watch`/`Stop` muestran `267011` (`0x00041303`, "la tarea nunca se ha ejecutado") — **normal**, aún no han disparado.
- Las 4 están `Habilitado` y en `Estado: Listo`.

### Timer del invitado (`TFG-Ghosts-Legit`)

- **Artefacto:** `guest/tfg-ghosts-legit.timer` (`OnCalendar=2026-10-18 23:55:00 UTC` = `t0−5 min`).
- **Se (re)instala en `arm`**: `guest/instalar_tarea_invitado.sh` hace
  `systemctl enable --now tfg-ghosts-legit.timer` → queda **`enabled`**.
- **Evidencia de la última corrida de `arm`** (`legitimo_host_control.log`, 20:50Z y 21:18Z):
  `tfg-ghosts-legit.timer   enabled  enabled` y `NEXT = Mon 2026-10-19 01:55:00 CEST`.
- **Nota:** la víctima está **apagada ahora** (lab limpio, §4); la confirmación **en vivo** la emite
  `arm` a las 01:40, que lo reinstala y lo deja `enabled` **antes de `t0`**. No se enciende la VM solo
  para comprobarlo (evita ensuciar/reconciliar).

---

## 4. Limpieza del PC/VMs (2026-10-18 23:40 local)

| Comprobación | Resultado |
|---|---|
| VMs en marcha (`vmrun -T ws list`) | **Total running VMs: 0** |
| Procesos de VM (`vmware-vmx`, etc.) | **0** |
| Procesos GHOSTS/internet (`ghosts`, `dotnet`, `postgres`, `serve_site`, `sink_*`) | **0** |
| Puertos del lab (`5000/8080/9090/9092/5432`) | **todos libres** |
| Firewall `TFG-ghosts-5000` | **retirada** (no existe) |
| `logall_json` (manager `.128`) | **`no`** — verificado en el `cleanup` del 18/10 21:19Z (`<logall_json>no</logall_json>`, manager `active`, config idéntica a la copia) |

> El estado limpio proviene del `cleanup` del ensayo (18/10 21:19Z) y se ha **re-verificado** aquí.
> La preparación real (revert a `lab-listo-legit` + arranque) la hace **`TFG-Legit-Prep`** a las 01:15.

---

## 5. Higiene

- **Sin secretos** en este fichero ni en `pausar_windows_update.ps1`/`.log`.
- Ficheros nuevos, todos dentro de `Soporte/Laboratorio/legitimo_72h/`: `windows_update_pausa.md`,
  `pausar_windows_update.ps1`, `windows_update_pausa.log`.
- No se tocó `_recursos/`, corpus, `Hojas/`, `Dataset/` ni `Soporte/Metrica/`. **Sin commit/push.**

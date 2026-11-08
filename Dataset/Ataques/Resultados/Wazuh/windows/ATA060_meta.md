---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA060
tecnica: T1496.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA060 - T1496.001 Compute Hijacking (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA060** |
| Tecnica | **T1496.001 - Compute Hijacking** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **manual** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `propio` |
| Prueba / mecanismo | 4 runspaces de computo 30 s |
| Adaptacion | manual: sin atomic Windows aprovechable en el clon |
| Motivo (`criterio_ataques`) | `propio_por_diseno` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1496.001-Compute_Hijacking/` |
| `sha256` ataque | `f91408fa8953ec245a4cf48e84f465526279ecc3b765a8498e913154c0b97c0b` |
| `sha256` esperado | `9b553e21bc249ba93895f57f62e474b75c540cf1036ede416c7dc148ab5ee731` |
| C0 | `Soporte/Ataques/c0/windows/ATA060_c0.md` (`sha256=4b0b15f533ca513ce33782b1364c8f4026e5bcbb838ac27152c968472cfcde93`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T19:46:31Z` | `2026-11-08T19:47:05Z` | 34 s | 21 | **5** | `67027,92032,92052` | 2 |
| 2 | `2026-11-08T19:50:21Z` | `2026-11-08T19:50:53Z` | 32 s | 21 | **5** | `67027,92032,92052` | 2 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA060\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA060_iter{1,2}/efecto.txt`: CPU 11,3 % -> 97,8 %; Available MBytes 2975 -> 2967.

**Iter 1** (`sha256=7698e33b7c681ae75c95e5886003d51e684c382c0ba4337a38405c2e7139ef87`):

```text
ata=ATA060
tecnica=T1496.001
fuente=propio
t0=2026-11-08T19:46:34Z
t1=2026-11-08T19:47:04Z
workers=4
duracion_objetivo_s=30
cpu_before_pct=11.3
cpu_during_samples=99.2316227772875,97.1857297677385,96.8784917191629
cpu_during_avg_pct=97.77
mem_before_available_mb=2975.4
mem_during_available_mb=2966.8
delta_cpu_pct=86.47
```

**Iter 2** (`sha256=de847e95834cbf3bcae058edf0f69bd60306d9ead401c646d456ccb810ba0e87`):

```text
ata=ATA060
tecnica=T1496.001
fuente=propio
t0=2026-11-08T19:50:23Z
t1=2026-11-08T19:50:53Z
workers=4
duracion_objetivo_s=30
cpu_before_pct=11.99
cpu_during_samples=95.3033325748528,100,94.6028821670147
cpu_during_avg_pct=96.64
mem_before_available_mb=3003.6
mem_during_available_mb=2993.8
delta_cpu_pct=84.65
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA060_iter1-Detalle.csv` | 21 | `015557ba39a4ecba37840f1ce83c68b5aef3732aebffa29bc7b02484bde75af6` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA060_iter2-Detalle.csv` | 21 | `9ec450c7fc168078dac702f2bb32de11b20c3b3374fa89a34627c304c5245ee5` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 21 | **5** | 3 | 10 | **0** | 3 | 21 | 0 | 0 | 0 |
| 2 | 21 | **5** | 3 | 10 | **0** | 3 | 21 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:46:33.370Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:50:22.900Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA060` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA060.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0` en ambas. Ver `Bitacora/ATA060.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
4. **Sin reglas de recursos** (R9): la CPU al 97,8 % no genera alerta propia; la deteccion es el proceso.
5. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


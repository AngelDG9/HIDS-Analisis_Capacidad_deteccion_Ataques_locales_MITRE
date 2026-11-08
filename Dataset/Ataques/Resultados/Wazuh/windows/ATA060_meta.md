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
| 1 | `2026-11-08T21:12:41Z` | `2026-11-08T21:13:17Z` | 36 s | 22 | **5** | `67027,92032,92052` | 2 |
| 2 | `2026-11-08T21:16:24Z` | `2026-11-08T21:16:56Z` | 32 s | 21 | **5** | `67027,92032,92052` | 2 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA060\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA060_iter{1,2}/efecto.txt`: CPU 11,3 % -> 97,8 %; Available MBytes 2975 -> 2967.

**Iter 1** (`sha256=50d08e11ef0679e89cda18b04c22bf2492d516f1508689d6a557c0c0c5d53a52`):

```text
ata=ATA060
tecnica=T1496.001
fuente=propio
t0=2026-11-08T21:12:46Z
t1=2026-11-08T21:13:16Z
workers=4
duracion_objetivo_s=30
cpu_before_pct=10.95
cpu_during_samples=100,97.0149749869232,100
cpu_during_avg_pct=99
mem_before_available_mb=3135.4
mem_during_available_mb=3115.4
delta_cpu_pct=88.05
```

**Iter 2** (`sha256=390c17172053351d39155a6220a38d46c88519991cc469471600e85175f331f2`):

```text
ata=ATA060
tecnica=T1496.001
fuente=propio
t0=2026-11-08T21:16:26Z
t1=2026-11-08T21:16:56Z
workers=4
duracion_objetivo_s=30
cpu_before_pct=2.26
cpu_during_samples=96.967229581206,98.5282432244557,95.4519412085175
cpu_during_avg_pct=96.98
mem_before_available_mb=3030.5
mem_during_available_mb=3023.3
delta_cpu_pct=94.72
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA060_iter1-Detalle.csv` | 22 | `e384216a87b9af3969b56fb9f7623aa7e6224d4afe316d8e66bd601c3b4b94bd` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA060_iter2-Detalle.csv` | 21 | `778c0ef69226138d4c295000e4d11aef96498a736f68cc158bd000d920e715d1` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 22 | **5** | 3 | 10 | **0** | 4 | 22 | 0 | 0 | 0 |
| 2 | 21 | **5** | 3 | 10 | **0** | 3 | 21 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T21:12:43.113Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T21:16:25.655Z` `rule_id=92052` |

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


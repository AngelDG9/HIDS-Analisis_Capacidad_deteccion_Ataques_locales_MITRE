---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA067
tecnica: T1529
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA067 - T1529 System Shutdown/Reboot (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA067** |
| Técnica | **T1529 - System Shutdown/Reboot** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `f4648f0d-bf78-483c-bafc-3ec99cd1c302` |
| Adaptación | shutdown /r /t 1 -> shutdown /r /t 5 /f (copia local de shutdown.exe); efecto host-side con boot_after |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1529-System_Shutdown_Reboot/` |
| `sha256` ataque | `05243b36559fc9c9d096b3ecb38bb2fdd73b87fc828bed4838a726e260b7a4b3` |
| `sha256` esperado | `49e4a5a841e6e8fb4c803b850bf9e5dd2d6f1282cb643aea4424b360b4d30549` |
| C0 | `Soporte/Ataques/c0/windows/ATA067_c0.md` (`sha256=bb601329d3dd0d6b023c5bfae8ac28dbc213b30a5231e98046be2d87fa6f1a63`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T22:55:53Z` | `2026-11-08T22:57:02Z` | 69 s | 203 | **19** | `503,67018,67027,92031,92032,92052,92066` | 53 |
| 2 | `2026-11-08T23:00:51Z` | `2026-11-08T23:02:01Z` | 70 s | 204 | **19** | `503,67018,67027,92031,92032,92052,92066` | 52 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA067\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA067_iter{1,2}/efecto.txt`: boot_before < boot_after; agente 002 Active tras el reinicio.

**Iter 1** (`sha256=ecb308bdf537c81e1020107527ec396e2994c652ef6210f4ce3bad5cd04a2890`):

```text
  guid=f4648f0d-bf78-483c-bafc-3ec99cd1c302
  t0=2026-11-08T22:55:57Z
  boot_before=2026-11-08T22:53:32Z
  comando=shutdown /r /t 5 /f
  nota=el efecto se cierra en el host con boot_after tras el reinicio
boot_after=2026-11-08T22:56:10Z

VEREDICTO: EFECTO DEMOSTRADO (boot_before=2026-11-08T22:53:32Z < boot_after=2026-11-08T22:56:10Z; agente Active)
```

**Iter 2** (`sha256=102f93b4b1b0bf47c3e731dff034f0b92b61fa69a1682172cf9b01ab6b4dd4c6`):

```text
  guid=f4648f0d-bf78-483c-bafc-3ec99cd1c302
  t0=2026-11-08T23:00:56Z
  boot_before=2026-11-08T22:58:14Z
  comando=shutdown /r /t 5 /f
  nota=el efecto se cierra en el host con boot_after tras el reinicio
boot_after=2026-11-08T23:01:11Z

VEREDICTO: EFECTO DEMOSTRADO (boot_before=2026-11-08T22:58:14Z < boot_after=2026-11-08T23:01:11Z; agente Active)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA067_iter1-Detalle.csv` | 203 | `d13db18c33846fa6a44d1d2925893731517353d09b0dca8a4cfd4b2a724ce91a` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA067_iter2-Detalle.csv` | 204 | `e7be02e9ded29e539fa64c9b183eaac37e3a3881f82682c72be77693ed91cf44` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 203 | **19** | 9 | 165 | **0** | 10 | 203 | 0 | 0 | 0 |
| 2 | 204 | **19** | 9 | 166 | **0** | 10 | 204 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 19 | 7 -> `503,67018,67027,92031,92032,92052,92066` | `2026-11-08T22:55:54.797Z` `rule_id=92052` |
| 2 | 19 | 7 -> `503,67018,67027,92031,92032,92052,92066` | `2026-11-08T23:00:53.357Z` `rule_id=92052` |

- Detección principal: procesos del ataque anclados por `win_command_line` a la carpeta.
- **El efecto no es detección**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteración - veredicto **`iguales`**

`{503,67018,67027,92031,92032,92052,92066} == {503,67018,67027,92031,92032,92052,92066}`; recuento 19 vs 19; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5′**: detección por proceso; sin capa de red ni de recursos.
2. **Canal SSH**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Elevación**: token SSH **High**; no se necesitó tarea `Highest`.
5. **Ruido de arranque**: `92066`/`92031` (novel) se cuentan como detección por la regla congelada `novel`; el TPR no cambia, pero infla `#Alertas`/`#rule.id`.
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.

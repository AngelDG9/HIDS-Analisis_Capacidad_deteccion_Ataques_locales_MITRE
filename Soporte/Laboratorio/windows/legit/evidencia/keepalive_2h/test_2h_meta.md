# Prueba de 2 h del keepalive Windows — T4 (W3-bis)

> **Ventana:** `2026-11-12T11:00:00Z` → `2026-11-12T13:00:00Z` (2 h exactas).
> **Ejecución:** T4 (C6), por `tfg-executor`. **No** es la ventana de 72 h.
> **Fuente:** `heartbeat.jsonl` (host), `keepalive.log`/`recovery.log`/`estado.json` (invitado).
> **Sin secretos.** La copia primaria vive fuera de la VM en
> `D:\TFG-VMs\legitimo-windows-2026-11-12\keepalive_2h\`.

## 1. Resultado en una tabla

| Dato | Valor | Criterio | Resultado |
|---|---|---|---|
| Latidos **emitidos** en la ventana | **24/24** (cada 5 min, :00/:05/.../:55) | 24 esperados | **PASA** |
| Latidos **recibidos** en el sink | **23/24** (falta `seq=12`, 11:45, prueba de sink caído) | — | declarado |
| `seq` | **3 → 26**, estrictamente creciente; único hueco `12` | monótono | **PASA** |
| `ka_instancias` | **1** en **23/23** latidos recibidos y en 24/24 emitidos | 1 | **PASA** |
| `ka_pid` | **256** único durante toda la ventana | 1 proceso | **PASA** |
| `delta_s` (`recv_utc − ts_envio`) | máx. **0,610 s**; 23/23 ≤ 2 s; 0 > 5 s | ≤ 2 s (99 %) | **PASA** |
| Cadena `sha256_prev` | **`OK` en 23/23** (el sink reiniciado re-siembra del JSONL) | sin `ROTA` | **PASA** |
| Muerte provocada del cliente | `taskkill /f /im ghosts.exe` a las **11:20:02Z** (pid 5264) | — | ejecutada |
| Recuperación | **11:25:08Z**, pid **6496**, `user=DESKTOP-BTMCFA5\angel`, `rc_run=0`; **1 ciclo** (5 min 6 s) | ≤ 2 ciclos | **PASA** |
| Duplicado | 2.ª instancia manual a las **11:14:05Z**: `segunda_instancia pid=5896`; salida 0; `ka_instancias=1` sigue | rechazado | **PASA** |
| `schtasks /run` con el bucle vivo | `INFO: ... is currently running`; no crea 2.ª instancia (`IgnoreNew`) | no duplica | **PASA** |
| Sink caído | stop **11:40:03Z**, start **11:47:05Z**; `11:45:04Z hb=FAIL motivo=timeout`; `estado.json` intacto; reanuda **11:50:01Z seq=13** | — | **PASA** |
| `win_user` tras recuperar | `DESKTOP-BTMCFA5\angel` | angel | **PASA** |
| Un solo proceso de trabajo | `ka_pid=256` único; el bucle no crea procesos por ciclo | 1 | **PASA** |

## 2. Horas UTC literales

```
primer latido de la ventana : 2026-11-12T11:00:02Z  (seq=3)
último latido de la ventana : 2026-11-12T12:55:01Z  (seq=26)
latido perdido              : 2026-11-12T11:45:04Z  (seq=12, hb=FAIL)
recuperación del cliente    : 2026-11-12T11:25:08Z  (pid=6496)
duplicado rechazado         : 2026-11-12T11:14:05Z  (pid=5896, segunda_instancia)
sink down / up              : 2026-11-12T11:40:03Z / 2026-11-12T11:47:05Z
```

## 3. Arranque y cierre

- `arm` a las **10:51:50Z**: `logall_json=yes` verificado, `ventana_actual.json`
  (`t0=11:00:00Z`, `t1=13:00:00Z`), `TFG-WinLegit-Keepalive` Running, cliente `angel`.
- Los latidos `seq=1` (10:51:08Z) y `seq=2` (10:55:00Z) son **anteriores** a `t0`:
  no cuentan en la ventana; se conservan en el JSONL para la cadena.
- El latido `seq=27` (13:00:02Z) es **posterior** a `t1`: no cuenta en la ventana.
- **Copia primaria:** `D:\TFG-VMs\legitimo-windows-2026-11-12\keepalive_2h\`.
- **Copia sellada:** `Soporte/Laboratorio/windows/legit/evidencia/keepalive_2h/`.
- `copiado_utc=2026-11-12T13:00:35Z` (scp de los logs del invitado).
  El snapshot v2 se crea **después** de borrar esos logs del invitado; por tanto,
  `copiado_utc < snapshot_utc`.

## 4. Declaraciones

1. El kill duro **no** se auto-reinicia (política del plan): se detecta en el siguiente
   ciclo y se recupera con `schtasks /run` (1 ciclo, 5 min 6 s). Es una incidencia
   declarada, no oculta.
2. El sink caído produce **un** latido no recibido (`seq=12`); el latido se **emitió**
   (`keepalive.log` con `hb=FAIL`) y el estado local quedó intacto. Al volver el sink,
   la cadena se re-siembra desde el JSONL y continúa `OK`.
3. El duplicado por `schtasks /run` está bloqueado por `MultipleInstances=IgnoreNew`;
   la prueba manual de una segunda instancia demuestra el **mutex global**
   (`segunda_instancia`) y que `ka_instancias` sigue **1**.
4. `M` del crudo (unidad = línea de `archives`, agente 002, `boveda_version=3`):
   **881 endpoint / 2.440 total** en `[11:00,13:00]`. No se usa aquí para FPR; es el
   control de que el `crudo` cubre la ventana.

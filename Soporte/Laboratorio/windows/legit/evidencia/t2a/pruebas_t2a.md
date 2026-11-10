# T2a — chivato por red + keepalive de un solo proceso (evidencia)

**Plan:** `_fases/windows-legit-prep/plan_w3bis.md` v2 (`approved_by_human`, commit `4237a16`).
**Tanda:** T2a (parte de T2: §4 y §6.2). **Sin ventana, sin ataques, sin snapshot nuevo, sin commits.**
**Snapshot usado:** `lab-listo-windows-legit` (v1), revertido al inicio y **no modificado**.
**VM:** `D:\TFG-VMs\victima-windows\victima-windows.vmx` (apagada al terminar).
**Sink:** `Soporte/Laboratorio/windows/legit/heartbeat_sink.py` en `192.168.65.1:9095`.
**Host:** Windows 10/11 del laboratorio. **Invitado:** `desktop-btmcfa5\angel` (`192.168.65.130`).

> Nota de ruta: el encargo de T2a fija el sink en `Soporte/Laboratorio/windows/legit/heartbeat_sink.py`
> (el plan §13 lo nombra en `windows/host/`). Se ha implementado en `legit/`, como ordena el encargo.

---

## Resumen

| Prueba | Resultado |
|---|---|
| 1. Una sola instancia (positiva + duplicado + tras reinicio) | **PASA** |
| 2. Dos ciclos alineados con `seq` consecutivo | **PASA** |
| 3. Sink caído: `hb=FAIL`, el bucle sigue, `estado.json` intacto; al volver, reanuda | **PASA** |
| 4. Puerto 9095 ocupado ⇒ `exit 48` | **PASA** |
| 5. 0 procesos externos por ciclo | **PASA** (CIM `hijos=1` = `conhost`; Sysmon 0 hijos) |
| 6. Reloj: `seq` monótono y timestamps alineados | **PASA** con cortes declarados |

**Hallazgo corregido durante T2a:** el mutex `Global\` creado por SYSTEM daba `ACCESS_DENIED`
a un duplicado lanzado como `angel`; el duplicado **arrancaba**. Se corrigió con una ACL
`Everyone` en el mutex y tratando “acceso denegado” como segunda instancia. Ver prueba 1.

---

## 1. Una sola instancia

Duplicado lanzado a mano (bypass del scheduler) con el bucle vivo:

```
ANTES_KA_PROCS=1
--- schtasks /run con el bucle vivo (IgnoreNew del scheduler) ---
INFO: scheduled task "TFG-WinLegit-Keepalive" is currently running.
SUCCESS: Attempted to run the scheduled task "TFG-WinLegit-Keepalive".
RC_SCHTASKS_RUN=0
--- duplicado a mano (bypass del scheduler; debe chocar con el mutex) ---
DUPLICADO_PID=6344
DUPLICADO_SALIO=True
DUPLICADO_EXITCODE=0
DESPUES_KA_PROCS=1
```

Log del invitado:

```
2026-11-10T19:16:43Z	keepalive	arranque modo=Loop pid=6344 intervalo_min=5 sink=http://192.168.65.1:9095/heartbeat powercfg_ok=True seq=1
2026-11-10T19:16:43Z	keepalive	segunda_instancia pid=6344 (mutex Global\TFG-WinLegit-Keepalive ocupado o inaccesible; no se hace nada)
```

`ka_instancias=1` en **todos** los latidos (5/5):

```
ka_instancias=1,1,1,1,1
ka_pid=5440,5440,5440,5440,1504
```

Tras **reiniciar el invitado** (disparador `AtStartup`), arrancó **una** instancia:

```
LAST_BOOT_UTC=2026-11-10T19:46:27Z
TAREA_ESTADO=Running
KA_PROCS=1
KA_PID=1504
2026-11-10T19:46:47Z	keepalive	arranque modo=Loop pid=1504 ... seq=5
2026-11-10T19:46:50Z	keepalive	latido seq=6 hb=OK ka_inst=1 ... hijos=1
```

---

## 2. Dos ciclos alineados

Latidos reales (`heartbeat.jsonl`):

```
{"ts_utc":"2026-11-10T19:20:00Z","seq":2,...,"ka_instancias":1,...,"sha256_prev":"bda327...","recv_utc":"2026-11-10T19:20:01Z","delta_s":1.679,"body_sha256":"9188bc...","cadena":"OK","seq_ok":true}
{"ts_utc":"2026-11-10T19:25:00Z","seq":3,...,"ka_instancias":1,...,"sha256_prev":"9188bc...","recv_utc":"2026-11-10T19:25:01Z","delta_s":1.147,"body_sha256":"8dd0e4...","cadena":"OK","seq_ok":true}
```

Análisis (`analisis_heartbeat.txt`):

```
seq=1,2,3,5,6
ts_utc=2026-11-10T19:16:20Z,2026-11-10T19:20:00Z,2026-11-10T19:25:00Z,2026-11-10T19:35:00Z,2026-11-10T19:46:47Z
ka_instancias=1,1,1,1,1
cadena=INICIO,OK,OK,OK,REINICIO_BUCLE
delta_s=2.139,1.679,1.147,1.036,3.758
CADENA 1->2: OK
CADENA 2->3: OK
CADENA 3->5: OK
CADENA 5->6: REINICIO_BUCLE
DESALINEADOS=2026-11-10T19:16:20Z,2026-11-10T19:46:47Z
INTERVALO 1->2: 220 s
INTERVALO 2->3: 300 s
INTERVALO 3->5: 600 s
INTERVALO 5->6: 707 s
SEQ_MONOTONO=True
SEQ_CONSECUTIVO=False
CADENA_OK=True
```

- `19:20:00` y `19:25:00` son múltiplos de 5 min ⇒ **alineados**, `seq` 2→3 consecutivo.
- `19:16:20` y `19:46:47` son los latidos **de arranque** (primer ciclo inmediato), declarados.
- `3→5` (600 s): el latido `seq=4` de las `19:30` **falló** con el sink caído (prueba 3).
- `5→6` (707 s): reinicio del invitado; `sha256_prev=""` ⇒ `REINICIO_BUCLE` (declarado, no manipulación).

---

## 3. Sink caído

Antes de parar el sink:

```
HB_LINES_BEFORE=3
HB_SHA_BEFORE=d4f73a8986427a2c517389902d818f29d3c5bd8bbf6c61dd5b1301174adc330d
ESTADO_SHA=caf98ced1e5b2c799749175c8595afacfcfe7be3cecc85aa9a82127d6bf81d57
ESTADO_MTIME=2026-11-10T19:16:22.1435858Z
```

Con el sink parado, ciclo de las `19:30`:

```
2026-11-10T19:30:05Z	keepalive	latido seq=4 hb=FAIL ka_inst=1 ... hijos=1 motivo=The operation has timed out
```

Estado del bucle y de la evidencia **durante la caída**:

```
KA_PROCS=1
KA_PID=5440
ESTADO_SHA=caf98ced1e5b2c799749175c8595afacfcfe7be3cecc85aa9a82127d6bf81d57   (idéntico)
ESTADO_MTIME=2026-11-10T19:16:22.1435858Z                                       (idéntico)
HB_LINES_AFTER_FAIL=3
HB_SHA_AFTER_FAIL=d4f73a8986427a2c517389902d818f29d3c5bd8bbf6c61dd5b1301174adc330d   (idéntico)
```

Al levantar el sink, ciclo de las `19:35`:

```
2026-11-10T19:35:01Z	keepalive	latido seq=5 hb=OK ka_inst=1 ... hijos=1
{"ts_utc":"2026-11-10T19:35:00Z","seq":5,...,"sha256_prev":"8dd0e46b...","cadena":"OK","seq_ok":true}
```

La cadena sigue desde el **último cuerpo aceptado** (`seq=3`); el `seq=4` fallido no actualizó
`sha256_prev`. `estado.json` no se reescribió (solo se escribe cada 60 min).

---

## 4. Puerto 9095 ocupado ⇒ `exit 48`

```
OCUPANTE_PID=2836 EXITED=False
OCUPANTE_OUT=LISTO
PUERTO_OCUPADO=1
--- ejecucion del sink con el puerto ocupado (sincrona: debe salir al instante) ---
2026-11-10T19:44:59Z ERROR no se pudo escuchar en 192.168.65.1:9095 -> [WinError 10048] Solo se permite un uso de cada dirección de socket (protocolo/dirección de red/puerto)
SINK_EXIT=48
PUERTO_LIBRE=1
```

El sink **no** hace fallback silencioso. `allow_reuse_address=False` es obligatorio en Windows:
con `SO_REUSEADDR` un segundo bind podría “robar” el puerto.

---

## 5. 0 procesos externos por ciclo

`prueba_5_procesos.txt`:

```
KA_PID=5440 (proceso del bucle durante las pruebas)
ARRANQUE_BUCLE Time=2026-11-10T20:16:19.9237045+01:00 PPID=1160 IMG=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
EID1_PROCESO_BUCLE=1
EID1_HIJOS_BUCLE=0
--- lineas del log con hijos= (una por ciclo) ---
2026-11-10T19:16:22Z	keepalive	latido seq=1 ... hijos=1
2026-11-10T19:20:01Z	keepalive	latido seq=2 ... hijos=1
2026-11-10T19:25:01Z	keepalive	latido seq=3 ... hijos=1
2026-11-10T19:30:05Z	keepalive	latido seq=4 hb=FAIL ... hijos=1
2026-11-10T19:35:01Z	keepalive	latido seq=5 ... hijos=1
```

Snapshot en vivo durante las pruebas (CIM):

```
KA_PROCS=1
--- hijos actuales del proceso del bucle ---
ProcessId Name        CreationDate
     1880 conhost.exe 11/10/2026 8:16:19 PM
```

**Cómo se demuestra “1 proceso” y “0 externos por ciclo”:**

1. **`ka_instancias=1` en 5/5 latidos** y `ka_pid` único por proceso (5440 hasta el reinicio; 1504
   después). El conteo se hace con `Get-CimInstance Win32_Process` filtrando `powershell.exe` cuya
   `CommandLine` contiene `tfg_keepalive_windows.ps1 -Loop`.
2. **Duplicado rechazado** por el mutex (prueba 1) y por `MultipleInstances=IgnoreNew` del scheduler.
3. **Hijos del bucle:** `hijos=1` en cada ciclo (solo `conhost.exe`, creado una vez al arrancar).
   `Get-CimInstance ... ParentProcessId = $PID` no ve ningún otro hijo.
4. **Sysmon EID 1:** 1 evento del propio `powershell.exe` del bucle (arranque) y **0** eventos con
   `ParentProcessId=5440`. La config de Sysmon del laboratorio **excluye `conhost.exe` y
   `powercfg.exe`**; por eso el `powercfg` de arranque no aparece en Sysmon (sí en el log:
   `powercfg_ok=True`). Para `cmd.exe`/`schtasks.exe`/`query.exe` no hay exclusión: si el ciclo los
   lanzara, aparecerían. No aparecen.
5. **Código:** el ciclo (`Invoke-Ciclo`, líneas 174-463) solo usa cmdlets en proceso
   (`Get-PSDrive`, `Get-Service`, `Get-Process`, `Get-CimInstance`, `Invoke-CimMethod`,
   `Get-NetRoute`, `Get-MpComputerStatus`, registro, `Get-FileHash`, `Get-ScheduledTask`).
   `powercfg` se ejecuta **una vez** al arrancar (`Get-PowercfgOk`, línea 511) y `schtasks` solo en
   las ramas de recuperación (líneas 268-341), que **no** se ejecutan con `armado=false`.

---

## 6. Reloj

De `analisis_heartbeat.txt`:

```
delta_s=2.139,1.679,1.147,1.036,3.758
INTERVALO 2->3: 300 s
SEQ_MONOTONO=True
```

- Δ(`recv_utc`, `ts_utc`) entre **1,0 y 3,8 s** en los 5 latidos (máximo tras el reinicio).
- Cadencia de **300 s** entre ciclos alineados (2→3). Los intervalos 600 s y 707 s corresponden a
  los dos cortes **declarados** (sink caído y reinicio).
- `seq` **monótono**; consecutivo en operación normal (1→2→3). El hueco `4` es el latido que falló
  con el sink caído; el `6` es el arranque tras reinicio (`REINICIO_BUCLE`).

---

## Tarea `TFG-WinLegit-Keepalive`

`prueba_3_tarea.txt`:

```
TAREA=TFG-WinLegit-Keepalive ESTADO=Ready
ACCION=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\angel\ghosts-client\tfg_keepalive_windows.ps1" -Loop
PRINCIPAL=SYSTEM/ServiceAccount/Highest
MULTIPLE_INSTANCES=IgnoreNew
EXECUTION_TIME_LIMIT=PT0S
RESTART_COUNT=3
RESTART_INTERVAL=PT1M
TRIGGER=MSFT_TaskBootTrigger
START_WHEN_AVAILABLE=True
```

---

## Ficheros y `sha256`

| Fichero | Tipo | `sha256` |
|---|---|---|
| `Soporte/Laboratorio/windows/legit/heartbeat_sink.py` | nuevo | `0f5fcfbaba65788e6be68f01a51e0e864cf5d6c630139e47acb80b05658b7670` |
| `Soporte/Laboratorio/windows/legit/heartbeat_sink_ctl.ps1` | nuevo | `bc9c37ef82eeb0c90f9a174e3b32aa6d979476bb9ac5da1ba0ce5be64758d475` |
| `Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1` | mod | `36e8dcbcbecfa0d1eff467b4c41e7314158d9f83e84f9371a00de1baf59517b1` |
| `Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1` | mod | `d7c17a3ff4a3cc78b03dbc85f18cd5b2679d248a0af4fa984426e899f032e54e` |

Plan `_fases/windows-legit-prep/plan_w3bis.md` **intacto**:
`4480e65707a1feebb4fe78d9166ad6475efb77d542f24cff0cf4578017c6b335`.

---

## Hallazgos y recomendaciones (no bloquean T2a)

1. **Mutex `Global\` y ACL (corregido y probado).** El mutex creado por SYSTEM daba
   `ACCESS_DENIED` a un duplicado lanzado como `angel`; el duplicado arrancaba. Se crea con
   una ACL que permite `Everyone` abrir el mutex y, además, cualquier fallo del mutex se
   trata como “ya hay instancia” (`segunda_instancia`, `exit 0`). Verificado.
2. **Orden mutex/powercfg (menor).** El duplicado registra `arranque` y ejecuta el
   `powercfg` de arranque **antes** de comprobar el mutex (el bloque de mutex está después
   del arranque). Funcionalmente no arranca el bucle (`segunda_instancia`), pero para T2b/T4
   conviene mover la comprobación del mutex **antes** de `Get-PowercfgOk` y del `arranque`,
   para que la 2.ª instancia no genere ni un proceso.
3. **`delta_s` incluye el trabajo del ciclo (menor).** `ts_utc` se toma al **inicio** de
   `Invoke-Ciclo` y el POST va al final; Δ incluye ~1-2 s de trabajo. Los Δ observados
   (1,0-3,8 s) son una **cota superior** del desfase de reloj. Para CA-W3b-21 conviene
   sellar `ts_utc` justo antes del POST.
4. **Sysmon excluye `conhost.exe` y `powercfg.exe`** en la config del laboratorio: no se
   pueden usar para contar esos dos; el `hijos=1` del latido (CIM) y el `powercfg_ok=True`
   del log son la evidencia. `cmd.exe`/`schtasks.exe`/`query.exe` **sí** se verían y no
   aparecen.
5. **`-Once`** comparte `Invoke-Ciclo` con `-Loop`, pero no se ha ejercitado en T2a (lo usa
   `deploy_windows.ps1`; se probará en T3/T4).

---

## Pendiente para T2b

- Controlador `windows_legit_host_control.ps1` v4: `watch` sin SSH leyendo `heartbeat.jsonl`,
  `G-W13` (frescura ≤ 12 min, `seq` monótono, `ka_instancias=1`), `arm` idempotente, `crudo`,
  `cleanup` bloqueado (`exit 84`), `prep` con sink arriba + POST de prueba, `stop` con `stop.flag`
  y parada del sink.
- `verificar_windows.ps1` v4 (Defender, sesión, manifiesto).
- Prueba de **0 alertas nuevas** por 1 chequeo del `watch` (CA-W3b-12) y la ventana de 2 h
  (24/24 latidos, kill duro + ALARMA ≤ 12 min) para CA-W3b-12b/20.
- Alinear `deploy_windows.ps1` con el cliente 8.3.1 y los nuevos scripts (T3/T4).

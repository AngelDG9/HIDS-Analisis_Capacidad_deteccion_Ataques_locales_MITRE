# prueba_en_seco.md - pruebas en seco del bloque legitimo-fix

> Generado por prueba_en_seco.ps1. Salida LITERAL (recortada). Horas UTC.
> Se ejecuta sobre la instancia arreglada, FUERA de la ventana, antes de crear
> lab-listo-legit-v2. Lo que ensucia se descarta revirtiendo al snapshot.
> Orden real de ejecucion: DT-B0 (browser_eval.md), DT1, DT10, DT2, DT8, DT0,
> DT4/DT7/DT6, DT5a, DT5b, DT9, DT11, DT3, DT12, DT13.

## DT1 - Arreglos y receta presentes (verificar_arreglos.sh)

**Inicio:** 2026-10-20T23:20:08Z

```text
nlog_console=Warn
nlog_sha=d8f5f1d1154601360e5d81c752ea50b034e915e10f9545625f4a5732352221fb
nlog_applog_archive=20
client_ctl_cap=20
keepalive_v3=1
recetas=f5fa5812,a75b4ca9,6d5ff4e6
recetas_sha=f5fa58120220041a24b20bbda09b1dca4f090090e7483b05dfdc187921430dba,a75b4ca9707a79113320be6eb4b907e10c27a4e938abc37064d4e9ffcaa3da45,6d5ff4e6e4bd33e138e88eeb1f1f10da1edfe222b1dcb1c4110ef4ecb88f4a9c
timeline_activa=f5fa5812
web_session=1
receptor_navegador=none
ram_free_mb=2400
swap_mb=1915
swap_estado=AVISO (swap_mb=1915 != 0; desviación declarada)
timer=not-found
df_free_mb=4555
df_libre_pct=48
df_inodes_libres_pct=84
RESULT=PASS
```

**Veredicto DT1: PASA** - nlog=Warn, tope=20, keepalive v3, recetas == repo, timer=NOT-FOUND  (2026-10-20T23:20:09Z)

### Resumen de esta ejecucion
- DT1: PASA

## DT10 - Invariantes de la receta (--check)

**Inicio:** 2026-10-20T23:21:25Z

```text
receta v1: dias={1: 111, 2: 117, 3: 105} total=333 web_session=1 handlers_browser=0
RESULT=PASS
```

**Veredicto DT10: PASA** - 111/117/105, hueco <= 12 min, 0 random, 0 Browser*, web_session=1  (2026-10-20T23:21:26Z)

### Resumen de esta ejecucion
- DT10: PASA

## DT2 - Tope del stdout (TFG_CLIENT_OUT_MAX_MB=1, 3 MB escritos)

**Inicio:** 2026-10-20T23:21:26Z

-rw-rw-r-- 1 angel angel 3145728 Oct 21 01:21 /home/angel/ghosts-client/client.out

```text
2026-10-20T23:21:30Z client_ctl: rotado client.out (3MB >= 1MB) -> client.out.1
2026-10-20T23:21:30Z client_ctl: ya estaba en marcha (pids=39771 ); NO se duplica (H-A)
-rw-rw-r-- 1 angel angel       0 Oct 21 01:21 /home/angel/ghosts-client/client.out
-rw-rw-r-- 1 angel angel 3145728 Oct 21 01:21 /home/angel/ghosts-client/client.out.1
39771 bash -c TFG_CLIENT_OUT_MAX_MB=1 bash /home/angel/ghosts-client/client_ctl.sh start; ls -l /home/angel/ghosts-client/client.out /home/angel/ghosts-client/client.out.1; pgrep -af ghosts.client.linux | head -1
```
```text
2026-10-20T23:21:30Z client_ctl: rotado client.out (3MB >= 1MB) -> client.out.1
-rw-rw-r-- 1 angel angel       0 Oct 21 01:21 /home/angel/ghosts-client/client.out
-rw-rw-r-- 1 angel angel 3145728 Oct 21 01:21 /home/angel/ghosts-client/client.out.1
39836
```
  client.out=0 B  client.out.1=3145728 B  procesos=0

**Veredicto DT2: FALLA** - ambos ficheros <= 1 MB y el proceso sigue vivo  (2026-10-20T23:21:31Z)

### Resumen de esta ejecucion
- DT2: PASA

## DT2 - Tope del stdout (TFG_CLIENT_OUT_MAX_MB=1, 3 MB escritos)

**Inicio:** 2026-10-20T23:25:59Z

-rw-rw-r-- 1 angel angel 3145728 Oct 21 01:26 /home/angel/ghosts-client/client.out

```text
2026-10-20T23:26:03Z client_ctl: rotado client.out (3MB >= 1MB) -> client.out.1 (ultimos 1MB)
2026-10-20T23:26:05Z client_ctl: arrancado pid=64843  (stdout -> client.out, tope 1MB x2)
-rw-rw-r-- 1 angel angel    1009 Oct 21 01:26 /home/angel/ghosts-client/client.out
-rw-rw-r-- 1 angel angel 1048576 Oct 21 01:26 /home/angel/ghosts-client/client.out.1
64835 bash -c TFG_CLIENT_OUT_MAX_MB=1 bash /home/angel/ghosts-client/client_ctl.sh start; ls -l /home/angel/ghosts-client/client.out /home/angel/ghosts-client/client.out.1; pgrep -af ghosts.client.linux | head -1
```
```text
2026-10-20T23:26:06Z client_ctl: rotado client.out (3MB >= 1MB) -> client.out.1 (ultimos 1MB)
-rw-rw-r-- 1 angel angel       0 Oct 21 01:26 /home/angel/ghosts-client/client.out
-rw-rw-r-- 1 angel angel 1048576 Oct 21 01:26 /home/angel/ghosts-client/client.out.1
64843
```
  client.out=0 B  client.out.1=1048576 B  procesos=1

**Veredicto DT2: PASA** - ambos ficheros <= 1 MB y el proceso sigue vivo  (2026-10-20T23:26:06Z)

### Resumen de esta ejecucion
- DT2: PASA

## DT8 - Extraccion con rotacion (datos REALES del intento fallido)

**Inicio:** 2026-10-20T23:26:09Z

  ficheros: archives.json, ossec-archive-19.json.gz, ossec-archive-20.json
```text
python.exe : ERROR --estricto: hay ficheros que SOLAPAN en tiempo:
En D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\legitimo_72h\prueba_en_seco.ps1: 
169 Carácter: 8
+   $r = & python (Join-Path $Repo '_artefactos\scripts\contar_denomina ...
+        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (ERROR --estrict...APAN en tiempo::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
  archives.json [2026-10-20T00:00:03Z..2026-10-20T13:09:47Z] x ossec-archive-20.json 
[2026-10-20T00:00:03Z..2026-10-20T13:10:20Z]
  archives.json: total=7854 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:09:47Z
  ossec-archive-19.json.gz: total=1552236 endpoint=1538601 rango=2026-10-19T00:00:02Z .. 2026-10-20T00:00:01Z
  ossec-archive-20.json: total=7940 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:10:20Z
M total=1568030 endpoint=1538601 no_ts=0 bad_json=1 ficheros=3 duplicados=0
cobertura endpoint: 2026-10-19T00:00:05Z .. 2026-10-19T22:00:11Z
```
  rc=3
  ficheros en Dataset/Legitimo/legitimo_72h: 0 (debe ser 0)

**Veredicto DT8: FALLA** - exit=3  (2026-10-20T23:26:26Z)

### Resumen de esta ejecucion
- DT8: FALLA

## DT8 - Extraccion con rotacion (datos REALES del intento fallido): 3 escenarios

**Inicio:** 2026-10-20T23:27:42Z

- (A) conjunto CORRECTO: .gz del dia + archives.json vivo (regla de borde)
```text
  ossec-archive-19.json.gz: total=1552236 endpoint=1538601 rango=2026-10-19T00:00:02Z .. 2026-10-20T00:00:01Z
  archives.json: total=7854 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:09:47Z
M total=1560090 endpoint=1538601 no_ts=0 bad_json=1 ficheros=2 duplicados=0
cobertura endpoint: 2026-10-19T00:00:05Z .. 2026-10-19T22:00:11Z
--estricto: sin solapes entre ficheros ·nicos
-> C:\Users\angel\AppData\Local\Temp\opencode\dt8\manifest.tsv
-> C:\Users\angel\AppData\Local\Temp\opencode\dt8\M.csv
```
  rc=0
  MANIFEST:
fichero	bytes	sha256	primer	ultimo
ossec-archive-19.json.gz	27768540	aef0a068bbed86c68b48691318ba689f2c0d889cb28d15ec3dee918682563115	2026-10-19T00:00:02Z	2026-10-20T00:00:01Z
archives.json	4757038	931382574b03da1b64d97f5e5c522e302ea842fc75a7fb0d9f10484c2c24d9e4	2026-10-20T00:00:03Z	2026-10-20T13:09:47Z
  CSV:
# contar_denominador.py | metrica_version=1 boveda_version=1 | desde=2026-10-19T00:00:00Z hasta=2026-10-22T00:00:00Z | agente=001/victima-linux | ficheros=2 | sha256_entradas=aef0a068bbed86c68b48691318ba689f2c0d889cb28d15ec3dee918682563115:ossec-archive-19.json.gz,931382574b03da1b64d97f5e5c522e302ea842fc75a7fb0d9f10484c2c24d9e4:archives.json
metrica_version,boveda_version,ambito,eventos,primer_ts,ultimo_ts
1,1,total,1560090,2026-10-19T00:00:02Z,2026-10-20T13:09:47Z
- (B) TRAMPA H-D/H-E: se anade el plano diario del mismo dia (solapa con el vivo)
```text
python.exe : ERROR --estricto: hay ficheros que SOLAPAN en tiempo:
En D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\legitimo_72h\prueba_en_seco.ps1: 
182 Carácter: 9
+   $rB = & python $script @args0 $gz19 $vivo $plano 2>&1 | Out-String
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (ERROR --estrict...APAN en tiempo::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
  archives.json [2026-10-20T00:00:03Z..2026-10-20T13:09:47Z] x ossec-archive-20.json 
[2026-10-20T00:00:03Z..2026-10-20T13:10:20Z]
  ossec-archive-19.json.gz: total=1552236 endpoint=1538601 rango=2026-10-19T00:00:02Z .. 2026-10-20T00:00:01Z
  archives.json: total=7854 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:09:47Z
  ossec-archive-20.json: total=7940 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:10:20Z
M total=1568030 endpoint=1538601 no_ts=0 bad_json=1 ficheros=3 duplicados=0
cobertura endpoint: 2026-10-19T00:00:05Z .. 2026-10-19T22:00:11Z
```
  rc=3 (3 = solape detectado; NO se cuenta dos veces)
- (C) DEDUPE por sha256: se anade una COPIA EXACTA del vivo
```text
  DUPLICADO descartado: archives_copia.json (sha256=931382574b03 == archives.json)
  ossec-archive-19.json.gz: total=1552236 endpoint=1538601 rango=2026-10-19T00:00:02Z .. 2026-10-20T00:00:01Z
  archives.json: total=7854 endpoint=0 rango=2026-10-20T00:00:03Z .. 2026-10-20T13:09:47Z
M total=1560090 endpoint=1538601 no_ts=0 bad_json=1 ficheros=2 duplicados=1
cobertura endpoint: 2026-10-19T00:00:05Z .. 2026-10-19T22:00:11Z
--estricto: sin solapes entre ficheros ·nicos
```
  rc=0 duplicado_detectado=True
  ficheros en Dataset/Legitimo/legitimo_72h: 0 (debe ser 0)

**Veredicto DT8: PASA** - A=0 (0) B=3 (3=solape) C=0 (0 con dedupe)  (2026-10-20T23:28:32Z)

### Resumen de esta ejecucion
- DT8: PASA

## DT0 - Hay semilla? (decision NPC): dos ejecuciones con Command=random

**Inicio:** 2026-10-20T23:28:38Z

- run 1 : 300 s de actividad con Command=random y delays fijos
  run 1: 0 acciones muestreadas; primeras 8 = 
- run 2 : 300 s de actividad con Command=random y delays fijos
  run 2: 0 acciones muestreadas; primeras 8 = 
  run1_n=0 run2_n=0 identicas=True

**Veredicto DT0: FALLA** - las secuencias DIFIEREN => GHOSTS no es reproducible sin parchear => receta (S4.3)  (2026-10-20T23:39:11Z)

### Resumen de esta ejecucion
- DT0: FALLA

## DT0 - Hay semilla? (decision NPC): dos ejecuciones con Command=random

**Inicio:** 2026-10-20T23:49:11Z

- run 1 : 300 s de actividad con Command=random y delays fijos
  run 1: 1 acciones muestreadas; primeras 8 = echo GAMMA echo GAMMA echo ALFA echo DELTA echo GAMMA echo ALFA echo ALFA echo BETA echo BETA echo DELTA echo GAMMA echo GAMMA echo BETA echo BETA echo GAMMA echo ALFA echo ALFA echo ALFA echo BETA echo DELTA echo ALFA echo GAMMA echo GAMMA echo DELTA echo GAMMA echo ALFA echo DELTA echo GAMMA echo GAMMA echo DELTA echo DELTA echo GAMMA echo DELTA echo GAMMA echo DELTA echo BETA echo ALFA echo BETA echo ALFA echo ALFA
- run 2 : 300 s de actividad con Command=random y delays fijos
  run 2: 1 acciones muestreadas; primeras 8 = echo DELTA echo BETA echo BETA echo DELTA echo DELTA echo ALFA echo GAMMA echo ALFA echo DELTA echo GAMMA echo ALFA echo GAMMA echo BETA echo BETA echo DELTA echo ALFA echo DELTA echo ALFA echo BETA echo GAMMA echo BETA echo GAMMA echo BETA echo ALFA echo DELTA echo BETA echo ALFA echo ALFA echo BETA echo BETA echo ALFA echo GAMMA echo ALFA echo DELTA echo DELTA echo DELTA echo BETA echo ALFA echo ALFA echo BETA
  run1_n=1 run2_n=1 identicas=False

**Veredicto DT0: PASA** - las secuencias DIFIEREN => GHOSTS no es reproducible sin parchear => receta (S4.3)  (2026-10-20T23:59:43Z)

### Resumen de esta ejecucion
- DT0: PASA

## DT4 - La vigilancia detecta "estar sin hacer" (kill -STOP)

**Inicio:** 2026-10-21T00:00:34Z

- cliente arrancado con la receta dry (base 00:02Z); 3 min de actividad
```text
antes: 1792541024
67443
```
- SIGSTOP al pid 4280 (proceso VIVO, congelado) a 2026-10-21T00:03:46Z
- GHOSTS: machines=1 statusUp=Up lastReportedUtc=2026-10-21T00:03:37.798564

## DT4 - La vigilancia detecta "estar sin hacer" (kill -STOP)

**Inicio:** 2026-10-21T00:04:53Z

- cliente arrancado con la receta dry (base 00:06Z); 3 min de actividad
```text
antes: 1792541282
67978
```
- SIGSTOP al pid 16304 (proceso VIVO, congelado) a 2026-10-21T00:08:06Z
- GHOSTS: machines=1 statusUp=Up lastReportedUtc=2026-10-21T00:07:59.147587

## DT4 - La vigilancia detecta "estar sin hacer" (kill -STOP)

**Inicio:** 2026-10-21T00:09:45Z

- cliente arrancado con la receta dry (base 00:11Z); 3 min de actividad
```text
antes: 1792541576
68696
```
- SIGSTOP al pid 68696 (proceso VIVO, congelado) a 2026-10-21T00:12:58Z
- GHOSTS: machines=1 statusUp=Up lastReportedUtc=2026-10-21T00:12:51.06781
```text
[2026-10-21T00:16:35Z] [watch] estado=ALARMA doing_age=4m bloque=si hb=n/a ag= mgr=/ arch=0B dia=0B df=0G tasa=MB/h db=66MB host=177.8G ram=post-hoc rec=0 rot=0 notas=agente>10m,daemons,df<2G
```
- GHOSTS: statusUp=Up lastReportedUtc=2026-10-21T00:12:51.06781
  check #2 -> ALARMA
**estado=ALARMA**
```text
[2026-10-21T00:29:42Z] [watch] estado=ALARMA doing_age=17m bloque=si hb=n/a ag= mgr=/ arch=0B dia=0B df=0G tasa=MB/h db=66MB host=177.8G ram=post-hoc rec=0 rot=0 notas=doing>15m,agente>10m,daemons,sin_eventos,df<2G
```
- GHOSTS: statusUp=Up lastReportedUtc=2026-10-21T00:12:51.06781
  check #2 -> ALARMA
**estado=ALARMA**
```text
[2026-10-21T00:41:47Z] [watch] estado=AVISO doing_age=29m bloque=si hb=18s ag=Active mgr=active/2 arch=604975B dia=498589B df=4.4G tasa=-1.4MB/h db=66MB host=177.8G ram=post-hoc rec=0 rot=0 notas=doing>15m
```
- GHOSTS: statusUp=Up lastReportedUtc=2026-10-21T00:12:51.06781
  check #2 -> AVISO
**estado=AVISO**
```text
[2026-10-21T00:45:14Z] [watch] estado=ALARMA doing_age=33m bloque=si hb=5s ag=Active mgr=active/2 arch=408837B dia=335897B df=4.4G tasa=-1.4MB/h db=66MB host=177.8G ram=post-hoc rec=0 rot=0 notas=doing>30m
```
- GHOSTS: statusUp=Down lastReportedUtc=2026-10-21T00:12:51.06781
  check #2 -> ALARMA
**estado=ALARMA**
```text
[2026-10-21T00:49:47Z] [watch] estado=OK doing_age=1m bloque=si hb=18s ag=Active mgr=active/2 arch=1961305B dia=1813737B df=4.4G tasa=-3.7MB/h db=66MB host=177.8G ram=post-hoc rec=0 rot=0 notas=
```
- GHOSTS: statusUp=Up lastReportedUtc=2026-10-21T00:49:30.246865
  check #3 -> OK

**Veredicto DT4: PASA** - tras SIGCONT + receta fresca vuelve a OK  (2026-10-21T00:49:52Z)

### Resumen de esta ejecucion
- DT4: PASA

## DT5a - Autocuracion (heartbeat): stop(TERM->KILL)+start y acciones reanudadas

**Inicio:** 2026-10-21T00:49:56Z

- SIGSTOP a 70318; keepalive con overrides (STALE=2, CONFIRMA=1, FORZAR_BLOQUE=1)
```text
2026-10-21T00:55:39Z client_ctl: parando pids=70318  (TERM)
2026-10-21T00:55:44Z client_ctl: sigue vivo tras 5s -> KILL (pids=70318 )
2026-10-21T00:55:45Z client_ctl: parado
2026-10-21T00:55:47Z client_ctl: arrancado pid=70841  (stdout -> client.out, tope 20MB x2)
2026-10-21T00:55:47Z keepalive: RECUPERACION n=1 motivo=heartbeat edad_min=4 pid_viejo=70318  pid_nuevo=70841
2026-10-21T01:01:48Z keepalive: ram_free_mb=2353 swap_mb=1915 bloque=TEST edad_app_min=0 free_mb=4550
---
1  (procesos del cliente)
---rec---
2026-10-21T00:55:47Z accion=recuperacion motivo=heartbeat edad_min=4 dia=TEST pid_viejo=70318  pid_nuevo=70841  recuperaciones=1 free_mb=4542 sha_timeline=6b17b173
---edad_app_log---
0 min
```
  recuperaciones=1 procesos=1 edad_app_log=0 min

**Veredicto DT5a: PASA** - 1 linea de recuperacion, 1 proceso y la actividad se reanuda (app.log fresco). La receta dry de DT5 se agoto antes de la recuperacion, por lo que el cliente nuevo arranca sin acciones hasta la siguiente ventana: se declara (el criterio es el reinicio + registro + proceso unico).

### Resumen de esta ejecucion
- DT5a: PASA

## DT5a - Autocuracion (heartbeat): stop(TERM->KILL)+start y acciones reanudadas

**Inicio:** 2026-10-21T01:06:58Z

- SIGSTOP a 84200; keepalive con overrides (STALE=2, CONFIRMA=1, FORZAR_BLOQUE=1)

## DT5a - Autocuracion (heartbeat): stop(TERM->KILL)+start y acciones reanudadas

**Inicio:** 2026-10-21T01:29:17Z

- SIGSTOP a 98554; keepalive con overrides (STALE=2, CONFIRMA=1, FORZAR_BLOQUE=1)

## DT5a - Autocuracion (heartbeat): stop(TERM->KILL)+start y acciones reanudadas

**Inicio:** 2026-10-21T01:53:35Z

- SIGSTOP a 100865; keepalive con overrides (STALE=2, CONFIRMA=1, FORZAR_BLOQUE=1)
- SIGSTOP al cliente (pid 104316) a **2026-10-21T02:44:41Z**; keepalive v3 con overrides de prueba
  (`TFG_STALE_MIN=2`, `TFG_CONFIRMA_MIN=1`, `TFG_MAX_RECUP=2`, `TFG_FORZAR_BLOQUE=1`).
```text
2026-10-21T02:48:57Z keepalive: AVISO bloque=TEST edad_min=4 (primera lectura stale; se confirma en 1 min)
2026-10-21T02:49:57Z client_ctl: parando pids=104316  (TERM)
2026-10-21T02:50:02Z client_ctl: sigue vivo tras 5s -> KILL (pids=104316 )
2026-10-21T02:50:03Z client_ctl: parado
2026-10-21T02:50:05Z client_ctl: arrancado pid=104675  (stdout -> client.out, tope 20MB x2)
2026-10-21T02:50:05Z keepalive: RECUPERACION n=1 motivo=heartbeat edad_min=4 pid_viejo=104316  pid_nuevo=104675
--- recovery.log ---
2026-10-21T02:50:05Z accion=recuperacion motivo=heartbeat edad_min=4 dia=TEST pid_viejo=104316  pid_nuevo=104675  recuperaciones=1 free_mb=4547 sha_timeline=ba236b2c
--- recuperaciones ---
1
--- procesos ---
1
```
  recuperaciones=1 procesos=1

**Veredicto DT5a: PASA** - dos lecturas separadas 1 min (AVISO -> recuperacion), `stop` escalado
TERM->KILL, `start` con el cliente nuevo, **1** linea en `recovery.log` y **1** proceso.

> **Nota de ejecucion (declarada).** Los dos primeros intentos de esta DT se quedaron colgados
> por dos defectos del **arnes**, no del keepalive: (a) `nohup ... &` por SSH dejaba el canal
> abierto (se resolvio con `setsid` y `< /dev/null`); (b) `DUR_H` era entero y la prueba usa
> fracciones de hora (se corrigio el keepalive para aceptar decimales, y se valido). Tambien se
> corrigio el **heartbeat**: `app.log` lo refresca el hilo de updates ("No new configuration
> found" cada 20 s) aunque el motor este muerto, asi que la senal pasa a ser la **ultima accion
> REPORTADA** (`lastReportedUtc` de la API de GHOSTS). Es la misma senal que usa la vigilancia y
> la unica que mide "hacer". Se declara como correccion del supuesto del plan (S6.3.1).
```text
huella activa (d1 normalizado por el cliente): 3bf4f88c
huella d1:                                     7f9d121c
--- dia 1 ---
2026-10-21T03:01:17Z accion=rotacion dia=1 sha_timeline=f5fa5812 huella=7f9d121c pid_nuevo=107263 resultado=ok
--- dia 2 ---
2026-10-21T03:02:37Z accion=rotacion dia=2 sha_timeline=a75b4ca9 huella=c431280b pid_nuevo=107633 resultado=ok
--- dia 3 ---
2026-10-21T03:04:07Z accion=rotacion dia=3 sha_timeline=6d5ff4e6 huella=b532cee6 pid_nuevo=108023 resultado=ok
procesos: 1
```
- `sha_timeline` de cada rotacion = **sha del fichero de receta del repo** (`d2=a75b4ca9`,
  `d3=6d5ff4e6`): la copia es la correcta y el cliente se reinicia (`pid_nuevo` distinto).
- **`machineid` NO cambia**: `7c33a13a-fe89-4a56-bf3c-fcd499e1e557` antes y despues (H-J).

**Veredicto DT5b: PASA** - la receta rota a `d2` y `d3` con el sha esperado, el cliente se
reinicia y la `machineid` se mantiene.

> **Hallazgos declarados (importantes para la ventana).**
> 1. **El cliente REESCRIBE `config/timeline.json` al arrancar** (anade `Id`, `CommandArgs`,
>    `DelayBefore`, `ScheduleType`). El **contenido es el mismo**, pero el **sha cambia**.
>    Consecuencia: `verificar_arreglos.sh` compara ahora **sha + huella de comandos** (y se usa
>    con el cliente parado); y el keepalive **no** decide la rotacion por sha.
> 2. Por eso el **dia 1** rotó en esta prueba (el estado `rotacion.estado` estaba vacio): en la
>    ventana eso **no** pasara porque `prep` **siembra `rotacion.estado` con la fecha de `t0`**
>    (dia 1 ya colocado) y el keepalive salta la rotacion del dia 1. Se declara el cambio
>    respecto de la letra del plan (que lo resolvia comparando shas): mismo efecto, mas robusto.
> 3. La huella de comandos cruda vs normalizada **no coincide** (el cliente reordena/anade
>    campos), asi que la huella es solo una **segunda barrera**; la decision es el estado.

## DT6 - Alarma de agente desconectado (is-active sigue active)

**Inicio:** 2026-10-21T03:06:23Z

```text

```
- agente matado a 2026-10-21T03:06:24Z; se espera >10 min para que el keep-alive envejezca
```text
[2026-10-21T03:18:53Z] [watch] estado=ALARMA doing_age=49m bloque=si hb=721s ag=Active mgr=active/2 arch=78622018B dia=72029344B df=4.4G tasa=-19.4MB/h db=67MB host=177.7G ram=post-hoc rec=0 rot=3 notas=doing>30m,agente>10m
```
- con el daemon caido : unidad/procesos -> is-active=active procs=1 | watch=ALARMA
**estado=ALARMA**
```text
Failed to start wazuh-agent.service: Interactive authentication required.
See system logs and 'systemctl status wazuh-agent.service' for details.
is-active=active
procs=1
```
```text
[2026-10-21T03:20:36Z] [watch] estado=ALARMA doing_age=51m bloque=si hb=828s ag=Active mgr=active/2 arch=138307B dia=23644B df=4.4G tasa=-19.4MB/h db=67MB host=177.7G ram=post-hoc rec=0 rot=3 notas=doing>30m,agente>10m
```
- tras reiniciar el agente : unidad/procesos -> is-active=active procs=1 | watch=ALARMA

**Veredicto DT6: FALLA** - vuelve a OK  (2026-10-21T03:20:36Z)

### Resumen de esta ejecucion
- DT6: FALLA
```text
[2026-10-21T03:22:23Z] [watch] estado=ALARMA doing_age=53m bloque=si hb=935s ag=Active mgr=active/2 arch=36958B dia=16363B df=4.4G tasa=-19.4MB/h db=67MB host=177.7G ram=post-hoc rec=0 rot=3 notas=doing>30m,agente>10m
```
- con el daemon caido : unidad/procesos -> is-active=active procs=0 | watch=ALARMA
**estado=ALARMA**
```text
[2026-10-21T03:27:17Z] [watch] estado=OK doing_age=1m bloque=si hb=4s ag=Active mgr=active/2 arch=4048651B dia=3292633B df=4.4G tasa=14.9MB/h db=67MB host=177.7G ram=post-hoc rec=0 rot=3 notas=
```
- con el daemon caido : unidad/procesos -> is-active=active procs=1 | watch=OK
**estado=OK**
```text
(daemon muerto)
● wazuh-agent.service - Wazuh agent
     Active: active (running) since Wed 2026-10-21 01:09:31 CEST; 3h 57min ago
   Tasks: 27
[2026-10-21T03:18:53Z] [watch] estado=ALARMA ... hb=721s ag=Active mgr=active/2 ... notas=doing>30m,agente>10m
[2026-10-21T03:22:23Z] [watch] estado=ALARMA ... hb=935s ag=Active ... notas=doing>30m,agente>10m
(tras sudo systemctl restart wazuh-agent)
is-active=active agente=1
[2026-10-21T03:27:17Z] [watch] estado=OK doing_age=1m bloque=si hb=4s ag=Active mgr=active/2 ... notas=
```
- **Engano reproducido**: la unidad `wazuh-agent` sigue `active (running)` con **0** procesos
  `wazuh-agentd` (los demas daemons del agente siguen vivos y escriben en `ossec.log`). Es
  exactamente el punto ciego de L1.
- El watch **no** se cree `is-active`: mira `Last keep alive` y da **ALARMA** con `hb=721s`
  (12 min) y `hb=935s` (15,6 min); al reiniciar el agente (`restart`, no `start`: la unidad ya
  estaba "activa") vuelve a **OK**.

**Veredicto DT6: PASA** - `is-active` miente, la vigilancia canta por `hb` y vuelve a OK.

> **Nota de ejecucion (declarada).** El primer intento de cierre fallo por el **arnes**
> (`systemctl start` no reinicia una unidad que ya esta `active`; hay que usar `restart`), y el
> primer `kill` no mato al daemon por autoemparejamiento de `pgrep -f` (se uso `pkill -x`).
> Corregido y repetido. La medicion de `procs` del arnes tambien se autoemparejaba: el numero
> fiable es el de `pgrep -x wazuh-agentd` (0 con el daemon muerto, 1 tras reiniciar).

## DT7 - Disco de la victima leido del agente (df -P): valor y tasa

**Inicio:** 2026-10-21T03:27:27Z

- logall_json ON y movimiento de ~500 MB en la victima
```text
ssh.exe : cp: warning: behavior of -n is non-portable and may change in future; use --update=none instead
En D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\legitimo_72h\prueba_en_seco.ps1: 
67 Carácter: 45
+ ... ManagerPw | & $Ssh -i $Key -o StrictHostKeyChecking=no $Man $cmd 2>&1 ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (cp: warning: be...te=none instead:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
valor aplicado:     <logall_json>yes</logall_json>
/tmp/logall_json_ctl.sh: line 22: 12517 Killed                  sudo -n pkill -9 -f wazuh_apid 2> /dev/null
manager=active (intento 1) agent_control=OK
```
  libre antes=4656412 KB; relleno de 500 MB creado
- esperando 2 muestras del agente (13 min)
```text
[2026-10-21T03:41:25Z] [watch] estado=OK doing_age=14m bloque=si hb=3s ag=Active mgr=active/2 arch=2100986B dia=1819384B df=4G tasa=-1.5MB/h db=67MB host=177.2G ram=post-hoc rec=0 rot=3 notas=
```
  real libre=4143620 KB | watch=-1 KB

**Veredicto DT7: FALLA** - dentro del +-5 % y con tasa calculada  (2026-10-21T03:41:26Z)

### Resumen de esta ejecucion
- DT7: FALLA

## DT9 - DOBLE EJECUCION de la receta (misma secuencia, 111 acciones)

**Inicio:** 2026-10-21T03:41:32Z

- run 1 : receta dry desde 03:43Z (16 min)
  run 1: acciones=106 lineas_recovery=0
- run 2 : receta dry desde 03:59Z (16 min)
  run 2: acciones=105 lineas_recovery=0
  run1=106 run2=105 secuencia_identica=False

**Veredicto DT9: FALLA** - 111 acciones en ambos runs y recovery.log vacio  (2026-10-21T04:14:07Z)

### Resumen de esta ejecucion
- DT9: FALLA

## DT9 - DOBLE EJECUCION de la receta (misma secuencia, 111 acciones)

**Inicio:** 2026-10-21T04:14:50Z

- run 1 : receta dry desde 04:15Z (13 min)
  run 1: acciones=108 lineas_recovery=0
- run 2 : receta dry desde 04:29Z (13 min)
  run 2: acciones=108 lineas_recovery=0
  run1=108 run2=108 secuencia_identica=True

**Veredicto DT9: FALLA** - 111 acciones en ambos runs y recovery.log vacio  (2026-10-21T04:41:23Z)

### Resumen de esta ejecucion
- DT9: FALLA

## DT9 - DOBLE EJECUCION de la receta (misma secuencia, 111 acciones)

**Inicio:** 2026-10-21T04:43:33Z

- run 1 : receta dry desde 04:44Z (13 min)
  run 1: acciones=111 lineas_recovery=0
- run 2 : receta dry desde 04:57Z (13 min)
  run 2: acciones=111 lineas_recovery=0
  run1=111 run2=111 secuencia_identica=True

**Veredicto DT9: PASA** - 111 acciones en ambos runs y recovery.log vacio  (2026-10-21T05:10:06Z)

### Resumen de esta ejecucion
- DT9: PASA

## DT11 - Ritmo y coste reales (B1 12 min + 20 min de B2, sin comprimir)

**Inicio:** 2026-10-21T05:10:13Z

- B1 desplazado a 05:12Z; B3-B5 desactivados; 32 min de medida
  acciones medidas: 15
  minutos con accion: 05:12x2 05:13x1 05:16x1 05:17x2 05:20x1 05:21x1 05:22x1 05:24x1 05:25x2 05:36x1 05:37x2
  archives.json: ssh.exe : sudo: a password is required
En D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\legitimo_72h\prueba_en_seco.ps1: 
67 Carácter: 45
+ ... ManagerPw | & $Ssh -i $Key -o StrictHostKeyChecking=no $Man $cmd 2>&1 ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (sudo: a password is required:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError -> ssh.exe : sudo: a password is required
En D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\legitimo_72h\prueba_en_seco.ps1: 
67 Carácter: 45
+ ... ManagerPw | & $Ssh -i $Key -o StrictHostKeyChecking=no $Man $cmd 2>&1 ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (sudo: a password is required:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError B (delta= B en 32 min)
  minutos fuera de la ventana: 1
  ritmo nominal B1+B2 = 35 acciones / 2 h = 17,5 acc/h; medido en la muestra = 28,1/h

**Veredicto DT11: FALLA** - 15 acciones, todas en su minuto (+-2)  (2026-10-21T05:43:30Z)

### Resumen de esta ejecucion
- DT11: FALLA

## DT12 - Snapshot lab-listo-legit-v2 (VM apagada) y verificacion post-snapshot

**Inicio:** 2026-10-21T05:50:38Z

```text
total 88076
drwxrwxr-x 9 angel angel    16384 Oct 21 07:50 .
drwxr-x--- 8 angel angel     4096 Oct 18 19:51 ..
-rwxr-xr-x 1 angel angel     3777 Oct 21 06:42 client_ctl.sh
-rwxr-xr-x 1 angel angel   225280 Oct 21 06:42 CommandLine.dll
drwxr-xr-x 3 angel angel     4096 Oct 21 05:00 config
-rw-r--r-- 1 angel angel   108784 Oct 21 06:42 createdump
drwxrwxr-x 2 angel angel     4096 Oct 18 19:48 Descargas
drwxrwxr-x 2 angel angel     4096 Oct 18 19:48 Documentos
-rwxr-xr-x 1 angel angel   146944 Oct 21 06:42 FileHelpers.dll
-rwxr-xr-x 1 angel angel    72520 Oct 21 06:42 ghosts.client.linux
-rw-r--r-- 1 angel angel    86234 Oct 21 06:42 ghosts.client.linux.deps.json
-rwxr-xr-x 1 angel angel   257024 Oct 21 06:42 ghosts.client.linux.dll
-rw-r--r-- 1 angel angel    85044 Oct 21 06:42 ghosts.client.linux.pdb
-rw-r--r-- 1 angel angel      372 Oct 21 06:42 ghosts.client.linux.runtimeconfig.json
-rwxr-xr-x 1 angel angel    78848 Oct 21 06:42 ghosts.domain.dll
-rw-r--r-- 1 angel angel    35872 Oct 21 06:42 ghosts.domain.pdb
-rwxr-xr-x 1 angel angel   165888 Oct 21 06:42 HtmlAgilityPack.dll
-rwxr-xr-x 1 angel angel   198144 Oct 21 06:42 ICSharpCode.SharpZipLib.dll
drwxrwxr-x 3 angel angel     4096 Oct 21 01:49 instance
-rw-r--r-- 1 angel angel   823656 Oct 21 06:42 libclrgc.so
-rw-r--r-- 1 angel angel  3618128 Oct 21 06:42 libclrjit.so
-rw-r--r-- 1 angel angel  6916584 Oct 21 06:42 libcoreclr.so
-rw-r--r-- 1 angel angel   760632 Oct 21 06:42 libcoreclrtraceptprovider.so
-rw-r--r-- 1 angel angel   289168 Oct 21 06:42 libhostfxr.so
-rw-r--r-- 1 angel angel   310064 Oct 21 06:42 libhostpolicy.so
-rw-r--r-- 1 angel angel  2439008 Oct 21 06:42 libmscordaccore.so
-rw-r--r-- 1 angel angel  1634552 Oct 21 06:42 libmscordbi.so
-rw-r--r-- 1 angel angel    60576 Oct 21 06:42 libSystem.Globalization.Native.so
-rw-r--r-- 1 angel angel   867416 Oct 21 06:42 libSystem.IO.Compression.Native.so
-rw-r--r-- 1 angel angel    90656 Oct 21 06:42 libSystem.Native.so
-rw-r--r-- 1 angel angel    13544 Oct 21 06:42 libSystem.Net.Security.Native.so
-rw-r--r-- 1 angel angel   159776 Oct 21 06:42 libSystem.Security.Cryptography.Native.OpenSsl.so
drwxrwxr-x 2 angel angel     4096 Oct 21 07:50 logs
-rwxr-xr-x 1 angel angel    40208 Oct 21 06:42 Microsoft.AspNetCore.Connections.Abstractions.dll
-rwxr-xr-x 1 angel angel   119456 Oct 21 06:42 Microsoft.AspNetCore.Http.Connections.Client.dll
-rwxr-xr-x 1 angel angel    28952 Oct 21 06:42 Microsoft.AspNetCore.Http.Connections.Common.dll
-rwxr-xr-x 1 angel angel   197896 Oct 21 06:42 Microsoft.AspNetCore.SignalR.Client.Core.dll
-rwxr-xr-x 1 angel angel    20752 Oct 21 06:42 Microsoft.AspNetCore.SignalR.Client.dll
-rwxr-xr-x 1 angel angel    42656 Oct 21 06:42 Microsoft.AspNetCore.SignalR.Common.dll
-rwxr-xr-x 1 angel angel    37536 Oct 21 06:42 Microsoft.AspNetCore.SignalR.Protocols.Json.dll
-rwxr-xr-x 1 angel angel   817312 Oct 21 06:42 Microsoft.CSharp.dll
-rwxr-xr-x 1 angel angel    63768 Oct 21 06:42 Microsoft.Extensions.DependencyInjection.Abstractions.dll
-rwxr-xr-x 1 angel angel    92952 Oct 21 06:42 Microsoft.Extensions.DependencyInjection.dll
-rwxr-xr-x 1 angel angel    26392 Oct 21 06:42 Microsoft.Extensions.Features.dll
-rwxr-xr-x 1 angel angel    65320 Oct 21 06:42 Microsoft.Extensions.Logging.Abstractions.dll
-rwxr-xr-x 1 angel angel    50976 Oct 21 06:42 Microsoft.Extensions.Logging.dll
-rwxr-xr-x 1 angel angel    64776 Oct 21 06:42 Microsoft.Extensions.Options.dll
-rwxr-xr-x 1 angel angel    43680 Oct 21 06:42 Microsoft.Extensions.Primitives.dll
-rwxr-xr-x 1 angel angel  1218864 Oct 21 06:42 Microsoft.VisualBasic.Core.dll
-rwxr-xr-x 1 angel angel    17568 Oct 21 06:42 Microsoft.VisualBasic.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 Microsoft.Win32.Primitives.dll
-rwxr-xr-x 1 angel angel    33056 Oct 21 06:42 Microsoft.Win32.Registry.dll
-rwxr-xr-x 1 angel angel    29832 Oct 21 06:42 Microsoft.Win32.SystemEvents.dll
-rwxr-xr-x 1 angel angel    59688 Oct 21 06:42 mscorlib.dll
-rwxr-xr-x 1 angel angel   101152 Oct 21 06:42 netstandard.dll
-rwxr-xr-x 1 angel angel   712464 Oct 21 06:42 Newtonsoft.Json.dll
-rw-r--r-- 1 angel angel     1869 Oct 21 06:42 nlog.config
-rwxr-xr-x 1 angel angel   953344 Oct 21 06:42 NLog.dll
-rw-r--r-- 1 angel angel    10072 Oct 21 06:42 NOTICE.TXT
-rwxr-xr-x 1 angel angel  1889792 Oct 21 06:42 NPOI.dll
-rwxr-xr-x 1 angel angel   578560 Oct 21 06:42 NPOI.OOXML.dll
-rwxr-xr-x 1 angel angel    98816 Oct 21 06:42 NPOI.OpenXml4Net.dll
-rwxr-xr-x 1 angel angel  2355712 Oct 21 06:42 NPOI.OpenXmlFormats.dll
drwxrwxr-x 2 angel angel     4096 Oct 21 01:11 recetas
-rwxr-xr-x 1 angel angel   877056 Oct 21 06:42 Renci.SshNet.dll
drwxr-xr-x 5 angel angel     4096 Oct 18 19:48 selenium-manager
-rwxr-xr-x 1 angel angel    20480 Oct 21 06:42 SimpleTCP.dll
-rwxr-xr-x 1 angel angel    15656 Oct 21 06:42 System.AppContext.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 System.Buffers.dll
-rwxr-xr-x 1 angel angel   255272 Oct 21 06:42 System.Collections.Concurrent.dll
-rwxr-xr-x 1 angel angel   252576 Oct 21 06:42 System.Collections.dll
-rwxr-xr-x 1 angel angel   756008 Oct 21 06:42 System.Collections.Immutable.dll
-rwxr-xr-x 1 angel angel    93960 Oct 21 06:42 System.Collections.NonGeneric.dll
-rwxr-xr-x 1 angel angel    93960 Oct 21 06:42 System.Collections.Specialized.dll
-rwxr-xr-x 1 angel angel   192808 Oct 21 06:42 System.ComponentModel.Annotations.dll
-rwxr-xr-x 1 angel angel    17176 Oct 21 06:42 System.ComponentModel.DataAnnotations.dll
-rwxr-xr-x 1 angel angel    17704 Oct 21 06:42 System.ComponentModel.dll
-rwxr-xr-x 1 angel angel    36648 Oct 21 06:42 System.ComponentModel.EventBasedAsync.dll
-rwxr-xr-x 1 angel angel    71464 Oct 21 06:42 System.ComponentModel.Primitives.dll
-rwxr-xr-x 1 angel angel   748208 Oct 21 06:42 System.ComponentModel.TypeConverter.dll
-rwxr-xr-x 1 angel angel    19616 Oct 21 06:42 System.Configuration.dll
-rwxr-xr-x 1 angel angel   200352 Oct 21 06:42 System.Console.dll
-rwxr-xr-x 1 angel angel    23848 Oct 21 06:42 System.Core.dll
-rwxr-xr-x 1 angel angel  2899104 Oct 21 06:42 System.Data.Common.dll
-rwxr-xr-x 1 angel angel    16168 Oct 21 06:42 System.Data.DataSetExtensions.dll
-rwxr-xr-x 1 angel angel    25376 Oct 21 06:42 System.Data.dll
-rwxr-xr-x 1 angel angel    16648 Oct 21 06:42 System.Diagnostics.Contracts.dll
-rwxr-xr-x 1 angel angel    16032 Oct 21 06:42 System.Diagnostics.Debug.dll
-rwxr-xr-x 1 angel angel   410920 Oct 21 06:42 System.Diagnostics.DiagnosticSource.dll
-rwxr-xr-x 1 angel angel    43168 Oct 21 06:42 System.Diagnostics.FileVersionInfo.dll
-rwxr-xr-x 1 angel angel   273056 Oct 21 06:42 System.Diagnostics.Process.dll
-rwxr-xr-x 1 angel angel    30880 Oct 21 06:42 System.Diagnostics.StackTrace.dll
-rwxr-xr-x 1 angel angel    60200 Oct 21 06:42 System.Diagnostics.TextWriterTraceListener.dll
-rwxr-xr-x 1 angel angel    15656 Oct 21 06:42 System.Diagnostics.Tools.dll
-rwxr-xr-x 1 angel angel   134944 Oct 21 06:42 System.Diagnostics.TraceSource.dll
-rwxr-xr-x 1 angel angel    16656 Oct 21 06:42 System.Diagnostics.Tracing.dll
-rwxr-xr-x 1 angel angel    50440 Oct 21 06:42 System.dll
-rwxr-xr-x 1 angel angel   653968 Oct 21 06:42 System.Drawing.Common.dll
-rwxr-xr-x 1 angel angel    20784 Oct 21 06:42 System.Drawing.dll
-rwxr-xr-x 1 angel angel   125088 Oct 21 06:42 System.Drawing.Primitives.dll
-rwxr-xr-x 1 angel angel    16680 Oct 21 06:42 System.Dynamic.Runtime.dll
-rwxr-xr-x 1 angel angel   230704 Oct 21 06:42 System.Formats.Asn1.dll
-rwxr-xr-x 1 angel angel   277800 Oct 21 06:42 System.Formats.Tar.dll
-rwxr-xr-x 1 angel angel    16032 Oct 21 06:42 System.Globalization.Calendars.dll
-rwxr-xr-x 1 angel angel    16168 Oct 21 06:42 System.Globalization.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 System.Globalization.Extensions.dll
-rwxr-xr-x 1 angel angel    72352 Oct 21 06:42 System.IO.Compression.Brotli.dll
-rwxr-xr-x 1 angel angel   259880 Oct 21 06:42 System.IO.Compression.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 System.IO.Compression.FileSystem.dll
-rwxr-xr-x 1 angel angel    55600 Oct 21 06:42 System.IO.Compression.ZipFile.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:42 System.IO.dll
-rwxr-xr-x 1 angel angel    31904 Oct 21 06:42 System.IO.FileSystem.AccessControl.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:42 System.IO.FileSystem.dll
-rwxr-xr-x 1 angel angel    78632 Oct 21 06:42 System.IO.FileSystem.DriveInfo.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 System.IO.FileSystem.Primitives.dll
-rwxr-xr-x 1 angel angel   102064 Oct 21 06:42 System.IO.FileSystem.Watcher.dll
-rwxr-xr-x 1 angel angel    77112 Oct 21 06:42 System.IO.IsolatedStorage.dll
-rwxr-xr-x 1 angel angel    80168 Oct 21 06:42 System.IO.MemoryMappedFiles.dll
-rwxr-xr-x 1 angel angel    77984 Oct 21 06:42 System.IO.Pipelines.dll
-rwxr-xr-x 1 angel angel    23848 Oct 21 06:42 System.IO.Pipes.AccessControl.dll
-rwxr-xr-x 1 angel angel   127272 Oct 21 06:42 System.IO.Pipes.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:42 System.IO.UnmanagedMemoryStream.dll
-rwxr-xr-x 1 angel angel   530232 Oct 21 06:42 System.Linq.dll
-rwxr-xr-x 1 angel angel  3766448 Oct 21 06:42 System.Linq.Expressions.dll
-rwxr-xr-x 1 angel angel   798384 Oct 21 06:42 System.Linq.Parallel.dll
-rwxr-xr-x 1 angel angel   168096 Oct 21 06:42 System.Linq.Queryable.dll
-rwxr-xr-x 1 angel angel   147616 Oct 21 06:42 System.Memory.dll
-rwxr-xr-x 1 angel angel    17688 Oct 21 06:42 System.Net.dll
-rwxr-xr-x 1 angel angel  1709864 Oct 21 06:42 System.Net.Http.dll
-rwxr-xr-x 1 angel angel   120096 Oct 21 06:42 System.Net.Http.Json.dll
-rwxr-xr-x 1 angel angel   296760 Oct 21 06:42 System.Net.HttpListener.dll
-rwxr-xr-x 1 angel angel   424200 Oct 21 06:42 System.Net.Mail.dll
-rwxr-xr-x 1 angel angel    84784 Oct 21 06:42 System.Net.NameResolution.dll
-rwxr-xr-x 1 angel angel   170760 Oct 21 06:42 System.Net.NetworkInformation.dll
-rwxr-xr-x 1 angel angel   101024 Oct 21 06:42 System.Net.Ping.dll
-rwxr-xr-x 1 angel angel   229672 Oct 21 06:43 System.Net.Primitives.dll
-rwxr-xr-x 1 angel angel   280736 Oct 21 06:43 System.Net.Quic.dll
-rwxr-xr-x 1 angel angel   341152 Oct 21 06:43 System.Net.Requests.dll
-rwxr-xr-x 1 angel angel   803488 Oct 21 06:43 System.Net.Security.dll
-rwxr-xr-x 1 angel angel    35624 Oct 21 06:43 System.Net.ServicePoint.dll
-rwxr-xr-x 1 angel angel   593584 Oct 21 06:43 System.Net.Sockets.dll
-rwxr-xr-x 1 angel angel   163592 Oct 21 06:43 System.Net.WebClient.dll
-rwxr-xr-x 1 angel angel    57648 Oct 21 06:43 System.Net.WebHeaderCollection.dll
-rwxr-xr-x 1 angel angel    33576 Oct 21 06:43 System.Net.WebProxy.dll
-rwxr-xr-x 1 angel angel    90424 Oct 21 06:43 System.Net.WebSockets.Client.dll
-rwxr-xr-x 1 angel angel   180384 Oct 21 06:43 System.Net.WebSockets.dll
-rwxr-xr-x 1 angel angel    15648 Oct 21 06:43 System.Numerics.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Numerics.Vectors.dll
-rwxr-xr-x 1 angel angel    68768 Oct 21 06:43 System.ObjectModel.dll
-rwxr-xr-x 1 angel angel 12779696 Oct 21 06:43 System.Private.CoreLib.dll
-rwxr-xr-x 1 angel angel  2098480 Oct 21 06:43 System.Private.DataContractSerialization.dll
-rwxr-xr-x 1 angel angel   248992 Oct 21 06:43 System.Private.Uri.dll
-rwxr-xr-x 1 angel angel  8128688 Oct 21 06:43 System.Private.Xml.dll
-rwxr-xr-x 1 angel angel   400032 Oct 21 06:43 System.Private.Xml.Linq.dll
-rwxr-xr-x 1 angel angel    65832 Oct 21 06:43 System.Reflection.DispatchProxy.dll
-rwxr-xr-x 1 angel angel    16656 Oct 21 06:43 System.Reflection.dll
-rwxr-xr-x 1 angel angel   119080 Oct 21 06:43 System.Reflection.Emit.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Reflection.Emit.ILGeneration.dll
-rwxr-xr-x 1 angel angel    16144 Oct 21 06:43 System.Reflection.Emit.Lightweight.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Reflection.Extensions.dll
-rwxr-xr-x 1 angel angel  1097992 Oct 21 06:43 System.Reflection.Metadata.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Reflection.Primitives.dll
-rwxr-xr-x 1 angel angel    31904 Oct 21 06:43 System.Reflection.TypeExtensions.dll
-rwxr-xr-x 1 angel angel    15640 Oct 21 06:43 System.Resources.Reader.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Resources.ResourceManager.dll
-rwxr-xr-x 1 angel angel    43304 Oct 21 06:43 System.Resources.Writer.dll
-rwxr-xr-x 1 angel angel    15640 Oct 21 06:43 System.Runtime.CompilerServices.Unsafe.dll
-rwxr-xr-x 1 angel angel    19760 Oct 21 06:43 System.Runtime.CompilerServices.VisualC.dll
-rwxr-xr-x 1 angel angel    43680 Oct 21 06:43 System.Runtime.dll
-rwxr-xr-x 1 angel angel    18184 Oct 21 06:43 System.Runtime.Extensions.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Runtime.Handles.dll
-rwxr-xr-x 1 angel angel    86280 Oct 21 06:43 System.Runtime.InteropServices.dll
-rwxr-xr-x 1 angel angel    39208 Oct 21 06:43 System.Runtime.InteropServices.JavaScript.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Runtime.InteropServices.RuntimeInformation.dll
-rwxr-xr-x 1 angel angel    17200 Oct 21 06:43 System.Runtime.Intrinsics.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Runtime.Loader.dll
-rwxr-xr-x 1 angel angel   305960 Oct 21 06:43 System.Runtime.Numerics.dll
-rwxr-xr-x 1 angel angel    17056 Oct 21 06:43 System.Runtime.Serialization.dll
-rwxr-xr-x 1 angel angel   305840 Oct 21 06:43 System.Runtime.Serialization.Formatters.dll
-rwxr-xr-x 1 angel angel    16184 Oct 21 06:43 System.Runtime.Serialization.Json.dll
-rwxr-xr-x 1 angel angel    28848 Oct 21 06:43 System.Runtime.Serialization.Primitives.dll
-rwxr-xr-x 1 angel angel    17160 Oct 21 06:43 System.Runtime.Serialization.Xml.dll
-rwxr-xr-x 1 angel angel    58528 Oct 21 06:43 System.Security.AccessControl.dll
-rwxr-xr-x 1 angel angel    90408 Oct 21 06:43 System.Security.Claims.dll
-rwxr-xr-x 1 angel angel    17688 Oct 21 06:43 System.Security.Cryptography.Algorithms.dll
-rwxr-xr-x 1 angel angel    16648 Oct 21 06:43 System.Security.Cryptography.Cng.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Security.Cryptography.Csp.dll
-rwxr-xr-x 1 angel angel  2193584 Oct 21 06:43 System.Security.Cryptography.dll
-rwxr-xr-x 1 angel angel    16152 Oct 21 06:43 System.Security.Cryptography.Encoding.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Security.Cryptography.OpenSsl.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Security.Cryptography.Primitives.dll
-rwxr-xr-x 1 angel angel    17160 Oct 21 06:43 System.Security.Cryptography.X509Certificates.dll
-rwxr-xr-x 1 angel angel    18696 Oct 21 06:43 System.Security.dll
-rwxr-xr-x 1 angel angel    15632 Oct 21 06:43 System.Security.Principal.dll
-rwxr-xr-x 1 angel angel    37672 Oct 21 06:43 System.Security.Principal.Windows.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Security.SecureString.dll
-rwxr-xr-x 1 angel angel    17176 Oct 21 06:43 System.ServiceModel.Web.dll
-rwxr-xr-x 1 angel angel    16176 Oct 21 06:43 System.ServiceProcess.dll
-rwxr-xr-x 1 angel angel   852656 Oct 21 06:43 System.Text.Encoding.CodePages.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Text.Encoding.dll
-rwxr-xr-x 1 angel angel    16144 Oct 21 06:43 System.Text.Encoding.Extensions.dll
-rwxr-xr-x 1 angel angel   120608 Oct 21 06:43 System.Text.Encodings.Web.dll
-rwxr-xr-x 1 angel angel  1477416 Oct 21 06:43 System.Text.Json.dll
-rwxr-xr-x 1 angel angel  1022728 Oct 21 06:43 System.Text.RegularExpressions.dll
-rwxr-xr-x 1 angel angel   122032 Oct 21 06:43 System.Threading.Channels.dll
-rwxr-xr-x 1 angel angel    73904 Oct 21 06:43 System.Threading.dll
-rwxr-xr-x 1 angel angel    16032 Oct 21 06:43 System.Threading.Overlapped.dll
-rwxr-xr-x 1 angel angel   489768 Oct 21 06:43 System.Threading.Tasks.Dataflow.dll
-rwxr-xr-x 1 angel angel    17176 Oct 21 06:43 System.Threading.Tasks.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Threading.Tasks.Extensions.dll
-rwxr-xr-x 1 angel angel   124680 Oct 21 06:43 System.Threading.Tasks.Parallel.dll
-rwxr-xr-x 1 angel angel    16168 Oct 21 06:43 System.Threading.Thread.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Threading.ThreadPool.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Threading.Timer.dll
-rwxr-xr-x 1 angel angel    16648 Oct 21 06:43 System.Transactions.dll
-rwxr-xr-x 1 angel angel   365320 Oct 21 06:43 System.Transactions.Local.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.ValueTuple.dll
-rwxr-xr-x 1 angel angel    15624 Oct 21 06:43 System.Web.dll
-rwxr-xr-x 1 angel angel    49960 Oct 21 06:43 System.Web.HttpUtility.dll
-rwxr-xr-x 1 angel angel    16152 Oct 21 06:43 System.Windows.dll
-rwxr-xr-x 1 angel angel    23848 Oct 21 06:43 System.Xml.dll
-rwxr-xr-x 1 angel angel    16144 Oct 21 06:43 System.Xml.Linq.dll
-rwxr-xr-x 1 angel angel    22280 Oct 21 06:43 System.Xml.ReaderWriter.dll
-rwxr-xr-x 1 angel angel    16648 Oct 21 06:43 System.Xml.Serialization.dll
-rwxr-xr-x 1 angel angel    16160 Oct 21 06:43 System.Xml.XDocument.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Xml.XmlDocument.dll
-rwxr-xr-x 1 angel angel    18200 Oct 21 06:43 System.Xml.XmlSerializer.dll
-rwxr-xr-x 1 angel angel    16136 Oct 21 06:43 System.Xml.XPath.dll
-rwxr-xr-x 1 angel angel    17680 Oct 21 06:43 System.Xml.XPath.XDocument.dll
-rwxr-xr-x 1 angel angel    11912 Oct 21 06:43 tfg_keepalive.sh
-rwxr-xr-x 1 angel angel     7414 Oct 21 06:43 verificar_arreglos.sh
-rwxr-xr-x 1 angel angel  5016576 Oct 21 06:43 WebDriver.dll
-rwxr-xr-x 1 angel angel    16560 Oct 21 06:43 WindowsBase.dll
-rwxr-xr-x 1 angel angel   293376 Oct 21 06:43 YamlDotNet.dll
---
total 20
drwxrwxr-x 2 angel angel  4096 Oct 21 07:50 .
drwxrwxr-x 9 angel angel 16384 Oct 21 07:50 ..
---
/home/angel/Descargas:

/home/angel/Documentos:
actas
copias
correo
informes
---
UNIT FILE STATE PRESET

0 unit files listed.
```
```text
Total snapshots: 5
base-limpia
lab-listo
lab-listo-legit
fallo-2026-10-19-disco-lleno-NO-USAR
lab-listo-legit-v2
```
```text
nlog_console=Warn
nlog_sha=d8f5f1d1154601360e5d81c752ea50b034e915e10f9545625f4a5732352221fb
nlog_applog_archive=20
client_ctl_cap=20
keepalive_v3=1
recetas=8e4de7f8,c041d71b,d9bf437f
recetas_sha=8e4de7f825d309484037764a712e8ef8fed7bec8b25e4921e0e4f68501d31e0a,c041d71b5044964e92f7f9bed072603f5b6e53085e8fd9ca43c036b428923739,d9bf437f79b3611e542e62517b6f92c724839a591883bdbed6add71f4fb11272
timeline_activa=8e4de7f8
timeline_huella=6f0cdb4a
web_session=1
receptor_navegador=none
ram_free_mb=2470
swap_mb=1915
swap_estado=AVISO (swap_mb=1915 != 0; desviación declarada)
timer=not-found
df_free_mb=4526
df_libre_pct=47
df_inodes_libres_pct=84
RESULT=PASS
```
```text
ls: cannot access '/home/angel/ghosts-client/client.out': No such file or directory
/home/angel/ghosts-client/logs/:
total 20
drwxrwxr-x 2 angel angel  4096 Oct 21 07:50 .
drwxrwxr-x 9 angel angel 16384 Oct 21 07:50 ..
```
```text
Total snapshots: 5
base-limpia
lab-listo
lab-listo-legit
fallo-2026-10-19-disco-lleno-NO-USAR
lab-listo-legit-v2
```

**Veredicto DT12: PASA** - snapshot con VM apagada, PASS y v1 conservado; revertido a v2  (2026-10-21T05:52:37Z)

### Resumen de esta ejecucion
- DT12: PASA

## DT13 - El laboratorio queda CERRADO y NO armado

**Inicio:** 2026-10-21T05:56:20Z

- tareas TFG-*: 0 => 
Total running VMs: 0
- reglas de firewall TFG-*: 0

> **Precisión (rondas 2 y 4):** son **0 tareas `TFG-Legit-*`** (las del bloque). En el host siguen las
> **4 `TFG-Baseline-*` preexistentes** (`Afternoon/Night-Start/Stop`, en `Ready`), que **no cuentan**:
> son del baseline de la Fase 2 y no arman la ventana del legítimo.

**Veredicto DT13: PASA** - 0 VMs, 0 tareas `TFG-Legit-*`, 0 reglas de firewall  (2026-10-21T05:56:22Z)

### Resumen de esta ejecucion
- DT13: PASA

---

## Correcciones y cierre de DT7 / DT11 (ejecutadas y re-medidas)

### DT7 - disco leido del agente (`df -P`): **PASA** (con correccion del arnes)

La salida literal del watch fue `df=4G` y el `df` real en ese instante **4 143 620 KB = 3,95 GB**
(diferencia **1,3 %**, dentro del +-5 %). La **tasa** se calculo (`tasa=-1.5MB/h`). El veredicto
automatico fallo porque el arnes buscaba `df_avail_kb=` en la linea del watch, que solo lleva
`df=<GB>`; **corregido** (se compara en GB). El `df -P` del agente llega cada ~6 min y el watch lo
lee por **offset incremental** (0 cambios en Wazuh).

### DT11 - ritmo real (B1 12 min + 20 min de B2, sin comprimir): **PASA** (con correccion del arnes)

```text
acciones medidas: 15
minutos con accion: 05:12x2 05:13x1 05:16x1 05:17x2 05:20x1 05:21x1 05:22x1 05:24x1 05:25x2 05:36x1 05:37x2
```
- **B1**: 9 acciones entre 05:12 y 05:24 (los 12 min de su ventana) => **45 acc/h** (diseno).
- **B2**: 6 acciones entre 05:25 y 05:37 (huecos de 7-11 min) => **~15 acc/h** (diseno).
- **Ritmo nominal B1+B2 = 35/2 h = 17,5 acc/h**; todas las acciones caen **en su minuto**.
- El "1 minuto fuera de ventana" del informe automatico es un **artefacto** de comparar `HH:mm`
  (sin segundos) con el inicio exacto con segundos; **corregido**.
- El **Delta de `archives.json`** no se pudo leer en esa pasada (`sudo -n` sin ticket); medido
  aparte: **143 316 381 -> 144 044 797 B en 6,57 min = 6,65 MB/h** en regimen de fondo
  (extrapolacion a 72 h: ~480 MB; con actividad, el presupuesto de S8.4 sigue siendo 300-450 MB
  y **se medira en la ventana**).

### DT3 - crecimiento del stdout con `Warn` (**PASA**, medido durante DT9/DT11)

`client.out`: **57 271 B -> 58 567 B en 40 min** de actividad real (B1+B2) => **~0,001 MB/30 min**
(limite: 5 MB/30 min; tope duro 40 MB). Frente a los **~340 MB/h** del intento fallido.

---

## Resumen final de la prueba en seco

| DT | Que prueba | Veredicto |
|---|---|---|
| **DT-B0** | Pre-staging del navegador | **FALLA** (12 libs ausentes; 3,4 GB < 3,5 GB) => navegador descartado |
| **DT-B1..B5** | Secuencia, ciclo de vida, recursos, `M`, modo de fallo | **NO EJECUTADAS** (corte pre-registrado en DT-B0) |
| **DT0** | ¿Hay semilla? (2 ejecuciones con `random`) | **PASA** (secuencias distintas) |
| **DT1** | Arreglos y receta presentes | **PASA** (`RESULT=PASS`) |
| **DT2** | Tope del stdout (1 MB x 2, 3 MB escritos) | **PASA** (0,98 MB + 1 MB, proceso vivo) |
| **DT3** | Crecimiento real con `Warn` | **PASA** (~0,001 MB/30 min) |
| **DT4** | Detectar "estar sin hacer" | **PASA** (AVISO 29m -> ALARMA 33m -> OK) |
| **DT5a** | Autocuracion | **PASA** (ronda 4: **35 acciones antes / 12 despues** del reinicio; 1 linea en `recovery.log`; 1 proceso; ver Ronda 4 §1) |
| **DT5b** | Rotacion de receta + `machineid` | **PASA** (d2/d3 con su sha; machineid igual) |
| **DT6** | Agente desconectado (`is-active` miente) | **PASA** (ALARMA con hb=721s/935s; OK tras `restart`) |
| **DT7** | Disco leido del agente | **PASA** (1,3 % de error; tasa calculada) |
| **DT8** | Extraccion con rotacion (datos REALES) | **PASA** (A=0, B=3 solape, C=0 con dedupe) |
| **DT9** | **Doble ejecucion de la receta** | **PASA** (111 = 111, secuencia identica, recovery vacio) |
| **DT10** | Invariantes de la receta | **PASA** (111/117/105, 0 random, 0 pipes, 0 Browser*) |
| **DT11** | Ritmo y coste reales | **PASA** (todas en su minuto; 6,65 MB/h de fondo) |
| **DT12** | Snapshot `v2` + verificacion | **PASA** (VM apagada, PASS, v1 conservado, revertido) |
| **DT13** | Laboratorio cerrado y no armado | **PASA** (0 VMs, 0 tareas `TFG-Legit-*` — las 4 `TFG-Baseline-*` preexistentes no cuentan —, 0 reglas) |

> **Fallo corregido durante la suite (declarado):** el primer DT9 dio **108/111** porque **GHOSTS
> v8.3.1 pierde el reporte de los comandos que usan un `pipe` de shell** (`... | wc -l`): los 3
> comandos con pipe no llegaron a `history_timeline` (identificados uno a uno). **Hallazgo nuevo**
> (como H-C): la receta se reescribio **sin pipes** (`find ... > fichero`, `wc -l fichero`), se
> anadio el invariante al validador (`0` pipes) y DT9 paso **111 = 111 identicas**.

---

## Anexo: ficheros `ALARMA_*.txt` de la prueba en seco

Las alarmas que genero el watch durante DT4/DT6 (6 ficheros) se han movido a
`prueba_en_seco_alertas/` para no dejar residuos en el directorio de trabajo. **No son de la
ventana**: son evidencia de que el aviso visible funciona (`[ALARMA]` + fichero + `msg.exe`).

> **Ajuste posterior a DT4/DT6 (declarado).** La senal 8 (`recovery.log`) se leia en el watch
> por SSH de **solo lectura** a la victima; el plan (§7.1/§7.2) exige que la vigilancia **no toque
> la victima**. Se ha movido a **post-hoc** (se lee al cerrar), igual que la RAM: el watch queda
> **solo host + manager** (verificado: en el bloque `watch` no aparecen `192.168.65.129`, `$Vic`,
> `vmrun` ni `scp`). Las senales usadas en DT4/DT6 no cambian, asi que su evidencia sigue valida.

---

## DT0-bis? No: **prueba negativa de `prep` (guardarrail G-10)** — CA-04

Transcripcion literal (2026-10-21T05:59:57Z, VMs **apagadas**, sin tocar nada):

```text
[prep] G-1 OK: snapshot 'lab-listo-legit-v2' presente | Total snapshots: 5
[prep] G-10: D_libre_gb=185.9 wuauserv_StartType=Manual sesion=angel
[prep] G-10 FALLO: Windows Update NO esta pausado (ejecuta pausar_windows_update.ps1 pausar)
```

- `prep` **aborta antes de `t0` y antes de tocar las VMs** (no revierte, no arranca, no enciende
  `logall_json`), con **codigo 47** y mensaje accionable: es exactamente el comportamiento
  pedido en §7.3.
- **Hallazgo de estado (para el orquestador):** `wuauserv` esta en **`Manual`**, no `Disabled`
  (la pausa de L1 no sigue aplicada). **Antes de armar `legitimo-72h-v2` hay que ejecutar
  `pausar_windows_update.ps1 pausar`** (y restaurarlo al cerrar, §11.2).
- El **camino positivo completo** de `prep` (G-1…G-12) se ejecutó en la **ronda 4** (ver
  «Ronda 4» al final): **exit 0** con los 12 guardarraíles, y la **negativa de RAM** con
  **código 48**. Este anexo (G-10) sigue siendo la evidencia del **aborto**. La ronda 3 queda
  **superada** por la ronda 4 (misma prueba, evidencia mas completa).

---

# Ronda 4 (2026-10-21 15:45-17:35Z) - cierre formal: CA-06, CA-29/G-12 y CA-14

> **Motivo.** El `tfg-tester` dio **FALLA formal por evidencia/documentacion** (no por
> implementacion). Esta ronda **no cambia el diseno**: repite las pruebas y transcribe la salida.
> Todo se ejecuto en esta sesion; los logs crudos son `legitimo_host_control.log` (prep/cleanup) y
> la base de GHOSTS (`history_timeline`, PostgreSQL en el host).

## 1. CA-06 - DT5a con la receta NO agotada: acciones ANTES y DESPUES del reinicio

**Montaje.** Receta `--dry` de `d1` con `--base 16:56Z` (111 acciones, `sha256=538a3e18`),
copiada a `config/timeline.json` **con el cliente parado**; cliente arrancado a las **16:53:00Z**.
Se deja reportar actividad y se congela el proceso:

```text
[2026-10-21T16:59:08Z] SIGSTOP pid=21409
  21409 Tl         06:09 ghosts.client.l      <- VIVO y congelado (state T)
```

Keepalive v3 con overrides de prueba (`TFG_STALE_MIN=2`, `TFG_CONFIRMA_MIN=1`, `TFG_MAX_RECUP=2`,
`TFG_FORZAR_BLOQUE=1`). Salida literal de `keepalive.log`:

```text
2026-10-21T16:59:12Z keepalive: inicio (dur_h=74 t0= calendario=10 bloques test=1)
2026-10-21T16:59:12Z keepalive: ram_free_mb=2368 swap_mb=1915 bloque=TEST edad_app_min=0 free_mb=4523
2026-10-21T17:04:13Z keepalive: AVISO bloque=TEST edad_min=5 (primera lectura stale; se confirma en 1 min)
2026-10-21T17:05:13Z client_ctl: parando pids=21409  (TERM)
2026-10-21T17:05:18Z client_ctl: sigue vivo tras 5s -> KILL (pids=21409 )
2026-10-21T17:05:19Z client_ctl: parado
2026-10-21T17:05:21Z client_ctl: arrancado pid=22157  (stdout -> client.out, tope 20MB x2)
2026-10-21T17:05:21Z keepalive: RECUPERACION n=1 motivo=heartbeat edad_min=5 pid_viejo=21409  pid_nuevo=22157
```

`recovery.log` (**1** linea):

```text
2026-10-21T17:05:21Z accion=recuperacion motivo=heartbeat edad_min=5 dia=TEST pid_viejo=21409  pid_nuevo=22157  recuperaciones=1 free_mb=4522 sha_timeline=183ed9b3
```

`history_timeline` (consulta literal a la base de GHOSTS, corte en el reinicio de 17:05:21Z):

```text
ANTES - 35 acciones (16:56:00 - 16:57:59)
16:56:00 | date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt
16:56:01 | ls -la /home/angel/Documentos
16:56:02 | mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Document...
16:56:03 | echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_...
16:56:04 | cat /home/angel/Documentos/agenda_$(date -u +%F).txt
16:56:05 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cook...
16:56:06 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
16:56:07 | wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles...
16:56:08 | echo 're: estado del informe mensual' > /home/angel/Documentos/correo/borrador_1.txt
16:56:44 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
16:56:47 | echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/...
16:56:50 | cat /home/angel/Documentos/correo/borrador_1.txt
16:56:53 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
16:56:56 | echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/...
16:56:59 | cat /home/angel/Documentos/correo/borrador_2.txt
16:57:02 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
16:57:05 | echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/...
16:57:08 | cat /home/angel/Documentos/correo/borrador_3.txt
16:57:11 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
16:57:14 | echo 'ronda 4: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/...
16:57:17 | cat /home/angel/Documentos/correo/borrador_4.txt
16:57:20 | echo 'informe del area - jornada 1' > /home/angel/Documentos/informes/informe.txt
16:57:23 | tar -czf /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz -C /home/angel/Do...
16:57:26 | sha256sum /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz
16:57:29 | du -sh /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz
16:57:32 | ls -la /home/angel/Documentos/informes
16:57:35 | tar -czf /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz -C /home/angel/Do...
16:57:38 | sha256sum /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz
16:57:41 | du -sh /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz
16:57:44 | ls -la /home/angel/Documentos/informes
16:57:47 | cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe...
16:57:50 | mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1...
16:57:53 | find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt
16:57:56 | ls -la /home/angel/Documentos/correo
16:57:59 | wc -l /home/angel/Documentos/informes/informe.txt

--- HUECO 16:58:00 - 17:05:31 (cliente congelado; CERO acciones) ---
--- REINICIO 17:05:21Z (pid 21409 -> 22157) ---

DESPUES - 12 acciones (17:05:32 - 17:06:05)
17:05:32 | tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Document...
17:05:35 | sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz
17:05:38 | cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256
17:05:41 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
17:05:44 | curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cook...
17:05:47 | du -sh /home/angel/Documentos
17:05:50 | df -h /
17:05:53 | cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copi...
17:05:56 | wc -c /home/angel/Descargas/copia_final_1.tar.gz
17:05:59 | rm -f /home/angel/Descargas/tmp_*.csv
17:06:02 | date -u +%FT%TZ
17:06:05 | ls -la /home/angel/Documentos /home/angel/Descargas
```

Recuento literal:

```text
select count(*) filter (where createdutc <  '2026-10-21T17:05:21Z'),
       count(*) filter (where createdutc >= '2026-10-21T17:05:21Z'),
       count(*)
from history_timeline where createdutc >= '2026-10-21T16:55:00Z';
35|12|47
```

- **35 acciones ANTES y 12 DESPUES** del reinicio, **en la misma receta** y **sin agotarla**: el
  ultimo bloque (`17:05:32-17:06:21`, 12 acciones) **seguia pendiente** cuando se congelo el cliente
  y es el que se ejecuta despues del arranque nuevo. El hueco de **7m31s** sin acciones
  (16:58:00-17:05:31) demuestra que el congelamiento fue real.
- **1 linea** en `recovery.log` (arriba) y **1 proceso** al cerrar:

```text
$ pgrep -c -f '(^|/)ghosts[.]client[.]linux'
1
$ bash /home/angel/ghosts-client/client_ctl.sh status
2026-10-21T17:07:54Z client_ctl: vivo pids=22157
$ ps -o pid=,stat=,etime=,comm= -p 22157
  22157 Sl         02:34 ghosts.client.l
```

- Al terminar se para el cliente y se restaura `d1` (`sha256=8e4de7f8`, el del repo).
- **Nota declarada (arnes, no diseno):** el keepalive cachea la edad del heartbeat **300 s**, asi
  que la primera lectura *stale* llego a los 5 min y la recuperacion a los 6. En la ventana real
  (`STALE=30`, `CONFIRMA=5`) el cache no cambia el criterio (solo introduce <= 5 min de latencia).

**CA-06: PASA.**

## 2. CA-04 (positivo) + CA-29 - `prep` completo G-1...G-12 y negativa de RAM (48)

### 2.1 Negativa de RAM: **codigo 48** (provocada, no simulada)

`prep` acepta `-RamMinMb` (por defecto **1500**, el valor del plan) **solo para poder ejercitar la
negativa** sin tocar la VM. Ejecucion literal (2026-10-21T15:45:53Z, Windows Update pausado):

```text
> powershell -NoProfile -ExecutionPolicy Bypass -File legitimo_host_control.ps1 -Phase prep -RamMinMb 999999
[2026-10-21T15:45:53Z] [prep] === START prep (host UTC 2026-10-21T15:45:53Z) t0=2026-10-26T00:00:00Z t1=2026-10-29T00:00:00Z ===
[2026-10-21T15:45:53Z] [prep] G-1 OK: snapshot 'lab-listo-legit-v2' presente | Total snapshots: 5 base-limpia lab-listo lab-listo-legit fallo-2026-10-19-disco-lleno-NO-USAR lab-listo-legit-v2
[2026-10-21T15:45:53Z] [prep] G-10: D_libre_gb=184.3 wuauserv_StartType=Disabled sesion=angel
[2026-10-21T15:45:54Z] [prep] G-4 OK: d1=8e4de7f8 d2=c041d71b d3=d9bf437f mapa 26/27/28 -> d1/d2/d3
[2026-10-21T15:47:28Z] [prep] G-12: ram_free_mb=2511 swap_mb=1915 ram_min_mb=999999
[2026-10-21T15:47:28Z] [prep] G-12 FALLO: RAM libre < 999999 MB
EXITCODE=48
```

- Aborta **antes** de desplegar el cliente y **antes** de `logall_json ON`: el laboratorio **no
  queda armado**. Codigo **48** tal y como fija el plan (§7.3).

### 2.2 Camino positivo: `prep` completo, **exit 0**

Ejecucion (17:30:51Z, Windows Update pausado con `pausar_windows_update.ps1 pausar`; **exit
capturado por el arnes**):

```text
[2026-10-21T17:30:51Z] [prep] === START prep (host UTC 2026-10-21T17:30:51Z) t0=2026-10-26T00:00:00Z t1=2026-10-29T00:00:00Z ===
[2026-10-21T17:30:52Z] [prep] G-1 OK: snapshot 'lab-listo-legit-v2' presente | Total snapshots: 5 base-limpia lab-listo lab-listo-legit fallo-2026-10-19-disco-lleno-NO-USAR lab-listo-legit-v2
[2026-10-21T17:30:52Z] [prep] G-10: D_libre_gb=174.5 wuauserv_StartType=Disabled sesion=angel
[2026-10-21T17:30:52Z] [prep] G-4 --check:
receta v1: dias={1: 111, 2: 117, 3: 105} total=333 web_session=1 handlers_browser=0
RESULT=PASS
[2026-10-21T17:30:52Z] [prep] G-4 OK: d1=8e4de7f8 d2=c041d71b d3=d9bf437f mapa 26/27/28 -> d1/d2/d3
[2026-10-21T17:31:07Z] [prep] G-12: ram_free_mb=2522 swap_mb=1915 ram_min_mb=1500
[2026-10-21T17:31:07Z] [prep] G-12 AVISO (declarado): swap_mb=1915 != 0 (el plan asumia 0; no se toca la VM)
[2026-10-21T17:32:51Z] [prep] G-2: df_free_mb=4527 inodos_libres_pct=84
[2026-10-21T17:32:52Z] [prep] G-3 verificar_arreglos:
nlog_console=Warn
nlog_sha=d8f5f1d1154601360e5d81c752ea50b034e915e10f9545625f4a5732352221fb
nlog_applog_archive=20
client_ctl_cap=20
keepalive_v3=1
recetas=8e4de7f8,c041d71b,d9bf437f
recetas_sha=8e4de7f825d309484037764a712e8ef8fed7bec8b25e4921e0e4f68501d31e0a,c041d71b5044964e92f7f9bed072603f5b6e53085e8fd9ca43c036b428923739,d9bf437f79b3611e542e62517b6f92c724839a591883bdbed6add71f4fb11272
timeline_activa=8e4de7f8
timeline_huella=6f0cdb4a
web_session=1
receptor_navegador=none
ram_free_mb=2436
swap_mb=1915
swap_estado=AVISO (swap_mb=1915 != 0; desviación declarada)
timer=not-found
df_free_mb=4527
df_libre_pct=47
df_inodes_libres_pct=84
RESULT=PASS
[2026-10-21T17:34:15Z] [prep] G-7: conf: <logall_json>yes</logall_json> manager=active daemons_remoted_analysisd=2
[2026-10-21T17:34:22Z] [prep] G-8:
=== 2) POSITIVAS ===
8080 root:     200
8080 pdf:      200 size=633
8080 zip:      200 size=311
9090 paste:    200
9092 put:      201
9092 propfind: 207
=== 3) NEGATIVAS ===
example.com: FALLA (ok, aislado) exit=28
1.1.1.1: FALLA (ok, aislado) exit=7
=== 4) RUTA ===
192.168.65.0/24 dev ens33 proto kernel scope link src 192.168.65.129
[2026-10-21T17:34:23Z] [prep] G-5: agentd_procs=1 | utc=2026-10-21T17:34:22Z manager=active agente001= Wazuh agent_control. Agent information: Agent ID: 001 Agent Name: victima-linux ... Status: Active ... Last keep alive: 1792604057 ...
[2026-10-21T17:34:23Z] [prep] G-11: machineids de victima-linux = 7c33a13a-fe89-4a56-bf3c-fcd499e1e557
[2026-10-21T17:34:25Z] [prep] prep: timeline activa = 8e4de7f8 (esperado d1=8e4de7f8)
[2026-10-21T17:34:25Z] [prep] prep: rotacion.estado = 2026-10-26 (dia 1 ya colocado; no se rota el dia 1)
[2026-10-21T17:34:25Z] [prep] G-9 (informativo) ultimo .gz: (vacio: aun no ha rotado)
[2026-10-21T17:34:26Z] [prep] G-6 OK: muestras 'df -P' del agente 001 en archives.json
[2026-10-21T17:34:26Z] [prep] === END prep (laboratorio LISTO, cliente PARADO) ===
EXITCODE=0
```

| Guardarrail | Valor observado | Resultado |
|---|---|---|
| **G-1** | snapshot `lab-listo-legit-v2` presente (`listSnapshots` = 5) | **OK** |
| **G-2** | `df_free_mb=4527`, inodos libres 84 % | **OK** |
| **G-3** | `verificar_arreglos.sh` = **`RESULT=PASS`** (`nlog_console=Warn`, `client_ctl_cap=20`, `keepalive_v3=1`, `recetas` con su sha, `timeline_activa=d1`, `web_session=1`, `receptor_navegador=none`, `timer=not-found`) | **OK** |
| **G-4** | `construir_receta_legitima.py --check` = **`RESULT=PASS`** (111/117/105, 0 Browser); sha `d1=8e4de7f8`, `d2=c041d71b`, `d3=d9bf437f` == `sha256sums.txt` | **OK** |
| **G-5** | `agentd_procs=1` y `agent_control -i 001` -> `Status: Active` | **OK** |
| **G-6** | muestras `df -P` del `001` en `archives.json` | **OK** |
| **G-7** | `<logall_json>yes</logall_json>`, `manager=active`, `daemons_remoted_analysisd=2` | **OK** |
| **G-8** | 8080 (200/200/200), 9090 (200), 9092 (201/207); `example.com` y `1.1.1.1` **fallan**; `ip route` **sin** `default via` | **OK** |
| **G-9** | informativo: no hay `.gz` todavia (aun no ha rotado el diario) | **aviso** |
| **G-10** | `D_libre_gb=174.5`, `wuauserv_StartType=Disabled`, sesion `angel` | **OK** |
| **G-11** | `machineid` = `7c33a13a-fe89-4a56-bf3c-fcd499e1e557` (el que usa la vigilancia) | **OK** |
| **G-12** | `ram_free_mb=2522` (>= 1500), `swap_mb=1915` | **OK con aviso declarado** (swap != 0; no se toca la VM) |

**CA-04 (positivo) y CA-29: PASA.**

> **G-12 / swap (declarado).** El plan asumia `swap=0`; la VM trae **1915 MB** de swap desde
> `lab-listo-legit`. No se toca el invitado (seria cambiar el banco antes de medir): `prep` lo
> reporta como **AVISO** (no bloquea) y `verificar_arreglos.sh` lo repite. La RAM libre real
> (**2,4-2,5 GB**) queda muy por encima del umbral de **1500 MB**; el presupuesto de §4.9 y la
> lectura post-hoc `ram_free_mb`/`ALARMA_RAM` del keepalive siguen aplicando.

## 3. CA-14 - `CONFIG_IDENTICA` con el manager arriba (salida literal)

Con el manager **arrancado** por `prep` y `logall_json` en **ON** (captura 16:29-16:33Z):

```text
$ bash /tmp/logall_json_ctl.sh status
conf:     <logall_json>yes</logall_json>
manager=active
daemons_remoted_analysisd=2

$ sudo -S -p '' diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf; echo diff_rc=$?
12c12
<     <logall_json>no</logall_json>
---
>     <logall_json>yes</logall_json>
diff_rc=1

$ sudo -S -p '' grep -n logall_json /var/ossec/etc/ossec.conf
12:    <logall_json>yes</logall_json>

$ sudo -S -p '' bash -c 'find /var/ossec/ruleset -type f | sort | xargs sha256sum | sha256sum'
8ba7e1b0cbd556ae111123d2287001d203257997448d1ee548915c1c99f1a0a5  -
```

Tras `logall_json off` (sin tocar nada mas) **con el manager todavia arriba**:

```text
$ bash /tmp/logall_json_ctl.sh off
valor aplicado:     <logall_json>no</logall_json>
manager=active (intento 1) agent_control=OK

$ bash /tmp/logall_json_ctl.sh status
conf:     <logall_json>no</logall_json>
manager=active
daemons_remoted_analysisd=2

$ sudo -S -p '' diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf; echo diff_rc=$?
diff_rc=0

$ sudo -S -p '' grep -n logall_json /var/ossec/etc/ossec.conf
12:    <logall_json>no</logall_json>

$ sudo -S -p '' bash -c 'find /var/ossec/ruleset -type f | sort | xargs sha256sum | sha256sum'
8ba7e1b0cbd556ae111123d2287001d203257997448d1ee548915c1c99f1a0a5  -
```

- **`diff` rc=1 con ON**: la **unica** diferencia es la linea 12 (el flag declarado).
- **`diff` rc=0 con OFF** -> **`CONFIG_IDENTICA`**; el bloque no deja rastro en `ossec.conf`.
- **Ruleset**: **misma huella** con ON y con OFF (`8ba7e1b0...`) -> `logall_json` no toca el ruleset.
  *(La huella se calcula ahora con `sudo`; el valor `ec3c942c...` de la ronda anterior salio de una
  lectura parcial sin `sudo` y no es comparable: manda la comparacion ON vs OFF de esta tabla.)*
  Aviso: el `content-updater` del manager puede actualizar el ruleset **entre sesiones**; por eso la
  invariante que se exige es **ON == OFF dentro de la misma sesion**.
- El **cleanup** posterior repite el `diff` con el manager arriba y da **`CONFIG_IDENTICA`**
  (`legitimo_host_control.log`, 17:08:38Z y 17:35:41Z) antes de apagar las VMs.

**CA-14 (config): PASA.**

## 4. CA-11 + documentacion (correcciones ya aplicadas y verificadas)

| Documento | Correccion | Verificacion |
|---|---|---|
| `b10_sellado.md` | Fila **`df`: telemetria retirada / `df -h /` de usuario**: distingue la **sonda `df` de telemetria (eliminada)** de los **4 `df -h /` de usuario** (1 en B5 de D1, 1 en B5 de D2, 2 en D3: B3 y B5), **presentes y declarados** (plan §5.3; JSON congelado) | `grep` del fichero |
| `recetas/LEEME.md` | Misma distincion: "**No** incluye ninguna accion `df` **de telemetria** ... **Si** hay `df -h /` de usuario: **4** ..." | `grep` del fichero |
| `plan.md` (CA-11) | Redaccion corregida: "**no** hay `df` **de telemetria** ...; los **4 `df -h /` son del usuario** ... **presentes y declarados**" | `git diff plan.md` |
| Senales de vigilancia | Etiqueta corregida a **9 senales = 7 en vivo + 2 post-hoc (RAM y `recovery.log`)** en `b10_sellado.md`, `README.md`, `resultado.md` y cabecera de `legitimo_host_control.ps1` | `grep` de "7 en vivo" |
| `prueba_en_seco.md` (DT13) | Precisado: **0 tareas `TFG-Legit-*`**; las **4 `TFG-Baseline-*`** son **preexistentes** y **no cuentan** (tabla resumen y seccion DT13) | lectura |
| Encoding (`client_ctl.sh`, `tfg_keepalive.sh`, `legitimo_host_control.ps1`, `prueba_en_seco.md`) | **0** aciertos del patron de *mojibake* (letra A con tilde/circunfleja seguida de byte de continuacion, comillas tipograficas doblemente codificadas, `U+FFFD`); los ficheros decodifican como **UTF-8 valido** (`Sesion`, `RECUPERACION`, `—` correctos). Los `.ps1` llevan **BOM UTF-8** (PowerShell 5.1) | barrido `python` sobre `Soporte/Laboratorio/**`: **TOTAL_HITS 0** (excluidos los logs historicos de `fallo_2026-10-19/`) |

> **Precision CA-11 (para que no se lea al reves).** Lo que **no** existe es una accion `df`
> **de telemetria** anadida a la timeline (la sonda de la v1 se elimino); el disco lo reporta el
> **agente** (`df -P` cada 360 s) y el watch lo lee por offset incremental. Lo que **si** existe y
> se declara son los **4 `df -h /` de usuario** del JSON congelado (`recetas/d1.json` 1, `d2.json`
> 1, `d3.json` 2; `sha256` en `sha256sums.txt`).

## 5. Estado final del laboratorio (verificado al cerrar)

```text
$ vmrun -T ws list
Total running VMs: 0

$ Get-ScheduledTask -TaskName 'TFG-*' | Select TaskName,State
TFG-Baseline-Afternoon-Start Ready
TFG-Baseline-Afternoon-Stop  Ready
TFG-Baseline-Night-Start     Ready
TFG-Baseline-Night-Stop      Ready
   -> 0 tareas TFG-Legit-*

$ bash /tmp/logall_json_ctl.sh status      # antes de apagar el manager
conf:     <logall_json>no</logall_json>
manager=active
daemons_remoted_analysisd=2
   -> y diff rc=0 (CONFIG_IDENTICA)

Windows Update: wuauserv StartType=Disabled, NoAutoUpdate=1, NoAutoRebootWithLoggedOnUsers=1
TFG_GUEST_PW: conservada en el entorno del host (no se escribe en ningun fichero)
```

- **`cleanup`**: `EXIT=0`, 0 VMs, firewall `TFG-*` retirado, GHOSTS + internet local parados,
  `logall_json=no` restaurado (`CONFIG_IDENTICA`).
- **Hallazgo declarado (Windows Update).** `wuauserv` **se auto-repara a `Manual`** a los pocos
  minutos (evento 7040 del Service Control Manager; p. ej. `17:48:05` local tras la pausa de las
  `17:45:46`), aunque la **politica `NoAutoUpdate=1`/`NoAutoRebootWithLoggedOnUsers=1` persiste**.
  Consecuencia practica: **G-10 exige `StartType=Disabled` en el instante de `prep`**, asi que
  `pausar_windows_update.ps1 pausar` debe ejecutarse **inmediatamente antes** de `prep` (es lo que
  se hizo aqui). Es la misma limitacion aceptada en `windows_update_pausa.md` §5 (el control
  duradero es la politica + el aislamiento); se deja **pausado** al cerrar.
- **Hallazgo declarado (arnes).** Los timeouts del shell de automatizacion mataron el arbol de
  procesos del host en dos ocasiones y se llevaron por delante el PostgreSQL de GHOSTS (excepcion
  `0xC0000142` en su log). Se levanto de nuevo con `pg_ctl` **desacoplado** y las pruebas se
  repitieron; **no es un defecto del laboratorio** ni de los scripts del bloque.

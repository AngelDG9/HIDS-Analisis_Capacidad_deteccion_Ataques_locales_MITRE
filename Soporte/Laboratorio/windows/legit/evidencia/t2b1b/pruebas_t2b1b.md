# T2b-1b — cierre de T2b-1 (correcciones F-1, G-1…G-8 y `G-W14`) · evidencia

> **Bloque:** `windows-legit-prep` · **Plan:** `plan_w3bis.md` v2 `approved_by_human`
> (`4237a16`) · **Ejecución:** 2026-11-11 por `tfg-executor`.
> **Sin snapshot nuevo, sin ventana, sin ataques, sin commits.**
> VM: **snapshot v1** `lab-listo-windows-legit` (revertida antes de empezar y al cerrar).
> **Sin secretos:** `TFG_GUEST_PW`/`TFG_MANAGER_PW` solo en la memoria de los procesos y
> borradas al terminar; no aparecen en ningún fichero.

## 0. Pila de la prueba

| Elemento | Estado |
|---|---|
| `victima-windows` | snapshot **v1** `lab-listo-windows-legit`, arrancada por `prep` |
| `wazuh-server` | encendido, `manager=active`, `daemons_remoted_analysisd=2`, `logall_json=yes` |
| GHOSTS API + PostgreSQL | **arriba** (`HTTP 200`), `ghosts.exe` vivo (pid 3592, `angel`) |
| Chivato | `heartbeat_sink.py` pid 15252 en `192.168.65.1:9095` |
| Host | 16 GB; **0** variables de entorno persistentes escritas |

## 1. Correcciones aplicadas (diff)

| # | Corrección | Fichero | Qué se ve |
|---|---|---|---|
| **F-1** | Un solo emisor del latido | `guest/tfg_keepalive_windows.ps1` + controlador | `-Once` no emite, no toca `heartbeat.seq`, no recrea `estado.json`; `prep` archiva `heartbeat.jsonl` (host) y `heartbeat.seq` (invitado) y re-siembra el sink; `arm` con el mismo `MANIFEST_SHA256` **no re-despliega** |
| **G-1** | `prep` exige `DEFENDER_OFF=1` y `SESION_ANGEL=1` | controlador | `exit 47` (entrada y post-deploy). Prueba **simulada** con `-SimularVerificador` (no se toca Defender) |
| **G-2** | Lista negra §7.3 completa | `guest/verificar_windows.ps1` | **11** ítems (`BLACKLIST_*`), `LISTA_NEGRA_OK=0` ⇒ `prep` **`exit 46`**. El 11.º es `BLACKLIST_marcas_campana` (`marcas == 0`), añadido en **T2b-1c** tras el hallazgo del tester (§11). `logs\*.log` se evalúa como **sin contenido de campaña** (los logs del operador `keepalive/recovery` son instrumentación declarada, §16.1) |
| **G-3** | `G-W7` lee `ventana_actual.json` si no hay `-T0/-T1` | controlador `Get-Ventana` | `fuente=ventana_actual.json`; los parámetros **mandan** si llegan |
| **G-4** | Misma ruta de `heartbeat.jsonl` en sink y controlador | `heartbeat_sink_ctl.ps1` + controlador | `legit/evidencia/` por defecto en los dos |
| **G-5** | Ruta del `crudo` | `Soporte/Laboratorio/crudo/estado_crudo.md` | `D:\TFG-VMs\legitimo-windows-<fecha>\crudo\` (ya alineada) |
| **G-7** | No curar la evidencia | `t2b1b/heartbeat_lineas.md` | `heartbeat.jsonl` real, 6 líneas, declaradas una a una; los archivados también |
| **G-8** | `arm` inocuo si ya está todo aplicado | `deploy_windows.ps1` + controlador | `DEPLOY_SKIP=1`: no sube payload ni re-registra tareas |
| **NUEVO** | `watch` mira `defender` y alarma si ON | controlador `G-W14` | `ALARMA … G-W14=DEFENDER=ON…`, `exit 60`, **sin SSH al invitado** |

**Extras necesarios (declarados, no cambio de diseño):**

1. **Rotación de receta por día, no por hash.** El bucle comparaba `timeline.json` con
   `timeline.dK.json`; GHOSTS **reescribe** `timeline.json` al ejecutar, así que reiniciaba
   el cliente **cada 5 min**. Ahora rota solo cuando cambia el día (`dia_aplicado.txt`,
   excluido del manifiesto). Sin esto la ventana de 72 h habría tenido ~864 muertes del cliente.
2. **Empaquetado del payload con `ZipFile::CreateFromDirectory`.** `Compress-Archive`
   abortó una vez (`prep` `exit 44`) con “no se pudo encontrar” un fichero recién copiado.
3. **`prep` archiva también `ventana_actual.json`** de la ventana anterior (si no, su
   `G-W7` se evaluaría contra una ventana caducada).
4. **Limpieza de residuos por STDIN** en `deploy` (regla del incidente de Defender) y
   sentencia a sentencia (`powershell -Command -` no admite bloques multilínea).
5. **`prep -SimularVerificador <fichero>`**: gancho de prueba de la puerta G-1 (no se toca
   Defender ni la VM). En operación normal no se usa.

## 2. Prueba 1 — `prep` + `arm` dos veces con la API arriba

**`prep`** (`prep_final.log`), salida literal (extracto):

```
[2026-11-11T10:12:01Z] [prep] prep: sink OK (POST /test ok len=51)
[2026-11-11T10:12:18Z] [prep] prep: revert a snapshot y arranque
[2026-11-11T10:13:02Z] [prep] prep: heartbeat.seq SEQ_AUSENTE
[2026-11-11T10:13:02Z] [prep] prep: deploy idempotente
[2026-11-11T10:13:37Z] payload construido: ...\payload.zip (52.1 MB)
[2026-11-11T10:13:57Z] residuos invitado: LIMPIEZA_OK
[2026-11-11T10:14:54Z] [prep] prep: gate Defender/sesion OK (DEFENDER_OFF=1 SESION_ANGEL=1)
[2026-11-11T10:14:54Z] [prep] prep: lista negra 7.3 OK (0 residuos)
[2026-11-11T10:14:54Z] [prep] prep: manifiesto SKIP (sin manifiesto_esperado.json; se sella en T2b-2)
```

Y en el arranque, la rotación F-1 (ficheros **movidos**, no borrados):

```
[2026-11-11T10:11:35Z] [prep] prep: heartbeat.jsonl anterior archivado -> ...\historico\heartbeat_20261111T094545Z.jsonl
[2026-11-11T10:11:35Z] [prep] prep: ventana_actual.json anterior archivado -> ...\historico\ventana_actual_20261111T094545Z.jsonl
```

**`arm` 1.ª y 2.ª vez** (`arm_final_a.log`, `arm_final_b.log`): las dos con **`DEPLOY_SKIP=1`**
(el `prep` ya había desplegado el mismo payload + mismo `MANIFEST_SHA256`). Literal:

```
[arm] arm: fijando mapa de dias con --t0 2026-11-11
DEPLOY_SKIP=1 payload_sha256=6f0b62f4… manifest_sha256=736bcf82…
[arm] arm: G-8 deploy SKIP (payload y MANIFEST_SHA256 ya coinciden; no se re-sube ni se re-registran tareas)
[arm] arm: deploy SKIP y cliente ya vivo -> NO se relanza la actividad
[arm] arm: logall_json ya estaba yes -> NO se ejecuta on (archives.json intacto)
[arm] arm: logall_json ON verificado (antes=yes on_ejecutado=False manager_active=True daemons=2)
[arm] arm: ventana_actual.json escrito (...)
```

`EXIT_ARM_B=0`. (La 1.ª tampoco re-desplegó: `prep` genera con las recetas vigentes y el
payload coincide; el `deploy` compara **payload + manifiesto**, no la fecha.)

**`heartbeat.jsonl` real** (`t2b1b/heartbeat.jsonl`, `sha256 d62bc1db…`, copia idéntica del
original en producción; declaración línea a línea en `heartbeat_lineas.md`):

```
seq=1 ts=2026-11-11T10:14:21Z cadena=INICIO        seq_ok=True ka_pid=4388 inst=1 armado=False n_ghosts=0 def=off
seq=2 ts=2026-11-11T10:15:00Z cadena=OK            seq_ok=True ka_pid=4388 inst=1 armado=False n_ghosts=0 def=off
seq=3 ts=2026-11-11T10:20:00Z cadena=OK            seq_ok=True ka_pid=4388 inst=1 armado=True  n_ghosts=1 user=DESKTOP-BTMCFA5\angel def=off
seq=4 ts=2026-11-11T10:25:00Z cadena=OK            seq_ok=True ka_pid=4388 inst=1 armado=True  n_ghosts=1 user=DESKTOP-BTMCFA5\angel def=off
seq=5 ts=2026-11-11T10:30:00Z cadena=OK            seq_ok=True ka_pid=4388 inst=1 armado=True  n_ghosts=1 user=DESKTOP-BTMCFA5\angel def=off
seq=6 ts=2026-11-11T10:35:00Z cadena=OK            seq_ok=True ka_pid=4388 inst=1 armado=False n_ghosts=0 def=off
ROTA_SEQ=0 · ROTA=0 · LINEAS=6 · ka_pid unico · ka_instancias=1 en 6/6
```

**`watch` final** (`watch_final_test1.log`), literal:

```
chequeo ok=9 fallos=0 skip=0 :: HB_EDAD_MIN=1.5 SEQ=5 KA_PID=4388 KA_INSTANCIAS=1 SSH_INVITADO=0
SSH_INVITADO=0
EXIT_WATCH_FINAL=0
```

⇒ **`G-W13 OK`** (frescura + `seq` monótono + 1 instancia), **0 `ROTA_SEQ`**, **`SSH_INVITADO=0`**.

## 3. Prueba 2 — `-Once` no emite, no toca `seq`, no recrea `estado.json`

`prueba_once_final.log` (script ejecutado **en el invitado por ruta**):

```
--- ANTES ---
heartbeat.seq size=3 mtime=2026-11-11T10:20:02Z sha16=24ba1e99dc06b193
estado.json size=548 mtime=2026-11-11T10:14:27Z sha16=e30830fcc8f9f2f6
keepalive.log size=1178 mtime=2026-11-11T10:20:02Z sha16=ed4da980b5b0cd8b
heartbeat.seq valor=3
ka_loop_instancias=1
once_rc=0
--- DESPUES ---
heartbeat.seq size=3 mtime=2026-11-11T10:20:02Z sha16=24ba1e99dc06b193
estado.json size=548 mtime=2026-11-11T10:14:27Z sha16=e30830fcc8f9f2f6
keepalive.log size=1533 mtime=2026-11-11T10:22:22Z sha16=89be4e7371f86a5a
heartbeat.seq valor=3
ka_loop_instancias=1
keepalive_log_lineas antes=9 despues=11
2026-11-11T10:22:19Z	keepalive	arranque modo=Once pid=6544 … seq=3
2026-11-11T10:22:22Z	keepalive	diagnostico modo=Once sin_latido sin_seq sin_estado n_ghosts=1 …
```

En el host, `heartbeat.jsonl` **2031 → 2031** bytes (sin línea nueva). `heartbeat.seq` y
`estado.json` con **mismo `mtime` y mismo `sha16`**. **`keepalive.log` sí cambia**:
**9 → 11 líneas** (`size=1178 → 1533`, `sha16=ed4da980… → 89be4e73…`), porque `-Once`
escribe **siempre 2 líneas** (`arranque modo=Once` y `diagnostico modo=Once`). **PASA**
en lo que mide F-1 (latido/seq/estado); el log del operador es instrumentación declarada
(plan §16.1) y no es un segundo emisor.

**Límites de `-Once` (declarados, T2b-1c):**
1. **Sí escribe 2 líneas en `keepalive.log`** (siempre; no es silencioso).
2. Al arrancar ejecuta `Rotar $Log $LogMaxMb` (`LogMaxMb=2`), igual que `-Loop`: si
   `keepalive.log` supera los 2 MB, `-Once` **puede rotarlo** a `keepalive.log.1` (no toca
   `heartbeat.seq` ni `estado.json`).
3. `-Once` ejecuta el ciclo completo, incluida la **rotación de receta por día**: si
   `TFG_MAPA_DIAS` mapea el día actual a un `diaK` distinto de `dia_aplicado.txt`, sí
   copia `timeline.dK.json` y, si está armado, reinicia la actividad. En esta prueba no
   ocurrió (mismo día, `dia=1` ya aplicado).

## 4. Prueba 3 — puerta de Defender **simulada** ⇒ `exit 47`

Sin tocar la VM ni Defender: se inyecta la salida de `verificar_windows.ps1` desde
`sim_defender_on_verificador.txt` (`DEFENDER_OFF=0`, `SESION_ANGEL=1`).

```
[2026-11-11T09:17:17Z] [prep] prep: verificador SIMULADO desde ...\sim_defender_on_verificador.txt (prueba G-1; NO se toca la VM)
[2026-11-11T09:17:17Z] [prep] prep FALLO: gate Defender/sesion en entrada (DEFENDER_OFF=0 SESION_ANGEL=1) -> exit 47
EXIT=47
```

`vmrun list` durante la prueba: **solo** `wazuh-server` (la VM Windows no se arrancó).
**PASA.** (La puerta real también abortó `exit 47` en el incidente del 2026-11-10 con
`DEFENDER_OFF=0`: mismo camino de código.)

## 5. Prueba 4 — lista negra §7.3 ⇒ `exit 46` / OK

**Con `armado.flag` de prueba** (invitado limpio tras `prep`, antes de `arm`):

```
EXIT_CON_FLAG=46
BLACKLIST_lab_attack_vacio=1   BLACKLIST_tareas_ataque=1   BLACKLIST_armado_flag=0
BLACKLIST_client_out=1         BLACKLIST_instance_vacio=1  BLACKLIST_logs_sin_campana=1
BLACKLIST_run_ghosts=1         BLACKLIST_wintemp_tfg=1     BLACKLIST_temp_opencode=1
BLACKLIST_b10=1
CHECK lista_negra   FALLO PRESENTES: armado_flag
LISTA_NEGRA_OK=0
```

**Quitado el flag**:

```
EXIT_SIN_FLAG=0
BLACKLIST_armado_flag=1 … CHECK lista_negra OK 0 residuos · LISTA_NEGRA_OK=1
```

(Repetido al final con el **mismo despliegue final**: `lista_negra_final_con_flag.log` /
`lista_negra_final_sin_flag.log`, mismos `46` / `0`. En esos dos el verificador completo
marca además `wu_servicio` en `FALLO` porque `wuauserv` se auto-arrancó puntualmente; no
afecta a la lista negra ni a ninguna puerta de `prep`.)

## 6. Prueba 5 — `G-W7` sin `-T0/-T1`, leyendo `ventana_actual.json`

`drytest_watch_t2b1b.out` (VM y manager arriba):

```
=== DRYTEST 2026-11-11T10:22:02Z host=DESKTOP-OIOLOPO vm_windows=on fases=watch ===
  G-W5 OK servicios_latido=True manager_active=True daemons=2 agente_002=Active
  G-W7 OK logall_json=yes (now dentro de [t0,t1] exige yes; fuente=ventana_actual.json)
  G-W8 OK hijos_vmtoolsd=0 (latido)
  G-W9 OK powercfg_ok=True (latido)
  G-W10 OK disco_invitado_mb=21266 min=4096 (latido; keepalive exige 500)
  G-W11 OK n_ghosts=1 (latido) win_user=DESKTOP-BTMCFA5\angel dueno_angel=True
  G-W12 OK ram_libre_mb=1952 min=1500 wu=Stopped/Manual
  G-W13 OK HB_EDAD_MIN=2 max=12 seq_monotono=True ka_instancias=1 seq=3 ka_pid=4388 parcial=False
  G-W14 OK defender=off (latido)
  SSH_INVITADO=0
DRYTEST watch PASS (ok=9 fallos=0 skip=0)
DRYTEST_RESULT=PASS
```

**PASA.** La ventana la escribió `arm` (`ventana_actual.json`), no los parámetros.

## 7. Prueba 6 — `watch` con un latido que dice `defender=ON` ⇒ ALARMA

Fichero **simulado** `sim_heartbeat_defender_on.jsonl` (2 líneas, `seq` 10/11, `defender:"on"`;
**no se toca la VM**): `watch -Heartbeat <fichero>`.

```
ALARMA chequeo ok=8 fallos=1 skip=0 :: G-W14=DEFENDER=ON en el latido (control ambiental roto: R4) :: HB_EDAD_MIN=0 SEQ=11 KA_PID=999001 KA_INSTANCIAS=1 SSH_INVITADO=0
SSH_INVITADO=0
EXIT_WATCH_DEFENDER_ON=60
```

**PASA:** el `watch` lee el campo `defender` del JSONL del host y **alarma sin entrar en la VM**.

## 8. Prueba 7 — RAM del host con la pila real (~2 min)

Pila: **2 VMs** (`wazuh-server` 6 GB + `victima-windows` 4 GB, ambas encendidas),
**GHOSTS API** (dotnet), **PostgreSQL**, cliente `ghosts.exe` corriendo y chivato.
Muestreo cada 10 s durante **2 min** (`memoria_pila.csv`):

| Hora UTC | FreePhysicalMemory (MB) | AvailableMBytes (MB) | ghosts.exe | dotnet API |
|---|---|---|---|---|
| 10:23:04 | 1977 | 1923 | 1 | 1 |
| 10:23:14 | 1908 | 1909 | 1 | 1 |
| 10:23:24 | 1936 | 1935 | 1 | 1 |
| 10:23:34 | 1930 | 1930 | 1 | 1 |
| 10:23:45 | 1933 | 1933 | 1 | 1 |
| 10:23:55 | 1918 | 1911 | 1 | 1 |
| 10:24:05 | 1870 | 1870 | 1 | 1 |
| 10:24:15 | 1867 | 1867 | 1 | 1 |
| 10:24:25 | 1892 | 1892 | 1 | 1 |
| 10:24:35 | 1895 | 1895 | 1 | 1 |
| 10:24:45 | 1897 | 1897 | 1 | 1 |
| 10:24:55 | 1899 | 1899 | 1 | 1 |
| 10:25:05 | 1886 | 1886 | 1 | 1 |

| Métrica | n | mín | máx | media |
|---|---|---|---|---|
| `FreePhysicalMemory` (MB) | 13 | **1867** | 1977 | 1908,3 |
| `AvailableMBytes` (MB) | 13 | **1867** | 1935 | 1903,6 |

**Lectura para `G-W12` (umbral 1500 MB):** con la pila completa la reserva **no baja de
~1,87 GB** en 2 min ⇒ `G-W12` **OK** (`ram_libre_mb=1941–1952` en el `drytest`). La cifra
de **1.409 MB** anotada en T2b-1 **no se reproduce** con esta pila (allí había más carga
del host); no se cambia el umbral. `AvailableMBytes` y `FreePhysicalMemory` van casi
pegados (diferencia < 55 MB): en este host **la métrica de WMI es suficiente** y no hace
falta cambiar `G-W12` a `AvailableMBytes` (decisión propuesta: **dejar `G-W12` como está**;
si en WE0 baja de 1500, se libera el host antes de `t0`, no se toca el umbral).

## 9. Prueba 8 — `pytest`

```
python -m pytest _artefactos/scripts/tests -q
399 passed in 48.01s
```

> Nota: `pytest` desde la raíz recoge `Soporte/Ataques/atomic-red-team/` (clon externo, sin
> `pydantic`) y aborta la colección. La suite del TFG es `_artefactos/scripts/tests` (399).

## 10. Qué **no** se ha probado aquí (para T2b-2 / T4)

| Pendiente | Por qué |
|---|---|
| `crudo` real (C-4, `exit 84`) | sin ventana no hay `archives` que copiar; se prueba en el ensayo de T4 |
| Manifiesto **sellado** (`manifiesto_esperado.json`, `exit 46` por `DIFIERE`) | se sella con el deploy 8.3.1 (T2b-2) |
| `arm` con recetas **nuevas** (deploy completo) | aquí las dos `arm` fueron `SKIP` a propósito (G-8); el deploy completo se ejercitó en `prep` |
| 2 h de keepalive, duplicado, kill duro, reinicio | T4 (§6.2 del plan) |
| Ruido del operador (0 alertas por chequeo) | T3; aquí solo se midió que el `watch` no abre SSH (`SSH_INVITADO=0`) |
| FIM del agente `002` en el v2 | T2b-2 (comprobar que sigue sin vigilar `ghosts-client`) |

---

## 11. T2b-1c — cierre de los hallazgos del tester (2026-11-11)

> **Sin snapshot, sin ventana, sin ataques, sin commits.** La VM `victima-windows` se
> arrancó desde su estado actual (sin revertir) **solo** para la prueba real de la lista
> negra y se apagó al terminar (`vmrun list` = **0 VMs**). No se tocó Defender en host ni
> en invitado. Sin secretos.

### 11.1 A — lista negra §7.3: 11.º ítem `marcas_campana` (BLOQUEANTE)

`guest/verificar_windows.ps1` añade el ítem que faltaba:

```powershell
# 11) marcas de campana `inicio`/`fin`/`hecho` ausentes (plan 7.3 / T2b-1c)
# Se evalua SIEMPRE (tambien con -SinCampana); `campana_marcas` (>= 22) sigue siendo la
# comprobacion de la ventana en curso y no sustituye a este item.
$bl['marcas_campana'] = ($marcas -eq 0)
```

Se publica como `BLACKLIST_marcas_campana` y **entra en `LISTA_NEGRA_OK`**, igual que los
otros 10 (no es informativo). No se ha usado `-LimpiarCampana`: el humano no lo aprobó.

**Prueba real** (verificador nuevo copiado a `C:\Users\angel\ghosts-client\verificar_windows.ps1`,
la ruta que usa `prep`; restaurado al original después):

*Sin marca* (`prep -SoloListaNegra`):

```
BLACKLIST_b10=1
BLACKLIST_marcas_campana=1
CHECK lista_negra            OK 0 residuos
LISTA_NEGRA_OK=1
FALLOS=wu_servicio
RESULT=FAIL
[2026-11-11T12:19:53Z] [prep] prep -SoloListaNegra OK: lista negra 7.3 sin residuos
EXIT_PREP_SIN_MARCA=0
```

*Con `C:\lab-legit\campana\inicio.txt`*:

```
CAMPANA_MARCAS=1
BLACKLIST_b10=1
BLACKLIST_marcas_campana=0
CHECK lista_negra            FALLO PRESENTES: marcas_campana
LISTA_NEGRA_OK=0
[2026-11-11T12:20:13Z] [prep] prep -SoloListaNegra FALLO: lista negra 7.3 con residuos (PRESENTES: marcas_campana) -> exit 46
EXIT_PREP_CON_MARCA=46
```

`wu_servicio` aparece en `FALLO` porque `wuauserv` se auto-arrancó puntualmente (mismo
fenómeno ya declarado en §5); no afecta a la lista negra ni al `exit 46`. La marca se
retiró y el verificador original se restauró (`sha256` local == remoto:
`0B5CF4B18F0CBD844E90C49A452DB2CFD3B30FC1761CCEF851328874087C0A2E`).

### 11.2 B — huérfano `ghosts.exe` del build 8.3.1 en el host

**Proceso encontrado:** pid **15552**, `D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1\client\ghosts.exe`,
arrancado **2026-11-11 09:31:53 local (~08:31Z)**, padre `explorer.exe` (5384) e hijo
`conhost.exe` (12884). La carpeta `logs\` estaba creciendo (`clientupdates_not_posted.log`
= 35.998.962 B; `app.96x.log` rotando).

**Parada:** `taskkill /PID 15552 /T /F` ⇒ terminados **15552** y **12884**.

**Verificación posterior:**

```
COUNT_GHOSTS=0
```

* **0** procesos `ghosts.exe` en el host.
* **0** procesos cuyo executable path cuelgue de `build-v8.3.1`.
* **0** `geckodriver`/`chromedriver`/`firefox`/`chrome`/`crashreporter` (los que lanzaría
  el cliente si siguiera vivo).

**Logs generados por ese proceso, borrados** (5 ficheros, **38.796.358 B**):

| Fichero | Bytes |
|---|---:|
| `logs\app.962.log` | 999.906 |
| `logs\app.963.log` | 999.962 |
| `logs\app.log` | 796.889 |
| `logs\clientupdates_not_posted.log` | 35.998.962 |
| `instance\files-created.log` | 639 |

Se **dejan** `logs\` vacío y `instance\timeline\{in,out}` (estructura del build, sin
contenido) y el resto del build intacto. No se borra nada más.

### 11.3 C — correcciones de evidencia exacta

1. **`heartbeat_lineas.md:66`**: el fichero archivado
   `historico/heartbeat_20261111T091735Z.jsonl` tiene **9 líneas** y **5**
   `REINICIO_BUCLE` (verificado contando `cadena` línea a línea), no 6. Corregido.
2. **§3**: el extracto de `prueba_once_final.log` omitía la línea
   `keepalive.log size=1533 mtime=2026-11-11T10:22:22Z sha16=89be4e7371f86a5a`.
   Añadida. El log **sí cambia** (`9 → 11` líneas; `size 1178 → 1533`;
   `sha16 ed4da980… → 89be4e73…`).
3. **`-Once` escribe siempre 2 líneas** en `keepalive.log` (`arranque modo=Once` y
   `diagnostico modo=Once`) y, como `-Loop`, ejecuta `Rotar $Log 2MB` al arrancar: si el
   log supera 2 MB **puede rotarlo** a `keepalive.log.1`. Además ejecuta el ciclo completo:
   si cambia el día del mapa, puede rotar la receta y (si está armado) reiniciar la
   actividad. Declarado en §3.
4. **`t2b1b/status.log` era de una ventana anterior** (`VMS=2`, `SEQ=4`, `KA_PID=6532`).
   Renombrado a **`status_ventana_anterior_20261111T0939Z.log`** (y su `.err.log`; la hora
   es la `mtime` UTC del fichero); no se usa como evidencia de esta tanda.

### 11.4 D — defecto latente de rotación de receta (recomendado)

En `guest/tfg_keepalive_windows.ps1`, `Copy-Item` ahora es `-ErrorAction Stop` y
`dia_aplicado.txt` **solo se escribe si la copia se aplicó** (`$rotacionOk`). Si falla, se
registra `alarma_rotacion` + `rotacion_dia … PENDIENTE` y el ciclo siguiente lo reintenta.

**Simulación** (copia del script con `$Dir` y `$CwdBase` redirigidos a un sandbox de
`%TEMP%`; `TFG_MAPA_DIAS=<hoy>:2`; `-Once -SinWu`; no toca la VM ni el host real):

*Fallo forzado* (`timeline.d2.json` es un directorio ⇒ `Copy-Item` falla):

```
RC=0
DIA_APLICADO_EXISTE=False
2026-11-11T12:17:18Z	keepalive	alarma_rotacion dia=2 copia_fallida=No se puede copiar el contenedor en el elemento de hoja existente.
2026-11-11T12:17:18Z	keepalive	rotacion_dia dia=2 PENDIENTE (copia fallida; dia_aplicado.txt no se escribe)
```

*Control de éxito* (`timeline.d2.json` es fichero):

```
RC=0
DIA_APLICADO_EXISTE=True
DIA_APLICADO_VALOR=2
2026-11-11T12:17:32Z	keepalive	rotacion_dia dia=2 origen=timeline.d2.json
```

### 11.5 Cierre

```
python -m pytest _artefactos/scripts/tests -q
399 passed in 27.26s
```

Estado final de la máquina: **0 VMs**, **0** procesos `ghosts`, **0** `dotnet` de la API,
**0** `postgres`, **0** `heartbeat_sink.py`, **0** tareas `TFG-*` y **0** variables `TFG_*`
en el entorno. Sin secretos en ficheros ni logs.

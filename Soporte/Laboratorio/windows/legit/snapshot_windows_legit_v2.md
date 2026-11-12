# snapshot_windows_legit_v2.md — snapshot `lab-listo-windows-legit-v2` (T4 / C6)

> **Bloque:** `windows-legit-prep` (W3-bis). **Plan:** `_fases/windows-legit-prep/plan_w3bis.md`
> v2 (`status: approved_by_human`, `4237a16`). **Ejecución:** 2026-11-12, `tfg-executor`.
> **Tanda 4:** re-WE0-2, canario real, W-07 real, ciclo completo de **2 h**, `crudo`,
> `stop`/`cleanup` y snapshot **v2**.
> **No** se ejecutó la ventana de 72 h, **no** se lanzaron ataques y **no** se hicieron commits.
> **Sin secretos:** credenciales solo en memoria (`TFG_GUEST_PW`/`TFG_MANAGER_PW`, valor `<oculto>`), borradas al cerrar.

---

## 0. Resumen en una tabla

| Qué | Resultado |
|---|---|
| **Snapshot** | `lab-listo-windows-legit-v2` (**8** snapshots; los **6 previos + v1 `lab-listo-windows-legit` intactos**) |
| **Base / linaje** | hijo de `lab-listo-windows-ataques-gui` (hermano de v1); cliente **8.3.1** (`Domain 8.2.7.90`, `exe 8.2.2.0`) |
| **Manifiesto** | **294** ficheros, `MANIFEST_SHA256=4621046f028cb37ad8bbc6a1e9c5adae29bc8c238f774471b6d579011afdf3f0`; `manifiesto_esperado.json` re-sellado (`5f8bf97c…`) |
| **Sellos** | `sha256sums.txt` **195** entradas (incluye `clasificar_w07_windows.py` y su test), `sha256sum -c` **0 fallos**, `prep -SoloSellos` **PASS**, `-SoloManifiesto` **PASS**, `-SoloParidad` **PASS** |
| **WE0-2** | **5/5** acciones `HandlerType=Command` reportadas, incluida la de `powershell` **sin pipe** (re-exportado de la BD; §3) |
| **Canary real** | **22/22** plantillas, **0 faltan, 0 sobran** |
| **W-07 real** | **6/6** acciones reportadas. **Canónico (bruto): 90 / `NO` (nivel 15)**; **`sin_artefactos_ps`: 87 / `SI` (nivel 6)**; **`sin_ambas`: 20 / `SI` (nivel 4)**. El `92213` de 10:06:02 es artefacto de la acción 3, no detección (ver §5) |
| **2 h** | **24/24** latidos emitidos, **23/24** recibidos (1 ciclo de sink caído); `seq` 3→26; `ka_instancias=1` en **23/23**; `ka_pid=256` único |
| **Muerte / recuperación** | cliente muerto a las **11:20:02Z**; recuperado **11:25:08Z** (1 ciclo, 5 min 6 s), `win_user=angel` |
| **Duplicado** | segunda instancia **rechazada** por mutex (`segunda_instancia`); `ka_instancias=1` sigue |
| **`crudo`** | `D:\TFG-VMs\legitimo-windows-2026-11-12\crudo\`; `M` **881 endpoint / 2.440 total** (`boveda_version=3`) |
| **Firewall** | `TFG-hb-9095` **presente** durante la ventana y **ausente** tras `cleanup` |
| **`stop` / `cleanup`** | bucle fuera en **4 min 20 s**; tareas `TFG-WinLegit-*` **retiradas** y `armado.flag` retirado; `logall_json=no` + `CONFIG_IDENTICA` |
| **Prueba del snapshot** | revert + arranque: `TFG-WinLegit-Actividad` **Ready**; cliente presente y **0 `ghosts.exe`**; `Sysmon64`/`WazuhSvc` **Running**; `powercfg` **0/0/0**; sin residuos; **0 tareas `TFG-Attack-*`** |
| **Laboratorio** | **0 VMs**, sink/API/PostgreSQL parados, **0 tareas `TFG-*`** en el host, variables **borradas** |

---

## 1. Qué contiene el snapshot v2

Creado con la **VM apagada** (`vmrun snapshot`) el **2026-11-12T13:19:40Z**.
Es **hijo de `lab-listo-windows-ataques-gui`** (el mismo padre que v1), no de v1.

### 1.1 Invitado (`victima-windows`, agente `002`)

| Elemento | Valor |
|---|---|
| **Cliente GHOSTS** | `C:\Users\angel\ghosts-client\ghosts.exe` + 293 ficheros de payload (294 en total con la tarea): `Domain 8.2.7.90`, `exe 8.2.2.0` |
| **Configuración** | `config\application.json` (API `http://192.168.65.1:5000/api`, `DisableStartup=true`), `nlog.config` (WARN, `app.log` 1 MB × 20) |
| **Receta** | `config\timeline.d1/d2/d3.json`; `config\timeline.json` = **d1** |
| **Calendario** | `recetas\bloques_windows.env` **sin mapa** (`TFG_MAPA_DIAS=` vacío) + `recetas\calendario_windows.json` |
| **Campaña** | `C:\lab-legit\campana\casos_windows.md` + `campana_windows.csv`; **0** directorios `W-*` |
| **Tarea actividad** | `TFG-WinLegit-Actividad`: **angel**, `Interactive`, `LeastPrivilege`, **Ready**, sin disparadores |
| **Tarea keepalive** | `TFG-WinLegit-Keepalive`: **SYSTEM**, al arrancar, `-Loop`, `IgnoreNew`, `RestartCount=3` |
| **Servicios** | `Sysmon64` y `WazuhSvc` `Running/Automatic` |
| **Energía** | `STANDBYIDLE=0`, `HIBERNATEIDLE=0`, `HYBRIDSLEEP=0` (AC) |
| **Windows Update** | `NoAutoUpdate=1`, `wuauserv` **Stopped/Disabled** |
| **Defender** | `DEFENDER_OFF=1` (`RTP=False`, `Behavior=False`, `Tamper=False`, `WinDefend=Stopped`) |
| **Sesión** | `SESION_ANGEL=1` (explorer sesión 1, `DESKTOP-BTMCFA5\angel`, IL Medium) |
| **Sin residuos** | 0 `armado.flag`, 0 `stop.flag`, 0 `keepalive.log`/`recovery.log`, 0 `client.out`, 0 `instance`, 0 `logs`, 0 `TFG-Attack-*`, `C:\lab-attack` vacío |

> **Sobre `keepalive.log`:** en el snapshot **no existe** (se borró antes de crearlo). Tras
> el **revert + arranque** de prueba, el bucle de arranque lo recrea con **4 líneas de
> 13:20** y **0 líneas** de la prueba (11:00–13:00): `TEST_LINES=0`.

### 1.2 Host

- `D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1\client` (build local, §2).
- `D:\TFG-VMs\legitimo-windows-2026-11-12\crudo\` (crudo de la ventana de 2 h).
- `D:\TFG-VMs\legitimo-windows-2026-11-12\keepalive_2h\` (copia primaria de la evidencia de 2 h).

---

## 2. Cliente 8.3.1 (procedencia)

| Dato | Valor |
|---|---|
| Origen | compilación local desde el tag **`v8.3.1`**, commit **`4d2e160860f508f699f935472b5515358f534844`** |
| `ghosts.domain.dll` | **`8.2.0.0` / `8.2.7.90`**, `sha256=e305cf2069e2ef9a16a2b9f10fab05a70ac6f0fef8042766cd52b15cf2eaa312` |
| `ghosts.exe` | **`8.0.0.0` / `8.2.2.0`**, `sha256=b0c5d33b9a20f8ee77a962f40f3dcd89c59f3dec33f6927249c9d18cefe44dec` |
| Procedencia | `Soporte/Laboratorio/windows/legit/BUILD.md` (`sha256=9dedb29d4168e2e81efafaccdbe4ce8bd750881cc60474406bf41a8119718a11`) |

> **Discrepancia declarada (M-1):** el ZIP «Windows x64» del release `v8.3.1` es de
> 2024-10-15 y trae `Domain 8.2.1.0`; por eso se compiló desde el tag. El `FileVersion`
> de `ghosts.exe` no cambia (8.0.0.0/8.2.2.0); el discriminador es `Ghosts.Domain.dll=8.2.7.90`.

---

## 3. WE0-2 — 5/5 acciones reportadas (literal)

Timeline `evidencia/t4b/we02_timeline_v2.json` (5 acciones `Command`; la 3.ª es
`powershell` **sin pipe**). Enviada a `desktop-btmcfa5` a las **10:00:49Z**.
Salida literal de `history_timeline` (`evidencia/t4b/we02_history_timeline.txt`):

> **TSV anterior sobrescrito (declaración T4b, 2026-11-12):** el primer
> `we02_history_timeline.txt` sellado contenía **solo 3 filas** (7255–7257) porque el
> export se cortó antes de que la BD confirmara las dos últimas. Ese TSV **se
> sobrescribió** al re-exportar; **no se conserva copia** del fichero de 3 filas. El
> actual (**5 filas**, `sha256=0616320fb1cc726f7eea6260c26d8ba153b6c018f85bc5707bf28dbd82474f30`)
> es la **salida literal de la BD** (`ghosts.history_timeline`, PostgreSQL del host) con
> la consulta `evidencia/t4b/we02_reexport_query.sql` (ids 7255–7259,
> `machineid=desktop-btmcfa5`) y el log `evidencia/t4b/we02_reexport.log`. Las **5 filas
> existen en la BD** (7258 y 7259 incluidas); **no se editó el TSV a mano**.

```text
  id  |     createdutc      | handler |                                                     command
------+---------------------+---------+-----------------------------------------------------------------------------------------------------------------
 7255 | 2026-11-12 10:01:02 | Command | cd /d C:\Users\angel && dir C:\Users\angel\Documentos > C:\Users\angel\Documentos\we02_1.txt
 7256 | 2026-11-12 10:01:06 | Command | cd /d C:\Users\angel && echo we02_accion_2 > C:\Users\angel\Documentos\we02_2.txt
 7257 | 2026-11-12 10:01:10 | Command | powershell -NoProfile -Command "Get-ChildItem C:\Users\angel\Documentos > C:\Users\angel\Documentos\we02_3.txt"
 7258 | 2026-11-12 10:01:14 | Command | cd /d C:\Users\angel\Documentos && type we02_2.txt
 7259 | 2026-11-12 10:01:18 | Command | cd /d C:\Users\angel && where curl.exe > C:\Users\angel\Documentos\we02_5.txt
(5 filas)
```

**Resultado: 5/5.** La acción `powershell` sin pipe **se reporta** (id 7257), a diferencia
del intento fallido de T4 con `|` (4/5).

---

## 4. Canary real — 22/22, 0 faltan, 0 sobran

Timeline `evidencia/canary_windows/timeline_canary.json` (22 plantillas) enviada a las
**10:02:16Z**; `history_timeline` exportado en `evidencia/t4b/canary_history_timeline.txt`
(22 filas, 10:02:43–10:03:48Z). Verificación con
`verificar_paridad_windows.verificar_canary`:

```text
{
 "ok": true,
 "enviados": 22,
 "reportados": 22,
 "faltan": [],
 "sobran": [],
 "error": ""
}
CANARY enviados=22 reportados=22 faltan=0 sobran=0 ok=True
```

**Resultado: 22/22 PASS.**

---

## 5. W-07 real — 6/6 acciones; bruto 90/`NO` y sensibilidades declaradas

Timeline `evidencia/t4b/w07_timeline.json` con las **6 acciones reales** de W-07
(inicio, export, `powershell` con variable intermedia **sin pipe**, `more`, `hecho`,
`fin`), enviada a las **10:05:31Z**. `history_timeline`
(`evidencia/t4b/w07_history_timeline.txt`) devuelve **6 filas** (ids 7282–7287), incluida
la de `powershell` con `Set-Content` (id 7284).

**Resultado canónico (bruto, sin filtros).** La extracción de campaña
(`extraer_campana_windows.py`) sobre la ventana de atribución `[ini−10 s, fin+60 s]`,
con las **6** acciones y las alertas del agente `002`, da:

```text
W-07,2026-11-12T10:05:46Z,2026-11-12T10:06:30Z,6,,90,60798;60805;60807;60808;60809;67027;91823;92032;92052;92200;92213;92217,15,NO
```

- **Fichero:** `evidencia/t4b/w07_campana_bruto.csv` (`w07_campana.csv` es byte a byte
  idéntico).
- **Log reproducible:** `evidencia/t4b/w07_extraer_campana.log` (incluye el comando exacto
  y la salida literal; `RESULT=PASS`, `esperado_no=1 ['W-07']`).
- **Detalle bruto:** `evidencia/t4b/w07_alertas_bruto.csv` (90 filas; copia con cabecera
  propia de `w07_alertas_detalle.csv`).

**Por qué el bruto es `NO`.** El nivel máximo 15 lo aporta la alerta `92213` de
**10:06:02.285Z** (`__PSScriptPolicyTest_cmewlqsn.k2p.ps1`, `powershell.exe`), generada por
el arranque del `powershell` de la **acción 3**. Es un **`artefacto_ataque`**, no una
detección de la técnica: el corpus ya clasificó `92213` así en **ATA073/ATA097**. El
canónico literal se mantiene **`NO` (90 / 15)** porque la extracción de campaña no filtra
artefactos.

**Las cuatro cifras (deterministas; `_artefactos/scripts/clasificar_w07_windows.py`).**

| Variante | Excluye | Alertas | `level` | Resultado |
|---|---|---:|---:|---|
| **canónico** | nada (bruto) | **90** | **15** | **`NO`** |
| `sin_ajenas` | 67 mantenimiento (10:07:19–10:07:29Z, **fuera** de `[t0,t1]`) | **23** | **15** | **`NO`** |
| `sin_artefactos_ps` | 3 artefactos PowerShell (1 dentro de `[t0,t1]`, 2 a las 10:07:29Z) | **87** | **6** | **`SI`** |
| `sin_ambas` | 67 + 3 (sensibilidad) | **20** | **4** | **`SI`** |

- **Fichero de las variantes:** `evidencia/t4b/w07_variantes.csv` (4 filas; regla de
  detección de la campaña: `67027` presente y `level < 7`).
- **Log reproducible:** `evidencia/t4b/w07_clasificacion.log` (incluye el bloque de
  variantes).

> **Lectura honesta.** El `SI` **no depende de excluir las 67 alertas ajenas**: `sin_ajenas`
> sigue `NO` (23/15). Depende de excluir el **artefacto de ataque** `92213` de la acción 3:
> `sin_artefactos_ps` da **87 / level 6 / `SI`**. El `level 6` de esa variante viene de
> `92200`/`92217` (mantenimiento); si se mira solo `[t0,t1]`, el máximo es 4. El `SI` **se
> sostiene** con la declaración de artefacto, pero el **canónico literal sigue siendo
> `NO` (90/15)** porque la extracción de campaña no filtra artefactos. `sin_ambas`
> (20/4/`SI`) es la tabla filtrada del caso y no es necesaria para el `SI`.

**Sensibilidad filtrada (no canónica).** Tras separar las alertas de las acciones
(20) de las ajenas (70), la misma extracción da:

```text
W-07,2026-11-12T10:05:46Z,2026-11-12T10:06:30Z,6,,20,67027;92032;92052,4,SI
```

- **Fichero:** `evidencia/t4b/w07_campana_filtrada.csv`
  (`w07_campana_sin_policytest.csv` es byte a byte idéntico; el nombre antiguo es ambiguo).
- **Log reproducible:** `evidencia/t4b/w07_extraer_campana_filtrada.log`.
- **Detalle filtrado:** `evidencia/t4b/w07_alertas_caso_w07.csv` (20 filas).
- **Trazabilidad de exclusiones:** `evidencia/t4b/w07_exclusiones.csv` (70 filas, con
  `motivo_exclusion` y `detalle_exclusion`) y `evidencia/t4b/w07_clasificacion.log`.

**Qué se excluye exactamente y por qué (70 alertas).** El criterio es determinista
(`_artefactos/scripts/clasificar_w07_windows.py`); no hay filtro manual por usuario ni
por `rule_id`:

| Grupo | Alertas | `rule_id` | Por qué |
|---|---:|---|---|
| **Artefactos de PowerShell** (`artefacto_powershell_policytest`) | **3** | `92213`×2, `91823`×1 | **2 a las 10:07:29Z** (`92213` de `sdiagnhost` y `91823` con `Invoke-command`) y **1 a las 10:06:02.285Z** (`92213`, `powershell.exe` de la **acción 3**, **dentro** de `[t0,t1]`). `92213` es `artefacto_ataque` (precedente ATA073/ATA097), **no** detección. |
| **Ajenas al caso** (`mantenimiento_windows_fuera_de_accion`) | **67** | `67027`×52, `92200`×9, `92217`×1, `60798`×1, `60805`×1, `60807`×1, `60808`×1, `60809`×1 | Ráfaga de mantenimiento programado de Windows entre **10:07:19 y 10:07:29Z**, **fuera** de `[t0,t1]` (posterior al `fin` de W-07, 10:06:30Z): `UCPDMgr`, `taskhostw`, `TrustedInstaller`, `TiWorker`, `Defrag`, `.NET ngen`, `sdiagnhost`/`SDIAG_*`, SQL Server Express (`60798/60805/60807/60808/60809`) y `DESKTOP-BTMCFA5$`. |

**Total:** 20 del caso + 3 artefactos + 67 ajenas = **90**. **No** se afirma que las 70
estén fuera de la ventana: **1 de las 70 está dentro** (10:06:02.285Z) y es artefacto de la
acción 3. La ventana de atribución `+60 s` es la que captura la ráfaga de 10:07; **no** es
actividad de W-07.

> **Aclaración de nombres (T4b).** `w07_alertas_detalle_sin_policytest.csv` tiene **78**
> filas (no 77): quita `92213` (2), `92200` (9) y `92217` (1), pero **no** quita `91823`;
> es un **intermedio**, no la tabla filtrada del caso. `w07_campana_sin_policytest.csv`
> es la tabla de **20/SI** (idéntica a `w07_campana_filtrada.csv`), aunque su nombre
> sugiera que solo quita policy test. El detalle de 20 filas es
> `w07_alertas_detalle_w07.csv` / `w07_alertas_caso_w07.csv`.
> **`n_acciones=6` es literal en todas las variantes.**

---

## 6. Prueba de 2 h (11:00–13:00Z) y evidencia sellada

| Dato | Valor |
|---|---|
| Ventana | **2026-11-12T11:00:00Z → 13:00:00Z** (`ventana_actual.json`) |
| Latidos emitidos | **24/24** (cada 5 min, :00/:05/…/:55) |
| Latidos recibidos | **23/24**; falta `seq=12` (11:45, prueba de sink caído) |
| `seq` | **3 → 26**, estrictamente creciente; único hueco `12` |
| `ka_pid` / `ka_instancias` | **256** único / **1** en **23/23** recibidos y 24/24 emitidos |
| Reloj | `delta_s` máx. **0,610 s**; 23/23 ≤ 2 s; 0 > 5 s |
| Cadena `sha256_prev` | **OK en 23/23** |
| Muerte del cliente | `taskkill` **11:20:02Z** (pid 5264) |
| Recuperación | **11:25:08Z**, pid **6496**, `user=angel`, `rc_run=0`; **1 ciclo** (5 min 6 s) |
| Duplicado | manual **11:14:05Z** `segunda_instancia pid=5896` (salida 0); `schtasks /run` con el bucle vivo no crea 2.ª (`IgnoreNew`) |
| Sink caído | stop **11:40:03Z** / start **11:47:05Z**; `11:45:04Z hb=FAIL` (timeout); `estado.json` intacto; reanuda **11:50:01Z seq=13** |
| `win_user` tras recuperar | `DESKTOP-BTMCFA5\angel` |

**Evidencia:** copia primaria en
`D:\TFG-VMs\legitimo-windows-2026-11-12\keepalive_2h\`; copia sellada en
`Soporte/Laboratorio/windows/legit/evidencia/keepalive_2h/`.
`MANIFEST.tsv` sha256 = **`562580c03faf50523c2b44ce61f85faded4c9e70608dcf63be7df945a8f8b74b`**.
`copiado_utc=2026-11-12T13:00:35Z`; `snapshot_utc=2026-11-12T13:19:40Z` ⇒
**`copiado_utc < snapshot_utc`**. `test_2h_meta.md` contiene horas, pids y recuperación.

- **`watch` real:** 5 chequeos (11:00, 11:30, 12:00, 12:30, 12:59) con
  `ok=9 fallos=0 skip=0` y **`SSH_INVITADO=0`**; `G-W7` **sin SKIP** (con
  `ventana_actual.json`). `HB_EDAD_MIN` 0,4–4,6 min.
- **Ruido del keepalive:** 1 proceso de trabajo (`ka_pid=256`), 1 recuperación
  (`schtasks`), 1 duplicado manual; **0** procesos por ciclo.

---

## 7. `crudo` real (regla dura)

| Dato | Valor |
|---|---|
| Destino | `D:\TFG-VMs\legitimo-windows-2026-11-12\crudo\` |
| `criterio` | **`utc_dias_D_D+2`** |
| `tz` / `dias` | **`CET`** / **`2026-11-12,2026-11-13,2026-11-14`** |
| Ficheros / `.sum` / planos | **3** / **0** / **3** |
| `manifest_sha256` | **`821111058096046151e604108937d9202bfd98d2f2f1d6d6b0e18a59933beb1a`** |
| `M` (unidad = línea de `archives`, agente 002, `boveda_version=3`) | **881 endpoint / 2.440 total**, `[11:00,13:00]` |
| `M_csv` | `D:\TFG-VMs\legitimo-windows-2026-11-12\crudo\denominador_M.csv` (`2DA3569A…`) |
| `archives.json` / `alerts.json` | `a1a3129e…` (6.386.345 B) / `8b03521d…` (10.675.298 B) |
| `crudo.done` | escrito; `M_rc=0`, `ficheros=3`, `sums=0`, `planos=3` |
| **Intentos** | **13:02:42Z FALLO** (el listado del manager volvió vacío: `angel` no puede leer `/var/ossec/logs`, `wazuh:wazuh 750`); **13:03:33Z OK** |
| **Fix aplicado** | `sudo -S -p '' bash -c '...'` en `windows_legit_host_control.ps1` (en el **diff sin commit**; no se toca el manager) |

> **Declaración del reintento:** el primer `crudo` de las 13:02:42Z falló con
> `crudo FALLO: no hay ficheros para dias 2026-11-12,2026-11-13,2026-11-14 TZ=CET`
> (`windows_legit_host_control.log:322-323`). La causa fue de **permisos**: el listado se
> ejecutaba como `angel` y `/var/ossec/logs` es `wazuh:wazuh 750`; el comando devolvía
> vacío. El fix `sudo -S -p '' bash -c '...'` está en el diff de
> `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` (sin commit). El segundo
> intento, **13:03:33Z**, copió los 3 ficheros y terminó `crudo OK` a las 13:03:37Z. El
> fallo **no** dejó `crudo.done` falso: el segundo intento lo escribió.

> **Declaración del `sums=0`:** el día 12 no tenía todavía `ossec-archive-12.json.gz` ni
> `.sum` (Wazuh rota el diario a las 00:00). Se copiaron los **planos vivos**
> `archives.json`, `alerts.json` y `ossec-archive-12.json`. `archives.json` y
> `ossec-archive-12.json` **no son el mismo inodo**: son **dos copias del mismo fichero
> lógico** (idéntico tamaño 6.386.345 B y `sha256 a1a3129e…`); `alerts.json` es otro
> fichero (`sha256 8b03521d…`, 10.675.298 B). `sums=0` queda escrito en `crudo.done`;
> **no** se inventa un `.sum`. La copia es anterior a `logall_json=no` y el `M` se calculó
> de la copia con `--estricto --boveda-version 3`.

---

## 8. Firewall `TFG-hb-9095`

**Presente tras `prep`/durante la ventana** (`evidencia/t4b/firewall_presente.txt`):

```text
DisplayName : TFG-hb-9095
Enabled     : True
Direction   : Inbound
Action      : Allow
Protocol    : TCP
LocalPort   : 9095
RemoteAddress : 192.168.65.0/255.255.255.0
```

**Ausente tras `cleanup`** (`evidencia/t4b/firewall_ausente.txt`):

```text
reglas=0
Ninguna regla coincide con los criterios especificados.
```

---

## 9. `stop`, `cleanup` y cierre

`stop` (`evidencia/t4b/stop.log`):

```text
stop: crudo=crudo.done
stop: creando stop.flag
stop: bucle_salio=True (espera <= 6 min)   # 13:05:51 -> 13:10:11 = 4m20s
stop: actividad: armado.flag FLAG_RETIRADO
stop OK (vmrun rc=0)
```

`cleanup` (`evidencia/t4b/cleanup.log`):

```text
cleanup: crudo.done presente (...)
cleanup: bucle_salio=True
cleanup: tareas invitado retiradas [actividad=...deleted. keepalive=...deleted.]
cleanup: GHOSTS/PostgreSQL parados (api_procesos=0 postgres_parado=True)
cleanup: logall_json=no verificado
cleanup: CONFIG_IDENTICA
cleanup: guardarrailes fallos=0 victima_windows_off=True victima_linux_off=True manager_on=True
```

> **Nota operativa declarada:** `stop` apaga la VM (diseño). Para que `cleanup` pudiera
> **desregistrar las tareas dentro del invitado** se volvió a arrancar la VM **después de
> `stop`** (sin revertir), se ejecutó `cleanup` y este volvió a apagarla. Es una acción
> **fuera de la ventana** (t1=13:00), no medida. El `armado.flag` ya lo había retirado
> `stop` (`FLAG_RETIRADO`); `cleanup` verificó `FLAG_AUSENTE` y retiró las 2 tareas.

> **Cierre del sink (corrección T4b).** El log sellado `t4b/heartbeat_sink_ctl.log`
> termina en **11:47:12Z** (`status`); los dos `stop` del cierre
> (**13:10:13Z** `pid=1676` y **13:12:54Z** `SINK_NO_ARRANCADO`) solo estaban en el log
> vivo `Soporte/Laboratorio/windows/legit/evidencia/heartbeat_sink_ctl.log`. Se copió
> **completo** a `t4b/heartbeat_sink_ctl_cierre.log` (`sha256
> 3aed61fe7abe73a07328ca10cefebebf719cc070679c3a69cc3c39ad713f80ee`) y se sella en el
> `MANIFEST.tsv`; el log de 11:47Z se conserva como foto intermedia.

---

## 10. Creación del snapshot y prueba de revert + arranque

- **Creado:** `vmrun snapshot ... lab-listo-windows-legit-v2` a las **13:19:40Z**, VM apagada.
- **Inventario:** **8** snapshots:
  `base-limpia`, `lab-listo-windows`, `lab-listo-windows-baseline`,
  `lab-listo-windows-ataques`, `lab-listo-windows-ataques-ssh`,
  `lab-listo-windows-ataques-gui`, `lab-listo-windows-legit` (v1), **`lab-listo-windows-legit-v2`**.
  Los 6 previos y v1 **intactos**.
- **Manifiesto v2:** **294** ficheros,
  `MANIFEST_SHA256=4621046f028cb37ad8bbc6a1e9c5adae29bc8c238f774471b6d579011afdf3f0`;
  `manifiesto_esperado.json` = `5f8bf97c7a44a726c5bbc71cf0e6248f51524722a73f0843b0148ac16543e1af`.
  `prep -SoloManifiesto` **OK**, `prep -SoloSellos` **PASS**, `prep -SoloParidad` **PASS**.

**Revert a `lab-listo-windows-legit-v2` + arranque** (`evidencia/t4b/revert_arranque_checks.txt`):

```text
TAREA_ACT=Ready
TAREA_KA=Running          # disparador "al arrancar"; el snapshot en reposo la tenía Ready
CLIENTE_EXE=True
GHOSTS_PROCS=0
Sysmon64=Running
WazuhSvc=Running
STANDBYIDLE_AC=0x00000000
HIBERNATEIDLE_AC=0x00000000
HYBRIDSLEEP_AC=0x00000000
ARMADO_FLAG=False
STOP_FLAG=False
CAMPANA_W=0
LAB_ATTACK_ITEMS=0
TFG_ATTACK_TASKS=0
KEEPALIVE TEST_LINES=0 / TOTAL_LINES=4 (solo arranque 13:20)
```

**6/6 comprobaciones:** tarea de actividad **Ready**, cliente presente y **0 `ghosts.exe`**,
`Sysmon64`/`WazuhSvc` **Running**, `powercfg` **0/0/0**, sin residuos de campaña/ataque,
**0 tareas `TFG-Attack-*`**. La tarea keepalive queda **Running** al arrancar por diseño
(disparador `AtStartup`); en el snapshot en reposo estaba **Ready** y **0 procesos**.

---

## 11. Hashes de los artefactos de la tanda

| Fichero | `sha256` |
|---|---|
| `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` (v4, T4) | `7f34b881661466a8047edb633658d1ac79b76a23b5213b6ebf483411e7c9c76c` |
| `Soporte/Laboratorio/windows/deploy_windows.ps1` | `c70453a0e850cc4ba6ec554e454d773acafc9f5fe08efa2c372a2e7bd146cf03` |
| `Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1` | `c05aed58ca415a193763601a3a0677032437db0280aa962b90e868612043c166` |
| `Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1` | `d7c17a3ff4a3cc78b03dbc85f18cd5b2679d248a0af4fa984426e899f032e54e` |
| `Soporte/Laboratorio/windows/guest/verificar_windows.ps1` | `c07ef52406253d26b2ff69f5262e2187a49c8cb57564108519e74c39f2ecce53` |
| `Soporte/Laboratorio/windows/guest/preparar_invitado_windows.ps1` | `8c4fef62234d9704db11a11d4ea633fd11d868c1e7ad45f85ffcb35fa4131a64` |
| `Soporte/Laboratorio/windows/legit/heartbeat_sink.py` | `82628f699b201902984eb3ef2b0a4680f4e73ad6b4c22ca46b88a8d92501fd86` |
| `Soporte/Laboratorio/windows/legit/heartbeat_sink_ctl.ps1` | `b1402741e5308b48ddcd9976f83b685d0747b317718be345c8fdeeae5ec21617` |
| `Soporte/Laboratorio/windows/legit/BUILD.md` | `9dedb29d4168e2e81efafaccdbe4ce8bd750881cc60474406bf41a8119718a11` |
| `manifiesto_esperado.json` | `5f8bf97c7a44a726c5bbc71cf0e6248f51524722a73f0843b0148ac16543e1af` |
| `keepalive_2h/MANIFEST.tsv` | `562580c03faf50523c2b44ce61f85faded4c9e70608dcf63be7df945a8f8b74b` |
| `crudo/MANIFEST.tsv` | `821111058096046151e604108937d9202bfd98d2f2f1d6d6b0e18a59933beb1a` |
| `crudo/denominador_M.csv` | `2da3569a6a3f3c991ea44a6cbc2327040d6c30f86896765bcd6c575815499e97` |

`sha256sums.txt`: **195** entradas (incluye `clasificar_w07_windows.py` y su test);
`sha256sum -c` ⇒ **0 fallos**; `verificar_sellos_windows.py` ⇒ `RESULT=PASS`
(SELLO-01…05 OK). `manifiesto_esperado.json.sha256` cuadra.

### 11.1 Corrección T4b (2026-11-12) — hashes de la evidencia re-sellada

| Fichero | `sha256` |
|---|---|
| `evidencia/t4b/we02_history_timeline.txt` (5 filas) | `0616320fb1cc726f7eea6260c26d8ba153b6c018f85bc5707bf28dbd82474f30` |
| `evidencia/t4b/we02_reexport_query.sql` | `e93683070276d68562cd7f85fb54bde1458d686f21699e8941156ad43f6f26ea` |
| `evidencia/t4b/we02_reexport.log` | `7fae31e2f99a570bad81948a3660b8dd5dc5cb42fe2a1ff2f6c08b6a27e051ac` |
| `evidencia/t4b/w07_alertas_bruto.csv` (90) | `836099c90683824c57035db8c0a18f4ddf20dea405dcc7021b8046b5c9b87160` |
| `evidencia/t4b/w07_alertas_caso_w07.csv` (20) | `85e3bfc66a45f48cfc4aadcccd819bb8743e7fc291f14628bebaf2fa7756bc8c` |
| `evidencia/t4b/w07_exclusiones.csv` (70; 3 PS, 1 dentro) | `b506db254ad5c78843092abbe9d7277c93142434c6107f427bb8124533088e4b` |
| `evidencia/t4b/w07_variantes.csv` (4 cifras) | `f76f3fa1ef73c7cc7dde551d278ef828b5242ba2835adf530ef38eae781efee5` |
| `evidencia/t4b/w07_clasificacion.log` | `b284014e9a8335abe74317a1e23d2bc04dd9d67fedf671c776c357be6bebe4d1` |
| `evidencia/t4b/w07_campana_bruto.csv` (90/NO) | `d1d0a4eca6cfcfb319f8216208650e031039d65d999a239a0bf1406210897e19` |
| `evidencia/t4b/w07_campana_filtrada.csv` (20/SI) | `ccec41d480a35fbb73f070254bc3e4f9ae9d05666e2978fd7d43fb89087abff8` |
| `evidencia/t4b/w07_extraer_campana.log` | `dba1441ee75be88f6658826d3c1ff3f0bca65821bb9520a2a7552a0641014ca1` |
| `evidencia/t4b/w07_extraer_campana_filtrada.log` | `0e4e7d6e4ca3ab1f287567c72e6cc8cc46ea9a721e4edde062a41861429db8c9` |
| `evidencia/t4b/w07_LEEME.md` | `ed2db5821da5f5f7edff685bd6c6af75a7626eb53fe5d74ad4e0b3c394473b54` |
| `evidencia/t4b/README.md` | `6212abf119592461a3a1d215d69332ef778e8b1f09aa6842832d9a30b31c1a6a` |
| `evidencia/t4b/pytest_defectos_t4b.log` | `7e4fb9435d646ac049093474267ef5c7643d330cecdd6cbdcdedb3895c01a209` |
| `evidencia/t4b/verificacion_defectos_t4b.txt` | `caca2d74c9acad6d81b2ba2b5f2ccbc46adf5e62ee4a5b42b61517c82317e002` |
| `evidencia/t4b/MANIFEST.tsv` (95) | `5844f496ed02a70433407c0b7f03f42aaaadfb41eb5b6d38a0a4e5136405c2e4` |
| `evidencia/t4b/MANIFEST.sha256` | `04f5a3f059f7c0f74338ff3738ed24916b66cead4bef8a19aa537d04a4e705f5` |
| `evidencia/t4b/heartbeat_sink_ctl_cierre.log` | `3aed61fe7abe73a07328ca10cefebebf719cc070679c3a69cc3c39ad713f80ee` |
| `evidencia/t4b/drytest_2026-11-10_fuera_tanda4.log` | `0844b5ddbe4099cdaffcdd0f240ce245eb82b739eb04e6fb02981cda2d7cc804` |
| `evidencia/t4b/cierre_verificacion_t4b.txt` | `3b0b07074ad8db81b7a9d52e27b6bbdbbb914c9563557ebdc6632e2b8d04c828` |
| `evidencia/t4b/verificacion_correccion_t4b.txt` | `a81ae25f9ea0fbd4f350d91cbec20869578b645aa155ff337a423c618525445f` |
| `evidencia/t4b/pytest_t4b_fix.log` | `153474e0e88e50fff61e332a149419dd45c4effa2c949763b648834518b68cd9` |
| `_artefactos/scripts/clasificar_w07_windows.py` | `bbc68b4537575a314baaaefb4860c50039669bbb90d22380394454e51879dbef` |
| `_artefactos/scripts/tests/test_clasificar_w07_windows.py` | `e9560c792b6df7ca74e77271425c8363f935857393ed3433755e273a650861ae` |
| `.gitignore` (excepciones T4b) | `0b9095f298f89559d6fb2a13e0fa9d53d51fdf0a6e779e2739f194cf8aff9e98` |
| `Soporte/Laboratorio/crudo/estado_crudo.md` | `043c094548e2fba4cb68433a64a948c80343862f508fca7c36ff2785c4610a69` |
| `_fases/windows-legit-prep/auditoria_espejo_linux_windows.md` | `6ddffb567dec44798dd9dd87234308e426f3670e262c382cc172b20b7525121f` |
| `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` (195) | `9f70af77bb7da26c4a730732df120eee2ad5d87da6367091848c965511bda4d2` |
| `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` (fix `sudo -S`) | `7f34b881661466a8047edb633658d1ac79b76a23b5213b6ebf483411e7c9c76c` |
| `Soporte/Laboratorio/windows/legit/comparabilidad_windows.md` | `0e82be45562a8dc106de4b5248ea4210a103bd5292c92d3f43afbfeb660206c9` |
| `Soporte/Laboratorio/windows/legit/snapshot_windows_legit.md` | `aa494dde814e60b29389a1b9b5efa6bbe6baec4e543cf8cdd4601067bdfbcce6` |

> El sello completo de **todos** los ficheros de `evidencia/t4b/` está en
> `evidencia/t4b/MANIFEST.tsv` (y su hash en `MANIFEST.sha256`).

---

## 12. Declaraciones (sin adornos)

1. **No se ejecutó la ventana de 72 h** ni ningún ataque. La medida de 2 h es un **ensayo**
   de cierre; su `M` (881) **no** es una tasa publicable.
2. **`sums=0`** en el `crudo`: el día en curso no tenía `.gz` ni `.sum`; se copiaron los
   planos vivos. No se inventó un `.sum`.
3. **W-07**: canónico bruto `6/90/NO` (nivel 15). El `NO` lo provoca el `92213` de
   **10:06:02.285Z**, un **`artefacto_ataque`** de la acción 3 (policy test de PowerShell;
   precedente ATA073/ATA097), **no una detección**. Cifras: `sin_ajenas` (67) **23/15/NO**;
   `sin_artefactos_ps` (3) **87/6/SI**; `sin_ambas` (20) **20/4/SI**. **1 de las 70
   exclusiones está dentro de `[t0,t1]`** (10:06:02.285Z) y es artefacto de la acción 3;
   las otras 69 (2 policy test + 67 mantenimiento) están fuera. El `SI` de
   `sin_artefactos_ps` **se sostiene** con la declaración de artefacto; el canónico literal
   sigue `NO` y no se maquilla. Detalle: `w07_variantes.csv`, `w07_exclusiones.csv` y
   `w07_clasificacion.log`; el log anterior (`5 acciones / 66 alertas / REVIEW`) queda
   **superado** por esta re-ejecución con las entradas selladas actuales
   (`w07_acciones.csv` = 6 acciones).
4. **`cleanup`** necesitó un arranque intermedio tras `stop` para poder desregistrar las
   tareas del invitado; es **fuera de la ventana** y no se mide.
5. **Keepalive al arrancar**: el snapshot en reposo tiene la tarea `Ready` y **0 procesos**;
   tras revert+arranque el disparador `AtStartup` la deja **Running** (1 `powershell.exe`).
   El cliente `ghosts.exe` sigue **0 procesos** (la tarea de actividad no tiene disparador).
6. **Defender OFF** es control ambiental declarado; se comprobó en `prep`, `arm`, `cleanup`
   y en el arranque del snapshot. No se tocó ninguna política de Defender.
7. **`M` y FPR**: la unidad es **línea de `archives`** (`boveda_version=3`), igual que Linux;
   el `M` de la ventana de 72 h sigue pendiente de WE0-9.
8. **`crudo` — reintento declarado:** el primer intento (13:02:42Z) falló porque el listado
   se ejecutaba como `angel` sobre `/var/ossec/logs` (`wazuh:wazuh 750`) y volvía vacío; el
   segundo (13:03:33Z) funcionó con `sudo -S -p '' bash -c '...'` (fix en el diff de
   `windows_legit_host_control.ps1`, **sin commit**). No se inventó ningún `.sum`.
9. **Sink — log de cierre:** el `t4b/heartbeat_sink_ctl.log` sellado termina en 11:47:12Z;
   los `stop` de 13:10:13Z y 13:12:54Z están en el log vivo, copiado completo a
   `t4b/heartbeat_sink_ctl_cierre.log` y sellado en el `MANIFEST.tsv`.
10. **Ficheros no listados en el README inicial (declarados):** `sha256sums.txt` (**195**
    entradas, actualizado con los hashes de `windows_legit_host_control.ps1`,
    `comparabilidad_windows.md`, `snapshot_windows_legit.md`, `clasificar_w07_windows.py`
    y su test) y el **anexo T4** de
    `_fases/windows-legit-prep/auditoria_espejo_linux_windows.md` (§11). También se
    **retiró/marcó** `t4b/drytest.log` como `drytest_2026-11-10_fuera_tanda4.log` (es un
    drytest de la tanda 3, no de T4).
11. **Nombres de W-07:** `w07_alertas_detalle_sin_policytest.csv` tiene **78** filas (no
    77) y no quita `91823`; es un intermedio. `w07_campana_sin_policytest.csv` es la tabla
    de **20/SI** (idéntica a `w07_campana_filtrada.csv`), aunque el nombre no lo diga. La
    tabla bruta canónica es `w07_campana_bruto.csv` (`w07_campana.csv` idéntica). Las
    cuatro cifras están en `w07_variantes.csv`.
12. **WE0-2 — TSV anterior sobrescrito:** el primer `we02_history_timeline.txt` sellado
    contenía **3 filas** y **se sobrescribió** al re-exportar; **no se conserva copia**
    del fichero de 3 filas. El actual (5 filas,
    `sha256=0616320fb1cc726f7eea6260c26d8ba153b6c018f85bc5707bf28dbd82474f30`) es la
    **salida literal de la BD** (`we02_reexport.log`), **sin edición manual**; las 5 filas
    existen en `ghosts.history_timeline` (7255–7259).

---

## 13. Veredicto

**Tanda 4 (C6 + T4) PASA con la evidencia corregida**: WE0-2 **5/5** (5 filas en el
fichero sellado; el TSV de 3 filas se sobrescribió y no se conserva copia), canary
**22/22**, W-07 **6/6 acciones** con canónico **90/`NO`** y sensibilidades `sin_ajenas`
**23/`NO`**, `sin_artefactos_ps` **87/`SI`** y `sin_ambas` **20/`SI`**; el `92213` de
10:06:02.285Z es artefacto de la acción 3, declarado. 2 h con **24/24** latidos emitidos,
**1** proceso, **1** recuperación en **1 ciclo**, duplicado rechazado, sink caído/reanudado
con log de cierre sellado, `crudo` con `M` de la copia y reintento declarado, firewall
simétrico, `stop`/`cleanup` con tareas y flag retirados, y snapshot v2 **verificado** con
revert + arranque. **W3-bis queda cerrado y listo para W4 (ventana real de 72 h).**

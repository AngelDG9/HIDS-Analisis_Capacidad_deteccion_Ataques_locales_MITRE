# `casos_windows.md` — campaña de falsos positivos de Windows (`B6`, 11 casos)

> **Pre-registro; `sha256` en la cabecera de `campana_windows.csv`.** Este fichero
> se **genera** desde los comandos literales de `recetas/w{1,2,3}.json` + los
> metadatos de `campana_windows.py`. **No se edita a mano.**
>
> ⚠️ **Es una predicción, no una medida.** En Linux la campaña se derivó del corpus
> de ataques (4 107 detecciones `80792`). **No existe corpus de ataques Windows**
> (plan §N-1): las reglas citadas son **hipótesis** salvo `67027`, que es la regla de
> creación de proceso observada en la baseline del 08/10 (132 de 159 alertas).

> **Bloque `B6` «repaso del sistema» = 17:05–17:50Z**, **11 casos** en **3/4/4**
> días, inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11) y
> separación **≥ 3 min**. Atribución: `timestamp ∈ [ini − 10 s, fin + 60 s]`.
> **63 acciones GHOSTS** (22 de ellas son las marcas `inicio`/`fin`).

## Qué mide y por qué está dentro de la ventana

La campaña **no** fabrica ataques: hace **11 tareas de oficina corrientes** que un
empleado ejecutaría en el mismo portátil, con las **mismas herramientas** que el
ruleset y el inventario P1-Windows señalan como sospechosas. Se ejecuta **dentro**
de `[t0, t1]`, en un bloque **declarado**, y se publica **aparte**
(`campana_fp_windows.csv`), sin recalcular `M` ni un FPR alternativo.

**No mutante** (misma definición que Linux): todo lo que se crea vive bajo
`C:\lab-legit\campana\W-XX\` y **se borra dentro del propio caso**; no se toca el Programador
de tareas, **no se modifica la configuración del registro**, ni los servicios, las
cuentas, el arranque o rutas del sistema. **W-10 escribe 1 evento declarado** en el
registro de aplicaciones (`Application`): no se borra (borrarlo sería otra mutación).
La comprobación literal está en `campana_windows.py --no-mutacion`.

**Efectos declarados fuera de la carpeta** (son los **dos únicos**):

- **`descargas_http`** — cuatro peticiones HTTP a la intranet local (W-08: dos a `:8080` y un intento a `:8081`; W-11: una a `:8080`); las **tres** que llegan al 8080 dejan rastro en el `web_access.log` del **servidor**, fuera de la víctima.
- **`registro_eventos`** — un evento INFORMATION (ID 100, origen `ofimatica`) en el registro **Application** de la víctima (W-10); no se borra (borrarlo sería otra mutación).

## Tabla de equivalencia Linux ↔ Windows

> **Cómo leerla.** `mecanismo` es lo que se quiere medir; `cambia` es la diferencia
> técnica; `comparable` dice si la fila se puede comparar **caso a caso** con Linux.
> **No** se comparan recuentos crudos de alertas entre plataformas (§W-L2): se compara
> «¿alertó?, ¿con qué regla?, ¿a qué nivel?».

| Linux | Windows | Mecanismo compartido | Qué cambia | ¿Comparable por caso? |
|---|---|---|---|---|
| `C-01` | `W-01` | descubrimiento de procesos, memoria y servicios (`free` + `systemctl`) | `systeminfo` + `sc query state= all` + `tasklist /svc` | sí |
| `C-02` | `W-02` | lectura de la configuración de red (`ip addr` + `ip route`) | `ipconfig /all` + `route print` | sí |
| `C-03` | `W-03` | comprobar la copia programada (`systemctl list-timers` + `crontab -l`) | `schtasks /query` + `reg query …\Run` (los dos de lectura) | sí (mismo mecanismo; la regla que puede saltar es otra) |
| `C-04` | — | persistencia benigna (crear y quitar una tarea programada) | no existe: retirada en Linux (v4) y en Windows por la misma decisión | **no** (sin espejo: no mutación) |
| `C-05` | `W-04` | cifrar un informe antes de enviarlo (`openssl enc -pass`) | AES en PowerShell con clave fija + `certutil -hashfile` | **parcial**: se pierde el cifrado con contraseña (T1486 legítimo) |
| `C-06` | `W-05` | borrar temporales y destruir un borrador (`rm -rf` + `shred`) | `rd /s /q` + sobrescritura y borrado en PowerShell (sin `cipher /w:`) | **parcial**: se pierde el borrado seguro de espacio libre (T1561) |
| `C-07` | `W-06` | sincronizar informes con la carpeta de copias (`rsync --delete`) | `robocopy … /MIR` | sí (mismo fan-in/fan-out local) |
| `C-08` | `W-07` | normalizar un CSV (`sed -i 's/;/ /g'`) | `powershell -Command` con variable intermedia (`$c = …; Set-Content`) y sin pipe (4104 real) | sí (mismo fichero reescrito; Windows añade telemetría 4104) |
| `C-09` | `W-08` | intranet que no responde: acotar tiempo y reintentar (`curl`+`timeout`) | `curl.exe --max-time` ×3 (8080, 8081, 8080) sin `timeout` | sí (mismas peticiones y mismo reintento) |
| `C-10` | `W-09` | abanico de 12 copias de una plantilla (`seq`+`xargs`+`cp`) | `for /L %i in (1,1,12) do @cmd /c copy` | sí (mismo fan-out de 12; cambia el shell, no la forma) |
| `C-11` | `W-10` | dejar constancia en el registro del sistema (`logger` + `tee`) | `eventcreate /T INFORMATION /L APPLICATION` + `type >>` | **parcial**: `eventcreate` puede exigir elevación (WE0-7); si falla se degrada a lectura y se declara |
| `C-12` | `W-11` | descargar el manual de la intranet (`wget`) | `curl.exe -o` | sí (misma descarga; `curl.exe` está en Windows 10 ≥ 1803) |

**Recuento:** 8 casos comparables, 3 parciales y **1 sin espejo** (`C-04`, persistencia benigna: retirada por no mutación).

## Resumen (11 casos · `N ≥ 7` = 0 en todos: predicción)

| # | Caso | Día | Hora (UTC) | Herramientas | Se confunde con | `N ≥ 7` | `N ≥ 3` | ¿Muta? | Coste |
|---|---|---|---|---|---|---|---|---|---|
| **W-01** | El equipo va lento: miro memoria y servicios | d1 | **17:06:00** | `systeminfo`, `sc`, `tasklist` | T1057, T1082, T1007 | **0** | 67027 L3 >=6 | **No** | 3 min · <1 MB |
| **W-02** | No me va la intranet: miro la red | d1 | **17:15:20** | `ipconfig`, `route` | T1016, T1018 | **0** | 67027 L3 >=5 | **No** | 2 min · <1 MB |
| **W-03** | Compruebo si la copia esta programada | d1 | **17:24:40** | `schtasks`, `reg` | T1053.005, T1547.001 | **0** | 67027 L3 >=5 | **No** | 2 min · <1 MB |
| **W-04** | Protejo el informe antes de enviarlo (cifrado, parcial) | d2 | **17:17:00** | `powershell`, `certutil` | T1486 | **0** | 67027 L3 >=7 | **No** | 4 min · <1 MB |
| **W-05** | Limpio temporales y destruyo un borrador (parcial) | d2 | **17:25:30** | `powershell` | T1070.004, T1485 | **0** | 67027 L3 >=7 | **No** | 2 min · <1 MB |
| **W-06** | Sincronizo los informes con la carpeta de copias | d2 | **17:33:10** | `robocopy` | T1039, T1074.001 | **0** | 67027 L3 >=5 | **No** | 3 min · <1 MB |
| **W-07** | Normalizo el CSV del informe | d2 | **17:41:20** | `powershell` | T1565.001 | **0** | 67027 L3 >=6 | **No** | 2 min · <1 MB |
| **W-08** | La intranet no responde: acoto el tiempo y reintento | d3 | **17:11:00** | `curl.exe` | T1071.001, T1048 | **0** | 67027 L3 >=6 | **No** | 3 min · <1 MB |
| **W-09** | Preparo el lote de plantillas del mes | d3 | **17:19:30** | `copy` | T1499.002, T1499.003 | **0** | 67027 L3 >=18 | **No** | 4 min · <1 MB |
| **W-10** | Dejo constancia de la incidencia en el registro | d3 | **17:27:10** | `eventcreate` | T1056.001 | **0** | 67027 L3 >=6 | **No** | 2 min · <1 MB |
| **W-11** | Descargo el manual de la intranet | d3 | **17:35:40** | `curl.exe` | T1105 | **0** | 67027 L3 >=4 | **No** | 2 min · <1 MB |

> **Cómo leer los umbrales.** `N ≥ 7` decide si el caso es un FP «de verdad»
> (`P2` o superior); `N ≥ 3` es donde **todo proceso creado** alerta por `67027`
> (hipótesis H-W1, predicción). **No** se promete el número exacto: la cota inferior
> es **1 `cmd.exe` por acción** (el handler ejecuta `cmd /c <comando>`), más 12
> `cmd /c` hijos en `W-09`. Lo exacto **se mide** y lo sella B10-W.
> Si un caso alerta a `N ≥ 7`, **es un hallazgo** y se publica; no se re-ejecuta.
> Si un caso **no** produce `67027`, **no se ejecutó** (no es «0 alertas»).

## Fichas

### W-01 · El equipo va lento: miro memoria y servicios

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:06:00** |
| Mecanismo (espejo de) | `C-01` |
| Herramientas | `systeminfo`, `sc`, `tasklist` |
| Se confunde con (MITRE) | `T1057`; `T1082`; `T1007` |
| Corpus **Linux** con el mismo mecanismo | `ATA004`; `ATA045`; `ATA038` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=6 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-01\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con «RESULTADO=OK», el recuento de servicios.txt (> 10), free.txt (>= 3) y fallidos.txt |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Cualquier empleado mira el estado del equipo y sus servicios cuando el portátil va lento, antes de abrir una incidencia. Solo lectura: `systeminfo`, `sc query` y `tasklist` no cambian nada. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-01 md C:\lab-legit\campana\W-01) & > C:\lab-legit\campana\W-01\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-01 && systeminfo > C:\lab-legit\campana\W-01\free.txt`
3. `comando` — `cd /d C:\lab-legit\campana\W-01 && sc query state= all > C:\lab-legit\campana\W-01\fallidos.txt`
4. `comando` — `cd /d C:\lab-legit\campana\W-01 && tasklist /svc > C:\lab-legit\campana\W-01\servicios.txt`
5. `evidencia` — `cd /d C:\lab-legit\campana\W-01 && > C:\lab-legit\campana\W-01\hecho.txt echo RESULTADO=OK && find /c /v "" C:\lab-legit\campana\W-01\servicios.txt C:\lab-legit\campana\W-01\free.txt C:\lab-legit\campana\W-01\fallidos.txt >> C:\lab-legit\campana\W-01\hecho.txt && type C:\lab-legit\campana\W-01\hecho.txt`
6. `fin` — `cd /d C:\lab-legit\campana\W-01 && del /f /q C:\lab-legit\campana\W-01\servicios.txt 2>nul & del /f /q C:\lab-legit\campana\W-01\free.txt 2>nul & del /f /q C:\lab-legit\campana\W-01\fallidos.txt 2>nul & > C:\lab-legit\campana\W-01\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-02 · No me va la intranet: miro la red

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:15:20** |
| Mecanismo (espejo de) | `C-02` |
| Herramientas | `ipconfig`, `route` |
| Se confunde con (MITRE) | `T1016`; `T1018` |
| Corpus **Linux** con el mismo mecanismo | `ATA054`; `ATA055` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=5 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-02\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con la IPv4 192.168.65.x (findstr) y la tabla de rutas |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Comprobar la IP y la puerta de enlace es el primer paso cuando una web interna no carga. `ipconfig /all` y `route print` son de lectura: no se usa `netsh` ni `route add`. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-02 md C:\lab-legit\campana\W-02) & > C:\lab-legit\campana\W-02\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-02 && ipconfig /all > C:\lab-legit\campana\W-02\ip_addr.txt`
3. `comando` — `cd /d C:\lab-legit\campana\W-02 && route print > C:\lab-legit\campana\W-02\ip_route.txt`
4. `evidencia` — `cd /d C:\lab-legit\campana\W-02 && > C:\lab-legit\campana\W-02\hecho.txt echo RESULTADO=OK && findstr /c:"192.168.65." C:\lab-legit\campana\W-02\ip_addr.txt >> C:\lab-legit\campana\W-02\hecho.txt && type C:\lab-legit\campana\W-02\ip_route.txt >> C:\lab-legit\campana\W-02\hecho.txt`
5. `fin` — `cd /d C:\lab-legit\campana\W-02 && del /f /q C:\lab-legit\campana\W-02\ip_addr.txt 2>nul & del /f /q C:\lab-legit\campana\W-02\ip_route.txt 2>nul & > C:\lab-legit\campana\W-02\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-03 · Compruebo si la copia esta programada

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:24:40** |
| Mecanismo (espejo de) | `C-03` |
| Herramientas | `schtasks`, `reg` |
| Se confunde con (MITRE) | `T1053.005`; `T1547.001` |
| Corpus **Linux** con el mismo mecanismo | `ATA021`; `ATA004` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=5 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-03\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con el nº de tareas (find /c) y tarea_rc=0/ge1 |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Comprobar si la copia automática está programada es una duda corriente. `schtasks /query` y `reg query` solo leen; no hay `/create`, ni `reg add`, ni `sc config`. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-03 md C:\lab-legit\campana\W-03) & > C:\lab-legit\campana\W-03\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-03 && schtasks /query /fo LIST > C:\lab-legit\campana\W-03\timers.txt`
3. `comando` — `cd /d C:\lab-legit\campana\W-03 && reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > C:\lab-legit\campana\W-03\crontab.txt 2>nul & if errorlevel 1 (> C:\lab-legit\campana\W-03\crontab_rc.txt echo tarea_rc=ge1) else (> C:\lab-legit\campana\W-03\crontab_rc.txt echo tarea_rc=0)`
4. `evidencia` — `cd /d C:\lab-legit\campana\W-03 && > C:\lab-legit\campana\W-03\hecho.txt echo RESULTADO=OK && find /c /v "" C:\lab-legit\campana\W-03\timers.txt >> C:\lab-legit\campana\W-03\hecho.txt && type C:\lab-legit\campana\W-03\crontab_rc.txt >> C:\lab-legit\campana\W-03\hecho.txt`
5. `fin` — `cd /d C:\lab-legit\campana\W-03 && del /f /q C:\lab-legit\campana\W-03\timers.txt 2>nul & del /f /q C:\lab-legit\campana\W-03\crontab.txt 2>nul & del /f /q C:\lab-legit\campana\W-03\crontab_rc.txt 2>nul & > C:\lab-legit\campana\W-03\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-04 · Protejo el informe antes de enviarlo (cifrado, parcial)

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:17:00** |
| Mecanismo (espejo de) | `C-05` |
| Herramientas | `powershell`, `certutil` |
| Se confunde con (MITRE) | `T1486` |
| Corpus **Linux** con el mismo mecanismo | `ATA001`; `ATA019`; `ATA041` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `91801-91846` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=7 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-04\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con las dos huellas SHA256 (original == descifrado) |
| Coste · disco | 4 min · <1 MB |
| Por qué es legítimo | Proteger un informe con datos de cliente antes de enviarlo es práctica de oficina. El fichero es de juguete y la clave es fija y simbólica. **Parcial**: Windows 10 Pro no trae cifrado simétrico con contrasena por linea de comandos sin instalar (§N-4); se pierde la variante `openssl enc -pass` de T1486. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-04 md C:\lab-legit\campana\W-04) & > C:\lab-legit\campana\W-04\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-04 && > C:\lab-legit\campana\W-04\informe.txt echo informe del area: datos de cliente, importe 1200`
3. `comando` — `cd /d C:\lab-legit\campana\W-04 && powershell -NoProfile -Command "$k=[byte[]](0..31); $v=[byte[]](0..15); $a=[IO.File]::ReadAllBytes('C:\lab-legit\campana\W-04\informe.txt'); $s=[Security.Cryptography.Aes]::Create(); $s.Mode='CBC'; $s.Padding='PKCS7'; $s.Key=$k; $s.IV=$v; $e=$s.CreateEncryptor(); $b=$e.TransformFinalBlock($a,0,$a.Length); [IO.File]::WriteAllBytes('C:\lab-legit\campana\W-04\informe.txt.enc',$b)"`
4. `comando` — `cd /d C:\lab-legit\campana\W-04 && powershell -NoProfile -Command "$k=[byte[]](0..31); $v=[byte[]](0..15); $a=[IO.File]::ReadAllBytes('C:\lab-legit\campana\W-04\informe.txt.enc'); $s=[Security.Cryptography.Aes]::Create(); $s.Mode='CBC'; $s.Padding='PKCS7'; $s.Key=$k; $s.IV=$v; $d=$s.CreateDecryptor(); $b=$d.TransformFinalBlock($a,0,$a.Length); [IO.File]::WriteAllBytes('C:\lab-legit\campana\W-04\informe.txt.rec',$b)"`
5. `comando` — `cd /d C:\lab-legit\campana\W-04 && certutil -hashfile C:\lab-legit\campana\W-04\informe.txt SHA256 > C:\lab-legit\campana\W-04\huellas.txt 2>&1 & certutil -hashfile C:\lab-legit\campana\W-04\informe.txt.rec SHA256 >> C:\lab-legit\campana\W-04\huellas.txt 2>&1`
6. `evidencia` — `cd /d C:\lab-legit\campana\W-04 && > C:\lab-legit\campana\W-04\hecho.txt echo RESULTADO=OK && type C:\lab-legit\campana\W-04\huellas.txt >> C:\lab-legit\campana\W-04\hecho.txt`
7. `fin` — `cd /d C:\lab-legit\campana\W-04 && del /f /q C:\lab-legit\campana\W-04\informe.txt 2>nul & del /f /q C:\lab-legit\campana\W-04\informe.txt.enc 2>nul & del /f /q C:\lab-legit\campana\W-04\informe.txt.rec 2>nul & del /f /q C:\lab-legit\campana\W-04\huellas.txt 2>nul & > C:\lab-legit\campana\W-04\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-05 · Limpio temporales y destruyo un borrador (parcial)

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:25:30** |
| Mecanismo (espejo de) | `C-06` |
| Herramientas | `powershell` |
| Se confunde con (MITRE) | `T1070.004`; `T1485` |
| Corpus **Linux** con el mismo mecanismo | `ATA003`; `ATA005` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `91801-91846` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=7 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-05\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con el tamaño previo y borrador_ausente=1 |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Borrar temporales y destruir un borrador con datos personales es lo que recomienda cualquier manual de protección de datos. Los dos objetos los crea el propio caso. **Parcial**: `cipher /w:` reescribe el espacio libre 3 veces (GB y horas de disco, §N-5); se sustituye por sobrescritura del propio fichero en PowerShell. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-05 md C:\lab-legit\campana\W-05) & > C:\lab-legit\campana\W-05\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-05 && (if not exist C:\lab-legit\campana\W-05\tmp md C:\lab-legit\campana\W-05\tmp) && > C:\lab-legit\campana\W-05\tmp\borrador_tmp.txt echo temporal del dia && > C:\lab-legit\campana\W-05\borrador.txt echo borrador con datos personales`
3. `comando` — `cd /d C:\lab-legit\campana\W-05 && for %I in (C:\lab-legit\campana\W-05\borrador.txt) do @echo %~zI > C:\lab-legit\campana\W-05\antes.txt`
4. `comando` — `cd /d C:\lab-legit\campana\W-05 && rd /s /q C:\lab-legit\campana\W-05\tmp 2>nul`
5. `comando` — `cd /d C:\lab-legit\campana\W-05 && powershell -NoProfile -Command "$p='C:\lab-legit\campana\W-05\borrador.txt'; $a=[IO.File]::ReadAllBytes($p); $z=New-Object byte[] $a.Length; [IO.File]::WriteAllBytes($p,$z); for($i=0;$i -lt $a.Length;$i++){$z[$i]=[byte](($i*37)%251)}; [IO.File]::WriteAllBytes($p,$z); Remove-Item -LiteralPath $p -Force"`
6. `evidencia` — `cd /d C:\lab-legit\campana\W-05 && echo RESULTADO=OK > C:\lab-legit\campana\W-05\hecho.txt && type C:\lab-legit\campana\W-05\antes.txt >> C:\lab-legit\campana\W-05\hecho.txt && if not exist C:\lab-legit\campana\W-05\borrador.txt >> C:\lab-legit\campana\W-05\hecho.txt echo borrador_ausente=1`
7. `fin` — `cd /d C:\lab-legit\campana\W-05 && del /f /q C:\lab-legit\campana\W-05\antes.txt 2>nul & > C:\lab-legit\campana\W-05\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-06 · Sincronizo los informes con la carpeta de copias

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:33:10** |
| Mecanismo (espejo de) | `C-07` |
| Herramientas | `robocopy` |
| Se confunde con (MITRE) | `T1039`; `T1074.001` |
| Corpus **Linux** con el mismo mecanismo | `ATA039`; `ATA040` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `92200-92227` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=5 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-06\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con dir /s de origen y destino (mismo tamaño) y dir del destino |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Sincronizar la carpeta de informes con la de copias es lo que hace cualquiera que haya perdido un fichero una vez. Origen y destino son del caso; `/MIR` solo afecta a `W-06\destino\`. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-06 md C:\lab-legit\campana\W-06) & > C:\lab-legit\campana\W-06\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-06 && (if not exist C:\lab-legit\campana\W-06\origen md C:\lab-legit\campana\W-06\origen) & (if not exist C:\lab-legit\campana\W-06\destino md C:\lab-legit\campana\W-06\destino) && > C:\lab-legit\campana\W-06\origen\informe_1.txt echo informe uno && > C:\lab-legit\campana\W-06\origen\informe_2.txt echo informe dos && > C:\lab-legit\campana\W-06\destino\obsoleto.txt echo copia obsoleta`
3. `comando` — `cd /d C:\lab-legit\campana\W-06 && robocopy C:\lab-legit\campana\W-06\origen\ C:\lab-legit\campana\W-06\destino\ /MIR /NFL /NDL /NJH /NJS /NP`
4. `evidencia` — `cd /d C:\lab-legit\campana\W-06 && > C:\lab-legit\campana\W-06\hecho.txt echo RESULTADO=OK && dir /s C:\lab-legit\campana\W-06\origen C:\lab-legit\campana\W-06\destino >> C:\lab-legit\campana\W-06\hecho.txt && dir C:\lab-legit\campana\W-06\destino >> C:\lab-legit\campana\W-06\hecho.txt`
5. `fin` — `cd /d C:\lab-legit\campana\W-06 && rd /s /q C:\lab-legit\campana\W-06\origen 2>nul & rd /s /q C:\lab-legit\campana\W-06\destino 2>nul & > C:\lab-legit\campana\W-06\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-07 · Normalizo el CSV del informe

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:41:20** |
| Mecanismo (espejo de) | `C-08` |
| Herramientas | `powershell` |
| Se confunde con (MITRE) | `T1565.001` |
| Corpus **Linux** con el mismo mecanismo | `ATA006`; `ATA032`; `ATA026`; `ATA017` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `91801-91846` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=6 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-07\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con el CSV normalizado (more) y el recuento de `;` |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Cambiar el separador de un export para abrirlo en Excel es una tarea de oficina diaria. El único fichero que se reescribe es el del caso; se hace con variable intermedia, sin pipe (D-01). |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-07 md C:\lab-legit\campana\W-07) & > C:\lab-legit\campana\W-07\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-07 && > C:\lab-legit\campana\W-07\export.csv echo referencia;area;importe && >> C:\lab-legit\campana\W-07\export.csv echo A-01;compras;1200 && >> C:\lab-legit\campana\W-07\export.csv echo A-02;ventas;980`
3. `comando` — `cd /d C:\lab-legit\campana\W-07 && powershell -NoProfile -Command "$c = (Get-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv') -replace ';',','; Set-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv' -Value $c"`
4. `comando` — `cd /d C:\lab-legit\campana\W-07 && more +0 C:\lab-legit\campana\W-07\export.csv > C:\lab-legit\campana\W-07\export_normalizado.txt`
5. `evidencia` — `cd /d C:\lab-legit\campana\W-07 && > C:\lab-legit\campana\W-07\hecho.txt echo RESULTADO=OK && more +0 C:\lab-legit\campana\W-07\export.csv >> C:\lab-legit\campana\W-07\hecho.txt && find /c ";" C:\lab-legit\campana\W-07\export.csv >> C:\lab-legit\campana\W-07\hecho.txt`
6. `fin` — `cd /d C:\lab-legit\campana\W-07 && del /f /q C:\lab-legit\campana\W-07\export.csv 2>nul & del /f /q C:\lab-legit\campana\W-07\export_normalizado.txt 2>nul & > C:\lab-legit\campana\W-07\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-08 · La intranet no responde: acoto el tiempo y reintento

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:11:00** |
| Mecanismo (espejo de) | `C-09` |
| Herramientas | `curl.exe` |
| Se confunde con (MITRE) | `T1071.001`; `T1048` |
| Corpus **Linux** con el mismo mecanismo | `ATA025`; `ATA009`; `ATA010`; `ATA020`; `ATA023`; `ATA028`; `ATA041`; `ATA050` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=6 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-08\`) |
| Efecto declarado | descargas_http |
| Evidencia de efecto | hecho.txt con http_code, fallo_rc, reintento_rc y el tamaño de intranet.html |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Cuando una web interna no responde, el usuario acota el tiempo de espera y reintenta. Los puertos son de la intranet local: 8080 (abierto) y 8081 (cerrado, el «no responde»). |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-08 md C:\lab-legit\campana\W-08) & > C:\lab-legit\campana\W-08\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-08 && curl.exe -sS --max-time 3 -o C:\lab-legit\campana\W-08\intranet.html -w "%{http_code}\n" http://intranet.local:8080/ > C:\lab-legit\campana\W-08\http_code.txt`
3. `comando` — `cd /d C:\lab-legit\campana\W-08 && curl.exe -sS --max-time 2 http://intranet.local:8081/ >nul 2>&1 & if errorlevel 1 (> C:\lab-legit\campana\W-08\fallo_rc.txt echo RC_FALLO=ge1) else (> C:\lab-legit\campana\W-08\fallo_rc.txt echo RC_FALLO=0)`
4. `comando` — `cd /d C:\lab-legit\campana\W-08 && curl.exe --max-time 5 -sS -o C:\lab-legit\campana\W-08\reintento.html http://intranet.local:8080/ && > C:\lab-legit\campana\W-08\reintento_rc.txt echo RC_REINTENTO=0`
5. `evidencia` — `cd /d C:\lab-legit\campana\W-08 && > C:\lab-legit\campana\W-08\hecho.txt echo RESULTADO=OK && type C:\lab-legit\campana\W-08\http_code.txt C:\lab-legit\campana\W-08\fallo_rc.txt C:\lab-legit\campana\W-08\reintento_rc.txt >> C:\lab-legit\campana\W-08\hecho.txt && dir C:\lab-legit\campana\W-08\intranet.html >> C:\lab-legit\campana\W-08\hecho.txt`
6. `fin` — `cd /d C:\lab-legit\campana\W-08 && del /f /q C:\lab-legit\campana\W-08\intranet.html 2>nul & del /f /q C:\lab-legit\campana\W-08\reintento.html 2>nul & del /f /q C:\lab-legit\campana\W-08\http_code.txt 2>nul & del /f /q C:\lab-legit\campana\W-08\fallo_rc.txt 2>nul & del /f /q C:\lab-legit\campana\W-08\reintento_rc.txt 2>nul & > C:\lab-legit\campana\W-08\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-09 · Preparo el lote de plantillas del mes

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:19:30** |
| Mecanismo (espejo de) | `C-10` |
| Herramientas | `copy` |
| Se confunde con (MITRE) | `T1499.002`; `T1499.003` |
| Corpus **Linux** con el mismo mecanismo | `ATA046`; `ATA047` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `92200-92227` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=18 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-09\`) |
| Efecto declarado | ninguno fuera de su carpeta |
| Evidencia de efecto | hecho.txt con el tamaño de lote_12.txt y dir de lote_*.txt |
| Coste · disco | 4 min · <1 MB |
| Por qué es legítimo | Preparar doce copias de una plantilla para el lote del mes es mecánico y corriente. **Cambia de mecanismo**: Windows no tiene `xargs`; se conserva el abanico de 12 con `for /L` + `cmd /c copy`. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-09 md C:\lab-legit\campana\W-09) & > C:\lab-legit\campana\W-09\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-09 && > C:\lab-legit\campana\W-09\plantilla.txt echo plantilla del informe del mes && for /L %i in (1,1,12) do @echo %i>>C:\lab-legit\campana\W-09\lotes.txt`
3. `comando` — `cd /d C:\lab-legit\campana\W-09 && for /L %i in (1,1,12) do @cmd /c copy /y C:\lab-legit\campana\W-09\plantilla.txt C:\lab-legit\campana\W-09\lote_%i.txt`
4. `comando` — `cd /d C:\lab-legit\campana\W-09 && find /c /v "" C:\lab-legit\campana\W-09\lote_1.txt > C:\lab-legit\campana\W-09\lote1_wc.txt`
5. `evidencia` — `cd /d C:\lab-legit\campana\W-09 && > C:\lab-legit\campana\W-09\hecho.txt echo RESULTADO=OK && for %I in (C:\lab-legit\campana\W-09\lote_12.txt) do @echo %~zI >> C:\lab-legit\campana\W-09\hecho.txt && dir C:\lab-legit\campana\W-09\lote_*.txt >> C:\lab-legit\campana\W-09\hecho.txt`
6. `fin` — `cd /d C:\lab-legit\campana\W-09 && del /f /q C:\lab-legit\campana\W-09\lote_*.txt 2>nul & del /f /q C:\lab-legit\campana\W-09\lotes.txt 2>nul & del /f /q C:\lab-legit\campana\W-09\plantilla.txt 2>nul & del /f /q C:\lab-legit\campana\W-09\lote1_wc.txt 2>nul & > C:\lab-legit\campana\W-09\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-10 · Dejo constancia de la incidencia en el registro

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:27:10** |
| Mecanismo (espejo de) | `C-11` |
| Herramientas | `eventcreate` |
| Se confunde con (MITRE) | `T1056.001` |
| Corpus **Linux** con el mismo mecanismo | `ATA018` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027`, `60600-61072` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=6 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-10\`) |
| Efecto declarado | registro_eventos |
| Evidencia de efecto | hecho.txt con el contenido de registro.log |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Dejar constancia de una incidencia en el registro de la aplicación es lo que pide cualquier procedimiento. Escribe **1 evento** INFORMATION declarado que no se borra (borrarlo sería otra mutación). |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-10 md C:\lab-legit\campana\W-10) & > C:\lab-legit\campana\W-10\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-10 && > C:\lab-legit\campana\W-10\nota.txt echo W-10: incidencia cerrada; copia del dia revisada`
3. `comando` — `cd /d C:\lab-legit\campana\W-10 && eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO ofimatica /D "W-10: incidencia cerrada; copia del dia revisada"`
4. `comando` — `cd /d C:\lab-legit\campana\W-10 && type C:\lab-legit\campana\W-10\nota.txt >> C:\lab-legit\campana\W-10\registro.log`
5. `evidencia` — `cd /d C:\lab-legit\campana\W-10 && > C:\lab-legit\campana\W-10\hecho.txt echo RESULTADO=OK && more C:\lab-legit\campana\W-10\registro.log >> C:\lab-legit\campana\W-10\hecho.txt`
6. `fin` — `cd /d C:\lab-legit\campana\W-10 && del /f /q C:\lab-legit\campana\W-10\nota.txt 2>nul & del /f /q C:\lab-legit\campana\W-10\registro.log 2>nul & > C:\lab-legit\campana\W-10\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

### W-11 · Descargo el manual de la intranet

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:35:40** |
| Mecanismo (espejo de) | `C-12` |
| Herramientas | `curl.exe` |
| Se confunde con (MITRE) | `T1105` |
| Corpus **Linux** con el mismo mecanismo | `ATA008`; `ATA043` — **no hay corpus Windows** |
| `rule_id` hipotéticos (predicción) | `67027` |
| **Esperado `N ≥ 7`** | **0 alertas** (predicción: ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **67027 L3 >=4 (1 cmd.exe por acción; predicción)** |
| ¿Cambia la máquina? | **No** (solo escribe bajo `C:\lab-legit\campana\W-11\`) |
| Efecto declarado | descargas_http |
| Evidencia de efecto | hecho.txt con el éxito y el tamaño de manual.pdf (> 500 bytes) |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Descargar el manual del empleado desde la intranet es lo que hace cualquiera el primer día. **Desviación declarada**: el plan preveía `certutil -urlcache`; la receta (W1) usa solo `curl.exe` porque `certutil -urlcache` es un patrón clásico de detección y habría mezclado la hipótesis con el mecanismo. |

**Comandos literales** (los del `w*.json`; las marcas van **primero** y **última**):

1. `inicio` — `cd /d C:\lab-legit\campana && (if not exist C:\lab-legit\campana\W-11 md C:\lab-legit\campana\W-11) & > C:\lab-legit\campana\W-11\inicio.txt echo %DATE%_%TIME%`
2. `comando` — `cd /d C:\lab-legit\campana\W-11 && curl.exe -sS -o C:\lab-legit\campana\W-11\manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf`
3. `evidencia` — `cd /d C:\lab-legit\campana\W-11 && > C:\lab-legit\campana\W-11\hecho.txt echo RESULTADO=OK && for %I in (C:\lab-legit\campana\W-11\manual.pdf) do @echo %~zI >> C:\lab-legit\campana\W-11\hecho.txt`
4. `fin` — `cd /d C:\lab-legit\campana\W-11 && del /f /q C:\lab-legit\campana\W-11\manual.pdf 2>nul & > C:\lab-legit\campana\W-11\fin.txt echo %DATE%_%TIME%`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.

## Orden, marcas y atribución

- **Por caso (rígido):** `inicio.txt` → preparación y comandos → **evidencia** (`hecho.txt`) → limpieza → `fin.txt`. Nada del caso se ejecuta después de `fin`.
- **Marcas:** `> …\inicio.txt echo %DATE%_%TIME%` y `…\fin.txt`. Son **22** (2 por caso). **Ojo:** `cmd` no formatea ISO/UTC, así que la marca es **hora local** (`%DATE%_%TIME%`); el extractor solo la convierte si se le pasa el **desfase declarado** (`--desfase-local`). Sin desfase **no adivina**: deja la ventana vacía y el caso queda `NO_EVALUABLE`.
- **Atribución:** alerta del agente **`002` (`victima-windows`)** con `timestamp ∈ [ini − 10 s, fin + 60 s]`. Se cuenta **todo** lo que caiga dentro (incluido el keepalive, declarado) y se distingue `win_image`/`rule_id`.
- **Evidencia de efecto (obligatoria):** cada caso deja `hecho.txt` con `RESULTADO=OK` y el predicado de su ficha. Sin `hecho.txt` el caso es `NO_EVALUABLE` (hay marcas, pero no prueba de efecto), no un 0-alerta.
- **Limpieza:** los temporales del caso se borran **antes** de `fin.txt`; solo sobreviven `inicio.txt`, `hecho.txt` y `fin.txt`.

## Volumen declarado (acciones y procesos)

- **Acciones GHOSTS:** **63** (**22** son marcas `inicio`/`fin`; las otras **41** son preparación de insumos, comandos propios, evidencia y limpieza). Idénticas a Linux (16/25/22).
- **Procesos (cota inferior):** **75** = **63 `cmd.exe`** (uno por acción) + **12** `cmd /c` hijos del fan-out de `W-09`. El recuento real será mayor (herramientas hijas: `systeminfo`, `sc`, `certutil`, `curl.exe`…); **se mide**.
- **B10-W lo sella:** esta previsión se compara con lo observado (`n_acciones` y `n_eventos` de `campana_fp_windows.csv`) y se fija en el sello.

## Prerrequisitos en el invitado (WE0-2b)

> **Bloqueante:** `C:\lab-legit\campana\` debe existir y ser escribible por
> `angel` **antes de B6**. Todas las acciones empiezan por `cd /d …`; si la carpeta
> no existe, no se escribe ninguna marca y los **11 casos se pierden**
> (`NO_EJECUTADO`).

| Comprobación (WE0) | Comando | Criterio |
|---|---|---|
| Carpeta de campaña | `if exist C:\lab-legit\campana (echo OK)` | `OK` |
| Herramientas | `where systeminfo sc tasklist ipconfig route schtasks reg powershell certutil robocopy curl.exe eventcreate find findstr more tar` | todas resuelven |
| Builtins de `cmd` | `copy`, `del`, `rd`, `type`, `dir` | no necesitan `where` |
| Intranet | `curl.exe -sS -o NUL -w "%{http_code}" http://intranet.local:8080/` | `200` |
| Puerto cerrado | `curl.exe -sS --max-time 2 http://intranet.local:8081/` | rc≠0 (7 o 28) |
| `eventcreate` como `angel` | el comando de W-10 | rc=0 (si no, WE0-7 lo degrada a lectura y se declara) |
| Disco | `dir C:\` (bytes libres) | ≥ 40 MB (presupuesto de la campaña) |

> Si falla la carpeta o una herramienta, **no se arranca B6**: el caso se marca
> `NO_EJECUTADO` y se corrige el deploy (nunca se instala, §P-2).

## Desviaciones respecto del plan (declaradas)

| # | Plan | Artefacto | Por qué |
|---|---|---|---|
| D-W1 | W-04 con `tar -a` + `certutil` | **AES en PowerShell + `certutil -hashfile`** | `tar -a` no cifra; el plan pedía «integridad + empaquetado» y eso no es T1486. Se conserva el mecanismo (cifrar) con clave fija, sin contraseña |
| D-W2 | W-05 con `del` + `rd` | **`rd /s /q` + sobrescritura en PowerShell** | `del` de un fichero inexistente devuelve rc=0 en Windows (no es error); el borrado seguro se escribe a mano (no hay `shred` ni `cipher /w:` asumible) |
| D-W3 | W-11 con `certutil -urlcache` y `curl` | **solo `curl.exe`** | `certutil -urlcache` es un patrón clásico de detección: usarlo habría mezclado la hipótesis abierta con el mecanismo. Se retira la hipótesis |
| D-W4 | C-10 con `xargs` | **`for /L` + `cmd /c copy`** | Windows no tiene `xargs`; se conserva el abanico de 12 procesos |
| D-W5 | «~40 comandos y ~55 procesos» (§5.2) | **63 acciones / 75 procesos (cota inferior)** | el número exacto lo fija el CSV y lo sella B10-W |
| D-W6 | `campana_windows.md` | **`casos_windows.md`** | el nombre del artefacto sigue el del espejo de Linux (`casos.md`); el CSV mantiene `campana_windows` |
| D-W7 | familia de error `rm_inexistente` con `del` | **`type` del temporal + `del` de reintento** | en Windows `del` de un fichero ausente devuelve **rc=0**: el fallo nunca se registraba. `type` del mismo temporal sí falla (rc=1); el reintento correcto sigue siendo `del /f /q` |

> Ninguna desviación añade mutación, ni elevación, ni **ningún `|`** (tampoco dentro de PowerShell, D-01), ni
> red fuera de la intranet local.

## Qué es predicción y qué queda para WE0

| Elemento | Estado |
|---|---|
| Comandos, horas, reparto, marcas y acciones | **medido** (salen de `w*.json`, que ya pasó `--check` en W1) |
| «No muta», rutas y ausencia de pipes | **verificado** aquí (`--no-mutacion`) |
| Técnicas MITRE y `ATA` Linux | **analogía declarada** (mismo mecanismo; no hay corpus Windows) |
| `rule_id` esperados salvo `67027` | **hipótesis** (`91801-91846`, `92200-92227`, `60600-61072`) |
| `N ≥ 7` = 0 y `N ≥ 3` con `67027` | **predicción**; WE0-3/WE0-4 confirman el mapeo evento→regla |
| `eventcreate` como `angel` | **abierto** (WE0-7) |
| Número exacto de alertas y niveles | **se mide** en la ventana; no se promete |

## Cómo se comprueba

```bat
python _artefactos\scripts\campana_windows.py --check
python _artefactos\scripts\campana_windows.py --no-mutacion
python _artefactos\scripts\construir_receta_legitima_windows.py --check
python _artefactos\scripts\extraer_campana_windows.py --test

rem extraccion (fuera de la ventana, tras cosechar)
python _artefactos\scripts\extraer_campana_windows.py --solo-ventanas --evidencia <cosecha> --desfase-local +01:00
python _artefactos\scripts\extraer_campana_windows.py --ventanas campana_ventanas_windows.tsv --alertas <alertas> --acciones <export> --evidencia <cosecha>
```

---

> **Sellado.** El `sha256` de este fichero está en la **primera línea** de
> `campana_windows.csv`. Cualquier cambio en el pre-registro obliga a regenerar
> ambos (`campana_windows.py --docs`) **y a firmarlos otra vez antes de `t0`**.

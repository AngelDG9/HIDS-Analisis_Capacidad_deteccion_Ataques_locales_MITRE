# `receta_windows_resumen.md` — receta Windows **espejo** de la de Linux

> Generado por `_artefactos/scripts/construir_receta_legitima_windows.py` (receta
> Windows v1, bloque `windows-legit-prep`, tanda **W1**). El ritmo **no**
> se inventa: se copia del vector `DelayAfter` de `legitimo_72h/recetas/d{1,2,3}.json`
> (**traslado por ranuras**, plan §D2). Solo cambian los **comandos**.

## Tabla de espejo (medida, no declarada)

| Día | Bloque | UTC | Acciones Linux | Acciones Windows | Huecos |
|---|---|---|---|---|---|
| w1 | B1 | 08:00–08:12 | 11 | 11 | 10 (`DelayAfter` idéntico) |
| w1 | B2 | 08:12–10:00 | 33 | 33 | 32 (`DelayAfter` idéntico) |
| w1 | B3 | 10:20–13:00 | 56 | 56 | 55 (`DelayAfter` idéntico) |
| w1 | B4 | 14:00–16:15 | 35 | 35 | 34 (`DelayAfter` idéntico) |
| w1 | B5 | 16:15–17:00 | 12 | 12 | 11 (`DelayAfter` idéntico) |
| w1 | B6 | 17:05–17:50 | 16 | 16 | idéntico (campaña) |
| **w1** | **jornada** | 08:00–17:00 | **147** | **147** | **146** |
| w2 | B1 | 08:00–08:12 | 11 | 11 | 10 (`DelayAfter` idéntico) |
| w2 | B2 | 08:12–10:00 | 39 | 39 | 38 (`DelayAfter` idéntico) |
| w2 | B3 | 10:20–13:00 | 48 | 48 | 47 (`DelayAfter` idéntico) |
| w2 | B4 | 14:00–16:15 | 43 | 43 | 42 (`DelayAfter` idéntico) |
| w2 | B5 | 16:15–17:00 | 12 | 12 | 11 (`DelayAfter` idéntico) |
| w2 | B6 | 17:05–17:50 | 25 | 25 | idéntico (campaña) |
| **w2** | **jornada** | 08:00–17:00 | **153** | **153** | **152** |
| w3 | B1 | 08:00–08:12 | 11 | 11 | 10 (`DelayAfter` idéntico) |
| w3 | B2 | 08:12–10:00 | 29 | 29 | 28 (`DelayAfter` idéntico) |
| w3 | B3 | 10:20–13:00 | 60 | 60 | 59 (`DelayAfter` idéntico) |
| w3 | B4 | 14:00–16:15 | 29 | 29 | 28 (`DelayAfter` idéntico) |
| w3 | B5 | 16:15–17:00 | 12 | 12 | 11 (`DelayAfter` idéntico) |
| w3 | B6 | 17:05–17:50 | 22 | 22 | idéntico (campaña) |
| **w3** | **jornada** | 08:00–17:00 | **141** | **141** | **140** |

**Total ventana (3 días):** **441** acciones de jornada + **63** de campaña = **504** acciones GHOSTS (idéntico a Linux).

## Qué cambia y qué no

| Elemento | Linux | Windows | ¿Cambia? |
|---|---|---|---|
| Handler (`HandlerType`) | `Command` → `bash -c` | `Command` → `cmd /c` (`Cmd.cs:106`) | sí (shell) |
| Ventanas `UtcTimeOn/Off` | 08:00–17:00Z + B6 17:05–17:50Z | **las mismas** | no |
| Nº de acciones y `DelayAfter` | 147/153/141 + 16/25/22 | **los mismos** | no |
| `cwd` | `cd /home/angel/… && ` | `cd /d C:\Users\angel\… && ` | misma regla |
| Errores | 10/día, `$?` exacto, `printf` TSV | 10/día, `if errorlevel`, `echo` TSV | sí (sintaxis y granularidad del `rc`) |
| Herramientas | corpus de ataques Linux | ruleset + inventario P1-Windows | sí (fuente) |

## Traducción aplicada (Linux → Windows)

| Familia | Linux | Windows |
|---|---|---|
| estructura de carpetas | `mkdir -p` | `(if not exist <dir> md <dir>) & …` (idempotente: días 2 y 3 no fallan) |
| fecha/hora | `date -u +%FT%TZ` | `echo %DATE% %TIME%` (local; sin ISO/UTC en `cmd`) |
| listar | `ls -la` / `ls -l` | `dir` |
| leer | `cat` | `type` |
| copiar / mover / borrar | `cp -f` / `mv -f` / `rm -f` / `rm -rf` | `copy /y` / `move /y` / `del /f /q` / `rd /s /q` (una orden por ruta) |
| contar | `wc -l` / `wc -c` | `find /c /v ""` / `dir` |
| tamaño | `du -sh` / `du -sb` | `dir /s` |
| disco | `df -h /` | `dir C:\` (la última línea da los bytes libres) |
| memoria / inventario | `free -m` / `stat` | `systeminfo` / `dir` |
| red | `ip -brief addr` / `ip route` | `ipconfig /all` / `route print` |
| huellas | `sha256sum` / `md5sum` / `openssl dgst -sha256` | `certutil -hashfile <f> SHA256|MD5` (`> <f>.sha256` cuando la huella se guarda) |
| empaquetar | `tar -czf` / `gzip -kf` | `tar -czf` (bsdtar de Windows 10) |
| desempaquetar (error) | `gzip -d` | `tar -xzf` de algo que no es un tar (falla) |
| buscar | `find -type f` / `grep -c` / `grep` | `dir /b /s /a-d` / `find /c` / `findstr /c:` |
| recortes de texto | `head -n N` / `tail -n N` | `more +0` / `more` (aproximado) |
| sincronizar | `rsync -a --delete` | `robocopy /MIR /NFL /NDL /NJH /NJS /NP` |
| web | `curl` (`-A/-b/-c/-e/-H/-o/-w/-T/--data`) | `curl.exe` (mismos flags) |
| descarga | `wget -q -O` | `curl.exe -sS -o` |
| acotar espera | `timeout 5 curl …` | `curl.exe --max-time 5 …` |
| registro de aplicación | `logger -t ofimatica` | `eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO ofimatica /D "…"` |
| bitácora | `tee -a f < nota` | `type nota >> f` |
| generar lote | `seq 1 12` | `for /L %i in (1,1,12) do @echo %i` |
| fan-out | `xargs -I{} cp` | `for /f %i in (lotes.txt) do @cmd /c copy /y` (12 hijos) |
| servicios / tareas (lectura) | `systemctl` / `crontab -l` | `sc query state= all` / `tasklist /svc` / `schtasks /query` / `reg query` |

## Comandos **sin equivalente exacto** (y qué se hizo)

| # | Linux | Qué se hizo en Windows | Qué se pierde |
|---|---|---|---|
| T-1 | `date -u +%FT%TZ` | `echo %DATE% %TIME%` | hora **local** y sin formato ISO: `cmd` no tiene reloj UTC sin PowerShell. La hora UTC de cada acción se ancla con el `timestamp` de Wazuh (W-V9) |
| T-2 | `head -n 5` / `tail -n 5` | `more +0` / `more` | no hay recorte exacto por número de líneas sin PowerShell: se muestran las primeras pantallas |
| T-3 | `sed -i 's/;/,/g'` (jornada) | se reescribe la cabecera normalizada (`export_comas.csv`) | no se transforman las filas de datos (en la **campaña** W-07 sí se transforma, con PowerShell, como fija el plan §5.2) |
| T-4 | `gzip -kf` / `gzip -d` | `tar -czf` / `tar -xzf` | el `.gz` lo produce `tar` |
| T-5 | `openssl dgst -sha256` | `certutil -hashfile … SHA256` | mismo algoritmo, otra herramienta |
| T-6 | `wget -q -O` | `curl.exe -sS -o` | sin `wget` nativo (plan N-9) |
| T-7 | `timeout 5 curl` | `curl.exe --max-time 5` | mismo límite, otra vía |
| T-8 | `rsync -a --delete` | `robocopy /MIR` | `robocopy` da 0–7 como éxito y ≥ 8 como fallo |
| T-9 | `du -sh` / `du -sb` | `dir /s` | formato distinto (bytes + cabecera) |
| T-10 | `logger -t` | `eventcreate … /D "…"` | escribe en el registro de **aplicaciones** (1 evento declarado, no se borra); puede exigir elevación (WE0-7) |
| T-11 | `rm -f` | `del /f /q` | `del` no tiene `-f`, pero **sin `if exist`** ya devuelve rc=0 cuando el fichero no está (en Windows no es un error) |
| T-12 | `cp` con destino directorio | `copy /y` con nombre de destino | `copy` no acepta un directorio como destino sin nombre |
| T-13 | fecha en el nombre (`llegada_$(date).txt`) | sin fecha (`llegada.txt`) | `%DATE%` lleva `/`, inválido en un nombre de fichero |

## Los casos escritos a mano en PowerShell

PowerShell **solo** sustituye a lo que no existe en `cmd`: el cifrado, el borrado seguro y la normalización de CSV. El **borrado seguro** se usa además en la **jornada** (B4, `shred`, herramienta del corpus, 1/día) con el mismo guion: es el único uso de PowerShell fuera de la campaña. Total: **7 acciones** (3 de jornada + 4 de campaña).

| Caso | Qué hace el `-Command` | Proceso | Telemetría distinta esperada |
|---|---|---|---|
| **W-04** (`C-05`, cifrar) | AES-256-CBC con clave/IV fijos (`[byte[]](0..31)` y `(0..15)`), `TransformFinalBlock` y `WriteAllBytes` | 1 `powershell.exe` | **4104** (ScriptBlockLogging, reglas `91801-91846`) con el script en claro + Sysmon 1 (`powershell.exe` con `-Command`); Linux no tiene canal equivalente |
| **W-04** (`C-05`, descifrar) | el mismo AES en modo descifrado → `informe.txt.rec` | 1 `powershell.exe` | **4104** + `certutil -hashfile` posterior, que prueba que el descifrado devuelve el original |
| **W-05** (`C-06`, borrado seguro) | sobrescribe con ceros, luego con un patrón determinista `(i*37)%251`, y **borra** | 1 `powershell.exe` | **4104** + Sysmon 11 (FileWrite) antes del borrado; `shred` no deja rastro equivalente en Windows |
| W-07 (`C-08`, CSV) | `(Get-Content) -replace ';',',' \| Set-Content` (`|` **dentro** de `-Command`, permitido por §4.5) | 1 `powershell.exe` | **4104** (previsto en el plan §5.2) |

> Clave/IV son **constantes de laboratorio** (no un secreto): el caso tiene que ser reproducible y determinista, como `-pass pass:demo-c05` en Linux.

## Procesos: 1 acción = 1 `cmd.exe`

El `Command` de la receta **no** lleva `cmd /c` porque el handler ya lo añade (`Cmd.cs:106`); ponerlo daría `cmd /c cmd /c …` y un proceso de más por acción. La única excepción declarada es el **fan-out** (`for … do @cmd /c copy`), donde el `cmd` hijo **es** el proceso que hace de `cp` (12 hijos, como en Linux). **504** entradas = **504** `cmd.exe` (la misma unidad que «1 acción = 1 `bash -c`» en Linux).

Acciones con **hijos** (las mismas que en Linux; no se multiplican):

| Acción | Linux | Windows | Hijos |
|---|---|---|---|
| lote de 12 copias (B3 `xargs`, diario) | 1 `xargs` + 12 `cp` | 1 `cmd` + 12 `cmd /c copy` | 12 |
| generación del lote (B3 `seq`) | 1 `seq` | bucle interno de `cmd` (`echo` es builtin) | 0 |
| requisitos web (B1) | 1 acción con 3 `curl` | 1 acción con 3 `curl.exe` | 3 |
| huellas dobles | 1 `sha256sum` con 2 ficheros | 1 acción con 2 `certutil` | 2 |
| W-09 (`C-10`) | 1 `xargs` + 12 `cp` | 1 `cmd` + 12 `cmd /c copy` (plan §5.2) | 12 |

**Acciones que cambian de número de procesos respecto de Linux: 0.** Lo que cambia es el **hijo**, no la unidad: en Windows `dir`, `type`, `copy`, `del`, `md`, `echo`, `if` y `for` son **builtins** (sin hijo); en Linux eran binarios. Afecta al recuento de eventos de proceso (`67027`), no al de acciones.

## Errores humanos (10/día, con reintento)

| Familia | Comando que FALLA | Reintento correcto |
|---|---|---|
| `ruta_mal` | `dir …\informe` | `dir …\informes` |
| `cp_dir` | `copy /y f …\informes_2026\f.bak` | `copy /y f …\informes\f.bak` |
| `opcion` | `dir /max-depth=1 C:\` | `dir C:\` |
| `opcion` | `dir /clasificar …` | `dir /a …` |
| `gzip` | `tar -xzf …\informe.txt -C …` | `tar -czf …\informe.txt.gz -C … informe.txt` |
| `rm_inexistente` | `type …\tmp_borradores.csv` | `del /f /q …\tmp_borradores.csv` |
| `cat_dir` | `type …\actas` | `type …\informes\informe.bak` |

> `rm_inexistente`: `del` de un fichero que no existe devuelve **rc=0** en Windows (en Linux `rm` devuelve 1), así que el **fallo** se escribe con `type` del mismo temporal: abrir el fichero que ya no está sí falla (rc=1). El reintento (`del /f /q`) es el que deja limpio y devuelve rc=0.

Registro: `C:\Users\angel\Documentos\errores.log`, **5 campos TSV** (`ts · tipo · familia · comando · rc`). `ts` = `%DATE%_%TIME%` (local) y el `rc` es `rc=ge1` en el fallo y `rc=0`/`rc=ge1` en el reintento: `cmd` no da el número exacto sin una acción extra de PowerShell (plan §4.4, descartada para no añadir procesos).

Patrón (no expande `%ERRORLEVEL%` antes de ejecutar):

```bat
cd /d C:\Users\angel\Documentos && dir C:\Users\angel\Documentos\informe>nul 2>&1 & if errorlevel 1 (>> C:\Users\angel\Documentos\errores.log echo %DATE%_%TIME%	error	ruta_mal	dir C:\Users\angel\Documentos\informe	rc=ge1)
```

## Correcciones de la prueba en seco (W-1…W-4)

| # | Síntoma medido | Causa | Arreglo |
|---|---|---|---|
| W-1 | 48 procesos fallidos, **0 ficheros** en el lote de 12 | `xcopy` con un fichero suelto y destino inexistente pregunta «¿archivo o directorio?» y sale rc=2 | `for … do @cmd /c copy /y …` (12 hijos, mismos ficheros que Linux) |
| W-2 | **9** líneas `error`/día en vez de 10 | `del` de un fichero ausente devuelve **rc=0** en Windows | el fallo de `rm_inexistente` se hace con `type` del mismo temporal (rc=1) |
| W-3 | el registro del reintento y el `fin.txt` de W-09 no se escribían | un `if` falso (o un `if exist` de un fichero ausente) **se traga el resto de la línea** | `rm -f` sin `if exist`; marcas `inicio.txt`/`fin.txt` separadas con `&`; `mkdir` con cada `if` entre paréntesis |
| W-4 | **rc=1** en la estructura de los días 2 y 3 | `md` de una carpeta existente falla | `(if not exist <dir> md <dir>)` |

> Comprobado **ejecutando** los comandos en un sandbox de Windows: `_artefactos/scripts/tests/test_ejecucion_windows.py` (12 ficheros del fan-out, 10+10 líneas de error/reintento, `fin.txt` de los 11 casos).

## Riesgos abiertos (se cierran en WE0, no aquí)

| # | Qué | Qué se hace si falla |
|---|---|---|
| R1 | **`where` de las herramientas** (`curl`, `tar`, `robocopy`, `certutil`, `find`, `findstr`, `more`, `eventcreate`, `sc`, `tasklist`, `schtasks`, `reg`, `systeminfo`, `ipconfig`, `route`) como `angel` (WE0-2b) | se **cae esa herramienta** y su acción se sustituye por otra nativa; **no se instala** (plan P-2) |
| R2 | **`rc` de los errores de builtin** (`dir /max-depth=1`, `dir /clasificar`, `del`, `type` de una carpeta) en WE0-5 | si un switch inválido devolviera `rc=0`, el par se sustituye por `certutil -hashfile … MD6` (fallo seguro) y se declara |
| R3 | **`eventcreate` como `angel`** (WE0-7): puede exigir elevación | se degrada a **lectura** (`wevtutil qe Application /c:5 /rd:true /f:text`) y se declara: afecta a 1 acción/día (`registro`) y al caso **W-10** |
| R4 | **`C:\Users\angel` bajo FIM** (R-W8) | si está vigilado, el numerador se dispara: la actividad se mueve a `C:\lab-legit` en W3 y se declara (sin tocar el FIM) |
| R5 | **`more` con salida redirigida** | si falla, `head`/`tail` se sustituyen por `findstr /n` y se declara la pérdida del recorte exacto |

## Cómo se comprueba

```bash
python _artefactos/scripts/construir_receta_legitima_windows.py          # genera
python _artefactos/scripts/construir_receta_legitima_windows.py --check   # valida
python _artefactos/scripts/verificar_espejo.py                            # espejo
```

## Desviaciones declaradas respecto del plan

| # | Plan | Artefacto | Por qué |
|---|---|---|---|
| DW-1 | `Soporte/Laboratorio/windows_legit/recetas_windows/` (§16.1) | `Soporte/Laboratorio/windows/recetas/` | destino pedido en la tanda W1; el generador acepta `--out` para escribir en la ruta del plan sin tocar código |
| DW-2 | `construir_receta_windows.py` (§16.1) | `construir_receta_legitima_windows.py` | nombre pedido en W1 y coherente con el generador Linux |
| DW-3 | ficheros `d1/d2/d3.json` | `w1/w2/w3.json` | para no confundir la receta Windows con la Linux; el mapeo es 1:1 (w1↔d1) |
| DW-4 | `t0` sin fijar | `mapa_dias` vacío | se fija al armar la ventana (`--t0`), igual que en Linux |


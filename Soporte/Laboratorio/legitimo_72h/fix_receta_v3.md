# `fix_receta_v3.md` — correcciones de ejecución de la receta (tanda W1)

> **Fecha:** 2026-10-29 · **Autor:** `tfg-executor` · **Origen:** defectos de **ejecución**
> encontrados por el tester en la tanda W1 de la receta Windows (espejo de la de Linux).
> **Alcance:** **sin VMs**. Todo se ha reproducido y verificado en un **sandbox de Windows**
> (`%TEMP%`, rutas remapeadas) y con los generadores en local.
> **Estado:** corregido y verificado. **Pendiente:** repetir **P1** antes del lunes (§6).

---

## 1. Qué ha cambiado y por qué

Los cinco defectos tienen la misma raíz: **el test era de texto**, así que daba por bueno un
comando que en `cmd.exe` real no hacía lo que decía. Se han corregido en el **generador**
(no a mano en los `.json`) y se han añadido tests que **ejecutan**.

| # | Síntoma medido en W1 | Causa real | Arreglo | Dónde |
|---|---|---|---|---|
| **W-1** | 48 procesos fallidos y **0 ficheros** en el lote de 12 (`W1B3#43`, `W2B3#13`, `W3B3#59`, `W3B6#8`/W-09); en cascada faltaban la evidencia y el `fin.txt` de W-09 | `xcopy /y origen destino\lote_%i.txt` con un **fichero suelto** y un destino que **no existe** pregunta «¿archivo o directorio?» por consola y termina con **rc=2** sin copiar | `for /f %i in (lotes.txt) do @cmd /c copy /y …` y `for /L %i in (1,1,12) do @cmd /c copy /y …`: `copy` **sí** renombra y el `cmd /c` hijo **mantiene los 12 procesos** (espejo de los 12 `cp` de Linux) | `W.py:480` (`_r_xargs`), `W.py:628` (`_c_xargs_camp`) |
| **W-2** | Solo **9** líneas `error`/día (la familia `rm_inexistente` no se registraba nunca) | En Windows `del` de un fichero **ausente** devuelve **rc=0** (en Linux `rm` devuelve 1). El fallo no fallaba ⇒ `if errorlevel 1` no escribía nada | El fallo de la familia se materializa con **`type` del mismo temporal** (abrirlo cuando ya no está **sí** falla, rc=1); el reintento sigue siendo `del /f /q` (rc=0) | `W.py:372` (`_r_rm`) |
| **W-3** | El registro del reintento no se escribía y el `fin.txt` de **W-09** (y el de cualquier caso cuya limpieza no encontrara algo) se perdía | `if exist A del A & if errorlevel 1 (…)` **no es** dos comandos: `cmd` le da al `if` **todo el resto de la línea** como cuerpo. Si el `if` es falso, se traga la marca y el registro | (a) `rm -f` → **`del /f /q` sin `if exist`** (ya devuelve rc=0 si no está); (b) `rm -rf` → **una orden `rd` por ruta** (`rd` solo acepta una); (c) las marcas `inicio.txt`/`fin.txt` se separan con **`&`** (comando independiente), nunca con `&&`; (d) el `mkdir` va con **cada `if` entre paréntesis** | `W.py:356` (`_r_rmrf`), `W.py:363` (`_r_rmf`), `W.py:650` (`RE_MARCA_CASO`) + `W.py:653` (`traducir_rest`), `W.py:711` (`traducir`) |
| **W-4** | **rc=1** en la acción de estructura de los **días 2 y 3** | `md <carpeta>` de una carpeta que ya existe devuelve **rc=1** | `(if not exist <dir> md <dir>) & …` (idempotente y sin tragarse la marca siguiente) | `W.py:261` (`_r_mkdir`) |
| **L-1** | **Linux**: `B5#1` no creaba el `.sha256` y `B5#2` (`cat …sha256`) **fallaba todos los días**. No estaba planificado | `sha256sum <copia.tar.gz>` **sin redirección**: imprime por pantalla y no escribe fichero | `sha256sum <copia.tar.gz> > <copia.tar.gz>.sha256` y, en Windows, `certutil -hashfile … SHA256 > ….sha256 2>&1` para que el `type` posterior lea algo | `L.py:584` (`b5`), `W.py:299` (`_r_sha256_out`) |
| **T-1** | Los **259** tests eran **estáticos** y no vieron nada de lo anterior | — | Test nuevo que **ejecuta** los comandos en sandbox y falla si no salen **12 ficheros**, **10+10 líneas** de 5 campos o falta un **`fin.txt`** | `tests/test_ejecucion_windows.py` (10 tests) |

### Auditoría L-1 (todas las lecturas de huellas)

Se revisaron **todas** las acciones que escriben una salida y luego la leen: `sha256sum`,
`md5sum`, `tar`, `gzip`, `>`, `>>`, `-o`, `tee`. **La única** lectura huérfana era
`B5#2` (`cat …tar.gz.sha256`). El resto de `cat` leen ficheros que sí se crean antes con
`echo >` o `curl -o`. Para que no vuelva a pasar sin que nadie lo vea, el validador de
Linux incorpora ahora **`auditar_huellas_escritas()`**: recorre cada día en orden y falla si
un `cat` de un `*.sha256|*.md5|*.sha1` no tiene una escritura con `>` anterior
(`L.py:1213`, invocado en `L.py:1403`).

---

## 2. Evidencia del sandbox (`%TEMP%`, sin VM)

Comandos **reales** de los `w*.json` generados, con las rutas remapeadas a un sandbox:

```text
== W-1 fan-out (B3, w1)
   ficheros lote_*.txt = 12
   ['lote_1.txt','lote_2.txt','lote_3.txt','lote_4.txt','lote_5.txt','lote_6.txt',
    'lote_7.txt','lote_8.txt','lote_9.txt','lote_10.txt','lote_11.txt','lote_12.txt']

== W-2/W-3 errores por día
   d1: 20 líneas = 10 error + 10 reintento; campos=[5]; familias=[cat_dir, cp_dir, gzip,
                                                               opcion, rm_inexistente, ruta_mal]
   d2: 20 líneas = 10 error + 10 reintento; campos=[5]  (ídem)
   d3: 20 líneas = 10 error + 10 reintento; campos=[5]  (ídem)

== W-3 fin.txt de los 11 casos (tras `inicio` + `fin`)
   W-01 … W-11: fin.txt=SÍ (sellado con %DATE%_%TIME%)

== W-09 completo (los 6 comandos del caso, en orden)
   [0..5] rc=0 ; al final la carpeta queda con: fin.txt, hecho.txt, inicio.txt
   hecho.txt: "RESULTADO=OK", tamaño de lote_12.txt = 32, y `dir` con **los 12 lotes**
   fin.txt: 29/10/2026_18:05:16,74
```

> El **reintento** también sale `rc=0` (el fallo, `rc=ge1`): la familia `rm_inexistente`
> ya escribe sus dos líneas. Antes: 9 + 9.

---

## 3. Verificación

| Comprobación | Resultado |
|---|---|
| `verificar_espejo.py` | **PASA** — 504 acciones Linux = 504 Windows (18 bloques, mismas ventanas, mismos `DelayAfter`) |
| Doble generación **Linux** (`d1-d3`) | **byte-idéntica** (6 ficheros, `sha256` iguales) |
| Doble generación **Windows** (`w1-w3`) | **byte-idéntica** (6 ficheros, `sha256` iguales) |
| `construir_receta_legitima.py --check` | **PASS** (`RESULT=PASS`, 147/153/141 + 16/25/22) |
| `construir_receta_legitima_windows.py --check` | **PASA** (147/153/141 + 16/25/22) |
| `pytest _artefactos/scripts/tests` | **269 passed** (259 + **10** nuevos de ejecución) |

Los conteos por bloque, las horas y **todos** los `DelayAfter` son los mismos: el diff de
comandos es de **1 acción/día** en Linux (`B5#1`) y de **12/18/16** acciones (w1/w2/w3) en
Windows (estructura, `rm`, fan-out, huella y marcas de la campaña) de 163/178/163.

---

## 4. Huellas nuevas de las recetas

| Fichero | `sha256` |
|---|---|
| `recetas/d1.json` | `0b2fa91cdbc7f16cfc3e59e3ace7b67269d78de4279b641f4fbfae221b50c7df` |
| `recetas/d2.json` | `0e0329cc979797f5fa63420a79a9d5d5af26ae6d4d6cec7dd961ed31adddc58a` |
| `recetas/d3.json` | `885a80b2f698ed2e6cc4a249a5f36bdd6756a246352b01dc52953638db611345` |
| `windows/recetas/w1.json` | `05dbf6b001c43ec60eadd44fad86a42aa7807941633ef9fd01cdc76bbc09497e` |
| `windows/recetas/w2.json` | `bc65250f0206d0996c537b257ba65e5f59ef1e1f73efc6a0c07dd3115b5fac22` |
| `windows/recetas/w3.json` | `8ed8fa16ccb942776be0c677db5e912140229222663093010baa85211af2335e` |

`sha256sums.txt` está regenerado (incluye ya la receta Windows y los scripts nuevos).

---

## 5. Lo que **no** cambia

- **Ni un `DelayAfter`**, ni las horas (`08:00–17:00Z` + `B6 17:05–17:50Z`), ni los conteos
  por bloque (**147/153/141** + **16/25/22** = 504). El espejo sigue **PASA**.
- `boveda_version` = 3, `receta_version` (Linux) = 2, `receta_version_windows` = 1: **no** se
  han tocado (cambiar la versión es decisión del humano; ver §7).
- No se ha tocado `_recursos/`, corpus, `Hojas/`, `Dataset/`, `Soporte/Metrica/`, ruleset ni
  snapshots.

---

## 6. ⚠️ Hay que repetir **P1** antes del lunes

**El hash de la receta Linux cambia** (`d1/d2/d3.json`), porque `B5#1` pasa de
`sha256sum X` a `sha256sum X > X.sha256`. Consecuencias:

1. La evidencia de **P1** (`ensayo_E0_v5/`, `prueba_en_seco_*`) es de la receta **anterior**:
   **hay que repetir P1** (armado + primer ciclo) con las recetas nuevas antes de abrir la
   ventana del **lunes**.
2. La huella nueva del `.json` es la de §4: si P1 selló un `sha256` distinto, es que está
   corriendo la receta vieja.
3. No hace falta repetir nada del lado Windows en VM (los defectos se han reproducido y
   cerrado en sandbox); sí conviene un `--check` en el host antes de armar.

---

## 7. Lo que no me cuadra / decisiones declaradas

1. **`rm_inexistente` en Windows se ejecuta como `type`.** `del` de un fichero ausente
   devuelve rc=0 y **no hay forma** de que falle; `rd` de una ruta inexistente **también**
   devuelve rc=0 en este Windows (comprobado). Se usa `type` del **mismo** temporal: es el
   único fallo determinista que conserva la familia (abrir lo que ya no está). Queda escrito
   en el comando que va al `errores.log`, así que es auditable.
2. **El hijo del fan-out cambia de nombre**: antes `xcopy.exe`, ahora `cmd.exe` (12 en ambos
   casos). El **número** de procesos no cambia, pero si alguna métrica cuenta por **nombre**
   de ejecutable, verá `cmd.exe`. No hay ningún script que filtre por `xcopy` (comprobado).
3. **`cmd /c` dentro de un bucle** es la única excepción a «un `Command` no lleva `cmd /c`».
   `verificar_espejo.py` y `validar_comando()` ahora solo rechazan el `cmd /c` de **primer
   nivel** (doble envoltorio) y cuentan `cmd` como proceso externo para que el fan-out siga
   midiendo **12** hijos.
4. **`VERSION_RECETA` sigue en 2** aunque la receta cambie. Cambiar la versión toca
   `calendario.json`, `bloques.env` y la documentación del plan (decisión de diseño, no mía).
   Si el humano quiere trazabilidad por versión, es un bump de una línea en `L.py:62`.
5. **No se han ejecutado VMs** (así se pidió). Lo que solo se puede cerrar en VM: `WE0-5`
   (rc de switch inválido) — ya verificado en sandbox — y `eventcreate`/elevación (WE0-7),
   que no toca este cambio.

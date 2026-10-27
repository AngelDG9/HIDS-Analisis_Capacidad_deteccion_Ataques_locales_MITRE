---
bloque: legitimo-v3
nombre: L1-v5 — estudio en frío del realismo, ventana de 72 h mejorada (receta v2) + campaña dirigida de falsos positivos (11 casos no mutantes)
version: 5
status: approved_by_human
fecha: 2026-10-27
fecha_aprobacion: 2026-10-27
aprobado_por: humano
autor: tfg-planner
depende_de: legitimo-72h-v2 (ABORTADO 2026-10-27, 39 h 53 min, sin analizar) · legitimo-fix (cerrado, PASA) · legitimo-infra (L0, GO) · reencuadre-metrica (métrica v1 congelada)
sustituye_a: la ventana de `legitimo-72h-v2` (no se reutiliza ni se analiza) · `plan.md` v1, v2, **v3 y v4** de este bloque
ventana: **sin fecha fija** — se fija **al cerrar T4** (ver §3.2): primera ventana **lunes 00:00Z → jueves 00:00Z** disponible
auditoria: |
  **v5 = decisión final del humano: la campaña es un trozo de la ventana.** Se **elimina la vista
  alternativa** y el **corte por rango**: **un solo `M`** (ventana completa) + **tabla propia de la
  campaña** con sus recuentos por caso. No se implementan cortes por rango; los scripts quedan como
  están **salvo MC-1**. Los hallazgos de la auditoría v4 y su estado final están en §0.2; el veredicto,
  en **§18**.
gate: |
  **APROBADO (2026-10-27) — luz verde del humano.** Decisiones cerradas y **no se vuelven a preguntar**:
  y **no se vuelven a preguntar**: campaña **dentro** con **11 casos no mutantes**, **un solo `M`**
  (ventana completa) + **tabla de campaña aparte**, compromiso de **3 días**, sin 2.º usuario, sin
  actividad **de usuario** nocturna, sin instalar, sin snapshot extra salvo imprescindible. Lo que se
  pide ratificar es solo lo que **no** estaba cerrado: (1) las **5 mejoras** (§1.4) y **H1**; (2) la
  **cláusula anti-aborto** (§3.4); (3) **E0 obligatorio** y su antigüedad ≤ 7 días (§6); (4) el
  **bump `boveda_version` → 2** + MC-1 (§10); (5) promoción a `Dataset/` **solo si VÁLIDA**; (6) el
  plan **en git** al aprobarse. **No hay pregunta sobre una vista alternativa**: esa vista se elimina.
---

# plan.md — Bloque `legitimo-v3` (v5)

## 0.1 Qué cambia respecto de la v1 (lista corta)

| # | Cambio | Motivo |
|---|---|---|
| **1** | **Sin fecha fija.** Se elimina `ventana_propuesta` y la alternativa "09/11". La fecha se fija **al cerrar T4**, con una regla escrita (§3.2) y justificación de **lunes→miércoles** | Decisión del humano: *"la fecha ya veremos… cuando tengamos lo otro lo hacemos y punto"* |
| **2** | **Fuera la pregunta del compromiso de 3 días** (sustituida por una nota) | Ya dado el 2026-10-27 |
| **3** | **Se elimina M5 (segundo usuario)** | 20 acciones ≈ **0,0008 % de `M`**; **redundante con un caso de `sudo`**; dependencia de `sudo` que, según el corpus, **probablemente no existe** |
| **4** | **Se elimina M6 (actividad nocturna *de usuario*)** | Una máquina de oficina **sin usuario por la noche es lo realista**; 12 acciones ≈ 0,0005 % de `M` y añade riesgo sobre V2. *Matiz v4:* el **keepalive** sí ejecuta `date`/`curl` de noche (≈290 `execve`/día): es **instrumentación declarada**, no actividad de usuario (§17.15) |
| **5** | **Entra una mejora nueva y prioritaria: `cwd` realista** (hallazgo en `Bash.cs` + `client_ctl.sh` + la unit) | Hoy **el 100 %** de las acciones corre con `cwd=/home/angel/ghosts-client` (§1.9.2) |
| **6** | **La selección de herramientas deja de ser intuitiva**: se deriva del **corpus** (`rule_description` de las 4 107 detecciones `audit_command`) y tiene criterio de aceptación numérico | Evidencia: la receta v1 cubre **11 de 50** binarios que el corpus usa para detectar (v2 decía 49; ver §1.9.3) |
| **7** | **Campaña**: justificado "dentro" + coste de "aparte"; **la campaña, sin `sudo`**; + columna de **severidad equivalente P1-P4** (como el TFM hermano). **v4: 11 casos no mutantes** (fuera C-04) | C-2 y comparabilidad |
| **8** | **Corrección C-1**: horas **en UTC** con la etiqueta correcta (y local explícito cuando aplica) | Error de v1 (horas UTC rotuladas "local") |
| **9** | **Corrección C-2**: **no se asume `sudo`** en ningún sitio; verificación en E0 y variantes sin `sudo` | `ATA024` usó `sudo -S` **con contraseña por stdin** ⇒ `sudo -n` probablemente falla |
| **10** | **Corrección C-3**: **V2 congelada antes de `t0`** con la tabla de bloques (`sha256` de `bloques.env`) | Trazabilidad de la validez |
| **11** | **H1 ampliada**: gracia de borde + **primer chequeo** + **`cleanup` sin SSH a VM apagada** + rotación post-hoc declarada | Lecciones de v2 que v1 solo cubría a medias |
| **12** | Nueva **§1.9 prueba adversarial**: qué rechazo de la lista, **2 mejoras nuevas** y **3 hallazgos** (uno de ellos quita trabajo) + **§1.10 trabajo futuro** | Encargo del humano |
| **13** | **Campaña rehecha de cero contra el corpus y contra el validador** (§5.2): **3 casos fuera**, **1 sin `\|`**, **2 nuevos**; esperado **por umbral**; ventana de atribución corregida; **conjunto** receta v2 + campaña **25/50 binarios** y **23/55 ATA** (la campaña aporta **2 binarios y 4 ATA marginales**) | Encargo del humano (2026-10-27): *"que no se fíe de nada de mis palabras"*. La lista v2 se había construido **por analogía**, no con evidencia |
| **14** | **v4: auditoría final + cierre de las horas.** La campaña baja a **11 casos no mutantes** (se retira **C-04**, la única que escribía en `crontab`); se separa la **validez de la ventana** (V1–V8) de la **validez de la campaña**; se corrigen los umbrales de `doing_age` para huecos de 22 min; y se elige la hora de la campaña (§3.1.1) | Decisión humana + auditoría de coherencia (§0.2). Sin estos arreglos, V9 y §9.3 podían **invalidar la ventana por un fallo de la campaña**, contra la regla acordada |
| **15** | **v5: una sola cifra.** Un solo `M` (ventana completa) + **tabla propia de la campaña** con sus recuentos. **No** se fabrica una segunda cifra; **no** se implementan cortes por rango; los scripts quedan **como están, salvo MC-1** | Decisión humana 2026-10-27: *"la campaña es un trozo de la ventana"*. Publicar dos denominadores era artificial y añadía código no necesario |

## 0.2 Auditoría de coherencia de la v3 (hallazgos y correcciones)

> **Regla de lectura:** nada de lo que sigue reabre una decisión humana. Son **incoherencias internas**
> de la v3 que se corrigen para que el documento diga lo mismo en todas sus secciones.

| # | Gravedad | Incoherencia en v3 | Corrección en v4 (dónde) |
|---|---|---|---|
| **A-1** | **ALTA** | **12 casos con C-04** (escritura en `crontab`) frente a la decisión vigente: **11 casos no mutantes**. La v3 repetía "12" en 30+ sitios (título, §1.4, §2.1, §5.2, §6, §9, §12, §14, §15, §17) | **11 casos**, C-04 **retirada** y todas las cifras recalculadas (§2.1, §5.2, §6, §9, §12, §14, §15, §17) |
| **A-2** | **ALTA** | **V9 + §9.3.9 violaban la no-invalidación**: "≥3 casos de campaña sin ejecutar" invalidaba la **ventana**. Un fallo de la campaña podía tirar 72 h de captura | **V1–V8 son la ventana**; **V9 sale a §9.4** ("validez de la campaña"). Un fallo de campaña **solo la descarta a ella** (§9.4, §18) |
| **A-3** | **ALTA** | **`doing_age` incompatible con huecos de 22 min**: el `watch` marca **AVISO a >15 min** (`legitimo_host_control.ps1:466-467`) y la v3 mantenía "umbrales sin cambios" (§7.3). Con huecos de 22 min habría **AVISO por diseño** | **AVISO > 25 min · ALARMA > 35 min**; `STALE=30` del keepalive **no se toca** (22 + caché 5 = 27 < 30) (§5.1, §7.3, §12 CA-02/CA-11) |
| **A-4** | ALTA (resuelta por decisión) | **El corte por rango exigía modificar `contar_denominador.py`/`exportar_acciones.sh`** y publicar un segundo denominador. La v4 lo había diseñado; **el humano lo elimina en v5** | **No se implementa**: un solo `M` (ventana completa) + **tabla de campaña** con sus propios recuentos (§8, §9.5). Los scripts quedan **como están, salvo MC-1** |
| **A-5** | ALTA (resuelta por decisión) | **Titular ambiguo**: la v3 no decía si la campaña entraba en el FPR. La v4 inventó una vista alternativa | **Titular = ventana completa** (la métrica congela `M` sobre `[t0,t1]`); la campaña se **reporta aparte** con sus marcas. **No hay vista alternativa ni titular alternativo** (§9.5, §18) |
| **A-6** | **ALTA** | **V2 vs B6**: si B6 no está en `bloques.env` o las marcas caen fuera, V2 ("0 acciones fuera de bloques") falla por diseño | **B6 es bloque declarado 17:05–17:50Z** en `bloques.env`; el generador lo escribe y `--check` lo valida (§3.1.1, §5.1, §5.2.6, §9.1 V2) |
| **A-7** | MEDIA | **§1.7 confundía `M` con acciones**: "+3-4 % de `M`" con 150 acciones/día. 450 acciones × ~2-11 eventos ≈ **0,1 %** de `M`, no 3-4 % | "+3-4 % de **acciones**; efecto en `M` ≈ **+0,1 %** (estimado; el real se sella)" (§1.7) |
| **A-8** | MEDIA | **"64 acciones (40 + 24)" mezclaba acciones y `execve`**: la tabla v3 lista **29 comandos** (41 `execve` por los hijos) + 24 marcas = **53 acciones / 65 `execve`**; el 40 no tenía fuente y el 64 se acercaba a los `execve`, no a las acciones | v4: **47-55 acciones GHOSTS / 59-65 `execve`** (25 comandos + preparación + 22 marcas, más hijos); el número exacto lo fija `campana_casos.csv` y se sella en B10 (§1.4, §5.2.6) |
| **A-9** | MEDIA | **`errores.log` no estaba en B10 ni en T1/T3**: la mejora 3 no tenía producto sellable | `errores.log` (o `reintentos.csv`) con `sha256`, conteo de `exit≠0` y muestra; entra en **T1, T3, B10 y CA-03** (§5.1, §5.3, §10, §12) |
| **A-10** | MEDIA | **`b10_sellado.md` ya está en v2** (`:1,12-13,62`) mientras `boveda_congelacion.md` sigue en **v1** (`:4`) y `metrica_hids.py:36` en 1. El plan decía "→2" sin reconciliar | El sidecar pasa a **v3** (contenido de esta ventana); el bump a **2** se aplica en **3 sitios** al cerrar; hasta entonces la fuente de verdad es v1 (§10) |
| **A-11** | MEDIA | **R6 decía "35 `command -v`"** y E0-2 dice **36** | **36/36** (§11 R6) |
| **A-12** | MEDIA | **"Sin actividad nocturna" era falso en sentido estricto**: el keepalive ejecuta `date`/`curl` cada ~5 min también de noche | Se declara: "sin actividad **de usuario** nocturna; el keepalive es instrumentación" (§0.1, §17.15) |
| **A-13** | MEDIA | **`stop` a t1+5 vs cosecha a t1+2**: 3 min sin señal de "cosecha terminada"; riesgo de matar la VM a mitad de `scp` | `stop` espera **marcador `cosecha.done`** (o `t1+15` como tope) (§7.1, §8) |
| **A-14** | MEDIA | **`exportar_acciones.sh` escribe por defecto en `Dataset/`** (`:17`), contra "Dataset solo si VÁLIDA" | Se invoca con la ruta de `ventana_<t0>/` (**sin cambiar el script**); promoción **solo si VÁLIDA** (§8, §15) |
| **A-15** | BAJA | **E0 no comprobaba la no-mutación** de la campaña (crontab, estado fuera de `$HOME`) | **E0-9**: `crontab -l` y `find` de estado **sin cambios** tras la campaña comprimida (§6) |
| **A-16** | BAJA | **"12 casos" / "4/día" / "35 min"** en título, resumen y opciones | **11 casos · 3/4/4** · ventana B6 45 min (holgada) (§0, §1.3, §1.4) |
| **A-17** | BAJA | **`2832` L5 "sí se mide (C-04)"** en §1.9.4 y §17.4 | Al retirar C-04, **no se mide**: se declara como **límite** de T5 (§1.9.4, §1.9.5, §5.2.7, §17.4) |
| **A-18** | BAJA | **TFM hermano: "lo cubre C-04"** (FP-003) | Al retirar C-04, **FP-003 queda sin cubrir**; se declara, no se maquilla (§1.9.6, §5.2.7) |
| **A-19** | BAJA | **`CAP_HUECO_S=720` (12 min)** y un `>20 min` en el validador (`construir_receta_legitima.py:96,649-652`) contradicen el "≤22 min" | `CAP_HUECO_S=1320`; una sola regla `>22 min` falla; tabla de jitter **literal** y CA-02 (§5.1) |
| **A-20** | BAJA | **`--check` no validaba la campaña** ni existía generador de B6 desde `campana_casos.csv` | `construir_receta_legitima.py` genera B6 desde el CSV y **valida** las 11 fichas con el mismo `binarios_de`/`BINARIOS_OK`; CA-27 (§5.1, §5.2.6, §12) |
| **A-21** | **ALTA** | **Doble conteo de `systemctl`/`crontab`**: la v3 los metía **en la receta** y **en la campaña**, pero la tabla de cobertura los contaba como "nuevos" de la campaña. La cobertura real habría sido **23/50**, no **25/50** | **`systemctl`/`crontab` solo en la campaña** (C-01/C-03, lectura); la receta añade **12**, la campaña **14**; la cobertura **25/50** se sostiene (§1.9.3, §5.2, §5.2.5, CA-04) |
| **A-22** | **ALTA** | **La campaña no aporta 14 binarios nuevos, aporta 2**: 12 de los 14 ya los añade la receta v2. La v3 presentaba "14 nuevos" para la campaña sin distinguir v1/v2 | Tabla de cobertura separada: **receta v2 23/50**, **campaña marginal 2** (`systemctl`, `crontab`), **conjunto 25/50**; ATA: **4** marginales, **23** en el conjunto (§5.2.1, §5.2.5) |

> **Lo que la auditoría NO cambia:** el objetivo, la métrica v1, el ruleset, el corpus, las 5 mejoras,
> la prohibición de instalar/ampliar disco, la campaña **dentro** y el compromiso de 3 días. Y no se
> toca nada de `_recursos/`, corpus, `Hojas/`, `Dataset/`, `Soporte/Metrica/`, recetas ni laboratorio.

---

## Índice

**Parte I — ESTUDIO EN FRÍO**
0. [Resumen ejecutivo](#0-resumen-ejecutivo) · 0.1 [Cambios vs v1](#01-qué-cambia-respecto-de-la-v1-lista-corta) · **0.2 [Auditoría de coherencia](#02-auditoría-de-coherencia-de-la-v3-hallazgos-y-correcciones)**
1. [El estudio](#1-el-estudio) — 1.1 [qué falta](#11-qué-falta-exactamente-y-cuánto-pesa) · 1.2 [dónde está el realismo](#12-dónde-está-el-realismo-que-importa-y-dónde-no) · 1.3 [opciones A–E](#13-opciones-ae) · 1.4 [tabla de mejoras](#14-tabla-de-mejoras-costebeneficio) · 1.5 [lo que no compensa](#15-lo-que-no-compensa-y-por-qué) · 1.6 [prerrequisitos](#16-prerrequisitos) · 1.7 [efecto en validez/bóveda](#17-efecto-sobre-validez-comparabilidad-y-bóveda) · 1.8 [recomendación](#18-recomendación-y-qué-se-sacrifica) · **1.9 [prueba adversarial](#19-prueba-adversarial-qué-rechazo-y-qué-he-encontrado-por-mi-cuenta)** · 1.10 [trabajo futuro](#110-trabajo-futuro-lo-que-es-bueno-pero-no-cabe)

**Parte II — PLAN DE EJECUCIÓN**
2. [Objetivo y alcance](#2-objetivo-alcance-y-qué-no-entra) · 3. [Ventana y anti-aborto](#3-la-ventana-regla-de-fijación-y-anti-aborto) · **3.1.1 [Horas de la campaña](#311-las-horas-de-la-campaña-opciones-y-decisión)** · 4. [Estado de partida](#4-estado-de-partida-verificado-2026-10-27) · 5. [Trabajo previo T1–T4](#5-trabajo-previo-t1t4-qué-se-construye-y-cómo-se-prueba) · 6. [E0](#6-e0--ensayo-de-armado-obligatorio) · 7. [Ejecución](#7-ejecución-arranque-vigilancia-y-disciplina) · 8. [Extracción](#8-extracción-después-de-t1) · 9. [Validez (V1–V8 + campaña)](#9-validez-v1v8-y-qué-invalida-la-ventana-y-qué-no) · 10. [B10 v5](#10-sellado-b10-v5-y-versiones) · 11. [Riesgos](#11-riesgos-y-mitigaciones) · 12. [CA](#12-criterios-de-aceptación-verificables) · 13. [Cómo se verifica](#13-cómo-se-verifica-tester) · 14. [Gate](#14-gate-humano-lenguaje-sencillo) · 15. [Ficheros](#15-ficheros-que-se-tocarán) · 16. [Trazabilidad](#16-trazabilidad) · 17. [Lo que no cuadra](#17-lo-que-no-cuadra-y-decisiones-abiertas) · **18. [Veredicto](#18-veredicto-es-metodológicamente-sólido-hacer-la-campaña-dentro)**

---

# Parte I — ESTUDIO EN FRÍO

## 0. Resumen ejecutivo

**El dato que manda.** No existe **ningún** dato legítimo válido (`L1` falló por disco; `v2` se abortó a
las 39 h 53 min **sin analizar**). `T3/T4/T5` están vacías y detrás de ellas están bloqueados `M1b`,
`L2`, `A1` y la memoria. **La ventana es el camino crítico del resultado titular.**

**Lo que el estudio encuentra (resumen):**

1. **Realismo ≠ volumen.** `M` lo domina el **fondo** (ensayo de `L0`: **2 474 eventos en 4,5 min** con
   214 acciones ⇒ a 72 h `M ≈ 2,4 M` y **las 333 acciones de la receta v1 son ~0,014 %**). Añadir acciones **no mueve el
   FPR**; añadir **tipos** de acción sí cambia **qué reglas** disparan.
2. **`80792` es el 98,4 % de todas las detecciones** del corpus (4 107 de 4 173 filas
   `categoria=deteccion`), y es **nivel 3**: dispara con cualquier `execve` auditado. A `N ≤ 3` **cada
   acción legítima es un FP**; el FPR "gordo" estará dominado por esa regla. **No** será comparable al
   "10/10 benignos, 0 hits" del TFM hermano (él medía **sus artifacts**). Se declara.
3. **El realismo que falta es de *variedad*, y hay una lista objetiva**: el corpus contiene **50
   binarios distintos** (basenames; 51 rutas) en sus detecciones por `audit_command`; la receta v1
   ejercita **11 (22 %)** y la campaña sube la cobertura a **25 (50 %)**.
   `xargs` solo (ATA046/ATA047) son **2 497 (60 %)** de esas detecciones y la receta **no lo usa nunca**.
4. **Artefacto nuevo y grave**: por `Bash.cs` + `client_ctl.sh`, **todas** las acciones legítimas
   corren con **`cwd=/home/angel/ghosts-client`**. Ningún humano trabaja desde el directorio de un
   binario. Arreglarlo cuesta **~1-2 h** y es la mejor relación valor/coste del bloque.
5. **Lo caro es caro por instalar**: navegador (DT-B0 falló: 12 librerías + 3,4 GB < 4 GB), LibreOffice,
   GUI exigen **ampliar volumen + `.deb` offline** y comerse el margen de `G-2`. **No compensan.**
6. **La campaña** (11 casos benignos pre-registrados, **no mutantes**, **sin `sudo`**, dentro de la
   ventana y **reportada aparte** con su tabla) es lo más barato y lo que da una tabla que el profesor
   reconoce de un vistazo. *La 12.ª (C-04, escritura en `crontab`) se retira por decisión humana: pierde
   `2832` L5 y se declara.*

**Recomendación: opción D acotada con 5 mejoras** — `cwd` realista, ritmo irregular determinista,
errores con reintento, herramientas **elegidas por el corpus**, y campaña; **sin instalar nada**, **sin
ampliar disco**, **sin fecha fija** (se fija al cerrar T4), con **E0 obligatorio** y **cláusula
anti-aborto**. Coste: **~19-22 h** de trabajo + **3 días de reloj desatendido**.

---

## 1. El estudio

### 1.1 Qué falta exactamente y cuánto pesa

| Pieza de la métrica (v1 congelada) | Estado | Qué la desbloquea |
|---|---|---|
| `N = 55` casos y `TPR` | **Hecho** (53/55; ATA013 y ATA034 = FN) | — |
| `M` y `FP_uni` (FPR por evento) | **No existe** | **La ventana** |
| Catálogo de ruido autoritativo | **No existe** (el sintético de 2×4 h es *histórico*) | **La ventana** |
| `T3`/`T4` legítimo · `T5` (reglas de doble uso) | Vacías | `L2` ← necesita la ventana |
| `Precisión`, `F1`, `GM`, `Usabilidad` | Bloqueadas (necesitan `A_FP`) | **La ventana** |
| Comparación Wazuh ↔ VR | Bloqueada | `V0/V1` (independiente) |

Sin ventana **no hay FPR, ni precisión, ni GM, ni usabilidad, ni T5**. Coste de "una ventana más":
**~0,5 día de preparación + 3 días de reloj desatendido + 1 día de extracción/sellado**.

### 1.2 Dónde está el realismo que importa (y dónde no)

**(a) El denominador no se mueve con más acciones.** Ensayo de `L0`: **2 474 eventos / 4,5 min** con
**214 acciones**; a 72 h `M ≈ 2,4 M`. Las 333 acciones de la receta v1 son **~0,014 %** de `M` (una acción,
**~0,00004 %**).

**(b) El numerador sí depende del *tipo* de acción.** Cuantificado sobre el corpus (130 017 filas
auditadas, 4 173 `deteccion`):

| `rule_id` · nivel | Filas `deteccion` | % |
|---|---|---|
| **80792** · 3 (*Audit: Command*) | **4 107** | **98,4 %** |
| 550 · **7** (FIM) | 26 | 0,6 % (solo **ATA024**) |
| 19011 · 9 (SCA) | 16 | 0,4 % |
| 503/506/80791/80781/80790/5901/5902/5903/5555/19010 | 24 | 0,6 % |

⇒ **H-A (hipótesis pre-registrada, falsable):** a `N ≤ 3` el FPR por evento ≈ (nº de `execve`
auditados)/`M`, y **cada acción legítima es un FP**; a `N ≥ 7` el legítimo casi no tendrá alertas
porque el usuario **no es root** (no toca `/etc`). Si H-A se cumple, **no es un defecto de la
captura**: es el hallazgo de que `80792` es, en la práctica, un *logger* con nivel 3.

**(c) Lo artificial que se ve a simple vista en la receta v1:**

| Síntoma | Evidencia | Gravedad |
|---|---|---|
| **`cwd` de bot** | las 3 piezas: `tfg-ghosts-legit.service` → `WorkingDirectory=/home/angel/ghosts-client`; `client_ctl.sh:54` → `cd "$DIR"`; `Bash.cs:106-118` → **no** fija `WorkingDirectory` | **Alta (nueva)** |
| **Metrónomo** | ráfagas de 2-6 acciones separadas **exactamente** 45-50 s; huecos uniformes; patrón "cada 11 min" en B3 | Alta |
| **Cero errores** | 333/333 comandos correctos; ni una ruta mal escrita ni un `exit≠0` | Alta |
| **Vocabulario pobre** | 11/50 binarios del corpus (**22 %**); nunca `xargs` (60 % de las detecciones), `sed`, `openssl`, `systemctl`, `crontab`, `rsync` | **Alta (medida)** |
| **Sin capa de sesión** | todo cuelga del servicio; **sin PAM ni login** | Media (estructural, §1.9.5) |
| **Volumen bajo** | 111 acciones/día ≈ 14/h | Baja (no mueve `M`) |

**(d) Implicación de diseño.** Pagan las mejoras que añaden **variedad verificable** (corpus en mano) y
las que **eliminan artefactos** (`cwd`). No pagan las que solo añaden volumen. Y hay una limitación
**estructural** que no se arregla barato: **no hay sesión interactiva real** (un `login` desde el host
contaminaría V4).

### 1.3 Opciones A–E

| Opción | Qué es | Coste (trabajo + reloj) | Qué **sí** responde | Qué **NO** responde | Riesgo | Veredicto |
|---|---|---|---|---|---|---|
| **A. Solo campaña** | 11 casos en una captura corta (2-3 h) fuera de ventana | ~1 día + 0 | «¿estas 11 acciones benignas disparan algo?» | `M` representativo, FPR, catálogo de ruido, T3/T4/T5; `M1b` sigue bloqueado | Bajo | **Insuficiente sola** |
| **B. Solo ventana** (receta v1) | 3 días con la receta actual | 0,5 día + 3 días | `M`, FPR, catálogo | Nada nuevo de realismo; **es la ventana ya rechazada**; conserva el `cwd` de bot | **Alto** (3.er aborto) | **No** |
| **C. Ventana + campaña** | B + 11 casos dentro | ~1,5 días + 3 días | FPR + catálogo dirigido + tabla comparable | Ritmo/errores/variedad; artefacto `cwd` | Medio | **Mínimo aceptable** |
| **D. Ventana mejorada + campaña** | C + `cwd` + ritmo + errores + herramientas del corpus | **~2,5 días + 3 días** | Todo lo de C + jornada creíble + T5 con base | Navegador/ofimática/GUI; ciclo semanal; sesión real | Medio | **RECOMENDADA (acotada)** |
| **E. No hacer nada** | Seguir con `M1b`/Windows/VR | 0 | Nada del FPR; **`B1`/`V0-V1` sí avanzan** | FPR, T3/T4/T5; **`M1b` tampoco** (depende del legítimo) | Bajo pero **bloquea el titular** | **No** |

**El piloto de 39 h no es una opción**: no es comparable con una ventana pre-registrada, se abortó
**antes** de analizar y usarlo ahora erosionaría la regla. Se queda **cerrado**.

### 1.4 Tabla de mejoras (coste/beneficio)

> **Criterio de entrada:** coste ≤ ~1 día **y** no instalar **y** no ampliar disco **y** no tocar nada
> congelado. **Tope: 5 mejoras** (las de esta tabla). Las **correcciones de instrumento** (H1) van
> aparte y se detallan abajo: no cambian la actividad ni la medida, arreglan aparatos que ya fallaron.

| # | Mejora | Qué aporta | Coste | Requisito técnico | Riesgo | Efecto en la medida | ¿Entra? |
|---|---|---|---|---|---|---|---|
| **1** | **`cwd` realista** | Quita el artefacto que delata al bot en **el 100 %** de las acciones; devuelve al campo `cwd` su valor discriminante | **1-2 h** | Cambiar el `cd` de arranque (`client_ctl.sh` + keepalive) a `/home/angel` y verificar que las rutas de config/logs siguen resolviendo (`ApplicationDetails.BaseDirectory` = dir del **exe**, no `cwd`) | Si NLog resolviera `app.log` por `cwd`, el log se movería ⇒ **se detecta en E0 en 2 min**; plan B: prefijo `cd X && cmd` (+1 fila `bash`/acción) | Ninguno en `M`; cambia el `cwd` de las filas | **SÍ (prioridad 1)** |
| **2** | **Ritmo irregular determinista** (jitter *horneado*: ráfagas 1-6, intra 30-180 s, huecos 2-22 min, 2 pausas largas/día) | Mata el metrónomo sin perder reproducibilidad | **2-3 h** | Tabla de jitter fija en `construir_receta_legitima.py` (sin `random` en ejecución) + regenerar + doble generación byte-idéntica | Huecos > `STALE=30` del keepalive y > umbral 30 min del `watch` ⇒ **acotado a 22 min** | Ninguno en `M` | **SÍ** |
| **3** | **Errores humanos con reintento** (~10/día: ruta mal escrita→reintento, `cp` a dir inexistente, `gzip` repetido, `rm` inexistente, `cat` de un directorio, opción inválida) | Familia nueva de eventos (`exit≠0`, dobles intentos) | **3 h** | Familias nuevas + **verificar que `exit≠0` no corta la ráfaga** | Que un fallo corte el handler (se prueba en E0) | Numerador más variado; +2 % acciones | **SÍ** |
| **4** | **Herramientas de doble uso elegidas POR EL CORPUS** (**12 en la receta**: `xargs`, `timeout`, `sed`, `ip`, `openssl`, `tee`, `free`, `logger`, `seq`, `rsync` local, `shred`, `wget`; **`systemctl`/`crontab` solo en la campaña, lectura**) + PDF/CSV como ofimática de consola | Sube la cobertura del **conjunto** receta v2 + campaña del **22 % al 50 %** (11 → 25 de 50); la campaña **sola** aporta 2 binarios marginales y **alimenta T5** justo por donde el corpus detecta | **3 h** | Verificar presencia en E0 (1 comando); `gawk`/`strings` con el **nombre real** del binario | `sed`/`openssl`/`shred` legítimos **dispararán** reglas ⇒ FP reales (es el objetivo) | **El mayor** en `N ≥ 7` y en T5 | **SÍ** |
| **5** | **Campaña dirigida de 11 casos no mutantes** (rehecha desde el corpus, **sin `sudo`**, §5.2) | Catálogo dirigido + **tabla propia por caso** + **23 ATA** con gemelo legítimo | **5-6 h** | Bloque `B6` **17:05-17:50Z** (inicio con **jitter fijo por día**, §3.1.1), marcas `inicio/fin/hecho`, esperado **por umbral**, generador B6 + validador, runner `extraer_campana.py` | Que se lea como "fabricar FPs" ⇒ **etiqueta + tabla aparte**; **C-04 retirada** (no hay escritura en `crontab`): se pierde `2832` L5 y se declara | **~47-55 acciones GHOSTS** (25 comandos + preparación + 22 marcas) y **~59-65 `execve`** (los hijos de `xargs`/`timeout`); el **número exacto** lo fija `campana_casos.csv` y se sella. **Eventos**: se miden (orden 10²-10³; **< 0,05 % de `M`**): no cambia la conclusión | **SÍ** |
| **H1** | **Correcciones de instrumento** (4 arreglos de ≤30 min): (a) **gracia de borde** en el `watch`; (b) **primer chequeo** sin `AVISO` (sembrar estado); (c) **`cleanup` sin SSH** a VM apagada; (d) rotación diaria **declarada como post-hoc** | Elimina las **2 falsas alarmas/día** y el hueco de 3 min; cierra las 4 lecciones de v2 | **~2 h** | `legitimo_host_control.ps1` + prueba en seco | Bajo | No cambia la medida | **SÍ (siempre)** |
| ~~M5~~ | ~~Segundo usuario local~~ | ~~Capa PAM/`sudo`~~ | 2 h | `useradd` + **`sudo -n`** | Dependencia real inexistente (ver §1.9.4) | 20 acciones = **0,0008 %** de `M` | **NO** |
| ~~M6~~ | ~~Actividad nocturna~~ | ~~`FP/hora` de noche~~ | 1 h | Bloque `N1` + V2 reescrita | Metrónomo del `watch`, más superficie | 12 acciones = **0,0005 %** de `M` | **NO** |
| M7 | Navegador real | Actividad web "de verdad" | 1-2 días + volumen + 12 `.deb` + 424 MB | — | **Alto** (DT-B0 ya falló) | Dominaría `M`; no comparable | **NO** |
| M8 | Ofimática headless (LibreOffice) | Documentos reales | 1-2 días + 400-700 MB | — | Alto (disco/`G-2`) | Firma distinta de un escritorio real | **NO** |
| M9 | GUI ligera (XFCE/`xdotool`) | Eventos de escritorio | 1-2 días + paquetes + X | — | Alto | Ruido ajeno a la superficie de los ataques | **NO** |
| M10 | Fallos de servicio reales | Ruido de servicio caído | 1 h | — | **Alto**: puede romper GHOSTS/agente **dentro** de la ventana | Ninguno limpio | **NO** |
| M11 | Ventana de 7 días | Ciclo semanal | +4 días de reloj + 4 recetas | — | Medio | Marginal (la métrica fija **72 h**) | **NO** |

**Coste total:** **~19-22 h** de trabajo (5 mejoras + H1) + 3 días de reloj desatendido.

### 1.5 Lo que NO compensa (y por qué)

1. **Navegador, LibreOffice, GUI**: los tres exigen **ampliar el volumen + `.deb` offline + comerse
   `G-2`**. El navegador ya falló (`browser_eval.md`: 12 librerías; 3,4 GB < 4 GB). Insistir es pagar
   dos veces el mismo peaje.
2. **Fallos de servicio reales**: un `systemctl stop` dentro de la ventana puede matar el cliente o el
   agente ⇒ **convierte una mejora en una invalidez** (V3). El sustituto barato (petición a un puerto
   cerrado + reintento) da el mismo tipo de evento sin riesgo.
3. **Ventana de 7 días**: +4 días de reloj y +4 recetas para un ciclo que **la métrica no pide**.
4. **Duplicar acciones para "subir `M`"**: el fondo domina `M` (§1.2a); subir acciones solo sube el
   numerador **sin** mejorar el realismo. Es la mejora que parece buena y no lo es.
5. **Analizar el piloto de 39 h "para aprender"**: rompe la regla pre-registrada a cambio de
   información que **ya** vamos a obtener con la ventana.

### 1.6 Prerrequisitos

| # | Prerrequisito | Estado | Si falta |
|---|---|---|---|
| **P-1** | **Cero instalaciones; no se amplía el volumen** | Decidido por el estudio | — |
| **P-2** | **Binarios de la receta v2 + campaña presentes** (los **14** nuevos + los 22 actuales = 36) | **Evidencia fuerte**: los 14 ya aparecen en el corpus de ataques, que corrió sobre **la misma imagen**; verificación en E0-2 (1 comando) | Se cae **esa** herramienta; **no se instala** |
| **P-3** | **Receta v2 + campaña** con `--check` PASS y `sha256sums` | T1/T2 | No se arma |
| **P-4** | **Deploy idempotente** sobre `lab-listo-legit-v2` (sin snapshot nuevo) | T3 | No se arma |
| **P-5** | **E0 PASS** con los artefactos nuevos | T4 | No se arma |
| **P-6** | **Windows Update re-pausado** justo antes de `prep` (`wuauserv` se auto-repara: hoy `Running`/`Manual`) | T4 + noche de `prep` | `G-10` aborta (47) |
| **P-7** | **`TFG_GUEST_PW`** en el entorno | **Presente** (verificado 27/10) | `prep`/`arm` salen con 30 |
| **P-8** | **Host**: `D:` ≥ 60 GB (hoy **181,3 GB**), sin suspensión (AC 0/0) | OK | — |
| **P-9** | **Disco de la víctima**: 4,4 GB libres (`G-2` ≥ 4 GB) | OK **sin instalaciones**; campaña ≤ 40 MB | Alarma de disco |
| **P-10** | **Manager** ≥ 10 GB libres (~700 MB de archives + alertas) | Verificar en `prep` | Limpiar antes de `t0` |

### 1.7 Efecto sobre validez, comparabilidad y bóveda

| Aspecto | Qué cambia | Qué hay que **declarar** |
|---|---|---|
| **`M`** | **+3-4 % de acciones** (≈150 acciones/día más y sus eventos); efecto en `M` **≈ +0,1 %** (estimado con 2-11 eventos/acción; el real se mide y se sella) | `M`, `acciones/día` y `acciones/h` **siempre** junto al FPR; **no** confundir "% de acciones" con "% de `M`" |
| **FPR** | Puede **subir** a `N ≤ 3`; en `N ≥ 7` seguirá casi vacío (usuario no root) | Que el objetivo **no** es bajar el FPR; es que la jornada sea creíble y el numerador variado |
| **`cwd`** | Deja de ser constante | Que el `cwd` es el del *shell del usuario*, y que las filas del `bash` padre también cambian |
| **TPR (ataques)** | **No cambia**: el corpus no se re-ejecuta | Nada nuevo |
| **Determinismo** | Se mantiene (jitter **horneado**; doble generación byte-idéntica) | Que la irregularidad es fija y reproducible |
| **Comparabilidad con el TFM hermano** | Su "10/10, 0 hits" mide **sus artifacts**, no el producto de fábrica | Declaración explícita; se compara **el método**, no el número |
| **Comparabilidad Wazuh ↔ VR** | Sin cambios (unidad común = acción/hora) | VR tendrá su **propia** captura con la **misma** receta v2 |
| **Bóveda** | `B10` cambia (receta v2, campaña, `cwd`, `errores.log`, deploy); `boveda_version` → **2** | No invalida nada: **no existía** medida legítima válida. El sidecar se reescribe **v3** y el bump se aplica en **3 sitios** (§10) |
| **Métrica v1** | **No se toca** | — |

### 1.8 Recomendación y qué se sacrifica

**Opción D acotada: 5 mejoras** (`cwd`, ritmo, errores, herramientas del corpus, campaña) **+ H1**,
sin instalar, sin ampliar disco, desde `lab-listo-legit-v2` + **deploy idempotente** (sin snapshot nuevo),
con **E0 obligatorio**, **sin fecha fija**
y **cláusula anti-aborto**.

**Se sacrifica (honesto):** (1) **calendario**: la ventana espera a que T1-T4 estén cerradas; (2)
**navegador/ofimática/GUI**: quedan como limitación declarada; (3) **un FPR "bonito"**: puede
**empeorar** (hipótesis H-A escrita **antes**); (4) **sesión interactiva real**: imposible sin
contaminar V4; (5) **`M1b`/`L2`/`A1`** esperan; `B1`/`V0-V1` no arrancan hasta cerrar v3 (host de 16 GB).

---

### 1.9 Prueba adversarial: qué rechazo y qué he encontrado por mi cuenta

#### 1.9.1 Qué rechazo de la lista que me diste (y con qué número)

| Idea de tu lista | Veredicto | Motivo con número/evidencia |
|---|---|---|
| **Errores humanos** | **ENTRA** | Aporta una familia de eventos que hoy **no existe** (0/333 comandos fallidos) |
| **Ritmo irregular fijo** | **ENTRA** | Hoy los huecos son **uniformes** (45-50 s intra, inter calculado); patrón "cada 11 min" en B3 |
| **Más herramientas (PDF/imagen/hoja de cálculo por consola)** | **ENTRA, redefinida** | Mi versión no era una lista intuida: se deriva de los **50 binarios** del corpus; hoy se cubren **11** |
| **Ofimática headless (LibreOffice)** | **NO** | 400-700 MB + decenas de `.deb` sin NAT + `G-2` (el navegador ya dejó **3,4 GB < 4 GB**) |
| **GUI ligera (XFCE/`xdotool`)** | **NO** | Paquetes + X + disco; una GUI falsa en un servidor **no es más realista** y añade ruido ajeno a los ataques |
| **Actividad nocturna** | **NO (cambio de criterio)** | Una máquina de oficina **sin usuario por la noche es lo realista**; 12 acciones = **0,0005 %** de `M` y obliga a reescribir V2 y el `watch` |
| **Fallos de servicio** | **NO (real), SÍ (barato)** | Un `systemctl stop` real puede invalidar la ventana (V3); el "puerto cerrado + reintento" entra **gratis** en la campaña |
| **Navegador real** | **NO** | `browser_eval.md` DT-B0 = **FAIL** (12 librerías, 3,4 GB); ya probado y descartado |
| **Segundo usuario** | **NO** | 20 acciones = **0,0008 %** de `M`; **redundante con un caso de `sudo`** (misma señal); necesita `sudo -n`, que **probablemente no existe** (§1.9.4) |
| **Ventana de 7 días** | **NO** | +4 días de reloj y +4 recetas para un ciclo que la métrica **no pide** (72 h canónicas) |

#### 1.9.2 Mejora nueva nº 1 — `cwd` realista (hallazgo, no intuición)

**Evidencia (3 piezas, leídas hoy):**

| Fichero | Línea | Qué dice |
|---|---|---|
| `Soporte/Laboratorio/legitimo_72h/guest/tfg-ghosts-legit.service` | 8 | `WorkingDirectory=/home/angel/ghosts-client` |
| `Soporte/Laboratorio/ghosts/client_ctl.sh` | 54-55 | `cd "$DIR"` + `nohup ./ghosts.client.linux` |
| `$GHOSTS/src/ghosts.client.linux/Handlers/Bash.cs` | 106-118 | crea el `Process` **sin `WorkingDirectory`** ⇒ hereda el del cliente |

**Consecuencia:** **todas** las acciones (y su `bash` padre) se registran con
`cwd=/home/angel/ghosts-client`. Un humano no trabaja desde el directorio de un binario; y el campo
`cwd`, que en el pipeline de ataques es **ancla de atribución**, quedaría inutilizado.

**Arreglo:** arrancar el cliente con `cwd=/home/angel` (el cliente resuelve su configuración por
`ApplicationDetails.BaseDirectory` = **directorio del ejecutable**, no `cwd`: verificado en
`ApplicationDetails.cs:55-61` y `Program.cs:56,70,134`). **Riesgo concreto y comprobable:** `nlog.config`
usa rutas **relativas** (`fileName="logs/app.log"`, `logs/clientupdates.log`) ⇒ si NLog las resolviera
contra el `cwd`, los logs se moverían a `/home/angel/logs/`. **Se comprueba en 2 minutos** (T3 y E0-4).
**Plan B** si se mueven: dejar el cliente en `$DIR` y poner el `cwd` **por comando**
(`cd <dir> && cmd`, +1 fila `bash` por acción, declarada).

**¿Es un "cambio del laboratorio"?** Sí, pero **no exige snapshot nuevo**: exige **E0** y un
**deploy idempotente** sobre `lab-listo-legit-v2` (§5.3). Si el deploy no fuera idempotente tras dos
intentos, entonces sí se justificaría un snapshot v3 (con OK humano). Coste 1-2 h.

#### 1.9.3 Mejora nueva nº 2 — herramientas elegidas por el corpus (cierre de doble uso)

Extraído de las **4 107** filas `deteccion` con `rule_description = "Audit: Command: <ruta>"`:

| Hecho medido | Número |
|---|---|
| Binarios distintos en las detecciones por `audit_command` | **50 basenames** (51 rutas; `git` sale como `/usr/bin/git` y `/usr/lib/git-core/git`) |
| De ellos, **usados por la receta v1** | **11** (22 %) |
| `xargs` (ATA046/ATA047) | **2 497 filas = 60 %** de esas detecciones — **nunca** en la receta |
| `curl` | 852 — sí está (campaña web) |
| `timeout` 96 · `cp` 92 · `ip` 73 · `losetup` 40 · `tar` 38 · `find` 31 · `git` 26 · `dd` 22 · `passwd` 22 · `grep` 20 | — |
| `openssl` 16 · `sed` 14 · `systemctl` 10 · `crontab` 10 · `sha256sum` 14 · `rsync` 10 · `shred` (vía ATA005) | — |

**Decisión de diseño (esto es lo que cambia respecto de v1):** la lista de herramientas **no se elige
por intuición**, se elige **del corpus** y se comprueba con un contador. Añadimos a la **receta** las
plausibles para un usuario de oficina: `xargs`, `timeout`, `sed`, `ip`, `openssl`, `tee`, `free`,
`logger`, `seq`, `rsync` (local), `shred` + `wget` (añadida en v3 por ATA008/ATA043) = **12**.
**`systemctl` y `crontab` (solo `-l`/`list-timers`) NO van en la receta: van solo en la campaña
(C-01/C-03)**, para no contar dos veces su cobertura. **Cobertura: 11 de la v1 + 12 de la receta + 2 de
la campaña = 25 de 50 (50 %)**, sobre un **techo realista de ~26**: los otros son `mke2fs`, `losetup`,
`mount`, `passwd`, `useradd`, `nc`, `sqlite3`, `xclip`, `xdotool`… que **un usuario no root no debe
ejecutar** (y si los ejecutara, sería el ataque). *Corrección v4: si `systemctl`/`crontab` estuvieran
también en la receta, la cobertura real sería 23, no 25; por eso se dejan **solo** en la campaña.*

**Criterio de aceptación nuevo (CA-04):** `python -c` script imprime
`cobertura_exes = n/50` y **falla si n < 22**. Es decir: el realismo se **mide**, no se opina.

> **Nota técnica aprendida del corpus:** registrar el **nombre real** del binario (`gawk`, no `awk`;
> `x86_64-linux-gnu-strings`, no `strings`) — misma lección que `nc`→`nc.openbsd` de ATA024/026.

#### 1.9.4 Hallazgo nº 3 (que **quita** trabajo) — ¿existe `sudo` sin contraseña?

`ATA024_ataque.sh` documenta: *"Elevacion: SI (`sudo -S` por stdin)"* y `sudo_cmd useradd -m …`. Si el
ataque necesitó **pasar la contraseña por `stdin`**, entonces **`sudo -n` no funcionaba** para `angel`.
Consecuencias:

1. **M5 (segundo usuario) queda fuera**: necesitaba `sudo -n -u` y **el corpus dice que no**.
2. **Toda la campaña debe ser sin `sudo`** (C-2). Se verifica en E0 (`sudo -n true`), pero
   **no se depende** de ello: si funciona, se declara como extra; **no se añaden casos**.
3. **T5 en `N ≥ 7` quedará casi vacía** (la única regla de nivel 7 del corpus, `550`, solo la dispara
   **ATA024** al tocar `/etc`). **No es un defecto de la captura**: es que **un usuario no root no
   modifica `/etc`**. Se declara como limitación y como *hallazgo* (la superficie de doble uso real de
   esta configuración está en **nivel 3**, no en nivel 7).
   **Matices de v4 (corrigen la v3):**
   - La regla de doble uso **más alta que la campaña puede medir sin mutar** es **`2832` (L5)** al
     escribir en `crontab`. **v4 NO la mide**: la única acción que la disparaba era **C-04**, y la
     decisión humana es una campaña **no mutante**. (`550` L7 es alcanzable con `passwd`, pero **cambia
     la credencial** y queda fuera, §17.11.) Por debajo de `N = 7`, pero **no es nivel 3**: queda como
     **límite declarado** de T5, no como resultado.
   - **`19011` (L9, SCA)** es una alerta que **no la provoca el usuario**: aparece **9 veces en un
     segundo** en las dos ventanas `_rev` de ATA038 (que reinician el agente). En una ventana estable
     no debería salir (solo alerta cuando **cambia** el estado de un check), pero **si el agente se
     recupera a mitad de ventana, sí**. ⇒ «T5 vacía a `N ≥ 7`» es una **predicción**, no un axioma: se
     comprueba en L2 y, si aparece, **es un FP de nivel 9 no atribuible al usuario** (y hay que decirlo).

> **Coste de averiguarlo mal:** si damos por hecho que hay `sudo` y no lo hay, la campaña pierde 4 casos
> y hay que repetirla **dentro** de la ventana (imposible). Por eso **E0 lo comprueba antes**.

#### 1.9.5 ¿Por qué no hay una tercera mejora? (lo que evalué y descarté)

Aquí es donde reconocería el sesgo si lo hubiera: **no encontré una tercera mejora que pase el filtro
de coste**. Lo que sí encontré son **dos mejoras** (1.9.2 y 1.9.3) y **tres hallazgos** que **ahorran**
trabajo (1.9.4 y los dos de la tabla de abajo). Candidatas evaluadas y **descartadas con motivo**:

| Candidata (fuente) | Qué aportaría | Por qué **no** |
|---|---|---|
| **Handler `Watcher`** (`Watcher.cs`, cliente Linux) | "Vigilar carpetas y borrar al pasar de tamaño" | Lo hace **.NET**, no `execve` ⇒ **ni una alerta** en Wazuh: **0 valor medible** |
| **Handlers `Ssh`/`Sftp`** (`Ssh.cs`, `Sftp.cs`) | Sesión/transferencia real | La sesión (PAM) ocurre en el **destino**, que no se mide; en la víctima solo queda el `execve` de `ssh`/`sftp` — ya cubierto |
| **Handler `Curl`** (en vez de `curl` por `Command`) | Peticiones "nativas" | Inyecta **UA aleatoria** (`Curl.cs`) ⇒ **rompe el determinismo** que exige la bóveda |
| **Permitir `\|` (pipes) en la receta** — un humano escribe `ls \| wc -l` | Comandos compuestos reales | **Probado en DT9**: GHOSTS **pierde el reporte** (108/111) ⇒ sin acción reportada **no hay `FP/acción`**. Se mantiene la prohibición |
| **`M` por hora** (`contar_denominador.py --por-hora`) | FPR por hora | 2 h de instrumentación **de análisis**, no de captura; va a **`L2`** (allí se calcula igual) |
| **Rotación diaria observable en vivo** (API de GHOSTS) | Detecta el fallo de rotación a las 07:45Z, no en `t1+90` | Añade una **10.ª señal** con su propio riesgo de falsa alarma; el fallo ya se **tolera** (V2 "con incidencia") |
| **`home` pre-poblado** (200 ficheros con `mtime` viejo) | `ls`/`find` realistas | Wazuh **no vigila** `~/Documentos` ⇒ **0 efecto** en la medida |
| **Permutar bloques entre días** | Evita secuencias idénticas | Los **eventos son los mismos**; solo cambia el orden ⇒ 0 efecto |
| **Tarea programada propia** (`crontab` + entrada) | Caso "persistencia benigna" | **NO ENTRA (v4).** v3 lo había metido como **C-04**; la decisión humana del 2026-10-27 es una campaña **no mutante**: nada escribe fuera de `$HOME` ni deja estado. Es la **única** acción benigna que dispararía **`2832` (L5)**, así que **se pierde esa medición** y se declara (§1.9.4, §17.4). El TFM hermano **sí** prueba persistencia benigna temporal (FP-003/FP-004, Tabla 32): su FP-003 **queda sin gemelo** en nuestra lista (§5.2.7) |

> **Conclusión honesta:** las mejoras que quedan por hacer son **caras** (instalar) o **no medibles**
> (handlers que no generan telemetría). Por eso el bloque se queda en **5**.

#### 1.9.6 Lo que he mirado y **no** aporta (para que conste)

| Fuente leída | Qué ofrece | Por qué no entra |
|---|---|---|
| **Handlers del cliente Linux** (`ghosts.client.linux/Handlers/`) | `Bash`, `Curl`, `Watcher`, `Ssh`, `Sftp`, `NpcSystem`, `Aws`, `Azure`, `BrowserChrome/Firefox/Crawl`, `Blog/Outlook/Sharepoint/Social` | `Watcher` borra ficheros **desde .NET** (ni un `execve` ni una alerta: **0 valor medible**); `Curl` inyecta **UA aleatoria** (rompe determinismo); `Ssh`/`Sftp` abren sesión **en el destino** (el destino no se mide); `Aws/Azure/Blog/Outlook/Sharepoint` exigen Internet o cuentas; `Browser*` ya descartados |
| **Métrica congelada** (`metrica_hids.md` §2, §10) | **Métricas adicionales** `FP/acción` y `FP/hora`; el **titular** es por evento | `FP/hora` **sí** está instrumentado (`exportar_acciones.sh` da acciones por hora + las alertas traen `timestamp`); lo que **no** existe es **`M` por hora** ⇒ el "FPR por hora" no se puede dar. **Va a `L2`** (§1.10) |
| **TFM hermano** (Tabla 32, pág. 53; Tabla 35, pág. 63; §4.3.4, pág. 88) | 10 casos benignos; **estado, duración, artefactos**, clasificación del FP por **perfil de severidad**, y **autocrítica** de la muestra | **Sí copiamos**: columna de **severidad equivalente** (P1-P4 ↔ nivel Wazuh), **duración por caso** y la **atribución por ventana temporal**. **Corrección v3:** v2 afirmaba que "ningún caso suyo queda sin cubrir"; **falso en 2 de 10** — su FP-003 **crea** una tarea programada temporal y su FP-004 **escribe** en el registro. **Corrección v4:** al retirar C-04, **su FP-003 queda sin gemelo** (nuestro C-03 solo **lee** el planificador); se declara como límite, **no se maquilla**. Su FP-004 sí queda cubierto por C-11 (escritura benigna en el registro) |
| **`change-doc` v2 + `incidencias.md`** | 5 lecciones | 4 estaban en v1; la 4.ª (**`cleanup` intenta SSH con la VM apagada**) **no** → entra en H1. Además el `incidencias` documenta que el **primer chequeo** sale `AVISO` por diseño → H1 |

### 1.10 Trabajo futuro (lo que es bueno pero no cabe)

| Idea | Por qué no entra ahora | Cuándo |
|---|---|---|
| **`M` por hora** (`contar_denominador.py --por-hora`) | 2 h, pero es **instrumentación de análisis**, no de captura; el FPR por hora se calcula igual en `L2` desde `archives` | `L2` |
| **Rotación diaria observable en vivo** (leer la firma de las acciones del día en la API) | Añade una 10.ª señal con su propio riesgo de falsa alarma; hoy el fallo se tolera (V2 "con incidencia") y se juzga post-hoc | Si se repite ventana |
| **`home` pre-poblado** (200 ficheros con `mtime` viejo) | No cambia ninguna regla (Wazuh no vigila `~/Documentos`) | Si se añade FIM al home |
| **Segundo usuario (con `sudo` real)** | Hoy no hay `sudo -n` (§1.9.4) y la señal ya la daría un caso con `sudo` | Cuando se resuelva la elevación |
| **Análisis del piloto de 39 h como contraste** | Rompe la regla pre-registrada | Después de v3, declarado |
| **7 días / navegador / LibreOffice / GUI** | Coste ≫ beneficio (disco + `.deb` + `G-2`) | No previsto |

---

# Parte II — PLAN DE EJECUCIÓN (opción D acotada)

## 2. Objetivo, alcance y qué NO entra

### 2.1 Objetivo

Producir, con **una sola ejecución**, el **dataset legítimo de 72 h** de `victima-linux` con Wazuh
virgen —**alertas**, **denominador `M`** y **acciones**— sobre una jornada **más creíble y sin
artefactos**, más un **catálogo dirigido de falsos positivos** (11 casos benignos pre-registrados y
**no mutantes**, **rehechos en v3 contra el corpus y contra el validador**, §5.2), **sellar B10 v5** y
**dictaminar la validez** con criterios escritos de antemano.

### 2.2 Entra

- **Construir y probar** la receta v2 (mejoras 1-4), la campaña (5), las correcciones H1 y el **deploy
  idempotente** sobre `lab-listo-legit-v2` (**sin snapshot nuevo**; ver §5.3).
- **Armar** (`prep` + `arm`) y **ejecutar** 72 h **sin acceso a la víctima**.
- **Vigilar** cada 30 min (9 señales + gracia de borde).
- **Extraer** en orden estricto (cosecha → parada → copia → **`M` único** → `logall_json off` →
  alertas → acciones → **tabla de campaña**).
- **Evaluar** **V1–V8 (ventana) + V9 (campaña, §9.4)**, escribir la ficha, **sellar B10 v5**,
  promocionar a `Dataset/` **solo si VÁLIDA**.
- **Cerrar limpio** (0 VMs, 0 tareas, 0 reglas, `logall_json=no`, WU restaurado, secreto retirado).

### 2.3 NO entra

- **Analizar** (T3/T4/T5, FPR, catálogo de ruido): es `L2`.
- **Instalar** software en la víctima; **ampliar el volumen**; tocar el ruleset, `ossec.conf` (salvo
  `logall_json`), la métrica congelada, el corpus, `Hojas/`, `_recursos/`, `Dataset/Legitimo` (salvo
  promoción declarada).
- **Re-ejecutar ataques** (el corpus de 55 casos no se repite).
- **Analizar el piloto de 39 h** (se queda cerrado).
- **Parchear** una ventana inválida: si es inválida, **se repite entera**.
- **Usar `sudo`** en la actividad legítima (§1.9.4).
- **Campaña mutante**: escribir en `crontab`, `/etc`, servicios o cualquier ruta fuera de
  `~/Documentos/campana_fp/C-XX/` (C-04 retirada; §5.2.1).
- **Commits/push** (los hace el orquestador; el plan **sí** se guarda en git al aprobarse).

## 3. La ventana: regla de fijación y anti-aborto

### 3.1 Parámetros (independientes de la fecha)

| Parámetro | Valor |
|---|---|
| **Duración** | **72 h exactas** (`t1 = t0 + 259 200 s`) |
| **`t0`** | **lunes 00:00:00Z** |
| **`t1`** | **jueves 00:00:00Z** |
| Días | lunes · martes · miércoles → recetas `d1` · `d2` · `d3` |
| **Jornada (UTC)** | **08:00-17:00** trabajo · **P1** 10:00-10:20 café · **P2** 13:00-14:00 comida. **`B6` = 17:05-17:50Z** (bloque **declarado** de campaña; **no** es jornada de trabajo; ver §3.1.1) |
| **`prep`** | **`t0 − 45 min` = domingo 23:15:00Z** (= 00:15 local, CET) |
| **`arm`** | **`t0 − 20 min` = domingo 23:40:00Z** (= 00:40 local) |
| **timer del invitado** | **`t0 − 5 min` = domingo 23:55:00Z** (= 00:55 local) |
| **`stop`** | **`t1 + 10 min` = jueves 00:10:00Z** (= 01:10 local) — espera el marcador `cosecha.done`; tope `t1+15` (§7.1, §8) |

> **Corrección C-1 (v1 tenía las horas UTC rotuladas "local").** Todo lo de arriba está en **UTC**; el
> equivalente **local** se da entre paréntesis y **solo** porque en invierno CET = UTC+1. *Si el TFG se
> retrasara más allá del 28/03/2027 (CEST = UTC+2), el local sería +1 h más.* El `watch` y las tareas
> trabajan **siempre** en UTC.

### 3.1.1 Las horas de la campaña: opciones y decisión

> **Punto de partida (v3):** B6 fijo **17:10-17:45Z** (18:10-18:45 local), 4 casos/día. La v4 lo revisa
> porque (a) la campaña baja a **11 casos** (3/4/4) y (b) un inicio **idéntico al minuto** los 3 días es
> otro pequeño metrónomo, justo lo que la mejora 2 quiere evitar. **La hora no es una variable del
> análisis**: la atribución se hace por **marcas** (`inicio.txt`/`fin.txt`), no por reloj.

| Opción | Ventaja | Inconveniente | Comparabilidad | Vigilancia (huecos / `doing_age`) | Coste |
|---|---|---|---|---|---|
| **(a) Fija 17:10-17:45Z** todos los días | Máxima simplicidad; idéntica a v2/v3; cero decisiones | **Metrónomo exacto de 3 días**; el "repaso" empieza al mismo segundo siempre | Total entre días (pero no se compara la hora) | Última acción de B5 ~16:58 → 17:10 = **12 min**; dentro de B6, `doing_age` ≤ 12 min: **sin AVISO** | **0** |
| **(b) Rotada por día** (16:45 / 17:15 / 16:30) | Más variedad; determinista | **16:45 y 16:30 caen dentro de B5** (16:15-17:00): obliga a **partir B5** o a solapar bloques; 16:30 es media tarde, no fin de jornada | Igual (marcas), pero **V2 se complica** (bloques solapados) | Peor: solape con B5 y dos bloques "activos" ⇒ `doing_age` y `sin_eventos` más difíciles de interpretar | **Medio** (rediseñar bloques) |
| **(c) Jitter predefinido** (p. ej. **17:06 / 17:17 / 17:11**) | **Fin de jornada** y **no al segundo exacto**; determinista; no toca B5; el hueco desde B5 queda ≤ 19 min | Hay que escribirlo en la receta y en `campana_casos.csv` (2 líneas) | **Total**: la campaña se extrae por marcas; no hay vista alternativa | **Seguro**: 19 min < **AVISO 25** y < `STALE=30` (con caché 5 min, 24 < 30); B6 declarado 17:05-17:50 | **~0** |
| **(d) Repartida** (2 mañana / 2 tarde) | Más variedad horaria; dos "repasos" | **Rompe la idea de "repaso de fin de día"**; duplica ventanas de atribución; mete campaña en medio de B2/B3; más riesgo de confundirla con actividad normal | Peor: deja de ser **un** bloque identificable; la tabla de campaña tendría **dos franjas** por día | Peor: 4 franjas/día, más bordes y más solapes con el `watch`; `doing_age` en medio de bloques ya densos | **Alto** |

> **DECISIÓN: opción (c), jitter predefinido dentro de `B6 = 17:05-17:50Z`.**
> **Inicios (UTC):** `d1` **17:06** · `d2` **17:17** · `d3` **17:11** (locales 18:06 / 18:17 / 18:11).
> **Reparto:** `d1` = C-01…C-03 (3) · `d2` = C-05…C-08 (4) · `d3` = C-09…C-12 (4). **Separación mínima
> entre casos: 3 min**; fin ≤ **17:50Z**.
> **Por qué:** lo natural es que el repaso caiga **al final de la jornada, pero no al segundo exacto**.
> (c) conserva las dos cosas: sigue siendo "antes de irse" (17:05-17:50Z) y **no** repite el minuto.
> No toca B5, no crea bloques solapados (a diferencia de b), no rompe el concepto (a diferencia de d),
> es determinista (se sella en `bloques.env` y `campana_casos.csv`) y **no añade coste**.
> **La comparabilidad no se resiente**: los casos se comparan **caso a caso** y contra el corpus; la
> hora solo sirve para **localizar** la ventana, y eso se hace con las marcas.

### 3.2 Cómo se fija la fecha (sin fecha fija)

1. **No se propone fecha.** Se fija **al cerrar T4** (receta + campaña + **deploy probado** + **E0 PASS**).
2. **Regla escrita:** se elige **la primera ventana lunes→miércoles** cuyo `t0` caiga **≥ 48 h después
   del cierre de T4** (para registrar tareas, re-pausar WU la tarde anterior y repetir E0 si hace falta).
3. **Por qué lunes→miércoles y no otro tramo:**
   - la receta es **una jornada de oficina** (B1 llegada 08:00Z, café, comida, cierre 17:00Z); incluir
     **sábado o domingo restaría realismo** (nadie "llega a la oficina" un sábado) y obligaría a inventar
     una receta de fin de semana;
   - `t0`/`t1` a **medianoche UTC** ⇒ **3 ficheros diarios exactos** y corte limpio de `M`;
   - **no cruza ningún cambio de hora** hasta el 28/03/2027;
   - deja **2 días de colchón** antes (`prep`/`arm` en domingo) sin gastar jornada laboral.
4. **`E0` y su antigüedad:** E0 debe ser **≤ 7 días antes de `t0`**. Si pasan más (espera larga, parche
   de Windows, cambio en el host), **se repite E0** (~60-75 min) antes de armar.
5. **Anuncio:** la fecha se escribe en `state.md` + `ventana_meta.md` **el mismo día que se fija**, con
   `t0/t1` en UTC, y se registran las 4 tareas.

### 3.3 Condición de viabilidad

- **(a)** T1–T3 en **PASS** (receta `--check`, campaña con esperados firmados, **deploy idempotente probado**);
- **(b)** **E0 PASS** con antigüedad ≤ 7 días;
- **(c)** WU re-pausado y las 4 tareas registradas con `NextRun` **en UTC** verificado.

**Si (a) o (b) fallan** ⇒ **no se arranca**; se corrige y se elige la siguiente ventana lunes→miércoles.
**No hay fecha "de reserva"**: la regla §3.2 la genera sola. *No se arranca sin E0.*

### 3.4 Cláusula anti-aborto (la lección más cara de v2)

> **La ventana v3 no se aborta por juicio de realismo.** Solo por **invalidez objetiva** (§9.3) o por
> decisión humana **con un motivo escrito que no sea "podría ser más realista"**. El criterio de
> "suficientemente realista" se fija **antes** (5 mejoras, ni una more); si al ver los datos parece poco
> realista, **se declara como limitación** y se mejora en un bloque futuro (VR tendrá su propia captura).

Un tercer aborto sería el peor resultado posible del bloque: **tres intentos, cero datos**.

## 4. Estado de partida verificado (2026-10-27)

| Elemento | Estado real | Cómo |
|---|---|---|
| **VMs** | **0 en marcha** | `vmrun -T ws list` |
| **Snapshots `victima-linux`** | **5**: `base-limpia`, `lab-listo`, `lab-listo-legit`, `fallo-2026-10-19-disco-lleno-NO-USAR`, **`lab-listo-legit-v2`**. **v4 no crea uno nuevo** (decisión humana): el retorno es `v2` + deploy | `vmrun listSnapshots` |
| **Snapshots `wazuh-server`** | `base-limpia`, `lab-listo` | ídem |
| **Tareas del host** | 4 `TFG-Baseline-*` (Windows); **0** `TFG-Legit-*` | `Get-ScheduledTask` |
| **Reglas de firewall** | **0** `TFG-*` | `Get-NetFirewallRule` |
| **`wuauserv`** | **`Running` / `Manual`** (se auto-repara) | `Get-Service` |
| **`TFG_GUEST_PW`** | **presente** (valor no mostrado) | `[Environment]::…` |
| **Disco del host** | `D:` **181,3 GB** libres | `Get-PSDrive D` |
| **Git** | árbol **limpio**; último commit = cierre de v2 | `git status` |
| **Métrica** | v1 congelada; `VERSION_METRICA=1`, **`VERSION_BOVEDA=1`** | `metrica_hids.py:35-36` |
| **Receta vigente** | v1 (111/117/105), `MAPA_DIAS` 26-28/10 | `recetas/*`, `construir_receta_legitima.py:86` |
| **`cwd` de las acciones** | **`/home/angel/ghosts-client`** en el 100 % (artefacto) | §1.9.2 |
| **`sudo -n`** | **No consta**; `ATA024` usó `sudo -S` con contraseña por stdin | `ATA024_ataque.sh` |
| **Piloto de 39 h** | preservado **fuera del repo** (331,6 MiB) | `D:\TFG-VMs\legitimo-2026-10-26-piloto\` |

## 5. Trabajo previo (T1–T4): qué se construye y cómo se prueba

> Regla de oro: **ningún artefacto se estrena la noche de `t0`**. Todo se prueba en seco **dos veces**
> (dos generaciones idénticas + dos ejecuciones completas sobre un revert desechable).
> **Sin fechas**: las tandas se ejecutan cuando haya hueco; el orden es obligatorio.

### 5.1 T1 — mejora 1 (`cwd`) + mejora 2 (ritmo) + mejora 3 (errores)  · ~8 h

1. **`cwd`**: cambiar el arranque del cliente a `cwd=/home/angel` (`client_ctl.sh`; el keepalive deja de
   `cd` a `$DIR` o pasa a `cd /home/angel && "$DIR/ghosts.client.linux"`). Verificar que `config/`,
   `nlog.config`, `app.log`, `client.out` siguen donde deben (E0 lo comprueba en 2 min).
   **Plan B** si algo se mueve: prefijo `cd <dir> && ` por comando (declarando **+1 fila `bash`/acción**).
2. **Ritmo**: tabla de jitter **fija** (constante literal, sin `random`): ráfagas 1-6, intra 30-180 s,
   huecos **2-22 min**, **2 pausas largas**/día. Regla dura: **hueco ≤ 22 min**; el validador pasa de
   `CAP_HUECO_S=720` a **`1320`** y se elimina el segundo umbral de 20 min (`construir_receta_legitima.py:96,649-652`).
   *Margen real:* 22 min < `STALE=30` (keepalive; con la caché de 5 min, 27 < 30) y < **AVISO de
   `doing_age` = 25 min** (v4). El umbral viejo de 15 min **no** era compatible con 22 (§7.3).
3. **Errores**: familias `familia=error`, ~10/día, **cada una seguida del reintento correcto**.
   **Registro obligatorio:** `errores.log` (o `reintentos.csv`) con `ts · familia · comando · rc ·
   reintento · rc_reintento`; es **producto sellable** (B10) y se cuenta en CA-03.
4. **Regenerar** `d1/d2/d3` + `calendario.json` + `bloques.env` + `receta_resumen.md`. **`bloques.env`
   incluye `B6=17:05-17:50`** y `TFG_MAPA_DIAS` parametrizado.
5. **Campaña (adelanto de T2):** el generador lee `campana/campana_casos.csv` y **construye B6**
   (3/4/4 casos, marcas `inicio`/`fin`, comandos literales) con el **mismo validador** (`binarios_de`,
   `BINARIOS_OK`, 0 pipes, 0 `sudo`, rutas `/home/angel`, sin estado fuera de `campana_fp/C-XX/`).
   **No** hay un segundo mecanismo de ejecución: la campaña corre por **GHOSTS** como el resto.
6. **CA-01/CA-02/CA-03/CA-04**: `--check` PASS con los conteos nuevos; 0 `random`; 0 pipes; 0
   `Browser*`/`Curl`; **dos generaciones byte-idénticas**; hueco máx ≤ 22 min y mín ≥ 40 s;
   **cobertura receta v2 = 23/50** y **conjunto con campaña = 25/50** (script contador; umbral ≥22).

> **Acoplamiento:** los conteos cambian ⇒ todo lo que hoy tiene 111/117/105 **hardcodeado** pasa a
> leerlos de `--check` (buscar con `Select-String` antes de cerrar T1).

### 5.2 T2 — mejora 4 (herramientas del corpus) + mejora 5 (campaña)  · ~8 h

**Herramientas (mejora 4).** Añadir a la **receta**, **por evidencia del corpus** y no por intuición:
`xargs`, `timeout`, `sed`, `ip`, `openssl` (`dgst` + `enc` de una copia propia y descifrado), `tee`,
`free`, `logger`, `seq`, `rsync` (local→local), `shred` (de un fichero propio), `wget` = **12**.
**`systemctl` y `crontab` (solo `-l`/`list-timers`) quedan fuera de la receta**: son **solo de la
campaña** (C-01/C-03, lectura), para que la cobertura 25/50 no cuente dos veces el mismo binario.
Ofimática de consola: `gawk`/`sort`/`cut`/`uniq` sobre `plantilla_informe.csv`,
`file`/`wc`/`od` sobre `manual_empleado.pdf`. **Nombre real del binario** en la declaración (`gawk`).
No se usan: `mke2fs`, `losetup`, `mount`, `passwd`, `useradd`, `nc`, `dd`, `sqlite3`, `xclip`, `xdotool`
(no son actividad de usuario no root).

**Campaña (mejora 5) — 11 casos, `sin sudo`, NO mutantes, dentro de la ventana. REHECHA en v3; RECORTADA en v4.**

> **Qué cambia y por qué.** La lista de v2 se construyó **por analogía** con el TFM hermano y
> **no se comprobó contra el corpus ni contra el validador**. La v3 la reconstruyó desde cero con
> filtros medibles (§5.2.1). La **v4 retira C-04** (la única que escribía en `crontab`) por decisión
> humana: la campaña es **no mutante**. Resultado: **11 casos**; **3 se caen** de v2 por **duplicar un
> mecanismo** ya medido, **1 se reescribe sin `|`**, **2 son nuevos** y **1 (C-04) se retira en v4**.
> Comparación caso a caso: **§5.2.4**.

#### 5.2.1 Criterios de selección (aplicados ANTES de mirar la lista de v2)

1. **El mecanismo está en el corpus.** El binario aparece en `audit_exe` de alguna fila
   `categoria=deteccion` (`Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*-Audited.csv`): **4 107**
   detecciones `80792` → **51 rutas / 50 basenames** distintos. Cada caso cita su `ATA<NNN>`, su
   técnica y su `rule_id`. Sin esa cita, el caso **no entra**.
2. **No duplicar un mecanismo ya medido.** Si el binario **ya está en la receta v2**, el caso **solo
   entra si aporta un escenario/regla distinta** (p. ej. `openssl` cifra/descifra, `sed -i` reescribe,
   `xargs` lanza 12 hijos, `logger`+`tee` escriben) y se marca **«ya medido»**: **no cuenta como
   cobertura nueva**. Se caen los que solo repetían el binario sin escenario nuevo (`FP-005`, `FP-007`).
   *La receta v1 ejecuta **21** binarios: **11 tienen gemelo** en el corpus (`curl` 58 acciones/día,
   `cat` 49, `sha256sum` 21, `cp` 15, `tar` 5, `find` 5, `gzip` 3, `mkdir` 3, `grep` 2, `head` 1,
   `rm` 1) y **10 no** (`echo` 50, `wc` 46, `ls` 27, `du` 16, `date` 6, `md5sum` 5, `df` 4, `mv` 3,
   `tail` 1, `stat` 1). La receta v2 añade **12**; por eso el valor de la campaña es la **tabla y la
   atribución**, no solo la cobertura (A-22).*
3. **Sin `sudo`, sin instalar, sin red externa.** Los **14 binarios que la campaña ejercita y no estaban
   en v1** aparecen en el corpus, que se ejecutó sobre la **misma imagen** (`lab-listo`) como usuario
   `angel`: presencia **probada**, no supuesta (`ATA001` usa `openssl`; `ATA018` usa `logger` y `tee`;
   `ATA039` usa `rsync`; …). *De ellos, 12 ya los añade la receta v2; la campaña solo aporta
   `systemctl`/`crontab`.*
4. **Sin dejar estado (definición operativa de "no mutante").** Todo lo que se crea vive bajo
   `~/Documentos/campana_fp/C-XX/` y **se borra dentro del propio caso**. **Ninguna** escritura en
   `crontab`, `/etc`, servicios, unidades, repositorios ni rutas del sistema; **ningún** cambio de
   credenciales. Efectos laterales **declarados**: (a) `logger` escribe **una línea** en el journal
   (C-11), que no se borra (borrarla sería otra mutación); (b) C-09/C-12 hacen `GET` a la
   **intranet local**, cuyo `web_access.log` crece (fuera de la víctima). Ambos se declaran.
5. **Reglas del validador.** `construir_receta_legitima.py` **rechaza pipes** ("GHOSTS pierde el
   reporte", DT9: 108/111) y **cualquier primer token fuera de `BINARIOS_OK`** (hoy **22**; **36** tras
   T1). La lista de v2 **no pasaba** este filtro: `FP-002` usaba `bash -c` y `FP-010` usaba `|`. En v4
   el **mismo validador** se aplica a los **11 casos** antes de generar B6 (CA-27).
6. **Tope: 11.** Con 11 se **ejercitan** los **14 binarios que no estaban en v1**; **12 de ellos ya
   los añade la receta v2**, así que la **campaña aporta 2 marginales** (`systemctl`, `crontab`) y
   **4 `ATA`**; el **conjunto** receta v2 + campaña cubre **25/50** y **23/55 ATA**. **C-04 se retira**
   (no mutación): se pierde la medición de `2832` L5 (§1.9.4).

#### 5.2.2 Tabla maestra (11 casos · `d1` 3 · `d2` 4 · `d3` 4 en `B6`)

> **Convención de severidad (para comparar con el TFM hermano, que clasifica el FP por perfil P1-P4):**
> `P4 = nivel 0-3` · `P3 = 4-6` · `P2 = 7-11` · `P1 = ≥ 12`. Es una **convención de este bloque**: la
> métrica congelada solo fija el **orden** (`P4 ≤ P3 ≤ P2 ≤ P1` ↔ nivel Wazuh), no los cortes.
>
> **Cómo leer «Esperado».** `N ≥ 7` es el umbral que decide si el caso es un FP «de verdad»; `N ≥ 3`
> es donde **todo** `execve` alerta por `80792` (hipótesis H-A). Se pre-registran **los dos**. El número
> exacto de filas **no** se promete: el corpus muestra **1-3 filas por `execve`** (ATA024 replica 8 veces
> el mismo `useradd`). Se pre-registra el **conjunto de `rule_id`**, que sí es falsable.

| # | Caso | Qué hace (resumen) | Binarios | Se confunde con (ATA · técnica · `rule_id`) | Esperado `N ≥ 7` | Esperado `N ≥ 3` | ¿Cambia la máquina? | Dónde | Evidencia de efecto | Coste · disco |
|---|---|---|---|---|---|---|---|---|---|---|
| **C-01** | El equipo va lento: miro memoria y servicios | `free -m`; `systemctl --failed`; `systemctl list-units --type=service --state=running` | `free`, `systemctl` | ATA004 · T1489 · `80792`; ATA045 · T1499.001 · `80792`; ATA038 · T1529 · `80792` | **0** | `80792` L3 ×3 | **No** (solo lectura) | **Dentro** | `hecho.txt` con el listado (>10 líneas) y `free` (>3) | 3 min · <1 MB |
| **C-02** | «No me va la intranet»: miro la red | `ip -brief addr`; `ip route` | `ip` | ATA054 · T1498.002 · `80792`; ATA055 · T1557.003 · `80792` | **0** | `80792` L3 ×2 | **No** | **Dentro** | `hecho.txt` con la IPv4 `192.168.65.x` y la ruta | 2 min · <1 MB |
| **C-03** | ¿Está la copia programada? | `systemctl list-timers --all --no-pager`; `crontab -l` | `systemctl`, `crontab` | ATA021 · T1029 · `80792`; ATA004 · T1489 · `80792` | **0** | `80792` L3 ×2 (**y 0 `2832`**: solo se lee) | **No** (lectura) | **Dentro** | `hecho.txt` con el nº de timers y el `rc=1` de `crontab -l` ("no crontab") | 2 min · <1 MB |
| **C-05** | Protejo el informe con contraseña antes de enviarlo | `openssl enc -aes-256-cbc -pbkdf2 -salt -in informe.txt -out informe.txt.enc -pass …`; `openssl enc -d …`; `sha256sum` ×2 | `openssl` | ATA001 · T1486 · `80792`; ATA019 · T1048.001; ATA041 · T1048.002 | **0** | `80792` L3 ×2 (+2 `sha256sum`) | **No** (ficheros propios; se borran) | **Dentro** | `hecho.txt` con `sha256(original) == sha256(descifrado)` | 4 min · <1 MB |
| **C-06** | Limpio temporales y destruyo un borrador | `rm -rf C-06/tmp`; `shred -n 1 -z -u C-06/borrador.txt` | `rm`, `shred` | ATA003 · T1490 · `80792`; ATA005 · T1561 · `80792` | **0** | `80792` L3 ×2 + `80791` L3 ×2-6 | **No** (borra solo lo suyo) | **Dentro** | `stat` antes (existe) y después (`rc≠0`) en `hecho.txt` | 2 min · <1 MB |
| **C-07** | Sincronizo informes con la carpeta de copias | `rsync -a --delete C-07/origen/ C-07/destino/` | `rsync` | ATA039 · T1039 · `80792`; ATA040 · T1074.002 | **0** | `80792` L3 ×1 + `80790` L3 por fichero creado y `80791` L3 por borrado (**predicción**: el corpus no aísla un `rsync` local) | **Sí, transitorio** (ficheros propios; se borran) | **Dentro** | `du -sb origen` == `du -sb destino` y `ls destino` | 3 min · <1 MB |
| **C-08** | Normalizo el CSV del informe | `sed -i 's/;/,/g' C-08/export.csv`; `sed -n '1,5p' C-08/export.csv` | `sed` | ATA006 · T1565 · `80792`; ATA032 · T1565.001; ATA026 · T1565.002; ATA017 · T1657 | **0** | `80792` L3 ×2 + `80790`/`80791` L3 (temporal de `sed -i`) | **Sí, transitorio** (fichero propio) | **Dentro** | `grep -c ';'` = 0 y `head -1` con comas (`hecho.txt`) | 2 min · <1 MB |
| **C-09** | La intranet no responde: acoto el tiempo y reintento | `curl --max-time 3 -o intranet.html -w '%{http_code}' http://intranet.local:8080/`; `curl --max-time 2 http://intranet.local:8081/` (falla); `timeout 5 curl -sS -o reintento.html http://intranet.local:8080/` | `curl`, `timeout` | ATA025 · T1496.001 · `80792`; ATA009/010/020/023/028/041/050 · exfiltración · `80792` | **0** | `80792` L3 ×4 | **No** | **Dentro** | `hecho.txt`: `RC_FALLO=7`, `RC_REINTENTO=0`, `HTTP=200` | 3 min · <1 MB |
| **C-10** | Preparo el lote de plantillas del mes | `seq 1 12 > lotes.txt`; `xargs -a lotes.txt -I{} cp informe.txt lote_{}.txt`; `wc -l lote_1.txt` | `seq`, `xargs`, `cp` | ATA046 · T1499.003 y ATA047 · T1499.002 · `80792` (**`xargs` = 2 497 detecciones, 60 %**) | **0** | `80792` L3 ×14 (1 `seq`, 1 `xargs`, 12 `cp`) | **Sí, transitorio** (12 ficheros propios) | **Dentro** | `stat -c %s lote_12.txt` > 0 y 12 rutas listadas | 4 min · <1 MB |
| **C-11** | Dejo constancia de la incidencia en el registro | `logger -t ofimatica '…'`; `tee -a registro.log < nota.txt` | `logger`, `tee` | ATA018 · T1056.001 · `80792`; syslog → **`40700` L0 (no emite)** | **0** | `80792` L3 ×2 · **y 0 por la vía syslog** | **No** (una línea de journal) | **Dentro** | `tail -3 registro.log` con la nota | 2 min · <1 MB |
| **C-12** | Descargo el manual con `wget` (no hay navegador) | `wget -q -O manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` | `wget` | ATA008 · T1048 · `80792`+`80791`; ATA043 · T1567.004 | **0** | `80792` L3 ×1 (+`80791` **solo si** borra temporales; **no** se promete) | **Sí, transitorio** (un PDF en la carpeta del caso) | **Dentro** | `stat -c %s manual.pdf` > 1 000 | 2 min · <1 MB |

#### 5.2.3 Fichas: por qué cada una es legítima, guardarraíl y comando literal

- **C-01 · «El equipo va lento».**
  `free -m` · `systemctl --failed --no-pager` · `systemctl list-units --type=service --state=running --no-pager`
  *Legítima:* cualquier empleado mira la memoria y los servicios cuando el portátil va lento, antes de
  abrir incidencia. *Guardarraíl:* solo lectura; **no** se nombra el agente en la actividad (nombrar
  `wazuh-agent` en un comando de la víctima es un artefacto en sí). *Coste:* 3 min.
- **C-02 · «No me va la intranet».**
  `ip -brief addr` · `ip route`
  *Legítima:* comprobar la IP y la puerta de enlace es el primer paso de cualquier usuario ofimático.
  *Guardarraíl:* lectura de la configuración; **no** se cambia nada (`ip` sin `set`/`add`).
- **C-03 · «¿Está la copia programada?».**
  `systemctl list-timers --all --no-pager` · `crontab -l`
  *Legítima:* comprobar si la copia automática está programada. *Guardarraíl:* `crontab -l` **lee**;
  con `crontab` vacío devuelve `rc=1` ("no crontab for angel"), que es un `exit≠0` realista.
- **C-04 — RETIRADA en v4 (no se ejecuta).** Era «Programo mi copia mensual y la quito»
  (`crontab mi_copia.cron` · `crontab -l` · `crontab -r`). **Motivo:** escribe estado en el
  `crontab` del usuario, fuera de `~/Documentos/campana_fp/`, y la decisión humana es una campaña
  **no mutante**. **Coste de retirarla:** se pierde la única medición legítima de **`2832` (L5,
  "Crontab entry changed")**; T5 por encima de L3 queda **sin evidencia propia** y se declara
  (§1.9.4, §17.4). **No se sustituye** por otra escritura de sistema: el objetivo es no mutar.
- **C-05 · «Protejo el informe antes de enviarlo».**
  `openssl enc -aes-256-cbc -pbkdf2 -salt -in …/informe.txt -out …/informe.txt.enc -pass pass:demo-c05` ·
  `openssl enc -d -aes-256-cbc -pbkdf2 -in …/informe.txt.enc -out …/informe.txt.rec -pass pass:demo-c05` ·
  `sha256sum …/informe.txt` · `sha256sum …/informe.txt.rec`
  *Legítima:* proteger con contraseña un informe con datos de clientes antes de enviarlo por correo es
  una práctica real de oficina (no observada en la receta: **se declara como elegida**). *Guardarraíl:*
  fichero de juguete del propio caso; la contraseña es simbólica y está en el guion (como en ATA001).
  *Coste:* 4 min.
- **C-06 · «Limpio temporales y destruyo un borrador».**
  `rm -rf /home/angel/Documentos/campana_fp/C-06/tmp` · `shred -n 1 -z -u /home/angel/Documentos/campana_fp/C-06/borrador.txt`
  *Legítima:* borrar temporales y destruir un borrador con datos personales es la recomendación de
  cualquier manual de protección de datos. *Guardarraíl:* ambos objetos los crea el propio caso.
- **C-07 · «Sincronizo informes con la carpeta de copias».**
  `rsync -a --delete /home/angel/Documentos/campana_fp/C-07/origen/ /home/angel/Documentos/campana_fp/C-07/destino/`
  *Legítima:* sincronizar la carpeta de informes con la de copias es lo que hace cualquiera que haya
  perdido un fichero una vez. *Guardarraíl:* origen y destino son del caso; `--delete` solo afecta a
  `C-07/destino/`.
- **C-08 · «Normalizo el CSV del informe».**
  `sed -i 's/;/,/g' /home/angel/Documentos/campana_fp/C-08/export.csv` ·
  `sed -n '1,5p' /home/angel/Documentos/campana_fp/C-08/export.csv`
  *Legítima:* cambiar el separador de un CSV exportado para poder abrirlo es la operación ofimática más
  común que existe. *Guardarraíl:* copia propia; el original del informe no se toca.
- **C-09 · «La intranet no responde».**
  `curl -sS --max-time 3 -o …/intranet.html -w '%{http_code}' http://intranet.local:8080/` ·
  `curl -sS --max-time 2 http://intranet.local:8081/` · `timeout 5 curl -sS -o …/reintento.html http://intranet.local:8080/`
  *Legítima:* cuando una web interna no carga, el usuario acota el tiempo de espera, comprueba si el
  puerto responde y reintenta. *Guardarraíl:* solo `GET` a la intranet local y a un puerto **cerrado**
  (no se toca ningún servicio); el 8081 no está publicado (el receptor de ataques usa 9090 y no está
  arrancado en esta ventana).
- **C-10 · «Preparo el lote de plantillas».**
  `seq 1 12 > /home/angel/Documentos/campana_fp/C-10/lotes.txt` ·
  `xargs -a /home/angel/Documentos/campana_fp/C-10/lotes.txt -I{} cp /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/campana_fp/C-10/lote_{}.txt` ·
  `wc -l /home/angel/Documentos/campana_fp/C-10/lote_1.txt`
  *Legítima:* generar N copias numeradas de una plantilla es una operación de lote corriente. *Por qué
  así:* `xargs` **sin `|`** (`-a fichero`), porque el validador prohíbe el pipe y DT9 demostró que
  GHOSTS pierde el reporte (108/111). *Guardarraíl:* 12 ficheros de ~1 KB; se borran en el caso.
- **C-11 · «Dejo constancia en el registro».**
  `logger -t ofimatica 'C-11: incidencia cerrada; copia del dia revisada'` ·
  `tee -a /home/angel/Documentos/campana_fp/C-11/registro.log < /home/angel/Documentos/campana_fp/C-11/nota.txt`
  *Legítima:* anotar en el registro del sistema que se ha cerrado una incidencia. *Por qué así:* `tee`
  **sin `|`** (redirección de entrada). *Valor:* mide el **punto ciego conocido** (`40700`, L0, no
  emite — caso límite L1 de la métrica) en el plano legítimo, no solo en el de ataque.
- **C-12 · «Descargo el manual con `wget`».**
  `wget -q -O /home/angel/Documentos/campana_fp/C-12/manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf`
  *Legítima:* el manual de empleado se descarga con la herramienta que haya; `wget` es la alternativa
  de consola a `curl`. *Guardarraíl:* la URL y el fichero son los que la receta ya usa a diario (d1,
  línea 39: mismo PDF por `curl`).

#### 5.2.4 Comparación: lista v2 (FP-001…FP-012) → lista v4 (C-01…C-12, sin C-04)

| v2 | Destino en v3 | Motivo (con evidencia) |
|---|---|---|
| **FP-001** `systemctl status`, `ps`, `free` | → **C-01** (sin `ps`) | `systemctl` = **10** detecciones (ATA004, ATA038) y `free` = **5** (ATA045): gemelo real. **`ps` no aparece en ninguna** de las 4 107 detecciones: no hay ataque con el que confundirlo. |
| **FP-002** `bash -c 'cd … && ls -la && wc -l'` | **SE CAE** | `bash` **no está** en `BINARIOS_OK` (22 binarios) ⇒ el validador lo rechaza. `ls` y `wc` ya se ejecutan **27** y **46** veces en la receta. Cobertura nueva: **0**. |
| **FP-003** `list-timers` + `crontab -l` | → **C-03** | Se mantiene: `crontab` (10 detecciones, ATA021) y `systemctl` (10) no están en la receta. **Solo lectura**: no dispara `2832`; el caso del TFM hermano que **crea** una tarea programada **no** queda cubierto (se declara, §5.2.7). |
| **FP-004** `journalctl`, `logger`, `tail` | → **C-11** (`logger` + `tee`) | `journalctl` **no aparece** en el corpus (ningún ATA lo usa) y `tail` ya está en la receta. `logger` y `tee` sí (ATA018): son los que aportan. |
| **FP-005** `systemctl list-units` + `ps aux` | **SE CAE** | Duplica C-01/C-03 (**mismo binario**, `systemctl`) y `ps` no tiene gemelo en el corpus. Dos casos con el mismo binario no miden dos cosas. |
| **FP-006** `id`, `whoami`, `uname`, `ip a`, `find` | → **C-02** (solo `ip`) | `ip` = **73** detecciones (ATA054/055). `id`/`whoami`/`uname` **no** aparecen en el corpus; `find` ya está en la receta (5 usos/día). |
| **FP-007** `tar -czf` + `sha256sum` | **SE CAE** | `tar` se ejecuta **5 veces/día** en la receta (d1: líneas 23, 27, 71, 90, 100) y `sha256sum` **21**. La ventana ya cuenta esos FP; el caso solo añadía una etiqueta. |
| **FP-008** `rm -rf` + `shred -u` | → **C-06** (el valor está en `shred`) | `rm` ya está en la receta (1/día); `shred` **no** (ATA005, 2 detecciones) y además produce `80791` (L3, "Deleted"), que la receta apenas genera. |
| **FP-009** `curl` intranet + puerto cerrado + `timeout` | → **C-09** (el valor está en `timeout`) | `curl` ya está (58 acciones/día); `timeout` **no** (**96** detecciones, 5 ATA: 025/045/046/047/048). |
| **FP-010** `seq 1 50 \| xargs …` | → **C-10**, **sin `\|`** | `xargs` es el **60 %** de las detecciones (2 497), pero `seq … \| xargs …` **no pasa el validador** (pipe prohibido; DT9 108/111) ⇒ `xargs -a fichero`. Además 50 copias eran ruido innecesario: 12. |
| **FP-011** `openssl enc` + descifrado | → **C-05** | Se mantiene entero: `openssl` = **16** detecciones (ATA001/019/041), gemelo exacto de T1486. |
| **FP-012** `rsync` + `curl -T` + `PROPFIND` | → **C-07** (solo `rsync`) | `curl -T` y `PROPFIND` se ejecutan **6 veces/día** en la receta (d1: líneas 84, 85, 86, 87, 103, 104). `rsync` **no** (10 detecciones, ATA039/040). |
| — | **C-04 RETIRADA en v4** | La v3 la había añadido para medir `2832` **L5**. La decisión humana es **no mutar**: se retira. **No se sustituye**; T5 por encima de L3 queda sin evidencia propia (§1.9.4). |
| — | **+ C-12** (nueva) | `wget` es el binario de **ATA008 (T1048, exfiltración)** y de ATA043 (T1567.004); la receta no lo usa (6 detecciones). Aporta un binario y dos ATA, **no** una regla nueva. |

**Lo que se queda igual:** la estructura (B6, marcas `inicio`/`fin`, evidencia de efecto obligatoria,
pre-registro firmado antes de `t0`, **publicación aparte de la campaña**, «si alerta es hallazgo»). **Lo que
cambia en v4:** el reparto **3/4/4** (no 4/día) y **11 casos** (no 12), con **jitter de inicio** (§3.1.1).
**v5:** una sola cifra; un solo `M` + tabla aparte.

**Lo que cambia en el método (no solo en la lista):**
1. **Esperado por umbral**, no un «0 alertas» genérico: a `N ≥ 3` **todos** los casos alertan por
   `80792` (H-A); a `N ≥ 7` **ninguno** debe alertar.
2. **Ventana de atribución `[inicio−10 s, fin+60 s]`** (v2: `+300 s`). Con 4 casos en 35 min y 5 min de
   cola, **las ventanas se solapaban** y una alerta podía atribuirse a dos casos. 60 s es **20×** la
   latencia observada en el corpus (ATA021: alerta a los 2 s del `execve`). **v4:** 11 casos en
   **B6 17:05-17:50** con separación ≥ 3 min ⇒ **no hay solape** (CA-27).
3. **Separación mínima de 3 min entre casos** (por lo mismo).
4. **`esperado_cumplido`** (SÍ/NO) en el CSV del runner: si `80792` **no** aparece, el caso **no se
   ejecutó** (o el agente perdió el evento): es un fallo de ejecución, **no** un 0-alerta.

#### 5.2.5 Cobertura de la campaña (medida, no estimada)

| Métrica | v2 | **v4** | Cómo se obtiene |
|---|---|---|---|
| Binarios distintos que la campaña ejecuta | **26** | **17** | unión de la columna «Binarios» |
| De ellos, **sin gemelo en el corpus** (no pueden ser FP de nada) | **6** (`ps`, `bash`, `id`, `whoami`, `uname`, `journalctl`) | **0** | `−` corpus(50) |
| De ellos, **ya en la receta v1** (solo ponen etiqueta) | 9 | **3** (`curl`, `cp`, `rm`) | `∩` receta v1 |
| De ellos, **ya en la receta v2** (solo ponen etiqueta) | — | **12** | `∩` receta v2 |
| De ellos, **marginales de la campaña** (no en la receta v2) | — | **2** (`systemctl`, `crontab`) | `−` receta v2 |
| Cobertura de la **receta v2** | — | **23/50 (46 %)** | `cobertura_exes.py` |
| Cobertura **receta v2 + campaña** | **22/50 (44 %)** | **25/50 (50 %)** | `cobertura_exes.py` |
| Detecciones `80792` de los **14 binarios** (v1 + receta v2 + campaña) | 2 725/4 107 (66 %) | **2 747/4 107 (67 %)** | recuento por `audit_exe` |
| Detecciones `80792` que representa **toda** la campaña | 3 756/4 107 (91 %) | **3 695/4 107 (90 %)** | idem |
| `ATA` con gemelo por binario **marginal** de la campaña | — | **4/55** (ATA004/021/038/045) | unión de `ata` de `systemctl`/`crontab` |
| `ATA` con gemelo en el **conjunto** (v1 + receta v2 + campaña) | 17 / 55 | **23 / 55 (42 %)** | unión de los 14 binarios |

> **La campaña NO sube la cobertura 14 puntos: sube 2.** La receta v2 ya ejecuta **12** de los 14
> binarios "nuevos"; la campaña solo añade **`systemctl` y `crontab`** (lectura). Su valor es la
> **tabla y la atribución**, no la cobertura. La v3 decía "14 nuevos" para la campaña sin distinguir
> v1/v2: era **cierto respecto de v1** y **engañoso respecto de v2** (A-22).

> **La retirada de C-04 no cambia la cobertura:** `crontab` sigue en la lista por **C-03 (solo
> lectura)**; C-04 no aportaba binario nuevo (usaba `crontab`, ya contado) ni `ATA` nuevo (ATA021 ya
> estaba en C-03). Lo que se pierde es la **regla** `2832` L5, no la cobertura de binarios.

> **Nota de conteo:** la tabla maestra **cita 29 `ATA`**; **23** se alcanzan en el **conjunto**
> (v1 + receta v2 + campaña) y los 6 restantes (`ATA009/010/020/023/028/050`) solo por **`curl`**, que
> la receta ya ejecuta 58 veces/día ⇒ **no** cuentan como cobertura nueva. **De esos 23, la campaña
> aporta 4** (los de `systemctl`/`crontab`); los otros 19 vienen de la receta v2. Se dan las cifras
> separadas para que nadie tenga que elegir cuál creer.

> **El resultado contraintuitivo, y conviene decirlo en la memoria:** v2 ejecutaba **26 binarios** y v4
> **17**, pero v4 **cubre más** (22 → 25) porque **6 de los de v2 no existen en el corpus** (no pueden
> confundirse con nada) y **9 ya estaban en la receta** (la ventana ya los medía). *Más binarios no es
> más cobertura.*

> **Corrección de un dato de v2:** el plan dice **49** binarios; el recuento reproducible sobre las
> 4 107 detecciones da **50 basenames** (51 rutas: `git` aparece como `/usr/bin/git` y
> `/usr/lib/git-core/git`). **CA-04 debe fijar el denominador en 50** (o **47** si se excluyen los 3
> binarios que solo existen para el ataque: `credfetch`, `memedit`, `rclone`). El umbral `≥ 22` sigue
> siendo válido; con la campaña se llega a **25**.

#### 5.2.6 Ejecución, aislamiento y pre-registro

- **Dónde:** bloque **`B6` "repaso del sistema" 17:05-17:50Z** (local 18:05-18:50), **declarado** en
  `bloques.env`. **Reparto `3/4/4`:** `d1` = C-01…C-03 · `d2` = C-05…C-08 · `d3` = C-09…C-12.
  **Inicio con jitter fijo** (§3.1.1): `d1` 17:06 · `d2` 17:17 · `d3` 17:11.
- **Cómo se ejecuta:** **por GHOSTS**, como el resto de la receta. B6 se **genera** desde
  `campana/campana_casos.csv` en `d1/d2/d3.json`; **no** hay un segundo runner de ejecución. Las marcas
  son **acciones** del bloque, no un script aparte.
- **Aislamiento:** `~/Documentos/campana_fp/C-XX/`; tope declarado **40 MB**, uso real estimado
  **< 2 MB**; cada caso deja `inicio.txt`, `fin.txt` y `hecho.txt` y **se limpia** (salvo las marcas).
- **Marcas:** `date -u +%FT%TZ > …/inicio.txt` (y `fin.txt`) ⇒ **2 `execve` extra por caso (22 en la
  campaña, 11 casos)**, declarados y contados como acciones de la receta.
- **Orden por caso (rígido):** `inicio.txt` → comandos del caso → **`hecho.txt`** → `fin.txt`. Nada del
  caso se ejecuta **después** de `fin`; si una limpieza necesaria cayera después, se marca como
  **post-caso** y se declara (no entra en la ventana de atribución).
- **Atribución:** alerta del agente `001` (`agent_name = victima-linux`) con
  `timestamp ∈ [inicio−10 s, fin+60 s]`; se cuenta **todo** lo que caiga dentro (incluido el keepalive,
  declarado) y se distinguen `audit_exe`/`rule_id` esperados.
- **Evidencia de efecto (obligatoria):** `hecho.txt` con `RESULTADO=OK` + el predicado de la tabla.
  **Cómo se escribe:** cada caso incluye **una acción de evidencia** (`echo`/`stat`/`ls`/`grep` con
  redirección a `hecho.txt`) que forma parte de la lista literal de `campana_casos.csv`; **cuenta como
  comando** (y como `execve` si no es builtin). *Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un
  0-alerta* (§9.4).
- **Pre-registro:** `campana/casos.md` con **esta** tabla (esperado por umbral + `rule_id`) y su
  `sha256` **fecha anterior a `t0`**; `campana/campana_casos.csv` con **11 filas** y, por caso, la
  **lista literal de comandos** (incluidos los de preparación de insumos) para que el generador y el
  validador usen **la misma fuente**.
- **Validador de campaña:** el mismo `binarios_de`/`BINARIOS_OK` de `construir_receta_legitima.py`
  comprueba los 11 casos: 0 pipes, 0 `sudo`, primer token permitido, rutas `/home/angel`, sin
  `crontab` de escritura, sin `rm` fuera del caso. **CA-27**.
- **Runner de extracción:** `_artefactos/scripts/extraer_campana.py` (+ tests) → `campana_fp.csv` con
  **`caso · ini · fin · nº acciones · nº eventos en la ventana · alertas · rule_id · level ·
  esperado_cumplido`**. **El runner no ejecuta nada**: lee las marcas, cuenta las **acciones** de
  `history_timeline` en `[ini,fin]`, cuenta los **eventos** de la **copia de `archives`** en `[ini,fin]`
  (agente `001`, **solo ficheros únicos del `MANIFEST`**, para no duplicar hardlinks) y cruza las
  alertas de `alertas_detalle.csv`. **No produce un `M` alternativo**: es un recuento **por caso**,
  derivado de las marcas.
- **Honestidad:** si un caso alerta a `N ≥ 7`, **es un hallazgo** (se publica con su `level` y su `P`) y
  **no se re-ejecuta**. Si un caso **no** alerta ni a `N ≥ 3`, el `80792` no llegó: **no se ejecutó**.
- **Volumen (no confundir acciones con `execve`):** **11 casos + 22 marcas**; la tabla lista **25
  comandos GHOSTS** pero **37 `execve`** (los 12 `cp` de `xargs` y el `curl` de `timeout` son hijos).
  Con preparación, **~47-55 acciones GHOSTS / ~59-65 `execve`**. **El número exacto lo fija
  `campana_casos.csv` y se sella en B10.** A `M ≈ 2,4 M`, sus **eventos** son **< 0,05 %**: no mueven
  el denominador, sí el numerador. *No se repite el "64" de la v3: mezclaba acciones y `execve`.*

#### 5.2.7 Qué dice el TFM hermano (leído: Tabla 32 pág. 53, Tabla 35 pág. 63, §4.1 pág. 62, §4.3.4 pág. 87)

Se abrió y se leyó el PDF (`_recursos/reuniones/03/TFM - Velociraptor como HIDS.pdf`, 216 págs.). Lo
verificado y lo que **no** estaba ya en el plan:

1. **Tabla 32 = 10 casos, y son exactamente los 10 que v2 decía haber mapeado** (PowerShell admin, CMD,
   *scheduled task* benigna temporal, registro benigno no persistente, consulta de servicios, discovery,
   ZIP, borrado, HTTP, operaciones masivas). El mapeo nominal **es correcto**.
2. **Pero el mapeo era de nombre, no de mecanismo, en 2 de los 10.** El suyo **FP-003 crea una tarea
   programada temporal** y **FP-004 escribe en el registro y lo deja no persistente**; nuestro FP-003
   solo **leía** `list-timers`/`crontab -l` y el FP-004 solo **leía** logs. Leer un planificador **no**
   se parece a crear persistencia. ⇒ **v2 no cubría esos dos casos aunque dijera que sí.** En v4, el
   **primero NO se cubre**: C-04 (crear + retirar la entrada de cron) **se retiró** por la regla de no
   mutación; se declara como **límite**. El segundo lo cubre **C-11** (una escritura benigna en el
   registro que **no** persiste nada).
3. **Tabla 35 = 10 OK / 0 hits**, y §4.1 lo repite. Pero **§4.3.4 (pág. 88) lo desautoriza como
   estimación**: *«no deben interpretarse como estimaciones de sensibilidad, especificidad o precisión
   en producción. La muestra es pequeña, deliberadamente diseñada y no representa la diversidad de
   comportamiento legítimo de un endpoint real»*. ⇒ El plan acierta al no comparar el número, y ahora
   tiene **cita literal** para decirlo en la memoria.
4. **Y añade un motivo que el plan no tenía:** *«gracias a que estos artifacts son modificables es
   sencillo excepcionar esos falsos positivos»*. Sus 0 hits son, en parte, propiedad de **haber escrito
   él las detecciones y poder ajustarlas**. Nuestro `80792` es una regla **de fábrica** con la bóveda
   congelada: **no se puede exceptuar sin invalidar la medida**. ⇒ «se compara el método» es más débil
   de lo que decía v2: el método **no es transferible** tal cual. Se declara.
5. **El runner revisa la ventana temporal de cada caso en `soc_alerts.jsonl`** y guarda *estado,
   duración, artefactos*: mismo método de atribución que el nuestro (ventana + evidencia), y confirma
   que la columna «duración» y la de «perfil de severidad» (P1-P4) son las que hay que reportar.
6. Aparte de lo anterior —que **corrige dos afirmaciones de v2** (el «ningún caso suyo queda sin
   cubrir» y el «se compara el método»)—, el PDF **no contradice** nada más del plan. **No** hay en él
   ninguna campaña benigna con **11** casos ni medición por umbral de nivel: eso es aportación nuestra.
   *Su FP-003 (tarea programada benigna temporal) queda sin gemelo al retirar C-04: se declara.*

#### 5.2.8 Lo que **no** entra en la lista (y por qué) — detalle en §17

`passwd` (única vía legítima a `550` L7, pero cambia la credencial), `dd` (26 detecciones, 5 ATA, pero
no es actividad de oficina), `git` (40 detecciones, requiere crear un repositorio y `status` no se
parece a un `push`), `sqlite3`/`nc.openbsd`/`perl`/`busybox` (no son actividad de usuario),
`xclip`/`xdotool`/`xwd`/`xwud`/`xinput` (no hay GUI instalada), `mount`/`losetup`/`umount`/`useradd`/
`userdel` (exigen root).

### 5.3 T3 — H1 (instrumentos) + **deploy idempotente** (sin snapshot nuevo) · ~5 h

> **Decisión v4 (humano):** **no se crea snapshot nuevo si no es imprescindible.** El `cwd`, la receta
> v2, `bloques.env`, la campaña y la unit se **despliegan** con `deploy_client.ps1` sobre un revert de
> **`lab-listo-legit-v2`**, que **se conserva intacto** y es el punto de retorno. Si E0 demuestra que el
> deploy **no** es idempotente (dos intentos fallidos), **entonces** se justifica un snapshot v3 y se
> pide OK; no antes.

1. **H1(a) gracia de borde** (`legitimo_host_control.ps1` ~465): si el bloque empezó hace **< 15 min** y
   `doing_age > 35`, **no** se juzga (nota `gracia_borde`). Dos pruebas en seco (inicio de bloque y
   reanudación tras pausa). *El umbral de AVISO sube a **25 min** (§7.3).*
2. **H1(b) primer chequeo**: sembrar el estado (`archives`/`alertas`/`df`) **en `prep`**, para que el
   chequeo de `t0` no salga `AVISO` (`sin_df`, `arch=-1B`).
3. **H1(c) `cleanup` sin SSH**: si la VM está apagada, **saltar** la fase remota (el hueco inofensivo de
   3 min que documentó v2).
4. **H1(d)** dejar escrito que la rotación es **post-hoc** y que su fallo se juzga en V2 (no se añade señal).
5. **`deploy_client.ps1`**: receta v2, `bloques.env` (con B6), `campana_fp/`, `cwd`, unit y
   `client_ctl.sh`; **idempotente** (aplicar dos veces deja el mismo `sha256`) y **reversible** (revert
   a v2). **Sin snapshot nuevo.**
6. **Pruebas en seco ×2**: `exit≠0` no corta la ráfaga · los **14** binarios nuevos existen y corren · el
   `cwd` es el esperado **y** `app.log`/`client.out` siguen donde deben · **11/11 casos y 22/22 marcas**
   de campaña · **no mutación** (`crontab -l` sin cambios) · **0 accesos del host** al invitado.
7. `sha256sums.txt` + `b10_sellado.md` (**v3**). **No** hay `snapshot_v3.md`; hay **`deploy_v5.md`** con
   la tabla "qué cambia respecto a v2" y el `sha256` de cada artefacto desplegado.

### 5.4 T4 — E0, tareas, WU, **y fijación de fecha**  · ~2,5 h

`pausar_windows_update.ps1 pausar` → `wuauserv` **Disabled** · borrar `%TEMP%\opencode\tfg_watch_estado.json` ·
**E0** (§6) · **fijar `t0`** por la regla §3.2 y registrar las 4 tareas con `NextRun` **en UTC** verificado ·
escribir la fecha en `state.md`/`ventana_meta.md`.

## 6. E0 — ensayo de armado (obligatorio)

| Paso | Qué se hace | Pasa si |
|---|---|---|
| **E0-1** | **`sudo -n true`** (solo comprobar; **no** se usa en la receta) | se **registra** el resultado (no bloquea) |
| **E0-2** | **Binarios**: `command -v` de los **22 de la lista blanca + 14 nuevos** (incl. `wget`) | **36/36** presentes (si falta alguno ⇒ se cae **esa** herramienta de la receta/campaña, con nota) |
| **E0-3** | `prep -T0 <T0_falso>` con receta v2 + `deploy_client` **v5** | `Res=0`; **G-1…G-12** en `OK`; `--check` con los conteos nuevos; **idempotencia** (2.ª aplicación = mismo `sha256`) |
| **E0-4** | **`cwd`**: ejecutar 3 acciones y leer `audit_cwd` en el manager | `cwd=/home/angel` (**no** `ghosts-client`); `app.log` y `client.out` en su ruta y creciendo |
| **E0-5** | `arm -T0 <T0_falso = ahora+25 min>` | timer `NEXT = T0_falso−5` **en UTC**; 1 proceso; `recovery.log` vacío |
| **E0-6** | 20 min de receta real + **un día comprimido de campaña (3 casos, `d1`)** | acciones según lo previsto; **`exit≠0` no corta**; **6/6 marcas** (3 casos × 2); `campana_fp` **generable**; **0 mutación** (E0-9) |
| **E0-7** | **Borde** del `watch` (2 chequeos en un inicio de bloque) y **primer chequeo** | `estado=OK` con `gracia_borde`; **sin** `AVISO` inicial |
| **E0-8** | `stop` + `cleanup` **con la VM apagada** | sin intento de SSH; 0 procesos; `logall_json=no`; `CONFIG_IDENTICA` |
| **E0-9** | **No mutación de la campaña**: tras el ensayo comprimido, `crontab -l` **idéntico** al de antes y `find` de estado **sin** ficheros fuera de `campana_fp/` | `diff` de `crontab -l` y listado de estado; **0** cambios |
| **E0-10** | Revert a `lab-listo-legit-v2` y dejarlo apagado | **5 snapshots**; 0 VMs; `verificar_arreglos.sh` = `PASS` |

- **Registro:** `ensayo_E0_v5.md` (salida literal, horas UTC, veredicto).
- **Antigüedad:** E0 **≤ 7 días** antes de `t0`; si no, **se repite**.
- **Coste:** ~60-75 min. **No ensucia** (se revierte).

## 7. Ejecución: arranque, vigilancia y disciplina

### 7.1 Tareas (nada a mano)

| Tarea | Ámbito | Cuándo (**UTC**) | Qué hace |
|---|---|---|---|
| **`TFG-Legit-Prep`** | host | `t0−45 min` | revierte a **`lab-listo-legit-v2`**, enciende, **despliega v4** (idempotente), `logall_json` ON, G-1…G-12, **siembra del `watch`** |
| **`TFG-Legit-Arm`** | host | `t0−20 min` | instala timer (`t0−5`), arranca cliente, checklist |
| **`TFG-Ghosts-Legit`** | invitado | `t0−5 min` | keepalive v3 (74 h; muere con la VM) |
| **`TFG-Legit-Watch`** | host | cada 30 min desde `t0` | 9 señales + gracia de borde (**no toca la víctima**) |
| **`TFG-Legit-Stop`** | host | `t1+10 min` (**tope `t1+15`**) | **espera `cosecha.done`** y para la víctima; el manager sigue |

### 7.2 Disciplina dentro de `[t0,t1]`

1. **CERO** acceso a `victima-linux` (SSH, consola, `vmrun`, snapshots).
2. El manager se consulta **solo lectura** por el `watch`.
3. **Ninguna** configuración se cambia dentro de la ventana.
4. El PC no se apaga, no se suspende y **no se cierra sesión** *(compromiso del humano, 2026-10-27)*.
5. **No se aborta por realismo** (§3.4).

### 7.3 Vigilancia (9 señales de v2 + gracia de borde)

`doing` (con **gracia de 15 min al inicio de bloque**), latido, daemons, entrada de eventos, **disco de la
víctima (valor y tasa)**, disco del host, BD de GHOSTS, recuperaciones/rotaciones (post-hoc), RAM
(post-hoc). **Umbrales v4 (corrigen la incompatibilidad con el ritmo):**

| Señal | AVISO | ALARMA | Por qué |
|---|---|---|---|
| **`doing_age`** (solo dentro de bloque, `legitimo_host_control.ps1:465-467`) | **> 25 min** | **> 35 min** | El hueco máximo de la receta es **22 min**; 25 deja **3 min** de margen y 35 evita que un hueco normal sea ALARMA. **El umbral de 15 min de v2 era incompatible** (A-3) |
| **`STALE` del keepalive** (`tfg_keepalive.sh:34`) | — | **30 min** (sin cambio) | 22 min + caché de 5 min = **27 < 30**; con `GRACIA=15` y `CONFIRMA=5` no hay recuperación espuria |
| **`sin_eventos`** (2 chequeos con delta 0 dentro de bloque) | — | 2 seguidos | Con hueco máximo 22 min, **ningún intervalo de 30 min** puede quedar a cero salvo borde; la gracia cubre el inicio |

`B6` entra en el calendario como **bloque declarado** (17:05-17:50Z) para que V2 no lo vea como "fuera
de bloque" y para que `doing_age` se evalúe con su ventana.

### 7.4 Chequeo diario y aborto temprano

1. Últimas 3 líneas del log de vigilancia · 2. uptime del host anterior a `t0` y 0 `Kernel-Power` 42/107 ·
3. `wuauserv` `Disabled`, `vmrun list` con 2 VMs, `D:` ≥ 60 GB · 4. `ALARMA` ⇒ se avisa y **se decide**.
**Aborto temprano** (primeras 24 h) solo por **invalidez objetiva** (§9.3).

## 8. Extracción (después de `t1`)

> **Orden crítico:** **cosechar → marcar `cosecha.done` → parar → copiar → contar `M` (único) →
> `logall_json off`** (`off` **borra** `archives.json`). Nombres reales:
> **`ossec-archive-NN.json[.gz]`** (singular).

| Momento | Paso | Producto |
|---|---|---|
| **`t1+2 min`** | **Cosecha** (ÚNICA sesión SSH al invitado, ya fuera de ventana): parar timer+cliente; `scp` de `recovery.log`, `keepalive.log`, `client.out`, `id.json`, `rotacion.estado`, `timeline.json`, **`errores.log`**, `campana_fp/**/{inicio,fin,hecho}.txt`, `crontab -l`, `ip route`, `df -h /`; al terminar, **crear `cosecha.done` en el host** | `ventana_*/evidencia/*.txt` + `ventana_*/cosecha.done` |
| **`t1+5`** | **Ventanas de campaña**: `extraer_campana.py --solo-ventanas` lee las 22 marcas y escribe `campana_ventanas.tsv` (`caso · ini · fin`) | `campana_ventanas.tsv` |
| **`t1+10`** | **Parada** soft de la víctima (**solo si `cosecha.done` existe**; tope `t1+15`) | — |
| **`t1+15`** | `exportar_denominador.sh info` | log |
| **`t1+30`** | `copiar-ventana t0 t1` (3 `.gz` + `.sum` + planos + vivo) + `MANIFEST.tsv` + **dedupe `sha256`**; `scp` **fuera del repo** | `D:\TFG-VMs\legitimo-<t0>\denominador\` |
| **`t1+45`** | **Puerta**: `MANIFEST` existe, vivo copiado, `sha256` cuadran. **Si no: NO se apaga `logall_json`** | checklist |
| **`t1+45…+55`** | **`M` único**: `contar_denominador.py --estricto --manifest --boveda-version 2` sobre `[t0,t1]` | `denominador_M.csv` |
| **`t1+60`** | **`logall_json off`** + `status` + `diff` `CONFIG_IDENTICA` | — |
| **`t1+70`** | **Alertas** de los 3 diarios (`extraer_alertas.py`) | `alertas_detalle.csv`, `ruleids_legitimos.csv` |
| **`t1+80`** | **Acciones** (`exportar_acciones.sh`, con **MC-1**), invocando la salida en `ventana_<t0>/` | `ghosts_acciones.csv` |
| **`t1+90`** | **Tabla de campaña** (`extraer_campana.py`, por marcas) | `campana_fp.csv` |
| **`t1+100`** | `sha256` de cada producto + `MANIFEST.md` | — |

**Borde y dedupe:** `[t0,t1]` inclusivo · 3 `.gz` = `[t0,t1)` · el vivo solo aporta `timestamp = t1`
exacto (si aporta más, **se investiga**) · `archives.json` es **hardlink** ⇒ dedupe `sha256` ·
`--estricto` aborta (`exit 3`) si dos ficheros únicos solapan. **Presupuesto:** ≈10 MB/h ⇒ **~720 MB**.

**Un solo `M` y una tabla de campaña (decisión v5):**
- **`M`** = **`[t0,t1]` completo**, con la campaña dentro. Es el **titular** (métrica §2: `M` es la
  ventana). **No** se calcula un `M` alternativo ni se fabrica una segunda cifra.
- **`campana_fp.csv`** = **tabla por caso** con `caso · ini · fin · nº acciones · nº eventos en la
  ventana · alertas · rule_id · level · esperado_cumplido`. Los recuentos salen de las **marcas**:
  acciones de `history_timeline` en `[ini,fin]`; eventos de `archives` en `[ini,fin]` (agente `001`);
  alertas de `alertas_detalle.csv` en `[ini−10 s, fin+60 s]`.
- **No hay corte alternativo**: los **huecos entre casos** y el keepalive que caiga dentro de una
  ventana **pertenecen a la ventana completa**; la tabla de campaña solo cuenta `[ini,fin]` de cada
  caso. Se declaran; **no se resta nada** de `M`.

## 9. Validez: V1–V8 y qué invalida la ventana (y qué **no**)

> **Regla de no-invalidación (decisión humana, §18):** un fallo de la **campaña** solo la descarta a
> **ella**; **nunca** invalida la ventana. Por eso V9 **sale** de los criterios de ventana.

### 9.1 Criterios de la VENTANA (se cumplen **todos**)

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **V1 — Cobertura** | primera alerta del `001` ≤ `t0+10 min`; última ≥ `t1−10 min`; **ningún hueco > 30 min** | `alertas_detalle.csv` |
| **V2 — Actividad** | cada día ≥ **90 %** de su receta (**contra `--check`**); **0 acciones fuera de los bloques** de la tabla **congelada** (`bloques.env` con **B6 17:05-17:50**, `sha256` en el manifiesto **antes de `t0`**), salvo recuperaciones declaradas | `ghosts_acciones.csv` + `bloques.env` |
| **V3 — Manager y diarios** | manager `active` en todos los chequeos; los **3 diarios** existen y crecen | log de vigilancia |
| **V4 — 0 contaminación** | **0** filas con `srcip = 192.168.65.1`; **0** sesiones del operador | `alertas_detalle.csv` + log host |
| **V5 — Aislamiento** | NAT off; la víctima solo habla con la "internet local" | `ip route` sin `default` + `web_access.log` |
| **V6 — `M`** | copiado **antes** de `off`; `--estricto` con `exit 0`; `MANIFEST` con `sha256`; **un solo `M`** sobre `[t0,t1]` | `denominador_M.csv` + `MANIFEST` |
| **V7 — Sin cambios a mitad** | `sha256sums.txt` coherente antes/después (salvo MC-1); `CONFIG_IDENTICA`; `git status` acotado. *Excepciones declaradas:* (a) ficheros que **crean y borran** los casos, **todos** bajo `campana_fp/`; (b) **una línea** de journal de C-11; (c) `web_access.log` de la intranet (fuera de la víctima) | recálculo + `diff` |
| **V8 — Host estable** | `LastBootUpTime` < `t0`; 0 `Kernel-Power` 42/107 | WMI + `Get-WinEvent` |

### 9.2 Válida **con incidencia** (solo ventana)

1-2 recuperaciones del cliente (sin huecos > 30 min sin explicar) · una rotación fallida · duplicados por
recuperación (contados) · fallo de la herramienta de extracción con fuente íntegra (se re-extrae).
**La campaña no aparece aquí:** tiene su propia escala (§9.4).

### 9.3 Qué **invalida la ventana** (⇒ se repite entera)

1. Acceso del operador a la víctima en `[t0,t1]` · 2. agente caído o hueco > 60 min · 3. manager caído
   más de 30 min o falta un diario · 4. `M` no recuperable · 5. un bloque de trabajo entero sin acciones ·
6. reinicio/suspensión/cierre de sesión · 7. cambio de configuración no declarado · 8. más de 2
recuperaciones o `ALARMA` de disco/agente sin explicar.

> **Lo que NO invalida la ventana:** ningún fallo de la campaña (casos no ejecutados, `hecho.txt`
> ausente, solape de ventanas, alerta inesperada, `2832` que no aparece...). Eso se resuelve en §9.4.

### 9.4 Validez de la CAMPAÑA (independiente de la ventana)

| # | Criterio | Resultado si falla |
|---|---|---|
| **C1 — Ejecución** | **≥ 9/11** casos con `inicio` y `fin` y `hecho.txt` | Campaña **parcial**; se publica lo ejecutado y se marca `NO_EJECUTADO` el resto |
| **C2 — Atribución** | ventanas `[ini−10 s, fin+60 s]` **sin solape** entre casos; `campana_fp.csv` con 11 filas (o las ejecutadas) | Campaña **no concluyente**; se publica el CSV con la incidencia |
| **C3 — Esperado** | cada caso con `esperado_cumplido` SÍ/NO; un `NO` a `N ≥ 3` ⇒ **caso no ejecutado** (no 0-alerta) | Se reclasifica el caso; **no** se re-ejecuta |
| **C4 — No mutación** | `crontab -l` idéntico antes/después; 0 ficheros fuera de `campana_fp/` | Campaña **inválida como campaña** (se retira del catálogo); **la ventana sigue** |

**Escala de la campaña:** **completa** (≥ 9/11 con evidencia) · **parcial** (5-8/11) · **no concluyente**
(< 5/11 o C2/C4 fallan). En los tres casos, **la ventana se publica igual** con la etiqueta que toque
(§18).

### 9.5 El titular (una sola cifra)

**El titular es la ventana completa** (la métrica congela `M` sobre `[t0,t1]`). **La campaña se reporta
aparte** con sus propios recuentos, que salen de sus marcas de tiempo. **No se publica una segunda cifra
de FPR**: `M` es uno solo y la tabla de campaña no lo modifica.

## 10. Sellado B10 v5 y versiones

| Elemento | Qué se sella (**medido**) |
|---|---|
| Ventana | `t0`/`t1` firmados, 72 h, 3 días, medianoche UTC |
| **Receta v2** | `sha256` de `d1/d2/d3` + calendario + `bloques.env` (congelado, **con B6 17:05-17:50**) + **conteos `--check`** + **tabla de jitter literal** + **cobertura de binarios n/50** |
| **`cwd`** | valor real medido (p. ej. `/home/angel`) y cómo se arranca el cliente |
| **Campaña** | `sha256` de `campana/casos.md` **con fecha anterior a `t0`** + `campana_casos.csv` (**11 filas**, comandos literales) + `campana_ventanas.tsv` + **horas de inicio por día** (§3.1.1) |
| **`errores.log`** | `sha256` + **conteo de `exit≠0` y reintentos** + muestra (T1) |
| **Deploy** | `sha256` de `deploy_client.ps1` y de los ficheros desplegados; **idempotencia** (2 aplicaciones = mismo hash) |
| Versiones | GHOSTS 8.3.1 (`4d2e160…`) + **`sha256` del binario del cliente** · Wazuh 4.14.7-1 · PostgreSQL · .NET 8 |
| Instrumentación | `logall_json` ON solo `[t0,t1]`; rotación `ossec-archive-<DD>.json.gz`; `--estricto`; **`M` único** |
| Lo que actúa dentro | recuperaciones / rotaciones / arranques **reales** + **campaña** (declarada, no mutante) |
| Medida | **`M` único (ventana completa)**, MB, eventos/h, **acciones/día reales**, alertas, `rule.id`, **tabla de campaña por caso** |
| **`sudo`** | **no se usa** (declarado); resultado de la comprobación de E0-1 |
| Navegador | `receptor_navegador=none` |
| Snapshot | **no se crea**; base **`lab-listo-legit-v2`** + deploy idempotente (§5.3) |
| Versiones de medida | `metrica_version=1`, **`boveda_version=2`** |

`boveda_version` → **2 en un solo paso y en tres sitios** (humano/orquestador): `boveda_congelacion.md`
(B10 + `version: 2`) · recalcular `boveda_congelacion.sha256` · `metrica_hids.py` `VERSION_BOVEDA = 2` +
`pytest -q`. **MC-1** (`exportar_acciones.sh`: versión de bóveda por parámetro, defecto 1) sigue pendiente
de v2 y entra aquí.

> **Reconciliación del sidecar (A-10):** `b10_sellado.md` ya está escrito como **v2**
> (`:1,12-13,62`), pero la fuente de verdad `boveda_congelacion.md` sigue en **v1** (`:4`) y
> `metrica_hids.py:36` en `1`. En este bloque el sidecar se reescribe **v3** (contenido de la ventana
> v5: receta v2, `cwd`, 11 casos, `M` único + tabla de campaña, `errores.log`, sin snapshot) y el bump a
> **2** se aplica **solo al cerrar**, en los 3 sitios. Hasta entonces, **la versión vigente es 1** y así
> se declara en cada CSV.

## 11. Riesgos y mitigaciones

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| **R1** | **Tercer aborto** por "no me parece realista" | 3 días perdidos | **§3.4** + criterio fijado antes |
| **R2** | T1-T3 se eternizan (sin fecha, se diluye) | Se pierde el año | **Tope de trabajo por tanda** (§5) + corte: si en 3 sesiones no cierra T1, se recorta a **`cwd` + campaña** (las 2 de mayor valor) |
| **R3** | **`cwd`** rompe rutas de `app.log`/`config` | Ventana sin logs | **E0-4** lo detecta en 2 min; **plan B**: prefijo `cd` |
| **R4** | `jitter` rompe el keepalive (`STALE=30`) o la señal 1 | Recuperación espuria / AVISO falso | Hueco **≤ 22 min** + **AVISO 25 / ALARMA 35** (§7.3) + prueba del peor caso |
| **R5** | Un comando con `exit≠0` **corta** la ráfaga | Bloque sin acciones ⇒ V2 | **E0-6** |
| **R6** | Un binario nuevo **no está** | Se cae la herramienta | **E0-2** (**36** `command -v`); **no se instala** |
| **R7** | La campaña dispara reglas de nivel alto | "Sorpresa" | **Es el objetivo**; esperado pre-registrado |
| **R8** | La campaña llena el disco | Repite L1 | ≤ 40 MB + limpieza por caso + señal 5 |
| **R9** | **Windows Update** se auto-repara y reinicia | V8 | Re-pausar en T4 **y en la tarde de `prep`** + política 1/1 + chequeo diario |
| **R10** | Agente `001` cae | Sin `M` ni alertas | Tope de log 40 MB + señal 2 + señal 5 |
| **R11** | `logall_json off` antes de copiar | **`M` perdido** | Orden §8 + puerta `t1+45` |
| **R12** | El humano toca la víctima | V4 | Regla dura + V4 |
| **R13** | Conteos viejos (111/117/105) hardcodeados | V2 mal juzgado | `Select-String` en T1; todo lee de `--check` |
| **R14** | E0 envejece (> 7 días) | Arranque sin ensayo válido | Regla §3.2.4: se repite E0 |
| **R15** | **`~/Documentos` crece** (errores + campaña + copias) | Disco de la víctima | Señal 5 + tope de campaña; si `< 3 GB`, aviso |
| **R16** | **La campaña deja estado** (crontab, `/etc`, servicios) | V7 / campaña inválida | **C-04 retirada**; C4 de §9.4 + **E0-9** (`crontab -l`, `find`) |
| **R17** | **B6 fuera de `bloques.env`** o marcas fuera del bloque | V2 falla por diseño | Generador escribe B6 17:05-17:50; `--check` lo valida; **CA-27** |
| **R18** | **`stop` mata la VM a mitad de la cosecha** | Evidencia perdida | `cosecha.done` + `stop` a `t1+10` (tope `t1+15`) |
| **R19** | **La campaña sube el contador** (alertas/acciones) y se lee como "más FP" | FPR mal interpretado | **`M` único + tabla de campaña aparte** (§9.5) + `FP/acción` sobre la ventana + etiqueta por caso |
| **R20** | **La hora de campaña pisa B5** | Bloque solapado / V2 | Jitter **solo 17:05-17:20**; decisión (c) §3.1.1; 16:30/16:45 **descartadas** |
| **R21** | **`errores.log` crece** o se pierde | Producto no sellable | Tope + rotación declarada; `sha256` y conteo en B10 |
| **R22** | **Deploy no idempotente** (sin snapshot) | `prep` deja la VM a medias | **E0-3** (2 aplicaciones = mismo hash); si falla 2 veces, **snapshot v3 con OK humano** |
| **R23** | **La extracción de campaña cuenta el keepalive** o alertas ajenas | Conteo por caso inflado | Ventana por marcas + `audit_exe`/`rule_id` esperados; **se declara** todo lo que caiga dentro |

## 12. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-01** | **Receta v2**: `--check` PASS con conteos nuevos; 0 `random`; 0 pipes; 0 `Browser*`/`Curl`; **dos generaciones byte-idénticas** | `--check` + `sha256` ×2 |
| **CA-02** | **Ritmo**: hueco máximo ≤ **22 min**, mínimo ≥ **40 s**; ≥ 2 pausas largas/día; ningún patrón periódico exacto de ≥ 5 huecos iguales; **`CAP_HUECO_S=1320`** y una sola regla `>22 min` falla | análisis del JSON |
| **CA-03** | **Errores**: ≥ **8/día** con `exit≠0` declarado y **reintento correcto** posterior; **`errores.log`** con `sha256` y conteo | receta + `errores.log` + prueba en seco |
| **CA-04** | **Cobertura de binarios del corpus**: **receta v2 = 23/50** y **conjunto con campaña = 25/50** (script contador, salida literal); umbral mínimo **≥ 22/50** | `cobertura_exes.py` |
| **CA-05** | **`cwd`**: 100 % de las acciones con `audit_cwd` **≠** `/home/angel/ghosts-client`; valor declarado en B10 | `alertas_detalle.csv` / E0-4 |
| **CA-06** | **Campaña definida ANTES**: **11 casos** con **esperado por umbral** (`N ≥ 7` y `N ≥ 3`), `rule_id` esperados, **comandos literales** y `sha256`, **con fecha anterior a `t0`** | `git log`/`sha256`/`campana_casos.csv` |
| **CA-07** | **Sin snapshot nuevo**: **`lab-listo-legit-v2` intacto** (5 snapshots); **deploy idempotente** (2 aplicaciones = mismo `sha256`) y reversible | `vmrun listSnapshots` + `sha256` ×2 |
| **CA-08** | **E0 PASS** completo (E0-1…E0-**10**) y **≤ 7 días** antes de `t0` | `ensayo_E0_v5.md` + fecha |
| **CA-09** | **Ventana**: `prep`/`arm` a su hora (±5 min); `stop` a `t1+10` (tope `t1+15`, tras `cosecha.done`); duración **72 h ± 1 min** | log + `keepalive.log` + `cosecha.done` |
| **CA-10** | **Cero acceso** a la víctima en `[t0,t1]`; **0** filas `srcip=192.168.65.1` | log + CSV |
| **CA-11** | **144 chequeos** (±2), **0** `ALARMA` no explicada, **0** falsas alarmas de borde, **0** `AVISO` en el primero, **0** `AVISO` por huecos (máx. 22 < 25) | log de vigilancia |
| **CA-12** | **3 diarios** presentes y crecientes; V1 | ficheros + CSV |
| **CA-13** | **Acciones** ≥ 90 % de la receta por día y **0** fuera de bloques congelados sin explicar (**B6 incluido**) | `ghosts_acciones.csv` |
| **CA-14** | **`M` único** (`.gz`+vivo, dedupe, `--estricto`, `exit 0`) **antes** de `off`, sobre `[t0,t1]` completo; **sin** segunda cifra | `denominador_M.csv` + `MANIFEST` |
| **CA-15** | **Campaña 11/11** (o ≥ 9/11, §9.4) con `hecho.txt` (evidencia de efecto) y `esperado_cumplido`; tabla alerta sí/no por caso y por `N ∈ {0,3,7,10,12}` + **severidad P** (+ **0** alertas `N ≥ 7` salvo hallazgo declarado) | `campana_fp.csv` |
| **CA-16** | **Tabla de campaña propia y separable**: `caso · ini · fin · nº acciones · nº eventos en la ventana · alertas · rule_id · level · esperado_cumplido`; el **titular es la ventana completa** y **no se publica un FPR alternativo** | `campana_fp.csv` + `campana_ventanas.tsv` + `denominador_M.csv` |
| **CA-17** | **`logall_json=no`** y `CONFIG_IDENTICA` al cerrar; ruleset con la misma huella | `diff` + huella |
| **CA-18** | **Copia cruda fuera del repo** con `sha256` por fichero y totales que cuadran con `M` | `MANIFEST.tsv` |
| **CA-19** | **B10 v5** con receta v2, `cwd`, campaña (11), `errores.log`, deploy, `sha256` del binario y `boveda_version=2` en los **3** sitios | `b10_sellado.md` + `pytest` |
| **CA-20** | **MC-1** aplicado (1 línea) y `pytest -q` verde | `git diff` + salida |
| **CA-21** | **Promoción a `Dataset/` solo si VÁLIDA**; ficha inválida anterior archivada con `sha256` | `git status` + ficha |
| **CA-22** | **Cero daño colateral**: `git diff --stat` vacío en `Soporte/Metrica/`, `Hojas/`, `_recursos/`, corpus y `Dataset/` (salvo CA-21) | `git status` |
| **CA-23** | **Sin secretos**; `TFG_GUEST_PW` **retirada** al cerrar | `Select-String` + entorno |
| **CA-24** | **Laboratorio cerrado**: 0 VMs, 0 `TFG-Legit-*`, 0 reglas `TFG-*`, GHOSTS/internet local parados, WU restaurado | `vmrun`, tareas, firewall, `Get-Service` |
| **CA-25** | **Piloto de 39 h intacto** y **no leído** | `sha256` del manifiesto preservado |
| **CA-26** | **Plan en git** desde la aprobación | `git log -- plan.md` |
| **CA-27** | **Campaña válida**: 11 casos con **comandos literales**; `--check` PASS con el **mismo** `binarios_de`/`BINARIOS_OK`; 0 pipes; 0 `sudo`; **B6 en `bloques.env`**; ventanas de atribución **sin solape** | `campana_casos.csv` + `--check` + `campana_ventanas.tsv` |
| **CA-28** | **No mutación**: `crontab -l` **idéntico** antes/después; **0** ficheros de estado fuera de `campana_fp/`; **0** escrituras en `/etc`/servicios | E0-9 + `git status`/`find` |
| **CA-29** | **Horas de campaña**: inicios `17:06 / 17:17 / 17:11` UTC, dentro de B6 17:05-17:50; **sin solape con B5** | `bloques.env` + marcas |
| **CA-30** | **Umbrales de vigilancia**: `AVISO=25`, `ALARMA=35`, `STALE=30`; **0** AVISO por hueco de 22 min en la prueba del peor caso | `legitimo_host_control.ps1` + `tfg_keepalive.sh` + log |
| **CA-31** | **`exportar_acciones.sh`** escribe en `ventana_<t0>/` (no en `Dataset/`); promoción solo si VÁLIDA | rutas + `git status` |
| **CA-32** | **`stop` espera `cosecha.done`** (tope `t1+15`); la evidencia está copiada antes de apagar | log + `cosecha.done` |

## 13. Cómo se verifica (tester)

1. **Determinismo**: generar dos veces y comparar `sha256`; `--check` PASS; 0 `random`/`Curl`/`Browser*`;
   hueco máx ≤ 22 min, mín ≥ 40 s; `CAP_HUECO_S=1320`.
2. **Cobertura**: ejecutar `cobertura_exes.py` y comprobar **receta v2 = 23/50** y **conjunto = 25/50** (umbral ≥22) con salida literal.
3. **`cwd`**: `Select-String` de `audit_cwd` sobre una muestra de `alertas_detalle.csv`: **0** filas con
   `ghosts-client`; y comprobar en el invitado que `app.log`/`client.out` siguen en `$DIR`.
4. **Campaña**: **11 filas** con **esperado por umbral**; `sha256` con fecha anterior a `t0`;
   `campana_fp.csv` con **11 filas** (o las ejecutadas, §9.4), **evidencia de efecto** (`hecho.txt`),
   `nº acciones`, `nº eventos`, `rule_id`, `level` y `esperado_cumplido` en cada una; **0 alertas
   `N ≥ 7`** salvo hallazgo declarado con su `level` y su `P`; **0 mutación** (`crontab -l`, `find`).
5. **E0**: leer `ensayo_E0_v5.md` (E0-1…E0-10) y su fecha frente a `t0`.
6. **Ventana**: recalcular **V1–V8**; `grep -c gracia_borde` ≥ 1 y **0** `ALARMA` sin explicación;
   **V9/C1–C4** aparte (§9.4).
7. **Extracción**: `--estricto` con `exit 0`; `MANIFEST` cuadra; orden correcto antes del `off`;
   **un solo `M`** (sin segunda cifra), `campana_ventanas.tsv` sin solapes y `campana_fp.csv` con sus
   recuentos por caso.
8. **Bóveda**: `pytest -q` verde; `boveda_congelacion.sha256` recalcula; `VERSION_BOVEDA == 2`.
9. **Higiene**: `git status` acotado; 0 secretos; laboratorio cerrado; piloto intacto; **5 snapshots**.

## 14. Gate humano (lenguaje sencillo)

> **Qué te pido.** Dejar el ordenador encendido **tres días** (cuando todo esté listo: un lunes, martes
> y miércoles) mientras un programa hace **una jornada de oficina creíble** —con prisa, algún error y
> reintento, los mismos programas que usan los ataques y desde una carpeta normal— y, al final de cada
> día, **once acciones que parecen peligrosas pero no lo son**. Después contamos cuántas veces se
> equivoca Wazuh. **El compromiso de los 3 días ya está dado (27/10): no se vuelve a preguntar.**

**Decisiones ya cerradas (no se preguntan):** campaña **DENTRO** de la ventana; **11 casos no
mutantes** (C-04 retirada: nada de `crontab`); sin segundo usuario; sin actividad **de usuario**
nocturna; sin instalar; **sin snapshot nuevo** (se despliega sobre `lab-listo-legit-v2`, y solo si el
deploy falla dos veces se pediría un snapshot); **3 días**.

**Las 4 condiciones de la campaña (escritas y verificables):**

1. **Expectativa pre-registrada** por caso **antes** de `t0`: `campana/casos.md` + `campana_casos.csv`
   con `sha256` y fecha anterior (`CA-06`).
2. **Marcas de inicio/fin** por caso (`inicio.txt`/`fin.txt`), que permiten **separarla** (`§5.2.6`,
   `§9.4`).
3. **Se publica aparte**: la campaña tiene su **tabla propia** con sus recuentos; **no** se fabrica un
   FPR alternativo (`§9.5`, `CA-16`). El titular es la **ventana completa**.
4. **No-invalidación**: un fallo de la campaña **solo la descarta a ella**; **nunca** invalida la
   ventana (`§9.3`, `§9.4`, `§18`).

1. **Qué se va a hacer.** Construir y probar la receta v2 y la campaña; **desplegar** el cambio de
   `cwd`/receta/campaña sobre `lab-listo-legit-v2` (sin snapshot nuevo); ensayar el armado; correr 72 h
   automáticas y copiar los datos **antes** de apagar la instrumentación.
2. **Qué necesito que firmes (solo lo que no estaba cerrado):**
   - **Q1. ¿Apruebas las 5 mejoras?** `cwd` realista, ritmo irregular **fijo**, errores con reintento,
     **herramientas elegidas por el corpus** (de 11 a **23/50 en la receta**; **25/50** con la campaña) y
     **campaña de 11 casos**. **No se instala nada y no se amplía el disco.**
   - **Q2. ¿Apruebas la cláusula anti-aborto?** Solo se para por un fallo **objetivo**, no porque los
     datos "podrían ser más realistas".
   - **Q3. ¿Apruebas que la fecha se fije al cerrar T4** por la regla "primer lunes→miércoles con ≥ 48 h
     de margen", y que **E0** se repita si tiene más de **7 días**?
   - **Q4. ¿Apruebas `boveda_version` → 2** en un solo paso (bóveda + huella + módulo) y el micro-cambio
     **MC-1** de 1 línea?
   - **Q5. ¿Apruebas que los datos se publiquen en `Dataset/` solo si la ventana es VÁLIDA?**
   - **Q6. ¿Apruebas que el plan se guarde en git al aprobarse?**
3. **Qué NO vas a ver.** No habrá análisis ni FPR todavía. **No se analiza el piloto de 39 h.**
4. **Qué puede salir mal.** (a) Que las tandas se dilaten: si T1 no cierra en 3 sesiones, se recorta a
   **`cwd` + campaña**; (b) que el `cwd` rompa un log: **E0 lo ve en 2 minutos** y hay plan B; (c) que
   el deploy no sea idempotente: **E0-3** lo detecta y, si falla dos veces, se pide snapshot v3; (d) que
   la campaña dispare reglas: **es un hallazgo**, no un fallo; (e) que un hueco de 22 min asuste al
   `watch`: los umbrales **25/35** están puestos **para que no**.

## 15. Ficheros que se tocarán

### 15.1 Nuevos

| Ruta | Qué |
|---|---|
| `plan.md` (raíz) | Este plan (se archiva al cerrar) |
| `_fases/legitimo-v3/{reviews.md,change-doc.md}` | Verificación y cierre |
| `Soporte/Laboratorio/legitimo_72h/campana/{casos.md,campana_casos.csv,campana_fp.csv,campana_ventanas.tsv}` | Definición + esperado **firmado antes** + ventanas + resultado |
| `_artefactos/scripts/{extraer_campana.py,cobertura_exes.py}` + tests | Runner por marcas (sin ejecutar) y contador de cobertura |
| `Soporte/Laboratorio/legitimo_72h/{deploy_v5.md,ensayo_E0_v5.md}` | Deploy idempotente (sin snapshot) y ensayo |
| `Soporte/Laboratorio/legitimo_72h/ventana_<t0>/{ventana_meta.md,veredicto_validez.md,MANIFEST.md,evidencia/*.txt,errores.log}` | Ficha, veredicto, evidencia y registro de errores |
| `Dataset/Legitimo/legitimo_72h/ventana_<t0>/{alertas_detalle.csv,ruleids_legitimos.csv,denominador_M.csv,ghosts_acciones.csv,campana_fp.csv,campana_ventanas.tsv,ventana_meta.md}` | **Solo si VÁLIDA** |

### 15.2 Modificados

| Ruta | Cambio |
|---|---|
| `Soporte/Laboratorio/ghosts/client_ctl.sh` · `guest/tfg_keepalive.sh` · `guest/tfg-ghosts-legit.service` | **`cwd` = `/home/angel`** |
| `_artefactos/scripts/construir_receta_legitima.py` | Jitter fijo (**tabla literal**), familias de error, **12 binarios nuevos en la receta + 2 en la campaña** (`systemctl`/`crontab`, lectura; total 14 y `BINARIOS_OK`=36), **B6 generado desde `campana_casos.csv`**, validador de campaña, `CAP_HUECO_S=1320`, `MAPA_DIAS` **parametrizado** |
| `Soporte/Laboratorio/legitimo_72h/recetas/*` | Regenerado (v1 → `recetas/superseded/v1/`) |
| `Soporte/Laboratorio/legitimo_72h/deploy_client.ps1` | Receta v2, `campana_fp/`, `cwd`, `bloques.env` con B6, **idempotente y reversible** |
| `Soporte/Laboratorio/legitimo_72h/legitimo_host_control.ps1` | **H1(a-d)**; `prep` siembra el `watch`; **umbrales 25/35**; **`stop` espera `cosecha.done`**; checklist con conteos de `--check` |
| `Soporte/Laboratorio/legitimo_72h/{sha256sums.txt,b10_sellado.md,resultado.md,README.md}` | Huellas, **sello v5** (sidecar v3), novedades |
| `Soporte/Laboratorio/legitimo_72h/exportar_acciones.sh` | **MC-1** únicamente; la salida se pasa por argumento a `ventana_<t0>/` (sin cambiar el script) |
| `Soporte/Metrica/{boveda_congelacion.md,.sha256}` + `_artefactos/scripts/metrica_hids.py` | `boveda_version=2` (**humano/orquestador**) |
| `state.md`, `roadmap.md` | Estado y **corrección de la dependencia `M1b` ← legítimo** (**orquestador**) |

### 15.3 Prohibido tocar

`_recursos/**` · corpus (`Soporte/Ataques/**`, `Dataset/Ataques/**`, `Bitacora/**`) · `Hojas/**` ·
`Soporte/Metrica/**` (el ejecutor) · `Dataset/**` (salvo §15.1) · `extraer_alertas.py` ·
`filtrar_ruido.py` · el ruleset y `ossec.conf` (salvo `logall_json`) · los snapshots `base-limpia`,
`lab-listo`, `lab-listo-legit`, `fallo-…-NO-USAR` y **`lab-listo-legit-v2`** · el piloto de 39 h.

## 16. Trazabilidad

| Afirmación | Fuente verificable |
|---|---|
| v2 abortada a las 39 h 53 min **sin analizar**, 4 falsas alarmas de borde, 5 lecciones | `_fases/legitimo-72h-v2/change-doc.md` §3, §5 |
| Patrón de la falsa alarma (`:00:02` sobre bloque que empieza a las `:00:00`) y `AVISO` del primer chequeo | `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/incidencias.md` |
| `cleanup` intenta SSH con la VM apagada | `change-doc` v2 §5.4 |
| **`cwd` = `/home/angel/ghosts-client`** | unit `WorkingDirectory=` · `client_ctl.sh:54` · `Bash.cs:106-118` |
| Config resuelta por **directorio del exe** (no `cwd`) | `ApplicationDetails.cs:55-61`, `Program.cs:56,70,134` |
| **4 107/4 173 = 98,4 %** de detecciones son `80792` nivel 3; `550` (nivel 7) solo en ATA024 | `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*-Audited.csv` (recuento propio) |
| **50 binarios** distintos (51 rutas) en `audit_command` de esas detecciones; **11** en la receta v1, **+12** en la receta v2 y **+2** marginales de la campaña (`systemctl`, `crontab`) = **25/50**; `xargs` = 2 497 (ATA046/047) | idem + `recetas/d1-d3.json` + §5.2.5 |
| `sudo -S` con contraseña por stdin en ATA024 | `Dataset/Ataques/Comandos/T1531*/ATA024_ataque.sh` |
| `M` del ensayo: 2 474 eventos con 214 acciones (4,5 min) | `ensayo/denominador_M.csv`, `ghosts_acciones.csv` |
| Navegador descartado (12 librerías, 3,4 GB < 4 GB) | `browser_eval.md` (DT-B0) |
| 10 casos benignos, estado/duración/artefactos y **severidad por perfil** | TFM hermano: Tabla 32 (pág. 53) y Tabla 35 (pág. 63) |
| **Su FP-003 crea una tarea programada temporal y su FP-004 escribe en el registro** (no solo consultan) | TFM hermano, Tabla 32, pág. 53 |
| **«no deben interpretarse como estimaciones de sensibilidad, especificidad o precisión en producción»** + *«los artifacts son modificables: es sencillo excepcionar esos falsos positivos»* | TFM hermano, §4.3.4, pág. 88 (cita literal) |
| El validador **rechaza pipes** y **binarios fuera de `BINARIOS_OK`** (22 hoy; 36 tras T1) | `_artefactos/scripts/construir_receta_legitima.py` (`BINARIOS_OK`, `binarios_de`, `fallos`) + `prueba_en_seco.md` (DT9: 108/111) |
| `crontab` escribir → `80792` ×5 **+ `2832` L5 + `80791`** | `ATA021_meta.md` §8.1 (rúbrica de dudosas) + `ATA021_iter1-Audited.csv` |
| `sed -i` se usó en ATA006/ATA032 (base para predecir `80790`/`80791` del temporal) | `ATA006_ataque.sh`, `ATA032_ataque.sh` |
| `19011` L9 (SCA) aparece 9 veces/segundo en las **dos** ventanas `_rev` de ATA038 | `ATA038_rev{1,2}-Audited.csv` |
| `sudo -n` **solo** funciona tras cachear credenciales con `sudo -S -v` | `guest/instalar_tarea_invitado.sh:18-20` (`echo "$SUDOPWD" \| sudo -S -v`) |
| `M1b` depende del legítimo | `roadmap.md` §4-§5 |
| **`M` = eventos decodificados; `FP_uni`; `FPR = FP_uni/M`; titular `C1×N=0`** | `Soporte/Metrica/metrica_hids.md:47-53, 93-104, 170-172` |
| **`doing_age`: AVISO >15 / ALARMA >30 solo dentro de bloque** | `legitimo_host_control.ps1:465-467`; `Get-BloqueEstado` en `:452` |
| **`STALE=30`, `GRACIA=15`, `CONFIRMA=5` del keepalive** | `guest/tfg_keepalive.sh:34`; `b10_sellado.md:27` |
| **`contar_denominador.py` acepta un solo `[desde,hasta]`** — **suficiente en v5**: no hay cortes por rango | `contar_denominador.py:286-287, 309-322` |
| **`exportar_acciones.sh` escribe por defecto en `Dataset/` y sella `boveda_version=1`** — en v5 se le pasa la salida por argumento (**sin cambiar el script**, salvo MC-1) | `exportar_acciones.sh:17,28` |
| **`b10_sellado.md` está en v2, pero `boveda_congelacion.md` sigue en v1 y `VERSION_BOVEDA=1`** | `b10_sellado.md:1,12-13,62`; `boveda_congelacion.md:4`; `metrica_hids.py:36` |
| **`CAP_HUECO_S=720` y doble umbral 20/12 min** | `construir_receta_legitima.py:96,649-652` |
| **C-04 era la única escritura en `crontab`** y se retira por no mutación | §5.2.3; decisión humana 2026-10-27 |
| **Horas: B6 17:05-17:50; inicios 17:06/17:17/17:11** | §3.1.1 (decisión de este plan) |
| Estado del laboratorio de partida | Verificado 2026-10-27 (§4) |

## 17. Lo que no cuadra y decisiones abiertas

1. **El riesgo real es el bucle de perfeccionismo** (2 ventanas, 0 datos). §3.4 lo mitiga, pero necesita
   tu respaldo explícito (**Q2** del gate). Sin él, este plan repite el patrón.
2. **Sin fecha, el riesgo cambia de sitio**: ya no es "llegar tarde a `t0`", es **"no llegar nunca"**. Por
   eso hay tope por tanda y un recorte mínimo (`cwd` + campaña) que **solo** necesita ~1 día y ya produce
   el 80 % del valor.
3. **`sudo`**: si dentro de unos meses el humano decide que la víctima tenga `sudo` sin contraseña, se
   abre la capa administrativa (y el 2.º usuario vuelve a tener sentido). Hoy **no** está y el corpus lo
   demuestra. No lo doy por bueno ni por malo: lo **declaro**.
4. **T5 en `N ≥ 7` nacerá vacía *por actividad del usuario*** (la única regla de nivel 7, `550`, exige
   tocar `/etc`). Es una consecuencia del **usuario no root**, no un fallo: hay que decirlo así en la
   memoria, no disimularlo.
   *Matiz v4 (corrige la v3):* la regla **más alta que la campaña puede medir sin mutar** es **`2832`
   (L5)**, pero **NO se mide**: exigía escribir en `crontab` (C-04) y la campaña es no mutante. `550` L7
   es alcanzable con `passwd`, pero **cambia la credencial** y queda fuera. Queda como **límite
   declarado**. `19011` (L9, SCA) puede aparecer **sin que el usuario haga nada** si el agente se
   recupera a mitad de ventana (§1.9.4.3).
5. **El "10/10, 0 hits" del TFM hermano no es comparable** (él medía sus artifacts; aquí `auditd` graba
   cada `execve` y `80792` es nivel 3). Declarado, es un hallazgo; sin declarar, parece una debilidad.
   **Y hay una razón más fuerte que v3 añade con cita literal (§5.2.7):** *«los artifacts son
   modificables: es sencillo excepcionar esos falsos positivos»*. Sus 0 hits se apoyan en que **él
   escribe las detecciones**; aquí la regla es **de fábrica** y la bóveda está congelada ⇒ «se compara
   el método» **no** es del todo cierto: el método **no es transferible** sin tocar el ruleset.
6. **No hay sesión interactiva** y no se puede crear sin contaminar V4. **Retiré el 2.º usuario**, así que
   la capa PAM/`auth.log` del legítimo queda **sin cubrir**. Es la limitación más importante que deja este
   bloque; conviene mencionarla en la memoria (ningún caso de la campaña toca PAM: todos corren como
   `angel` sin login interactivo).
7. **`boveda_version` sigue en 1** pese al gate de v2, y **MC-1** sigue pendiente: se aplican **una vez**,
   al cerrar v4.
8. **El `cwd` es un cambio del laboratorio**, pero **no exige snapshot nuevo**: exige **E0** y un
   **deploy idempotente** sobre `lab-listo-legit-v2` (§5.3). Si el deploy no fuera idempotente tras dos
   intentos, **entonces** se justificaría un snapshot v3 (con OK humano). Si el humano prefiere "no
   tocar nada más", el precio es que el 100 % del dataset legítimo llevará `cwd=ghosts-client`; **no lo
   recomiendo**.
9. **`MAPA_DIAS` deja de estar hardcodeado** (v2 lo tenía fijo a 26-28/10): pasa a parámetro, porque sin
   fecha fija ese hardcode es una bomba de relojería.
10. **La campaña es una decisión de diseño**: **B6 17:05-17:50Z** (18:05-18:50 local), inicio con
    **jitter fijo** (17:06 / 17:17 / 17:11). Plausible, pero **elegido**, no observado. Se declara
    (§3.1.1).
11. **Pruebas que quería poner y no puedo** (y por qué):
    - **`passwd` cambiando la contraseña propia**: es **la única acción benigna** que, sin `sudo`, escribe
      en `/etc` y dispara **`550` (L7)** — el hueco de T5 a `N ≥ 7`. **No entra** porque (a) cambia la
      **credencial que usa la automatización** (`TFG_GUEST_PW`), (b) exige TTY y la contraseña actual, y
      (c) si falla a medias deja la VM inaccesible. Se podría hacer **fuera de ventana sobre un revert
      desechable** (coste ~30-40 min) y **no** lo propongo sin tu OK explícito. *Consecuencia honesta:
      T5 a `N ≥ 7` sigue sin evidencia propia; queda declarado como límite del usuario no root.*
    - **`dd`** (26 detecciones, 5 ATA, incluido T1485): no es actividad de oficina; el único uso legítimo
      (`dd` de un fichero para copiarlo) es artificial y se confunde con "hacer el ataque más fino".
    - **`git`** (40 detecciones, ATA022/T1567.001): `status`/`log` **no se parece** a un `push`; para que
      se pareciera habría que crear un remoto local y hacer `git push` — más montaje y más estado.
    - **`sqlite3`** (14), **`nc.openbsd`** (17), **`perl`**, **`busybox`**: no son actividad de usuario
      ofimático. **`xclip`/`xdotool`/`xwd`/`xwud`/`xinput`** (14 detecciones, ATA051/052/053): **no hay
      GUI instalada** (decisión §1.4) ⇒ imposibles. **`mount`/`losetup`/`umount`/`sfdisk`/`wipefs`/
      `mke2fs`/`useradd`/`userdel`**: exigen root.
    - **`yes`** (ATA025): un `yes` legítimo no existe; solo sirve para inundar.
12. **Lo que la campaña va a demostrar antes de ejecutarse** (y conviene no confundir con un fracaso):
    a `N ≥ 3` **los 11 casos alertan** (cada `execve` es `80792`, L3) ⇒ el FPR por evento a `N ≤ 3` es
    ≈ (nº de `execve` auditados)/`M`. La campaña **no** puede bajar ese número; sirve para **atribuirlo**
    y para medir qué reglas **por encima de L3** se encienden con actividad benigna. **Esperado:
    ninguna** (la única que se medía, `2832` L5, se pierde con C-04; §1.9.4).
13. **El denominador del corpus estaba mal contado** (49 vs **50**): no cambia ninguna conclusión, pero
    **CA-04** y el sello B10 deben usar **50** (o **47** si se excluyen los 3 binarios de ataque). Es el
    tipo de dato que, repetido en la memoria, se detecta en la defensa.
14. **C-04 se retira por decisión humana (no mutación)**: se pierde la única medición legítima de
    **`2832` L5** y el gemelo del **FP-003** del TFM hermano. **No se sustituye**; se declara como
    límite de T5 y del catálogo. *Preferible un límite honesto a una mutación del sistema.*
15. **"Sin actividad nocturna" se matiza**: la actividad **de usuario** es cero, pero el **keepalive**
    ejecuta `date`/`curl` cada ~5 min (~290 `execve`/día, también de noche). Es **instrumentación
    declarada** y entra en `M` y en el numerador; no se puede confundir con la jornada.
16. **El titular es la ventana completa** porque la métrica congela `M` sobre `[t0,t1]` (§9.5). La
    campaña **se reporta aparte** con su tabla; **no hay vista alternativa** ni segunda cifra de FPR.
17. **La hora elegida (c) no es "la única"**: (a) era más simple y (b) más variada, pero (a) repite el
    metrónomo y (b) pisa B5. (c) es la que mejor cumple "final de jornada, no al segundo exacto" a coste
    cero (§3.1.1).

---

## 18. Veredicto: ¿es metodológicamente sólido hacer la campaña dentro?

### 18.1 Las 4 condiciones, cumplidas y citadas

| # | Condición | Dónde está escrita |
|---|---|---|
| **1** | **Expectativa pre-registrada por caso**, antes de `t0` | `campana/casos.md` + `campana_casos.csv` con **11 filas**, `rule_id` y `N≥7/N≥3`; `sha256` y fecha anterior (§5.2.2, §5.2.6, CA-06) |
| **2** | **Marcas de inicio/fin** que permiten separarla | `inicio.txt`/`fin.txt` por caso (22 marcas), cosechadas en `t1+2` y convertidas en `campana_ventanas.tsv` (§5.2.6, §8) |
| **3** | **Se publica aparte** | Titular **único** (ventana completa) + **tabla de campaña** con sus recuentos; **sin** segunda cifra de FPR (§8, §9.5, CA-14/CA-16) |
| **4** | **Regla de no-invalidación** | V1–V8 = ventana; V9/C1–C4 = campaña; **ningún fallo de campaña invalida la ventana** (§9.3, §9.4) |

### 18.2 Los 3 riesgos residuales (y su mitigación)

1. **Que la campaña se lea como "fabricar FPs".** Mitigación: expectativa pre-registrada, etiqueta
   `campaña`, **tabla aparte** y `FP/acción` sobre la ventana completa. **No se puede evitar del
   todo**: es una actividad **elegida**, no observada (§17.10).
2. **Que C-04 deje un hueco en T5 (`2832` L5) y en el gemelo del FP-003 del TFM hermano.** Mitigación:
   **declararlo** como límite (no maquillarlo) y no sustituirlo por otra mutación. **No se puede
   arreglar** sin escribir en `crontab`, que la decisión prohíbe.
3. **Que la ventana se contamine por el propio diseño** (B6 fuera de `bloques.env`, `doing_age` con
   huecos de 22 min, tabla de campaña mal atribuida). Mitigación: B6 declarado, umbrales **25/35**,
   ventanas por **marcas** y **un solo `M`**; la tabla no resta nada de `M`.

### 18.3 Qué NO se puede afirmar con este diseño

- **NO** se puede afirmar que exista un FPR alternativo: **solo hay el de la ventana completa**. La
  campaña se reporta con **recuentos por caso**, no con un FPR propio (§9.5).
- **NO** se puede afirmar que la campaña mida **toda** la superficie de doble uso: `2832` L5 y `550` L7
  quedan **fuera** (C-04 retirada; usuario no root) (§1.9.4, §17.4).
- **NO** se puede afirmar que la campaña sea **imprescindible para la cobertura**: solo añade **2
  binarios** (`systemctl`, `crontab`) y **4 `ATA`**; su valor es la **tabla por caso** y la
  **atribución**, no subir el 23/50 de la receta v2 (§5.2.5, §18.4).
- **NO** se puede afirmar que los 11 casos sean una **muestra representativa** de la actividad legítima:
  son **elegidos** y **pre-registrados**, no observados (§17.10).
- **NO** se puede afirmar que la jornada sea una **sesión interactiva real**: no hay PAM/login; todo corre
  como `angel` desde el servicio (§1.9.5, §17.6).
- **NO** se puede afirmar que el resultado sea **comparable en crudo** con el "10/10, 0 hits" del TFM
  hermano: él medía **sus artifacts** y podía excepcionarlos; aquí `80792` es **de fábrica** (§5.2.7,
  §17.5).
- **NO** se puede afirmar que la campaña **suba o baje** el FPR: a `N≥3` **todos** los casos alertan por
  `80792`; la campaña **atribuye**, no reduce (§17.12).
- **NO** se puede afirmar que la hora de la campaña sea una variable del análisis: se extrae por
  **marcas**, no por reloj (§3.1.1).

### 18.4 Veredicto

> **SÓLIDO CON RESERVAS.** El diseño cumple las **4 condiciones** y separa **ventana** de **campaña**
> (V1–V8 vs V9/C1–C4), que era el riesgo metodológico principal. Las reservas son **3 y están
> declaradas**: (1) la campaña es una actividad **elegida**, no observada, y se reporta **aparte**;
> (2) **C-04** deja sin medir `2832` L5 y el gemelo del FP-003; (3) la campaña **no tiene FPR propio**:
> se publica con sus recuentos por caso. Ninguna de las tres **invalida** la ventana ni la campaña: se
> publican como límites.
>
> **Condiciones para que el veredicto se mantenga:** (a) las **4 condiciones** siguen escritas y
> verificables (CA-06, CA-14/16, §9.4); (b) **un solo `M`** (ventana completa) y **tabla de campaña
> aparte** (CA-14/CA-16); (c) **ningún fallo de campaña** se usa para invalidar la ventana (§9.3/§9.4).
> Si alguna de las tres se rompe, el veredicto baja a **"no sólido"** y se corrige antes de `t0`.

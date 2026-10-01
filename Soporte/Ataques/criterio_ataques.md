# Criterios para elegir y construir un ataque (Fase 3)

> **Documento vivo** del bloque `fase-03-auditoria-metodologica`. Redactado el **2026-10-01**.
> Fija **cómo se decide y cómo se construye** un ataque del corpus, **antes de atacar**.
> Es **neutro de plataforma**: sirve hoy para la víctima **Linux** y mañana para **Windows**
> (allí el reparto cambia y hará falta su **línea base** y **adaptar el filtro** — ver §D).
> Enlaces: `plantilla_esperado.md`, `criterio_doble_iteracion.md`,
> `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`, `Hojas/auditoria_origen.csv`.

La regla que gobierna todo el documento: **la decisión de diseño se toma ANTES de atacar y
se deja escrita con cita** (guion, README y bitácora). Lo que no conste en el repositorio se
declara **`no_consta`/`no_se_comprobo`**; **nunca se inventa ni se supone**.

---

## §A — Elección y grado de uso de Atomic Red Team (ART)

Para cada técnica, **antes de escribir nada**, se comprueba si ART ofrece una prueba
**utilizable en el laboratorio** y se decide en **uno** de estos tres grados:

| Grado | Cuándo se usa |
|---|---|
| **ART_tal_cual** | La prueba de ART corre **en esta plataforma**, **sin internet** y con el **mismo mecanismo**, admitiendo solo la **parametrización de entrada/salida** (endpoint, fichero, servicio) para encajar en el laboratorio. |
| **ART_adaptado** | Se parte del **enfoque** de una prueba de ART, pero se **recorta o modifica** el mecanismo (contención, otra herramienta, alcance reducido). Se anota **qué se cambió**. |
| **propio** | No hay prueba aplicable → se escribe a mano, **con motivo obligatorio** (`motivo_codigo`). |

### A.1 Condiciones para usar ART (las tres)

1. **Prueba de esta plataforma** — el mapa `Hojas/cobertura_atomic.csv` da `tests_linux`/`tests_windows`.
2. **Ejecutable offline sin NAT** — o bien **pre-staging declarado** (§C) para lo que falte.
3. **Mismo mecanismo** — la prueba hace *lo mismo* que la técnica que se quiere medir
   (no vale "la técnica es la misma" si el mecanismo es otro).

Si **falla alguna**, el ataque es **propio** con un `motivo_codigo` de la lista cerrada.

### A.2 Lista cerrada de `motivo_codigo` (neutra de plataforma)

| Código | Significado | `motivo_detalle` |
|---|---|---|
| `art_no_prueba_plataforma` | ART no trae prueba para **esta** plataforma. El detalle aclara **«ninguna»** (no hay prueba en ninguna) o **«solo la otra»**. | **Sí** |
| `art_requiere_red_nube` | La prueba de ART pide internet / nube / SaaS. | No |
| `art_mecanismo_no_coincide` | Hay prueba para la plataforma, pero **no coincide con el mecanismo** del corpus. | No |
| `propio_por_diseno` | Se diseñó a mano **a propósito** (factibilidad offline, otra capa del HIDS, seguridad, medir otra variante, control del efecto…). | **Sí** |
| `no_se_comprobo` ⚠️ | **No se comprobó** ART al diseñar **y** no hay evidencia en el repo. **Es un hueco declarado**, no un motivo. | No |
| `na_art_usado` | **No aplica**: el ataque **sí usó ART** (`ART_tal_cual`/`ART_adaptado`). El motivo describe *por qué NO se usó ART*, así que aquí no hay motivo. | `se usó ART` |
| `otro` | No clasificable arriba. | **Sí** |

> **Semántica de `motivo_codigo`.** Este campo describe **por qué NO se usó ART**; por tanto **no
> aplica** a las filas con `fuente=ART_tal_cual`/`ART_adaptado`: allí se usa
> **`na_art_usado`** con `motivo_detalle="se usó ART"`. La misma regla está fijada en la **nota de
> cabecera** de `Hojas/auditoria_origen.csv` y en el bloque `atomic` de las bitácoras.

### A.3 Se usa y **se cita**

Cuando se usa ART (tal cual o adaptado), se deja la **provenance** en la bitácora
(`Bitacora/ATA<NNN>.json`, bloque `atomic`): **`guid`** de la prueba + **`path`** en el clon +
**`commit`** fijado (hoy `388942a…`) + **`nota`** con lo que se cambió. Si hubo adaptación, la
`nota` y el README explican **qué se cambió** respecto a la atómica.

### A.4 Registro estructurado (aditivo) en la bitácora

Cada bitácora lleva, en su bloque `atomic`, tres claves **aditivas** (no sustituyen a `fuente`,
`nota` ni a nada existente): **`fuente_norm`** (`art_tal_cual` / `art_adaptado` / `propio`),
**`motivo_codigo`** y **`motivo_detalle`**. El `fuente` literal se conserva como **provenance
histórica** (hoy no está normalizado: `"ART"`, `"atomic-red-team"`, `"custom"`). El conjunto es
auditable en `Hojas/auditoria_origen.csv`.

---

## §B — Cómo se diseña un ataque manual

Pasos fijos, **en este orden**, antes de sellar `t0`:

1. **Técnica MITRE** — nodo ATT&CK concreto (padre o sub-técnica) y su táctica.
2. ***Data components*** — qué capa de telemetría del HIDS debería ejercitar
   (`execve`/`audit_command`, `watch`/`audit_file`, FIM/`syscheck`, syslog/journald,
   estado del agente, red…). Se declara **cuál** se espera ver.
3. **Acciones** — el comando o el guion que materializa el mecanismo de la técnica **y nada más**
   (retirar acciones que pertenezcan a **otra** técnica; p. ej. no colar *timestomp* dentro de
   *Data Manipulation*).
4. **Guardarraíles** — en el guion: rutas obligatoriamente bajo `lab-attack`/`lab-legit`,
   **aborta** si la ruta sale del laboratorio, si toca un disco/partición real, si toca una
   cuenta/servicio real, si el remoto de red no es el local, o si se supera una cota
   (volumen, tiempo, nº de procesos). Guardarraíl **duro** para lo destructivo.
5. **C0 (pre-flight base-contra-base)** — `wazuh-logtest` con una línea **real** del binario clave
   para descubrir **silenciadores de fábrica** (como `92600` con `python3`). Si aparece uno, se
   **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben
   reglas propias para "arreglarlo" en este ciclo.
6. **Prueba del efecto** — **independiente de la alerta**: descifrado válido, marcador inyectado,
   `sha256` antes ≠ después, fichero que deja de existir, `sink.log` con el hash del dato,
   `boot_id` distinto… La alerta es la **medición**; el efecto es la **prueba** del ataque.
7. **`esperado` escrito ANTES y validado por el humano** — `ATA<NNN>_esperado.csv` con las señales
   (`deteccion`/`ambigua`), la **convención H4** (`audit_exe` **+** `audit_cwd` de la carpeta) y
   las señales de contexto en rutas vigiladas. Se firma con la validación humana **antes del
   primer `t0`** y **no se recalibra** después.
8. **Realismo acotado declarado** — en el README: *la técnica y el comando son reales; el alcance
   es de laboratorio; el entorno no tiene usuarios/servicios reales; las rutas son conocidas por
   el analista; los datos son de juguete*.

---

## §C — Pre-staging

> Cuando un ataque necesita **algo que no está en el laboratorio** para ser fiel al mecanismo,
> ese algo **no** se consigue durante la ventana. Aquí se decide **cuándo** (§C.1) y **cómo**
> (§C.2). **Aplica a ataques NUEVOS**; los 43 ya ejecutados **no se re-atacan** por esto.

### §C.1 — CUÁNDO se usa pre-staging

1. **Solo** cuando el ataque necesita algo que **NO está en el laboratorio** (herramienta,
   fichero o servicio) para ser fiel al mecanismo.
2. Si ese algo es **pequeño y fijable** (**URL + `sha256`**) → **se trae antes de `t0`**.
3. Si es un **servicio real externo** (nube / AWS / web real) → se declara **«no factible»**
   y **no se fuerza** el ataque.
4. La decisión se toma **al diseñar el ataque** (en el `c0/ATA<NNN>_c0_plan.md`), **no** durante
   la ventana.

### §C.2 — CÓMO (las 3 reglas)

1. **Antes de `t0`** — el material entra **fuera de `[t0,t1]`** (el revert + la copia previa al
   ataque no contaminan la ventana).
2. **Pequeño y fijado** — se deja constancia de **URL + `sha256`** para que sea **reproducible**;
   queda versionado o documentado (nunca un secreto).
3. **Nada de nubes/emuladores** — lo que no se resuelva así se declara **«no factible»**.

### §C.3 — Un solo modo por técnica

Cada técnica tiene **un** modo de preparación declarado (nada de rutas alternativas a la vez):
o todo está ya en el laboratorio, o entra por pre-staging fijado, o se declara no factible.
Esto mantiene la comparación **determinista** entre iteraciones y entre técnicas.

---

## §D — Nota de plataforma (constancia para Windows)

Todo lo anterior es **neutro de plataforma**, pero el **reparto cambia** al pasar a **Windows**:

- ART tiene **muchas más** pruebas Windows → **sube el uso de ART tal cual/adaptado** y baja el
  trabajo manual.
- Habrá que **levantar la línea base Windows** (los procesos internos y los campos de telemetría
  del HIDS **no** son los de Linux).
- Habrá que **adaptar el filtro** (`filtrar_ruido.py` lleva dentro supuestos **de Linux**) para
  los nombres de proceso del propio Wazuh y para los campos del sistema.
- La columna `nota` de `Hojas/cobertura_atomic.csv` y la clasificación de motivos son **neutras**:
  se rellenan igual para Windows.

> **Es otro bloque.** Aquí solo queda **escrito** que el cambio es de reparto y de línea base,
> no de criterio.

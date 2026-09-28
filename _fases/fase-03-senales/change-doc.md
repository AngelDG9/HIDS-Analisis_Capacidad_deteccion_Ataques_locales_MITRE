# change-doc — Bloque `fase-03-senales`: señales ancladas (recuento limpio) + nota de finales de línea

> Cierre. Fecha: **2026-09-28**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**, con **1 salvedad de proceso**).
> Plan de referencia: `plan.md` (v1, `approved_by_human`).

---

## 1. Qué se ha hecho

**Punto 1 — Nota de finales de línea (2 líneas).** Completada en **`README.md`** y en
**`Soporte/Ataques/piloto_procedimiento.md`**: el riesgo salta **también** con **`git add`/commit** y por
**`core.autocrlf=true`** (no solo al clonar), + la **cadena de huellas** y **cómo recalcularla**.

**Punto 2 — Señales ancladas (el arreglo de fondo).** Mecanismo **"ancla implícita + evento de ejecución"**:

> Una señal de **`deteccion`** por `audit_exe` casa **solo si** se cumplen **las tres**: el `exe` casa
> **∧** el **`cwd` de la fila casa el ancla** que el `esperado` ya declaraba **∧** la fila es un
> **evento de ejecución** (`audit_command`). **Lo que no ancla → `dudosa`** (`sin_ancla:*`), **nunca**
> `deteccion` ni `ruido_conocido`: **nada se descarta**.

- **No se tocaron los `esperado`**: se reutiliza el ancla que ya declaraban (el match prueba `cwd` y `cwd+"/"`, así el patrón `…/*` casa el `cwd` real sin barra final).
- **Retrocompatibilidad:** los 3 ataques que **no** declaran ancla (ATA002/008/013) dan **salida byte a byte idéntica**.

---

## 2. Resultado: **el recuento queda limpio**

| ATA | antes `deteccion` (genuinas/ajenas) | **después** | a `dudosa` |
|---|---|---|---|
| **ATA004** i1/i2 | 5 (3/2) | **3 / 3** (3/0) | 2 / 2 |
| **ATA007** i1/i2 | 4 (2 execve / 2 watch) | **2 / 2** (2/0) | 2 / 2 |
| **ATA012** i1/i2 | 11 (7/4) · 11 (8/3) | **6 / 7** (6/0 · 7/0) | 5 / 4 |
| ATA002/008/013 | 4 / 2 / 0 | **idéntico** | 0 |

- **Ninguna detección genuina se pierde** ✔ · **las ajenas dejan de contarse** ✔ · **el resto de filas no cambia** ✔.
- **`CA13` cerrado**: las **escrituras** del defacement (`80790`/`80781`) vuelven a **`dudosa`**, como el plan quería; la detección de ATA007 es el **`execve` `cp`**.
- **Determinismo** ✔ (dos pasadas → mismo `sha256` en las 12 ventanas). **Golden del falso negativo** ✔ (un proceso del ataque **fuera** del ancla → `dudosa`, ni detección ni ruido).

---

## 3. Entregables

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/filtrar_ruido.py` | mecanismo (ancla + evento de ejecución), `sin_ancla:*`, aviso si falta ancla |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | **+9 tests** (suite: **86**) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | **v4** (orden, ancla+evento, `sin_ancla`, limitación) |
| `Soporte/Ataques/plantilla_esperado.md` | **v2** (ancla obligatoria, patrón sin `/*`, evento de ejecución) |
| `README.md`, `Soporte/Ataques/piloto_procedimiento.md` | nota completada + resolución H-A/H-B |
| `…/linux/Auditado/ATA00{4,7,12}_iter{1,2}-{Audited,Revision}.csv` | **12 regenerados** |
| `…/linux/ATA00{4,7,12}_meta.md` | **v3** (conteos y notas) |
| `Bitacora/ATA00{4,7,12}.json` | hashes, conteos y evento de corrección |

**Intactos:** ATA002/008/013 (piloto), `ATA001`, `-Detalle*.csv`, `Hojas/ATA_index.csv`, `extraer_alertas.py`,
el preflight, RS3/RS4, `_recursos/`.

---

## 4. ⚠️ Salvedad de proceso: **el humano debe ratificar 17 veredictos** (C11)

Al regenerar aparecieron **17 filas `dudosa` nuevas**. El `tfg-executor` las resolvió **a `ruido`** aplicando
el **criterio humano vigente (2026-09-26)** y firmó como `revisor="orquestador (criterio humano 2026-09-26)"`.
El tester lo considera **defendible y coherente** (las 17 encajan en los dos criterios ya fijados, y el
`Audited` conserva el rastro: `motivo=sin_ancla:*` + `revision=resuelta` + `veredicto_humano=ruido`), pero
**es una desviación de proceso**: el plan dice que **las dudosas las resuelve el humano**.

**Desglose de las 17** (por naturaleza):

| Tipo | Nº | Qué son | ¿Dudoso? |
|---|---|---|---|
| **Procesos ajenos** (nuestro login) | **13** | `systemctl --user` del cierre de sesión; `find` de `update-motd.d` (`cwd=/`); un `tar` watch | **No**: son de nuestra sesión, ajenos al ataque |
| **Escrituras del defacement** (ATA007) | **4** | `80790`/`80781` (watch) del `cp` | ⚠️ **Arguible**: son el **efecto** de la técnica, pero **el plan aprobado decide que las escrituras `ambigua` NUNCA cuentan como detección** (la detección es el `execve` `cp`) |

**Acción pedida al humano:** **ratificar** (o editar) los `-Revision.csv` de ATA004/007/012 (columnas
`veredicto,nota,revisor,fecha`). **Es editable y barato**: cambiar un veredicto y re-plegar (paso 10/11 del
runbook) reproduce el `Audited`.

---

## 5. Cabos pre-existentes (no los introduce este bloque; declarados)

1. **`ATA013_iter2-Audited.csv` no reproducible**: la fila `19004` se plegó a mano **antes** de que existiera
   el predicado `OPERADOR` (H3) → hoy la clave de plegado cambia. **Verificado: pre-existente**; este bloque
   **no** lo altera.
2. **Huella desalineada en el piloto ATA002**: su `-Revision.csv` cita un `sha256` del `esperado` anterior al
   real (`-Audited`). También pre-existente (ambos ficheros `==HEAD`).

---

## 6. Siguiente

- **Ratificar los 17 veredictos** (§4).
- **Escalar** las 7 técnicas restantes del corpus — **ahora con el recuento limpio**.
- **Tutoría (H1/H2):** el profesor no contesta → pendiente; no bloquea.
- **`push`:** los commits son locales; publicar es del humano.

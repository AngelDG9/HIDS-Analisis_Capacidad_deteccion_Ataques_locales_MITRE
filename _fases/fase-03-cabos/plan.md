---
fase: 3
bloque: fase-03-cabos
tarea: cabos de la verificación del segundo piloto (fase-03-piloto-custom §5)
nombre: Cabos del piloto-custom — 4 arreglos de registro/documentación
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-planner
gate: humano — **APROBADO ✔ (2026-09-28)**: (1) cabo 1 = corregir la cita (**no** generar el fichero); (2) cabo 2 = editar las 3 cabeceras + **regenerar los 6 audited** + actualizar hashes, **sin tocar los Revision**; (3) cabo 3 = corregir el texto (**sin** cambiar el diseño de H3); (4) cabo 4 = **documentar** el hallazgo del `40700` (nivel 0). Alcance: **bloque doc-only, cero cambios de cifras**.
---

# Plan — Bloque `fase-03-cabos`: cerrar los 4 cabos menores del piloto-custom

> **Objetivo:** dejar el **registro** coherente con la realidad. Son los **4 cabos** que anotó el
> tester en `_fases/fase-03-piloto-custom/change-doc.md` **§5**: (1) un fichero de evidencia citado
> que no existe; (2) las cabeceras de los 3 `esperado` diciendo *"PENDIENTE"* cuando el humano **sí**
> validó; (3) un texto del filtro que **miente** sobre las PAM; (4) una **hipótesis de journald sin
> comprobar**.
>
> **Principio del bloque (KISS):** son **arreglos de registro/documentación**. **No** cambian cifras,
> **no** re-miden ataques, **no** rediseñan señales y **no** crecen. **8/10 hecho > 10/10 sin hacer.**
>
> **Fichero único de retorno: este `plan.md`.** Nada más se escribe hasta el gate.

---

## 0. Objetivo y alcance

- **Entra:** los **4 cabos** (§1–§4), las correcciones de registro que arrastran (hashes de
  bitácoras/fichas), y la **nota de hallazgo** de journald (cabo 4).
- **NO entra:** el **rediseño de las señales** (H-A/H-B: semántica AND / `rule_id` del `execve`) →
  **otro bloque**; el **escalado**; **Windows**; **η**; la **memoria**; cualquier **ataque nuevo**.
  Detalle en §8.
- **Recursos:** este bloque es **offline** (cabo 2 re-ejecuta el filtro, que es local y
  determinista). **No requiere VMs ni root**, salvo que el humano elija la variante **4-b** (§4).
- **No se cambia ninguna cifra** de las fichas/bitácoras: `deteccion`, `auto_ruido`,
  `ruido_conocido`, `dudosa`, `rule_id`, genuinas/ajenas → **intactas**.

---

## 1. Cabo 1 — Fichero de evidencia ausente (`sha256_artefacto.txt`)

**Hecho real (inspeccionado):** las 3 fichas (`ATA00{4,7,12}_meta.md` **§6**) citan
`sha256_artefacto.txt` en sus `Logs/ATA<NNN>_iter{1,2}/`, pero **ese fichero no existe** en ninguno
de los **6** directorios. Lo que sí hay es `times.log`, `ejecucion.out`, `deps_ps_antes.txt` y
`ps_despues.txt` (el piloto `fase-03-piloto` **sí** generó `sha256_artefacto.txt`).

### ✅ Decisión: **corregir la cita** en las 3 fichas (NO generar el fichero)

**Razón (KISS + integridad):**

1. **El `sha256` del script ya está registrado** en la ficha **§2** y en la bitácora
   (`ataque_sha256`) → **no se pierde trazabilidad**; el fichero es **redundante**.
2. **Generar el fichero hoy** sería una **reconstrucción post-hoc** colocada dentro de `Logs/`
   (cuyo significado es *"capturado en ejecución"*) → **ambigüedad de integridad** que no
   compensa: el hash es **el mismo dato duplicado**.
3. **Es el mismo patrón que el cabo 3**: *lo que está mal es el texto, se corrige el texto.*
4. **Coste mínimo y verificable**: 3 edits + `ls`; **sin VMs, sin root, sin nuevas huellas.**

**Acción concreta:** en **§6 "Evidencia"** de las 3 fichas, listar **exactamente** lo que el
directorio contiene hoy (`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`) y
**añadir una nota**: *"en este bloque no se generó `sha256_artefacto.txt`; el `sha256` del script
consta en §2 y en `Bitacora/ATA<NNN>.json` (`ataque_sha256`) — idéntico repo↔víctima."*

> **Alternativa descartada:** generar los 6 `sha256_artefacto.txt` a partir del hash ya conocido.
> Se descarta por (2): sería presentar como "evidencia capturada" un fichero creado a posteriori.

---

## 2. Cabo 2 — Cabeceras de los `esperado` desactualizadas (**⚠️ impacto en las huellas**)

**Hecho real:** los 3 `Dataset/Ataques/Comandos/…/ATA<NNN>_esperado.csv` llevan en su cabecera
comentada `# Gate humano (2º): PENDIENTE de validacion ANTES del primer t0 de la tecnica.`, pero el
humano **SÍ los validó** el **2026-09-26** (consta en `plan.md` del piloto-custom, en las fichas
§2 y en las bitácoras). → **CA5 incompleto en el artefacto** (el mismo fallo que el piloto y que el
bloque `fase-03-afinado`).

### ✅ Decisión: **arreglar la cabecera + regenerar los 6 `-Audited.csv`** (precedente del piloto)

**Precedente a imitar (verificado):** el piloto arregló **exactamente este fallo**
(`_fases/fase-03-piloto/change-doc.md` **§5**): *"los 3 CSV registran «Gate humano: validado…» y
los artefactos afectados se regeneraron (los `-Audited.csv` llevan en cabecera el `sha256` del
esperado → actualizado; determinismo re-verificado)"*. Hoy se ve en la ficha `ATA002_meta.md` §2
(*"reescrito de «PENDIENTE» a «validado»"*) y en la cabecera del `ATA002_iter1-Audited.csv`
(cita el `sha256` **actual** del esperado).

### ⚠️ Impacto en las huellas (cadena completa)

El `sha256` del `esperado` **está incrustado** en la cabecera `#` de cada `-Audited.csv` (campo
`esperado=… sha256=…`). Al editar el `esperado`, **su `sha256` cambia** ⇒ hay que **regenerar los
6 audited** y **actualizar todos** los sitios que citan el hash:

| Huella | Qué pasa | Acción |
|---|---|---|
| `esperado.csv` (cabecera `#`) | se edita 1 línea comentada (datos intactos) | **edit** |
| `ATA<NNN>_iter{1,2}-Audited.csv` (cabecera) | cita el `sha256` del esperado | **regenerar** (filtro determinista) |
| `ATA<NNN>_iter{1,2}-Revision.csv` (cabecera) | **también** cita el `sha256` del esperado | ⛔ **NO se toca** (registro humano) — ver nota |
| `Bitacora/ATA<NNN>.json` | `esperado_sha256` + `audited_sha256` (×2) | **actualizar** |
| `ATA<NNN>_meta.md` §2 | cita el `sha256` del esperado | **actualizar** |

**Acción concreta (orden):**

1. **Editar solo el texto de la cabecera** (no tocar filas de datos, ni `·`/`º`, ni fin de línea):
   `PENDIENTE de validacion ANTES del primer t0 de la tecnica.`
   → `validado el 2026-09-26 (antes del primer t0 de la tecnica).`
   *(UTF-8 sin BOM, LF; el reemplazo es ASCII puro → no altera la `·`/`º` de las líneas vecinas.)*
2. **Regenerar los 6 audited** con `filtrar_ruido.py`, **reproduciendo la invocación original** y
   leyendo del **propio encabezado actual** las cadenas exactas de `--alerta`/`--revision`
   (así el único cambio en la cabecera es el `sha256=` del esperado):
   ```bash
   python _artefactos/scripts/filtrar_ruido.py \
     --alerta  "Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA<NNN>_iter<N>-Detalle.csv" \
     --ata ATA<NNN> --iter <N> \
     --revision "Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iter<N>-Revision.csv" \
     --out      "Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iter<N>-Audited.csv" \
     --rev-out  "_artefactos/tmp/cabos/ATA<NNN>_iter<N>-Revision.csv"
   ```
   - El `esperado` se **autodescubre** (`Dataset/Ataques/Comandos/*/ATA<NNN>_esperado.csv`) →
     el campo `esperado=` de la cabecera conserva la **misma ruta** que ya tenía.
   - **`--rev-out` a un temporal** (ignorado por git: `.gitignore` → `_artefactos/tmp/`) para que
     **nunca** se escriba sobre el `-Revision.csv` versionado.
3. **Demostrar determinismo:** buscar el `esperado` del **mismo** `rule_id` de detección
   (demo determinista = **cabecera** idéntica y **filas de datos idénticas**):
   - `git diff` de cada audited → **una sola línea cambiada** (la 1), y **solo** el
     `sha256=` del `esperado`;
   - re-ejecutar el filtro una 2ª vez a un temporal → `sha256` **idéntico** byte a byte (R-13);
   - `conteos:` de cabecera y filas de datos **sin cambios**.
4. **Actualizar** `esperado_sha256` y `audited_sha256` en las 3 bitácoras; el `sha256` del esperado
   en las fichas §2.

> **⛔ Nota (declarada): los `-Revision.csv` NO se tocan.** Son el **registro humano** (veredictos
> `veredicto/nota/revisor/fecha`). Su cabecera cita el `sha256` del esperado **en el momento en que
> se generó** ⇒ tras el arreglo queda **"anticuada"**. **Es el mismo patrón que ya existe en el
> piloto**: `ATA002_iter1-Revision.csv` cita `9739db1f…` mientras el esperado actual es
> `970c5dfc…`. Se documenta en el change-doc y se deja constancia de que **el hash canónico vive en
> el audited + ficha + bitácora**.

---

## 3. Cabo 3 — Texto que miente sobre las PAM (`politica_filtrado_ruido.md` §3.bis)

**Hecho real (verificado en los audited):**

| ATA | PAM `5501`/`5502` | Motivo real |
|---|---|---|
| **ATA004** | `ruido_conocido` | `baseline` (su esperado declara `rule_id` → **campo siempre evaluable**) |
| **ATA007** | `ruido_conocido` | `baseline` (ídem: `rule_id` `80790`/`80781`) |
| **ATA012** | `ruido_conocido` tras resolver; **en crudo `dudosa`** | `sin_campos` (su esperado **solo** declara `audit_exe`/`audit_cwd`) |

El texto actual dice que las `5501`/`5502` **quedan `dudosa`** (y solo menciona ATA002 como
excepción). **El resultado ES el deseado; el texto es el que está mal.**

### ✅ Decisión: **corregir el texto** para describir el comportamiento real (sin cambiar H3)

- En la **tabla** de `§3.bis` (filas `5501`/`5502`), matizar el *"queda `dudosa`"*:
  *"→ `dudosa` (`sin_campos`) **solo si** el `esperado` no declara ninguna señal de campo
  siempre evaluable; **si declara `rule_id`/`rule_group`, `sin_campos` no dispara** y caen al paso 6
  → `ruido_conocido`/`baseline`."*
- En **"Limitación declarada (residual)"**, reescribir la explicación con **ambos** casos y los
  ejemplos reales: **ATA002/ATA004/ATA007 → `baseline`**; **ATA012 → `dudosa` → resuelta a `ruido`**
  por el humano.
- **No se cambia el diseño de H3**: el predicado `OPERADOR` sigue eximiendo **solo** `5715`
  (`srcip`) y `19004` (grupo `sca`); `5501`/`5502` **siguen sin auto-excluirse** (el resultado
  `baseline` es un efecto del **orden de decisión + señales evaluables**, no del predicado).

---

## 4. Cabo 4 — Hipótesis de journald sin comprobar (ATA004)

**Hecho real:** para ATA004 se esperaban alertas de **journald/systemd** (`40700`) y salieron
**0** en las 2 ventanas; la **captura C0** solo cubrió la línea `execve` de `systemctl` → la
expectativa **quedó sin probar**.

### 🔎 Hallazgo (inspección, coste cero): `40700` es una regla de fábrica **`level=0`** (agrupador)

El manifiesto `Soporte/Wazuh/Configuracion/active_ruleset.txt` (línea 87) fija
`RS1 40700 40705 6 /var/ossec/ruleset/rules/0285-systemd_rules.xml`. La regla de fábrica
(`0285-systemd_rules.xml`, Wazuh **v4.14.7**, pin del laboratorio) es:

```xml
<rule id="40700" level="0"><program_name>^systemd$|^systemctl$</program_name>
  <description>Systemd rules</description></rule>
```

⇒ **`40700` es el agrupador con `level=0`** (no emite alerta). Sus **hijas** `40701`–`40705`
(level 2/5) **solo** disparan con patrones de **fallo** (`Stale file handle`, `entered failed
state`, `status=1/FAILURE`, `Time has been changed`…). Una **parada normal** de servicio
(`systemctl stop cron`, mensaje `Stopping/Stopped …`) **no casa ninguna hija** → gana `40700`
(level 0) → **NO hay alerta journald**.

### ✅ Decisión: **(a) documentar** como limitación/hallazgo (NO extender C0 en este bloque)

**Coste/beneficio:**

- **El hallazgo ya está obtenido** por inspección del ruleset de fábrica: **la expectativa de
  `40700` era estructuralmente imposible** (nivel 0) → *no era una detección "silenciada", era una
  detección **inexistente** de fábrica*. La única detección del ataque es el **`execve`**
  (`80792`, audit).
- **(b) extender el C0** exigiría **VMs + root** (todo el bloque pasaría a depender de ellas) y una
  **línea sintética de journald** de formato **no trivial**; en el repo **no hay ninguna muestra
  journald** con la que anclarla → riesgo de **`garbage-in`** y de una conclusión engañosa. El
  resultado (40700 level 0) **ya se conoce**.
- **(b) NO aporta hallazgo nuevo**: el "punto ciego" **ya se ha descubierto** (sin root).

**Acción concreta:**

1. **ATA004 ficha §8.1/§10** y **`T1489-Service_Stop/README.md` §7**: sustituir el *"0 detecciones
   `40700` (sin probar)"* por el **resultado documentado**: *"`40700` es `level=0` (agrupador de
   fábrica) → la parada de `cron` **no genera alerta journald**; la detección efectiva es el
   `execve` `80792`. La hipótesis queda **resuelta** (no 'sin probar')."*
2. **`Soporte/Ataques/piloto_procedimiento.md` §8** (hallazgos del piloto-custom): añadir
   **§8.3 — punto ciego de journald**: *la vía journald/systemd del ruleset base no alerta de una
   parada de servicio (solo de fallos); si el escalado necesita detección por journald, exige
   **regla propia (RS3)** o declarar la detección por el `rule_id` del `execve`.*
3. **Registrar como cabo del escalado** en el cambio de bloque: *"si una técnica depende de
   journald, confirmar empíricamente con un C0 sobre una **línea journald real** capturada en la
   víctima y, si aplica, escribir la regla RS3."*

> **Variante 4-b (solo si el humano la pide):** extender `Soporte/Ataques/c0/ATA004_logtest.txt`
> con una línea de journald **real** capturada en la víctima y re-pasar el pre-flight **en el paso 0**
> (VMs + root, contraseña solo en memoria). **No recomendada** (ver coste/beneficio).

---

## 5. Ficheros que se tocarán

| Fichero | Cabo | Cambio |
|---|---|---|
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA004_meta.md` | 1, 2, 4 | §6 cita; §2 hash; §8.1/§10 journald; `version: 2` |
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA007_meta.md` | 1, 2 | §6 cita; §2 hash; `version: 2` |
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA012_meta.md` | 1, 2 | §6 cita; §2 hash; `version: 2` |
| `Dataset/Ataques/Comandos/T1489-Service_Stop/ATA004_esperado.csv` | 2 | 1 línea de cabecera (datos intactos) |
| `Dataset/Ataques/Comandos/T1491-Defacement/ATA007_esperado.csv` | 2 | ídem |
| `Dataset/Ataques/Comandos/T1119-Automated_Collection/ATA012_esperado.csv` | 2 | ídem |
| `…/linux/Auditado/ATA00{4,7,12}_iter{1,2}-Audited.csv` (6) | 2 | **regenerados** (solo cabecera `sha256` del esperado) |
| `Bitacora/ATA004.json`, `ATA007.json`, `ATA012.json` | 2 | `esperado_sha256`, `audited_sha256`×2 + **evento append** (corrección) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | 3 | §3.bis (texto) + `version: 3` |
| `Dataset/Ataques/Comandos/T1489-Service_Stop/README.md` | 4 | §7 hipótesis journald |
| `Soporte/Ataques/piloto_procedimiento.md` | 4 | §8.3 (hallazgo journald) |
| `state.md`, `roadmap.md` | cierre | los actualiza el **orquestador** al cerrar |

**No se toca (salvo lo anterior):** los `-Detalle.csv` y los **`-Revision.csv`** de los 6; los
artefactos del **piloto/afinado**; `extraer_alertas.py`; `preflight_enmascaramiento.py`;
`Soporte/Wazuh/Reglas/**` (RS3/RS4); `Hojas/Detecciones.xlsx`; `BBDD/`; `_recursos/`;
`Hojas/ATA_index.csv` (las cifras no cambian).

---

## 6. Criterios de aceptación y casos de prueba

| # | Criterio (verificable) | Caso de prueba |
|---|---|---|
| **CA1** | **Cabo 1:** la lista de evidencia de las 3 fichas **coincide** con el contenido real de los 6 `Logs/`. | `ls Logs/ATA<NNN>_iter{1,2}/` ↔ §6 de cada ficha (sin `sha256_artefacto.txt` citado). |
| **CA2** | **Cabo 2:** las 3 cabeceras dicen `validado el 2026-09-26` y **ninguna** dice `PENDIENTE`; **los datos no cambian**. | `git diff` del esperado → **1 sola línea** (`#`), filas intactas. |
| **CA3** | **Cabo 2:** los 6 audited citan el **nuevo** `sha256` del esperado; **la única** diferencia es esa. | `git diff` de cada audited → **1 línea**; y `sha256(esperado)` == el de la cabecera. |
| **CA4** | **Cabo 2 (determinismo):** 2ª pasada del filtro → audited **byte a byte** idéntico (R-13). | `sha256` igual en 2 pasadas; `conteos:` y filas de datos idénticos a los previos. |
| **CA5** | **Cabo 2:** los 6 **`-Revision.csv` intactos**. | `sha256` de los 6 == los de la cabecera del audited previo (sin cambios en `git status`). |
| **CA6** | **Cabo 2:** hashes coherentes en **todos** los sitios. | `esperado_sha256` (bitácora) == §2 ficha == cabecera audited; `audited_sha256` (bitácora) == fichero. |
| **CA7** | **Cabo 3:** el texto describe los **dos** casos PAM y ambos ejemplos; **H3 sin cambios**. | Leer §3.bis; cruzar con los 6 audited (`5501`/`5502` → `baseline` en ATA004/007; `sin_campos` en ATA012). |
| **CA8** | **Cabo 4:** se documenta que `40700` es `level=0` → **0 alertas journald es lo esperado**; la hipótesis queda **resuelta**, no "sin probar". | Leer ficha ATA004 §8.1/§10 + README §7 + runbook §8.3; el manifiesto cita `40700-40705` (n=6). |
| **CA9** | **Sin regresión de cifras:** `deteccion`/`ruido_conocido`/`auto_ruido`/`dudosa`/`rule_id` y `Hojas/ATA_index.csv` **no cambian**. | Comparar conteos de las 6 cabeceras contra los anteriores; `git status` sin `ATA_index.csv`. |
| **CA10** | **Higiene:** sin secretos; `pytest` verde; `_recursos/` intacto. | `pytest _artefactos/scripts/tests/`; `grep` de la contraseña; `git status`. |

---

## 7. Cómo se verifica (`tfg-tester`) — **sin ataques, sin VMs, sin root**

El tester **no enciende VMs ni ataca**. Verifica **registro + determinismo + coherencia**:

1. **CA1:** `ls` de los 6 `Logs/` ↔ §6 de las 3 fichas.
2. **CA2/CA3:** `git diff` de los 3 esperado (**1 línea**) y de los 6 audited (**1 línea**, el
   `sha256` del esperado); recalcular `sha256` del esperado y casarlo con la cabecera.
3. **CA4:** **re-ejecutar** el filtro a un temporal (reproduciendo la invocación) → `sha256`
   idéntico (determinismo) y filas de datos idénticas.
4. **CA5:** comprobar que los 6 `-Revision.csv` **no** aparecen en `git status` y que su `sha256`
   no cambió; **nota declarada** de que su cabecera cita el esperado previo (patrón ya existente
   en el piloto, `ATA002`).
5. **CA6:** recorrer las referencias de hash (bitácoras, fichas, cabeceras) y comprobar que
   **todas** apuntan al valor actual.
6. **CA7:** leer `politica_filtrado_ruido.md` §3.bis y **cruzar** con los 6 audited (PAM).
7. **CA8:** leer ficha/README/runbook y comprobar la afirmación `40700 = level=0` contra el
   manifiesto (rango `40700-40705`, n=6) y la fuente fijada; **no** debe declararse ninguna
   detección journald inexistente.
8. **CA9/CA10:** cifras intactas, `ATA_index.csv` intacto, `pytest` verde, sin secretos,
   `_recursos/` intacto. **Veredicto PASA/FALLA con evidencia.**

---

## 8. Qué NO entra (fuera de alcance)

- **El rediseño de las señales (H-A/H-B):** semántica **AND** (`exe AND cwd`) o declarar la
  detección por el `rule_id` del `execve` (`80792`). → **otro bloque** (lo decidirá el plan del
  escalado o un bloque corto previo).
- **Escalar** a las 7 técnicas restantes; tocar sus filas de `ATA_index.csv`.
- **Windows**, **η**/Fase 4, **gráficas** y **memoria** (`_recursos/`).
- **Instalar** dependencias, **re-baselinar**, **reconectar NAT**, **arrancar VMs** o pedir root
  (salvo la variante **4-b**, que el humano decidiría).
- **Re-medir** los 3 ataques o recalcular **cifras**; tocar los `-Detalle.csv` y los
  **`-Revision.csv`**.
- Cambiar el **diseño** de H3 (solo su **texto**).

---

## 9. Qué tiene que aprobar el humano (gate)

1. **Cabo 1 — corregir la cita** (no generar `sha256_artefacto.txt`): **KISS + integridad**; el hash
   ya consta en ficha/bitácora. *(Alternativa: generarlo, descartada.)*
2. **Cabo 2 — arreglar la cabecera de los 3 `esperado` (validado 2026-09-26) + REGENERAR los 6
   `-Audited.csv` + actualizar hashes** (bitácoras y fichas), **sin tocar los `-Revision.csv`**
   (su cabecera queda citando el esperado previo — patrón ya existente en el piloto).
3. **Cabo 3 — corregir el texto** de `§3.bis` (PAM), **sin cambiar el diseño de H3**.
4. **Cabo 4 — (a) documentar** el resultado como hallazgo (`40700 = level=0` → journald no alerta
   de una parada normal). *(**Recomendada**.)* **Alternativa (b):** extender el C0 de ATA004 con una
   línea journald real y re-pasarlo → **VMs + root** (paso 0). **El humano decide (a) o (b).**
5. **Alcance:** bloque **doc-only, offline** (sin VMs ni root, salvo 4-b); **cero** cambios de
   cifras; **no** toca el diseño de las señales, ni escala, ni toca `_recursos/`/`BBDD/`/`xlsx`.

---

## 10. Notas de ejecución (orden y cuidados)

1. **Orden recomendado:** Cabo 2 primero (editar esperado → regenerar audited → actualizar hashes);
   luego Cabo 1 y Cabo 4 (edits de ficha/README/runbook); Cabo 3 (texto del filtro).
2. **Encoding:** los CSV son **UTF-8 sin BOM** con `LF`; los caracteres `·` (`C2 B7`) y `º`
   (`C2 BA`) deben **preservarse**. El reemplazo del Cabo 2 es **ASCII puro** (no los toca).
3. **Hashtags en minúsculas** (`sha256sum`/`Get-FileHash` → `.ToLower()`), como en los ficheros.
4. **`--rev-out` a `_artefactos/tmp/`** (ignorado por git) → **nunca** escribir sobre el
   `-Revision.csv` versionado; verificar su `sha256` tras la regeneración.
5. **Bitácoras = append-only:** actualizar los campos de hash **y** **añadir un evento** del tipo
   `correccion` (fecha 2026-09-28) que registre el arreglo del cabo 2.
6. **Meseta de éxito:** si un dato no cuadra (p. ej. la ruta `esperado=` de la cabecera no se
   reproduce), **parar** y reportar en vez de "forzar" la cabecera a mano.

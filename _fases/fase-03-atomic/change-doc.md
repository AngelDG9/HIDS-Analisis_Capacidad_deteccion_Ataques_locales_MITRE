# change-doc — Bloque `fase-03-atomic` (A2.3): Atomic Red Team (el "cajón de los ataques")

> Cierre del bloque. Fecha: **2026-09-25**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`, aprobado el 2026-09-25).

---

## 1. Qué se ha hecho

Dejar **Atomic Red Team** (biblioteca pública de pruebas de MITRE ATT&CK) **descargado, fijado,
documentado y usable** (R-12), y producir el **mapa de cobertura** de las 13 técnicas del corpus
(insumo directo para T-09). **No se ha ejecutado ninguna prueba atómica** (lo aprobó así el humano:
la primera ejecución real será el piloto).

**Decisiones del plan que han funcionado:**
- **Dónde vive:** en el **host/repo** (`Soporte/Ataques/atomic-red-team/`), **nunca dentro de la víctima**
  (el revert a `lab-listo` lo borraría). En ataque se **copian al vuelo** solo los ficheros de la técnica.
- **Versionado:** clon **`.gitignore`ado** + **sidecar** con `url`/`commit`/licencia (precedente del STIX).
  **Sin submódulo.**
- **NAT:** la descarga va en el **host** (que tiene internet) → **el NAT de las VMs no interviene** y
  permanece **DESCONECTADO**. *(El encargo asumía lo contrario; corregido por el plan.)*

---

## 2. Entregables

| Fichero | Estado |
|---|---|
| `Soporte/Ataques/atomic-red-team/` | **clonado** (NO versionado; 884,8 MB; **344 dirs `atomics/T*`**) |
| `Soporte/Ataques/atomic-red-team.version` | creado (sidecar: URL + **commit** + fecha + licencia MIT) |
| `Soporte/Ataques/atomic_red_team.md` | creado (qué es, dónde vive y por qué, receta, copia al vuelo, NAT, cobertura, dry-run de T1486) |
| `_artefactos/scripts/cobertura_atomic.py` | creado (solo stdlib, determinista, offline) |
| `_artefactos/scripts/tests/test_cobertura_atomic.py` + fixtures | creados (**12 tests**; suite total **58 en verde**) |
| `Hojas/cobertura_atomic.csv` | creado (13 filas, orden estable) |
| `.gitignore` | añadido `Soporte/Ataques/atomic-red-team/` |

**Pin:** `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` (master, commit del 2026-09-05).

---

## 3. Resultado principal: el mapa de cobertura

**Recomputado de forma independiente por el `tfg-tester` desde los índices crudos del clon: coincide
fila a fila (13/13) con `Hojas/cobertura_atomic.csv`** y con el borrador del plan (§4).

| | |
|---|---|
| Técnicas con pruebas en ART | **11 / 13** |
| **Cubiertas en Linux** | **7 / 13** |
| Solo Windows (→ hay que escribirlas para Linux) | **4 / 13**: `T1490`, `T1491`, `T1041`, `T1119` |
| **Sin pruebas en ART** (→ custom obligatorio) | **2 / 13**: `T1561`, `T1565` |
| **TOTAL que requiere script propio en Linux** | **6 / 13** |

> **Distinción que queda documentada (importante para la memoria):** *"la técnica no aplique a Linux"*
> y *"la biblioteca no la cubra en Linux"* son **cosas distintas**. En los 4 casos de "solo Windows",
> la técnica **sí es válida en Linux**; lo que falta es la prueba hecha. Por eso se escriben **a mano**,
> **no** se excluyen del TFG.

---

## 4. Verificación (`tfg-tester`)

**Veredicto: PASA.** Entre otras comprobaciones:

- Clon **completo y limpio**: `HEAD` == pin del sidecar, rama `master`, `status --short` **vacío**, 344 dirs.
- Clon **ignorado** por git; **sidecar versionable** (`git check-ignore` → exit 1).
- **Mapa recomputado** (PowerShell propio, sin usar el script) → **13/13 filas coinciden**; spot-check crudo de `T1486`, `T1490`, `T1561`, `T1565`, `T1119`, `T1560`.
- **Determinismo**: dos ejecuciones → mismo `sha256`. **Fallo claro** (`exit 2`) sin clon/índice/corpus.
- **CA6 — no se ejecutó ninguna atómica**: clon sin modificar, sin payloads ni artefactos de ataque en el host, sin procesos sospechosos, sin ficheros fuera de los esperados.
- Suite **58 tests** en verde; sin regresión. Sin secretos; `_recursos/` intacto; sin commit.

---

## 5. Hallazgos y notas

1. **El mapa preliminar del plan coincidió con la realidad** (mismos recuentos y veredictos). Único matiz
   cosmético: `T1567` también tiene la subtécnica `.003` (no altera recuentos ni veredicto).
2. **Las VMs estaban apagadas** durante la ejecución de este bloque (el bloque es **todo del host**, así que
   no afectó). Los snapshots **`base-limpia` y `lab-listo` siguen intactos** en ambas.
3. **Proceso (3ª vez, ya registrado):** una operación larga lanzada en **segundo plano** murió al acabar el
   turno (esta vez, el `git clone`). **Regla:** las operaciones largas, en **primer plano con timeout amplio**.
4. **Dependencias de las atómicas** (`gpg`, `ccrypt`, `7z`…) se resolverán, si hacen falta, en **T-09**
   (requerirían NAT puntual y están **fuera** de este bloque).

---

## 6. Cabos conocidos

| # | Cabo | Nota |
|---|---|---|
| 1 | **6/13 técnicas requieren script propio en Linux** | Es **trabajo de la Fase 3** (T-09), no una carencia del bloque. |
| 2 | El **sidecar** y el resto de artefactos están **sin commitear** | Se commitean al cerrar (lo hace el orquestador). |
| 3 | El **dry-run de T1486** está documentado, **no ejecutado** | La ejecución real es el piloto. |
| 4 | Los **tests usan un clon en miniatura** (fixtures) | Correcto por diseño; la validez de los **números reales** la da la verificación contra el clon completo (hecha). |

---

## 7. Siguiente

- **Termina la preparación de la Fase 3:** con A2.1, A2.2 y A2.3 cerrados, **no queda ningún bloque
  de herramientas** (A2.4, el cronómetro, va **dentro** del plan de los ataques).
- **Después: el PILOTO** (2-3 ataques) — primera vez que se junta todo el ciclo:
  `lab-listo` → t0 → ataque → t1 → extraer (del **fichero diario**) → filtrar → etiquetar → **pasar el examen**.
- **Recordatorios para la Fase 3:** (a) extraer del **fichero diario**; (b) **C2 del pre-flight con los
  eventos de cada ataque**; (c) el fichero de **señales esperadas** lo valida el humano; (d) **la
  convención de carpetas por sistema** (`Dataset/…/<so>/…`) está anotada en `state.md`.

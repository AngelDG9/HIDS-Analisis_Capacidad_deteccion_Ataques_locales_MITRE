---
fase: 3
bloque: fase-03-atomic
tarea: A2.3 (R-12 / R-13 · T-09)
nombre: Atomic Red Team — el "cajón de los ataques" (descarga, fijado y cobertura)
version: 1
status: approved_by_human
fecha: 2026-09-25
fecha_aprobacion: 2026-09-25
aprobado_por: humano
autor: tfg-planner
gate: humano (aprobación de este plan antes de implementar)
---

# Plan — Bloque `fase-03-atomic` (A2.3): Atomic Red Team

> Tercera y última herramienta de preparación de la Fase 3. **No ejecuta ataques**: deja la
> biblioteca de pruebas de MITRE ATT&CK **descargada, fijada, documentada y consultable**, y
> entrega el **mapa de cobertura** de las 13 técnicas del corpus. KISS: 8/10 hecho > 10/10 sin hacer.

## 0. Objetivo y alcance

**Objetivo:** cumplir **R-12** — `Soporte/Ataques/atomic-red-team/` **clonado y usable** — sin
engordar el repo, y **apoyar R-13** (toda técnica tendrá artefacto + README) con un **mapa de
cobertura** que decide qué técnicas cubre ART y cuáles necesitan **script custom**.

**Entra:** el clon fijado a un commit, su sidecar de versión, la documentación de uso, la
herramienta de cobertura (+ tests) y su salida `Hojas/cobertura_atomic.csv`.
**NO entra:** ejecutar ataques (ni una atómica "benigna"), el cronómetro A2.4, escribir reglas RS3,
η (Fase 4), instalar dependencias en la víctima, víctima Windows. Ver §11.

## 1. Decisión 1 — DÓNDE VIVE el cajón y cómo sobrevive al revert ⚠️

**El cajón vive en el SOBREMESA/REPO: `Soporte/Ataques/atomic-red-team/`** (ruta que exige R-12).

- **Ataca time (T-09):** se **copian al vuelo solo los ficheros de la técnica necesaria** (p. ej.
  `atomics/T1486/`) del host a la víctima por `scp` sobre `VMnet1` (`192.168.65.0/24`), a un
  directorio de trabajo tipo `/home/angel/lab-attack/`. **La víctima revierte a `lab-listo` antes de
  cada ataque** (`vmrun_config.md` §4), así que ese copiado es **efímero y no contamina**.
- **Por qué NO dentro de la víctima:** todo lo clonado ahí **desaparece al revertir**; y
  re-clonarlo en cada ataque exigiría **NAT encendido durante el ataque** (prohibido, §5).
- **Por qué NO en el manager (`wazuh-server`):** el manager es el **detector**; no es sitio para
  payloads, y R-12 nombra la ruta del repo. (Aunque no se revierte, se descarta.)
- **Alternativa descartada — "hornear" ART en un snapshot nuevo** (`lab-listo-attack`): obligaría a
  tocar/renombrar el snapshot sobre el que se grabó el baseline de Fase 2 y alteraría la imagen
  limpia de la víctima. Se mantiene **`lab-listo` prístino**; el copiado al vuelo es más limpio.

**Consecuencia:** el cajón **sobrevive a todos los reverts** (está fuera de la víctima) y en ataque
**no se necesita internet**.

## 2. Decisión 2 — Cómo se versiona sin engordar el repo

**Precedente de Fase 1 (STIX): se `.gitignore`a el material pesado y se versiona URL + pin.** Se imita:

| Qué | Decisión |
|---|---|
| El clon (`atomic-red-team/`) | **`.gitignore`ado** (miles de ficheros; repo ≈ **0,6 GB** en GitHub). **NO se versiona.** |
| La versión usada | **Sidecar `Soporte/Ataques/atomic-red-team.version`** con `url`, `commit`, `fecha_commit`, `clonado`, `licencia (MIT)`. |
| Reproducción | Receta exacta en la doc: `git clone <url> …` + `git checkout <commit>`. |

**Alternativas y por qué se descartan:** un **submódulo** git sería más "correcto" pero añade un
repo anidado, `.gitmodules`, y exige `git submodule update` (más complejidad para el mismo repo
público y ligero); el precedente fijado por el humano (state.md) es **gitignore + URL/hash**. El
contenido es **MIT**, pero **no se redistribuye** (no se commitea).

> **Commit de referencia (observado hoy, master 2026-09-05):**
> `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. **Regla:** el sidecar registra **exactamente** lo que
> se clone. Si master ha avanzado, se registra el nuevo `HEAD`. **Regenerar la cobertura si cambia.**

## 3. Decisión 3 — Cómo se prueba que el cajón FUNCIONA (sin ejecutar ataques)

Ejecutar atómicas = **ejecutar ataques** → es T-09/T-10, **fuera de alcance**. La prueba mínima que
sí demuestra "descargado y usable" es **integridad + consulta + preparación en seco, offline**:

1. **Integridad/fijado:** el clon existe y `git rev-parse HEAD` == commit del sidecar; se registra el
   nº de directorios `atomics/T*`.
2. **Consulta (la prueba central):** `_artefactos/scripts/cobertura_atomic.py` (solo stdlib)
   cruza el corpus (`Hojas/ATA_index.csv`) con los índices del clon
   (`atomics/Indexes/Indexes-CSV/{index,linux-index,windows-index}.csv`) y **genera el mapa** →
   `Hojas/cobertura_atomic.csv`. **Determinista** (byte a byte) y **offline**.
3. **Preparación en seco de UNA técnica:** se localiza su YAML/payload, se lista el comando que
   *se ejecutaría* y lo que *se copiaría* a la víctima, **sin lanzarlo** (dry-run).
4. **Offline:** los tres puntos anteriores funcionan **con NAT desconectado**.

**Justificación:** el DoD del bloque es "descargado + documentado + usable"; eso lo prueba el poder
**seleccionar y preparar** una prueba de forma reproducible, no el detonarla. La ejecución real
(los ataques) es el **piloto T-09**. Si el humano quiere más certeza, se autoriza una
micro-ejecución benigna **como excepción explícita** (por defecto: **NO**).

## 4. Decisión 4 — Mapa de cobertura del corpus (dato real, preliminar)

Cruce de las **13 técnicas** (`ATA_index.csv`) con el índice ART de **Linux** y **Windows** (master
`388942a`, 2026-09-05). La columna clave es **Linux** (SO víctima por defecto).

| ATA | Técnica | Dir ART | tests Linux | tests Windows | Veredicto (Linux) |
|---|---|---|---|---|---|
| ATA001 | T1486 Data Encrypted for Impact | sí | 4 | 4 | **cubierta** |
| ATA002 | T1485 Data Destruction | sí | 1 | 3 | **cubierta** |
| ATA003 | T1490 Inhibit System Recovery | sí | **0** | 12 | solo Windows |
| ATA004 | T1489 Service Stop | sí | 5 | 4 | **cubierta** |
| ATA005 | T1561 Disk Wipe | **no** | 0 | 0 | **sin pruebas → custom** |
| ATA006 | T1565 Data Manipulation | **no** | 0 | 0 | **sin pruebas → custom** |
| ATA007 | T1491 Defacement | solo `T1491.001` | 0 | 4 | solo Windows |
| ATA008 | T1048 Exfil. Over Alternative Protocol | sí (+`.002/.003`) | 9 | 7 | **cubierta** |
| ATA009 | T1567 Exfil. Over Web Service | solo `.002/.004` | 3 | 4 | **cubierta (sub)** |
| ATA010 | T1041 Exfil. Over C2 Channel | sí | **0** | 2 | solo Windows |
| ATA011 | T1074 Data Staged | solo `T1074.001` | 1 | 2 | **cubierta (sub)** |
| ATA012 | T1119 Automated Collection | sí | **0** | 4 | solo Windows |
| ATA013 | T1560 Archive Collected Data | sí (+`.001/.002`) | 9 | 8 | **cubierta** |

**Conclusión (insumo directo para T-09):** en **Linux quedan cubiertas 7/13**; **6/13 requieren
script custom** — **T1561 y T1565 no existen en ART** (custom obligatorio) y **T1490, T1491, T1041,
T1119 solo tienen atómicas de Windows** (custom en Linux, o replantear víctima Windows, decisión
**pendiente de tutoría**). Afina el riesgo ya previsto en `roadmap.md`.

## 5. Decisión 5 — NAT: **corrección de premisa**

La premisa del encargo ("la descarga necesita NAT") **no aplica**: el clon se hace en el
**sobremesa (host)**, que **sí tiene internet** — el NAT de las VMs es solo para tráfico *dentro* de
la VM. Por tanto:

- **El NAT de las VMs no interviene en esta descarga.** El cajón **no** se descarga dentro de la VM
  (sería inútil: lo perdería el revert).
- **El NAT permanece DESCONECTADO** (`ethernet1.startConnected = "FALSE"`) y **se verifica**.
- La receta de reactivación/desconexión (`vmrun_config.md` §5) **se documenta igualmente** como
  contingencia para el caso (fuera de alcance aquí) de que un test necesite **dependencias en la
  víctima**, que se resolverá en T-09. Regla de oro: **NAT OFF** en todo ataque.

> Si el humano **exige** que la descarga se haga dentro de una VM, este plan **cambia** (habría que
> reactivar NAT, clonar, extraer al host y volver a desconectar). Es un punto de gate.

## 6. Paso 0 (primera tarea del ejecutor)

1. Confirmar internet en el host y **clonar** en `Soporte/Ataques/atomic-red-team/`; **fijar el
   commit** (sidecar) y volcar `atomics/Indexes/Indexes-CSV/*.csv` (ya vienen en el clon).
2. Verificar **NAT desconectado** en ambos `.vmx` (lectura) y, si están encendidas, `ip route` sin
   `default` en la víctima.
3. Registrar nº de dirs `atomics/T*` y `git log -1`.

> **No se necesita root** (todo es del host) ni tocar las VMs (salvo *leer* su estado de red). No se
> inventan datos: la cobertura se **deriva del clon real**, no de este borrador.

## 7. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `.gitignore` | **añadir** `Soporte/Ataques/atomic-red-team/` |
| `Soporte/Ataques/atomic-red-team/` | **clonado** (NO versionado) |
| `Soporte/Ataques/atomic-red-team.version` | **nuevo** (sidecar: url + commit + fechas + licencia) |
| `Soporte/Ataques/atomic_red_team.md` | **nuevo** (qué es, dónde vive, cómo se clona/usa/copia, NAT, cobertura, pin) |
| `_artefactos/scripts/cobertura_atomic.py` | **nuevo** (mapa de cobertura, solo stdlib) |
| `_artefactos/scripts/tests/test_cobertura_atomic.py` + `tests/fixtures/atomic_*` | **nuevos** (tests offline con fixtures pequeños) |
| `Hojas/cobertura_atomic.csv` | **nuevo** (salida determinista del mapa) |

## 8. Criterios de aceptación y casos de prueba

| # | Criterio | Verificación |
|---|---|---|
| **CA1** | `Soporte/Ataques/atomic-red-team/` existe y `git rev-parse HEAD` == commit del sidecar | comando |
| **CA2** | El clon está **`.gitignore`ado** y el **sidecar sí versionado** | `git status --ignored` |
| **CA3** | `Hojas/cobertura_atomic.csv` cubre **las 13** técnicas con `ata_id,tecnica,nombre,prueba_art,tests_linux,tests_windows,path,nota` | inspección |
| **CA4** | **Determinismo:** dos ejecuciones → mismo `sha256` | re-ejecutar |
| **CA5** | La doc explica dónde vive, cómo se reproduce y que **NAT queda OFF** | lectura |
| **CA6** | **No** se ejecutó ninguna atómica | no hay payloads/procesos fuera del cajón |

**Casos de prueba (tool, offline con fixtures pequeños):**
`(a)` técnica cubierta (`T1486`) → `prueba_art=sí`; `(b)` sin pruebas (`T1561`) → `no`;
`(c)` solo Windows (`T1490`) → `sí` con `tests_linux=0` y `nota=solo_windows`;
`(d)` falta el índice/clon → **exit ≠ 0** con mensaje claro; `(e)` orden estable por `ata_id`.

## 9. Cómo se verifica (`tfg-tester`)

1. `pytest _artefactos/scripts/tests/test_cobertura_atomic.py` → **verde**.
2. Reproduce **CA1/CA2** (`git rev-parse`, `git status --ignored`).
3. Re-genera el CSV → **byte a byte idéntico** (CA4).
4. Coteja el mapa contra el clon real (spot-check: `T1561`/`T1565` ausentes; `T1490` sin Linux).
5. Ejecuta con **NAT desconectado** (offline) → funciona (CA5).
6. Confirma **CA6** (no se lanzó nada) y **no regresión** de los scripts existentes.

## 10. Trazabilidad

| Requisito / norma | Dónde se cumple |
|---|---|
| **R-12** (cajón clonado y usable) | §1 clon en `Soporte/Ataques/atomic-red-team/` + §2 fijado + §3 cobertura |
| **R-13** (reproducibilidad) | sidecar con commit + herramienta **determinista** |
| **T-09** (artefacto por ataque) | el mapa §4 decide ART vs **custom**; el artefacto se escribe en T-09 |
| **Riesgo roadmap** (ART no cubre) | §4: 6/13 necesitan custom |
| **NAT OFF** (`vmrun_config.md` §5) | §5 |

## 11. Qué NO entra

**Ejecutar ataques** (ni una atómica benigna; el piloto es T-09/T-10) · cronómetro `t0`/`t1`
(A2.4) · escribir/desplegar reglas RS3 · η (Fase 4) · instalar dependencias de las atómicas en la
víctima · víctima Windows · tocar `ATA_index.csv`. El laboratorio no se modifica (solo se **lee**
su estado de red).

## 12. Qué tiene que aprobar el humano (gate)

1. **Dónde vive:** cajón en el **host/repo** (`Soporte/Ataques/atomic-red-team/`), **copia al
   vuelo** por técnica a la víctima; **nunca** dentro de la víctima ni del manager. `lab-listo`
   permanece prístino (§1).
2. **Versionado:** **clon + `.gitignore` + sidecar URL/commit** (imitando el STIX), **sin
   submódulo** (§2).
3. **Prueba de operatividad:** **integridad + consulta + preparación en seco, offline**; **NO
   ejecutar** atómicas (§3). ¿Se autoriza una micro-ejecución benigna, o se deja al piloto?
4. **PIN del commit** de ART y que **la cobertura se regenera** si el pin cambia (§2).
5. **Corrección NAT:** confirmar que la descarga va en el host y que el **NAT queda desconectado**
   (sin reactivarlo) (§5).

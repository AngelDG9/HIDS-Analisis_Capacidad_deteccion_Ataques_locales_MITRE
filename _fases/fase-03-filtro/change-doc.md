# change-doc — Bloque `fase-03-filtro` (A2.1): filtro de ruido y etiquetado auditado

> Cierre del bloque. Fecha: **2026-09-25**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`, aprobado el 2026-09-25).

---

## 1. Qué se ha hecho

Construir la **primera herramienta de preparación de la Fase 3**: la que convierte las alertas de
una ventana de ataque en una **tabla auditada**, etiquetando cada alerta con un criterio
**explícito, determinista y reproducible**. No detecta ataques: **organiza y etiqueta la evidencia**.

**Criterio implementado** (gana el primero que casa): `auto_ruido` (por campos: proceso/cwd/ruta del
propio Wazuh) → `deteccion` (señal esperada) → `dudosa` (señal ambigua o sin campos) →
`deteccion` (motivo `novel`: `rule.id` no en el catálogo) → `ruido_conocido`.

---

## 2. Entregables

| Fichero | Estado |
|---|---|
| `_artefactos/scripts/filtrar_ruido.py` | creado (la herramienta) |
| `_artefactos/scripts/extraer_alertas.py` | ampliado: `--muestra`, `--detail`, `--max-por-regla` (agregado y `--test` **intactos**) |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` + fixtures | creados (**27 tests en verde** en total) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | creado (la política, coincide con el código) |
| `Dataset/Muestras/baseline_muestra.jsonl` | creado (54 líneas reales, sin secretos) |
| `Dataset/Legitimo/baseline_detalle_{v1,v2}.csv` | creados (una fila por alerta; **6.837 / 6.737**, 0 UNKNOWN) |
| `Dataset/Ataques/Resultados/Wazuh/Auditado/EJEMPLO_ATA000_iter1-Audited.csv` | ejemplo de salida (+ `_Revision.csv`) |
| `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` | ejemplo del fichero de señales esperadas |

---

## 3. Verificación (`tfg-tester`)

**Veredicto: PASA.** El tester **reprodujo por su cuenta** los 8 casos de aceptación y comprobó que
el **código coincide literalmente** con el plan y con la política.

| Caso | Resultado real |
|---|---|
| a) Basado en el baseline (v1 y v2) | **0 detecciones**; todo ∈ {`auto_ruido`, `ruido_conocido`} |
| b) `rule.id` inventado | `deteccion` / `novel` |
| c) Auto-ruido (`wazuh-agentd`, `cwd=/var/ossec`) | `auto_ruido`; **no** cuenta como detección |
| d) Determinismo (dos ejecuciones) | `sha256` **idéntico** |
| e) Señal sobre regla conocida | `deteccion` (el catálogo **no** la absorbe) |
| f) Ambigua → revisión → veredicto → `--revision` | `revision=resuelta` + `veredicto_humano` trazable |
| g) `rs_origen` RS1..RS4 / UNKNOWN | copiados **sin alterar** |
| h) Ataque sin fichero de señales | **exit ≠ 0**, no escribe salida |

Además: **no regresión** (`--test`, agregado y detalle regenerados **byte a byte idénticos**),
**sin secretos**, `_recursos/` intacto, sin commit.

---

## 4. Desviaciones y hallazgos

1. **⚠️ `alerts.json` ROTA a diario** (no es append-only). En la Fase 3 hay que extraer del
   **fichero diario** `/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`, porque
   `alerts.json` solo contiene el día en curso y se reinicia al arrancar el manager. **No se perdió
   nada**: el diario del 23-sep conserva **28.480 líneas** con las dos ventanas completas
   (6.837 / 6.737, 0 UNKNOWN). *(La nota contraria que llevaba el encargo de ejecución era
   incorrecta; verificada y corregida por el ejecutor y el tester.)*
2. **Acción fuera del plan (menor, declarada):** para confirmar los campos de FIM se creó y borró un
   fichero benigno de prueba en la víctima → **2 alertas FIM** (554 *added*, 553 *deleted*) del
   25-sep. **No contaminan el baseline**: `grep hids_fim_probe ossec-alerts-23.json` = **0**.
   El fichero **no existe** y no hay rastro en la configuración.
3. **Campos reales confirmados:** la lista candidata del plan coincidía; se **añadieron**
   `audit_file` y `audit_dir` porque la cláusula de auto-ruido por ruta los necesita.
4. **Contradicción interna del plan (§4 vs §5):** al plegar la revisión, `revisor`/`fecha`/`nota`
   se guardan **dentro de `evidencia`**, respetando las **15 columnas aprobadas** en §5.
5. **Corrección de errata del plan:** el motivo se llamaba `novedad` en §2 y `novel` en §5/§8;
   el código implementa `novel` y el plan se corrigió antes de archivar.

---

## 5. Cabos y limitaciones conocidas

| # | Cabo | Nota |
|---|---|---|
| 1 | Cláusula de auto-ruido por ruta `/var/ossec/var/run/*` **no portable** (separadores Windows) | Inerte hoy: **0 filas** del baseline dependen de ella (el auto-ruido sale por `exe`/`cwd`). Requiere test explícito si algún ataque dependiera. |
| 2 | **Determinismo condicionado al nombre** del fichero de salida | El `#` de cabecera incrusta el `basename` del `--out`. Cumple R-13 para una misma invocación. Documentado. |
| 3 | Interpretaciones declaradas | `sin_campos`, `--modo baseline` absorbiendo `novel`, y `audit_exe` comparado por ruta **y** nombre base: razonables y **documentadas** en la política (§3/§4/§5/§7). |
| 4 | **Depende del fichero de señales esperadas por ataque** | **Es el punto donde se puede sesgar el resultado.** Mitigación vigente: se redacta **antes** de ejecutar el ataque (T-09) y **lo valida el humano**. Añade **trabajo por ataque**. |

---

## 6. Siguiente

- **A2.2** — pre-flight anti-enmascaramiento (bloque `fase-03-preflight`).
- **A2.3** — Atomic Red Team. **A2.4** — cronómetro `t0`/`t1` por ataque.
- Después: **los ataques** (T-09/T-10/T-11).
- **Recordatorio para la Fase 3:** extraer las alertas del **fichero diario**, no de `alerts.json`.

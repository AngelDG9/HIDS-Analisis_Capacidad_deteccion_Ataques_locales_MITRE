---
fase: 3
bloque: fase-03-preflight
tarea: A2.2 (§9.8 · R-09/R-13)
nombre: Pre-flight anti-enmascaramiento (operacionalización del §9.8)
version: 1
status: approved_by_human
fecha: 2026-09-25
fecha_aprobacion: 2026-09-25
aprobado_por: humano
autor: tfg-planner
gate: humano (aprobación de este plan antes de implementar)
---

# Plan — Bloque `fase-03-preflight` (A2.2): pre-flight anti-enmascaramiento

> Segunda herramienta de preparación de la Fase 3. **No detecta ataques: impide medir mal.**
> En Wazuh hay **una alerta por evento**; una regla propia que case el mismo evento que una base
> **suprime** la base y **infravaloraría RS1** (bug real del *smoke* `100000`, `rulesets_diseno.md`
> §9). Esta herramienta convierte el **punto 8 del §9** en un **examen con código de salida**: si
> una regla propia (RS3/RS4) enmascara una base (RS1/RS2) y el solapamiento **no está declarado**,
> **FALLA y no se despliega**. KISS: 8/10 hecho > 10/10 sin hacer.

## 0. Objetivo y alcance

**Objetivo:** construir `_artefactos/scripts/preflight_enmascaramiento.py`, que analiza las reglas
propias candidatas (aún **sin desplegar**, desde `Soporte/Wazuh/Reglas/`) contra el ruleset base
real (índice `active_ruleset.txt`) y decide **PASA / FALLA / INCOMPLETO** con un informe legible.

**Entra:** la herramienta, su procedimiento escrito (cuándo se ejecuta), el **fichero de
declaración de solapamientos**, tests offline con fixtures, y la **demostración empírica del caso
"hermana"**.
**NO entra:** Atomic Red Team (A2.3), cronómetro `t0`/`t1` (A2.4), ejecutar ataques, escribir reglas
RS3 reales, desplegar reglas, η (Fase 4), tocar el laboratorio salvo el **paso 0** (captura
autorizada y reversible, §1).

## 1. Paso 0 — lo que no está en el repo (requiere **root** en el manager)

No se inventa ni el comportamiento de `wazuh-logtest` ni el formato real de las reglas. El ejecutor
(con la contraseña de root del manager) lo vuelca y hace los tests **offline para siempre**
(patrón de A2.1):

1. **`wazuh-logtest`:** confirmar que existe, su `-h`, si requiere root, y **si carga solo las reglas
   desplegadas** (¿hay forma de apuntar a otro directorio?). Volcar la ayuda al repo.
2. **Fixtures golden:** capturar `wazuh-logtest -v` sobre un **conjunto pequeño y curado de eventos
   reales** (derivados de `full_log` de `Dataset/Muestras/baseline_muestra.jsonl` + una línea sshd de
   usuario inexistente), **sin** reglas propias → salida "base".
3. **Demostrar el caso "hermana"** (hoy solo razonado): añadir **temporalmente** una regla hermana
   mínima (sin `<if_sid>`, p. ej. `<if_group>sshd</if_group>` + `<match>Invalid user</match>`),
   capturar la salida "candidato" y comprobar que **`5710` deja de ser la ganadora**; **restaurar**
   el estado. Evidencia en un doc. (Es el mismo experimento que reveló el bug de `100000`, ahora
   controlado y reversible.)
4. **Forma real de `<if_sid>`** en el ruleset base: ids múltiples, separadores, `<if_matched_sid>`,
   `<if_group>` (muestras a `preflight_*`).

> **⛔ Pido explícitamente la contraseña de root del manager** (o que el humano ejecute el paso 0).
> Sin ese dato, el chequeo **C2** y la demostración hermana quedan **bloqueados**; el chequeo **C1**
> (el que causó el bug real) es **offline** y no necesita root.

## 2. Qué comprueba el examen (dos chequeos, un mismo gate)

**C1 · Cadena `<if_sid>` / `<if_matched_sid>` (estático, OFFLINE).** Parsea las reglas propias
(`local_rules.xml` = RS3, `external_*.xml` = RS4; **ignora comentarios XML**), construye el grafo
`regla → padres` y resuelve el RS de cada ancestro con el **índice por fichero de
`active_ruleset.txt`** (RS1/RS2 = base; RS3/RS4 = propias). Recorre **transitivamente** (cubre
**multinivel**: propia → propia → base). Si una regla propia alcanza un ancestro **RS1/RS2** →
**ENMASCARA (cadena)**. Es la operacionalización directa del §9.1/§9.8.

**C2 · Hermana (empírico).** Una regla **sin `<if_sid>`** que capture **el mismo evento** que una
base (por `if_group`/`<match>`/`<decoded_as>`/campos) **también** la suprime, y **no es detectable
estáticamente** (equivalencia de predicados no es decidible en general). Se detecta **cotejando
sobre una muestra de eventos reales** con `wazuh-logtest -v`: dadas dos salidas capturadas sobre la
**misma lista de eventos** — `--logtest-base` (sin propias) y `--logtest-candidato` (con propias) —
se parsea la regla ganadora por evento; si un evento cuya base ganaba RS1/RS2 pasa a ganarla una
propia → **ENMASCARA (hermana)**. Si no se aportan las capturas, C2 se declara **NO EJECUTADO**
(nunca se pasa en silencio) y el resultado es **INCOMPLETO**.

**Ámbito:** C1 y C2 cubren **RS3 y RS4** y **cadenas de varios niveles** por construcción.

## 3. Cómo se declara un solapamiento aceptado (§9.5–§9.6)

Fichero **`Soporte/Wazuh/Configuracion/solapamientos_declarados.csv`** (mismo lector que el repo:
ignora líneas `#`). Columnas:

```text
regla_propia,tipo,regla_base,motivo,revision_rs1,revisor,fecha
```

- `tipo ∈ {cadena, hermana}`; `revision_rs1` documenta la **regla de recuento `RS1∩RS3`** (§9.6).
- El examen **PASA una pareja `(regla_propia, regla_base)` solo si existe su fila**; sin fila → FALLA.
- Sin ese fichero, el examen sería siempre un "no": declarar es la **única vía** de aceptar un
  solapamiento consciente, y queda **trazado y versionado**.

## 4. Cuándo se ejecuta (§9.8)

1. **Antes de desplegar** cualquier regla propia (RS3/RS4) → si `exit ≠ 0`, **no se despliega**.
2. **Al cierre de cada tanda de ataques** → re-ejecución barata y determinista; queda como evidencia.
3. **Tras cambiar el ruleset base** (regenerar `active_ruleset.txt`) → re-validar.

## 5. Salida y contrato

- **Informe legible** (stdout y, con `--out`, `Soporte/Wazuh/Configuracion/preflight_informe.md`):
  reglas propias analizadas, cadenas encontradas, hallazgos hermana, declaraciones aplicadas y línea
  final **`RESULTADO: PASA|FALLA|INCOMPLETO`**. **Sin reloj** → misma entrada = informe **byte a byte**
  idéntico (R-13).
- **Códigos de salida:** `0` PASA (se puede desplegar) · `1` FALLA (enmascaramiento **no declarado**)
  · `2` uso/entrada · `3` INCOMPLETO (C2 no ejecutado o ancestro no resoluble). **Solo `exit 0`
  permite desplegar.**
- **Sin reglas propias** (estado actual de Fase 2) → PASA trivial (`0 reglas propias`), sin exigir C2.

## 6. Casos de prueba (para el `tfg-tester`, offline)

| # | Caso | Resultado esperado |
|---|---|---|
| **MALO** | regla propia hija de `5710` (`<if_sid>5710</if_sid>`, el histórico `100000`) | **FALLA** (`exit 1`) |
| **BUENO** | regla propia suelta, sin `<if_sid>` ni match de base | **PASA** (`exit 0`) |
| **HERMANA** | regla sin `<if_sid>` que casa el mismo evento | C2 la marca → **FALLA** sin declarar; **PASA** si `tipo=hermana` |
| **DECLARADO** | el caso MALO + fila en `solapamientos_declarados.csv` | **PASA** |
| **MULTINIVEL** | propia A `<if_sid>` propia B; B `<if_sid>5710` | **FALLA** (transitivo) |
| **RS4** | `external_*.xml` con `<if_sid>` de base | **FALLA** (ámbito RS4) |
| **INCOMPLETO** | reglas propias y **sin** capturas logtest | `exit 3` + aviso explícito |
| **DETERMINISMO** | dos ejecuciones, misma entrada | informe byte a byte idéntico |

## 7. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/preflight_enmascaramiento.py` | **nuevo** (la herramienta; C1 + C2) |
| `_artefactos/scripts/tests/test_preflight_enmascaramiento.py` + `tests/fixtures/preflight_*` | **nuevos** (tests offline; fixtures del paso 0) |
| `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` | **nuevo** (procedimiento: chequeos, declaración, cuándo se ejecuta) |
| `Soporte/Wazuh/Configuracion/solapamientos_declarados.csv` | **nuevo** (solo cabecera + ejemplo comentado) |
| `Soporte/Wazuh/Configuracion/preflight_informe.md` | **nuevo** (ejemplo real de salida) |
| `Soporte/Wazuh/Configuracion/preflight_demo_hermana.md` | **nuevo** (evidencia del paso 0) |

## 8. Cómo se verifica (`tfg-tester`)

1. `pytest _artefactos/scripts/tests/test_preflight_enmascaramiento.py` → **todo PASA**.
2. Reproduce los 8 casos de §6 con los fixtures del repo y comprueba **exit codes** e informe.
3. Corre el pre-flight sobre el repo (**0 reglas propias hoy**) → **PASA**.
4. Comprueba **determinismo** (informe byte a byte) y que el **código coincide** con el doc.
5. **No regresión** de `extraer_alertas.py`/`filtrar_ruido.py`.

## 9. Trazabilidad

| Requisito / norma | Dónde se cumple |
|---|---|
| **§9.1/§9.3** prohibición + verificación `wazuh-logtest -v` | C1 acota `<if_sid>`; C2 consume las capturas |
| **§9.6** recuento `RS1∩RS3` | campo `revision_rs1` de la declaración |
| **§9.7** ámbito RS4 y multinivel | chequeos por construcción (§2) |
| **§9.8** pre-flight | esta herramienta (informe + exit code) |
| **R-09 / R-13** | RS por fichero de origen; determinista, re-ejecutable |
| **R-06** | no toca `<active-response>`; el paso 0 restaura el estado |

## 10. Qué NO entra

Atomic Red Team (A2.3); cronómetro `t0`/`t1` (A2.4); ejecutar ataques; escribir reglas RS3 reales;
desplegar reglas; η (Fase 4); tocar el laboratorio salvo el paso 0 (autorizado y reversible).

## 11. Qué tiene que aprobar el humano (gate)

1. Los **dos chequeos** y que **ambos bloqueen** salvo solapamiento declarado (§2).
2. El **formato del fichero de declaración** y que declarar sea la única vía de PASA (§3).
3. Los **códigos de salida** y que **solo `exit 0` permita desplegar** (§5).
4. Que el caso **HERMANA se detecta por logtest diferencial** (no estáticamente) y que el **paso 0
   es requisito** (§1–§2).
5. **Autorizar el root del manager** para el paso 0 (captura + demostración hermana reversible).

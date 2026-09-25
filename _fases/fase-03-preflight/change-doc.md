# change-doc — Bloque `fase-03-preflight` (A2.2): pre-flight anti-enmascaramiento

> Cierre del bloque. Fecha: **2026-09-25**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`, aprobado el 2026-09-25).

---

## 1. Qué se ha hecho

Construir el **examen** que impide que una regla propia **tape** una detección de fábrica
(la norma §9 de `rulesets_diseno.md`), con **dos chequeos** y **código de salida**:

- **C1 — Cadena (estático, OFFLINE):** recorre el grafo `<if_sid>`/`<if_matched_sid>` de nuestras
  reglas candidatas y resuelve el RS de cada ancestro **por fichero de origen** (`active_ruleset.txt`).
  Si alcanza una base (RS1/RS2) → **enmascara**. Cubre **multinivel** y **RS4**. **No necesita root.**
- **C2 — Hermana (empírico):** compara dos capturas de `wazuh-logtest -v` sobre la **misma lista de
  eventos** (`--logtest-base` sin propias vs `--logtest-candidato` con propias). Si un evento que
  ganaba RS1/RS2 pasa a ganarlo una propia → **enmascara**. Sin capturas → **INCOMPLETO** (nunca pasa en silencio).

**Declaración:** un solapamiento **consciente** solo se acepta si existe su fila en
`solapamientos_declarados.csv` (con `motivo` y `revision_rs1` para el recuento `RS1∩RS3`).
**Solo `exit 0` (PASA) permite desplegar** una regla.

---

## 2. Entregables

| Fichero | Estado |
|---|---|
| `_artefactos/scripts/preflight_enmascaramiento.py` | creado (C1 + C2; exit 0/1/2/3) |
| `_artefactos/scripts/tests/test_preflight_enmascaramiento.py` + fixtures | creados (**19 tests**; suite total **46 en verde**) |
| `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` | creado (procedimiento y cuándo se ejecuta) |
| `Soporte/Wazuh/Configuracion/solapamientos_declarados.csv` | creado (cabecera + ejemplo) |
| `Soporte/Wazuh/Configuracion/preflight_informe.md` | creado (salida real, byte a byte = la del repo) |
| `Soporte/Wazuh/Configuracion/preflight_demo_hermana.md` | creado (**evidencia del caso hermana**) |
| `_artefactos/scripts/tests/fixtures/preflight_*` | creados (ayuda de logtest, capturas base/candidato, eventos, muestra del ruleset) |

---

## 3. Hallazgo principal: el caso "hermana" queda **DEMOSTRADO**

Hasta ahora era **un aviso razonado** (el tester lo marcó como "no demostrado"). En este bloque
se ha **probado empíricamente**:

> Una regla **sin** `<if_sid>` (solo `<if_group>sshd</if_group>` + `<match>Invalid user</match>`),
> desplegada temporalmente, **hizo que `5710` dejara de ser la ganadora**: el mismo evento pasó a
> emitir la regla propia. Las 12 capturas son idénticas **salvo el evento 12**.

**Y refuerza la premisa:** se verificó en vivo que una regla **base real** (RS2, `80790`) usa
exactamente ese patrón (`if_group` + `<match>`, **sin** `<if_sid>`). O sea: **el patrón existe en el
propio ruleset de Wazuh**, no es una hipótesis.

**Consecuencia:** la norma §9 estaba en lo cierto y **no basta con "no usar `<if_sid>`"**. El examen
C2 es, por tanto, **imprescindible**, no un extra.

---

## 4. Verificación (`tfg-tester`)

**Veredicto: PASA.** El tester **reprodujo los 8 casos** con sus exit codes, comprobó el
**determinismo** byte a byte, la suite (**46/46**) y la **no regresión**, y —lo prioritario—
verificó **in situ** que **el manager quedó restaurado**:

```
/etc/rules/  →  solo 2 .bak (retirada 100000 / tfg28)   ·   find "*.xml" → vacío
login SSH fallido → id: '5710'  (NO 100000)
systemctl is-active → active / active / active       ·   sin restos en /tmp
sha256 de los .bak = los de la documentación
```

| Caso | Resultado |
|---|---|
| MALO (hija de `5710`) | **FALLA** (exit 1) |
| BUENO (suelta) | **PASA** (exit 0) |
| HERMANA sin declarar / declarada | **FALLA** (1) / **PASA** (0) |
| DECLARADO · MULTINIVEL · RS4 | PASA (0) · **FALLA** (1) · **FALLA** (1) |
| INCOMPLETO (sin capturas) | exit **3** |
| DETERMINISMO | informe byte a byte idéntico |
| Repo actual (0 reglas propias) | **PASA** (exit 0) |

---

## 5. Hallazgos y desviaciones

1. **`wazuh-logtest` NO admite otro directorio de reglas** (solo `-h -V -d -U -l -q -v`) y **requiere root**.
   → **C2 obliga a desplegar temporalmente** las reglas candidatas. Queda documentado el orden
   operativo: **C1 offline** (decide) → **C2 en ventana reversible** → PASA solo con `exit 0`.
   La promesa "antes de desplegar" se cumple **estrictamente para C1**; para C2 es una ventana
   **reversible y verificada**.
2. **Reglas con memoria** (`if_fts`/`frequency`) **no se reproducen** en `wazuh-logtest` → por eso C2
   es **diferencial** (misma herramienta en ambos lados; el efecto se cancela).
3. **El paso 0 tocó el manager** (regla hermana temporal) **y lo dejó restaurado y verificado**
   (0 reglas propias, `5710` recuperado, servicios sanos). Reversibilidad probada.
4. **Desviación menor:** la declaración exige que `tipo` **coincida** con el hallazgo (más estricto
   que la letra "solo la pareja" del plan). Coherente con §6; documentado.

---

## 6. Cabos conocidos

| # | Cabo | Nota |
|---|---|---|
| 1 | **C2 depende de la muestra de eventos** | Un solapamiento en un evento **no muestreado** pasa en silencio. Inherente (no es decidible estáticamente). **Hay que repetir C2 con eventos de cada ataque/tanda.** |
| 2 | **C2 exige desplegar temporalmente** | Riesgo pequeño, ya ejecutado con éxito; el estado se restaura y se verifica. |
| 3 | **Rangos del manifiesto solapados** | RS1 (fortigate `44600–81646`) **cubre** el subrango RS2 (`80700–80794`). Se resuelve por **rango más específico** y se marca `ambigua_por_rangos`. Al ser base-vs-base **no cambia el veredicto del examen**, pero la **etiqueta RS** podría ser incorrecta para una regla fortigate en ese subrango. **Revisar si afecta al recuento por capas de Fase 3.** |
| 4 | `if_matched_sid` tratado como arista padre | Puede dar **falsos positivos conservadores** (lado seguro del examen). |

---

## 7. Siguiente

- **A2.3** — Atomic Red Team (bloque `fase-03-ataques-herramientas` o similar).
- **A2.4** — cronómetro `t0`/`t1` por ataque.
- Después: **los ataques** (T-09/T-10/T-11).
- **Recordatorios para la Fase 3:** (a) extraer alertas del **fichero diario**; (b) **C2 con los
  eventos de cada ataque**; (c) el fichero de **señales esperadas** lo valida el humano.

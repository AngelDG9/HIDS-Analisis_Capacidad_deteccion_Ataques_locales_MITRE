---
fase: 3
tarea: A2.2 (§9.8 · R-09/R-13)
nombre: Pre-flight anti-enmascaramiento (procedimiento)
version: 1
status: implementada
fecha: 2026-09-25
autor: tfg-executor
---

# Pre-flight anti-enmascaramiento (`preflight_enmascaramiento.py`) — procedimiento

> Fase 3 · bloque `fase-03-preflight` (A2.2) · **R-09 / R-13** · operacionaliza el
> **§9.8** de `rulesets_diseno.md`.
> **No detecta ataques: impide medir mal.** En Wazuh hay **una alerta por evento**;
> una regla propia (RS3/RS4) que case el mismo evento que una base (RS1/RS2)
> **suprime** la base e **infravaloraría RS1**. Este examen convierte el compromiso
> escrito del §9 en un **examen con código de salida**.

- **Herramienta:** `_artefactos/scripts/preflight_enmascaramiento.py`
- **Ejemplo real de salida (repo, 0 reglas propias):** `preflight_informe.md`
- **Evidencia del caso "hermana":** `preflight_demo_hermana.md`

---

## 1. Qué comprueba (dos chequeos, un mismo gate)

### C1 · Cadena `<if_sid>` / `<if_matched_sid>` — estático, **offline**, sin root

Parsea las **reglas propias candidatas** (aún sin desplegar):

| Fichero (repo) | RuleSet |
|---|---|
| `Soporte/Wazuh/Reglas/local_rules.xml` | **RS3** |
| `Soporte/Wazuh/Reglas/external_*.xml` | **RS4** |

**Ignora los comentarios XML** (un fichero sin `<rule>`, como el esqueleto de RS3 en
Fase 2, aporta **0 reglas**, no un error). Construye el grafo `regla → padres` con los
ids de `<if_sid>` (separados por **coma**, con o sin espacios) y `<if_matched_sid>`, y
**resuelve el RS de cada ancestro por el fichero de origen** usando el manifiesto
`Soporte/Wazuh/Configuracion/active_ruleset.txt` (rango `MIN_ID..MAX_ID` de cada
fichero; ver `preflight_demo_hermana.md` §2 para las formas reales). Recorre el grafo
**transitivamente** (cubre **multinivel**: propia → propia → base). Si una regla propia
alcanza un ancestro **RS1/RS2** → **ENMASCARA (cadena)**.

> **Ancestro no resoluble:** un id que no está ni en las reglas propias ni en ningún
> rango del manifiesto → el examen **no lo ignora**: queda en "no resolubles" y el
> resultado es **INCOMPLETO**.

### C2 · Hermana — empírico, `wazuh-logtest` diferencial

Una regla **sin `<if_sid>`** que captura **el mismo evento** que una base (por
`if_group` / `<match>` / `<decoded_as>` / campos) también la suprime, y **no es
decidible estáticamente**. Se detecta cotejando **dos capturas de `wazuh-logtest -v`
sobre la misma lista de eventos**:

| Captura | Contenido |
|---|---|
| `--logtest-base` | **sin** reglas propias |
| `--logtest-candidato` | **con** las reglas propias (desplegadas temporalmente) |

Se parsea la **regla ganadora por evento** (`**Phase 3: … id: 'NNNN'`). Si un evento
cuya base ganaba RS1/RS2 pasa a ganarlo una propia RS3/RS4 → **ENMASCARA (hermana)**.

> **Sin capturas → C2 se declara `NO EJECUTADO`** (nunca se pasa en silencio) y el
> resultado es **INCOMPLETO**.

---

## 2. Cómo se declara un solapamiento aceptado (§9.5–§9.6)

Fichero **`Soporte/Wazuh/Configuracion/solapamientos_declarados.csv`** (el lector
ignora las líneas `#`):

```text
regla_propia,tipo,regla_base,motivo,revision_rs1,revisor,fecha
```

- `tipo ∈ {cadena, hermana}`.
- `revision_rs1` documenta la **regla de recuento `RS1∩RS3`** del §9.6 (obligatorio).
- El examen **PASA una pareja `(regla_propia, tipo, regla_base)` solo si existe su
  fila**; sin fila → **FALLA**. Una fila de un `tipo` distinto **no** excusa el
  hallazgo (una hermana no declara una cadena).
- **Declarar es la única vía** de aceptar un solapamiento; queda **trazado y
  versionado**.

---

## 3. Cuándo se ejecuta (§9.8)

1. **Antes de desplegar** cualquier regla propia (RS3/RS4) → si `exit ≠ 0`, **no se
   despliega** (y se rediseña, §9.1–§9.3).
2. **Al cierre de cada tanda de ataques** → re-ejecución barata y determinista; queda
   como evidencia.
3. **Tras cambiar el ruleset base** (regenerar `active_ruleset.txt`) → re-validar.

### Procedimiento operativo (con las dos fases C1/C2)

`wazuh-logtest` **no puede apuntar a otro directorio de reglas** (ver
`preflight_demo_hermana.md` §1): C2 necesita las reglas **desplegadas**. Por eso el
orden es:

```text
1) C1 offline sobre los ficheros candidatos del repo (barato, sin tocar el manager):
     python _artefactos/scripts/preflight_enmascaramiento.py
   Si C1 FALLA (o hay no resolubles) -> rediseñar. NO desplegar.

2) C2 (si C1 ha salido limpio): desplegar las reglas propias de forma
   TEMPORAL y REVERSIBLE, reiniciar el manager, capturar `wazuh-logtest -v`
   (candidato) sobre el conjunto de eventos, y RESTAURAR el estado (patrón de
   preflight_demo_hermana.md §5). Con las dos capturas:
     python _artefactos/scripts/preflight_enmascaramiento.py --logtest-base <base.txt> --logtest-candidato <candidato.txt> --eventos <eventos.jsonl>

3) Solo si el resultado es PASA (exit 0) la regla se despliega de forma definitiva.
```

> **Atajo válido (estado actual):** con **0 reglas propias** el examen es **PASA
> trivial** y **no exige C2**.

### Ejemplo (repo, 0 reglas propias)

```bash
python _artefactos/scripts/preflight_enmascaramiento.py \
    --out Soporte/Wazuh/Configuracion/preflight_informe.md
# -> RESULTADO: PASA  (exit 0)
```

---

## 4. Salida y contrato (§5)

- **Informe legible** por stdout; con `--out` se escribe además en el fichero indicado
  (el ejemplo versionado es `preflight_informe.md`). Línea final
  **`RESULTADO: PASA|FALLA|INCOMPLETO`**.
- **Sin reloj** → misma entrada = informe **byte a byte** idéntico (R-13). Se
  normalizan las rutas a `/` para el mismo resultado en Windows y Linux.
- **Códigos de salida:**

  | Código | Resultado | Significado |
  |---|---|---|
  | `0` | `PASA` | se puede desplegar |
  | `1` | `FALLA` | enmascaramiento **no declarado** |
  | `2` | — | uso / entrada (fichero ausente, capturas de distinto tamaño, declaración malformada) |
  | `3` | `INCOMPLETO` | C2 no ejecutado **o** ancestro no resoluble |

  **Solo `exit 0` permite desplegar.**

---

## 5. Entradas (CLI)

| Opción | Por defecto | Qué es |
|---|---|---|
| `--local-rules` | `Soporte/Wazuh/Reglas/local_rules.xml` | reglas propias RS3 |
| `--external-rules` | `Soporte/Wazuh/Reglas/external_*.xml` | glob de reglas propias RS4 |
| `--active-ruleset` | `Soporte/Wazuh/Configuracion/active_ruleset.txt` | manifiesto RS por fichero |
| `--declaraciones` | `Soporte/Wazuh/Configuracion/solapamientos_declarados.csv` | solapamientos aceptados |
| `--logtest-base` | — | captura `wazuh-logtest -v` sin reglas propias (C2) |
| `--logtest-candidato` | — | captura `wazuh-logtest -v` con las propias (C2) |
| `--eventos` | — | (opcional) JSONL de eventos para cotejar el nº de eventos |
| `--out` | — | escribe además el informe en este fichero |

> Un fichero de declaraciones **ausente** no es error de uso: se trata como vacío
> (todo hallazgo será `NO DECLARADO` → `FALLA`). Una entrada **malformada** sí es
> `exit 2`.

---

## 6. Límites declarados

- **C1** solo modela `<if_sid>` y `<if_matched_sid>`. **No** modela `if_group`,
  `<match>`, `<decoded_as>` ni otros predicados (no decidible en general): eso es
  exactamente lo que cubre **C2** de forma empírica.
- La resolución de ancestros por **rangos** del manifiesto puede ser **ambigua**
  (hay rangos de RS1 que solapan con el de RS2, p. ej. fortigate ↔ auditd); se elige
  el rango **más específico** y, si el empate persiste, se marca `ambigua_por_rangos`
  en el informe. **Ambas son base**, así que la decisión no cambia.
- C2 compara **base vs candidato con la misma herramienta**; no contra el baseline
  vivo, porque `wazuh-logtest` no reproduce el estado de las reglas con memoria
  (`if_fts`/`frequency`) — ver `preflight_demo_hermana.md` §4.3.

---

## 7. Verificación (`tfg-tester`)

1. `pytest _artefactos/scripts/tests/test_preflight_enmascaramiento.py` → todo PASA
   (offline, sin VMs), con los **8 casos del `plan.md` §6**.
2. Pre-flight sobre el repo (**0 reglas propias**) → `PASA` (`exit 0`).
3. Determinismo: dos ejecuciones con la misma entrada → informe **byte a byte**
   idéntico.
4. Los códigos de salida coinciden con los de este documento.

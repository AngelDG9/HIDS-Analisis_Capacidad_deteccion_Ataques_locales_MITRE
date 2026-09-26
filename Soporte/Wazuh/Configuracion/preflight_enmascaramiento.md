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

## 1. Qué comprueba (tres chequeos, un mismo gate)

### C0 · base-contra-base — empírico, **offline** (H1)

Una regla de **fábrica** puede **silenciar la detección esperada** de una técnica
**sin que intervenga ninguna regla propia**. Caso real del piloto: la regla base
**`92600`** (`0850-audit_rules.xml`, `level 0`, grupo `audit`, campo
`audit.exe ~ python`) es **hermana** de `80792` (`0365-auditd_rules.xml`, `level 3`)
y **suprime** la alerta del `execve` de `python3` → un "0 detecciones" que, sin
esta comprobación, se vería como un fallo del ataque y no como lo que es (un
**punto ciego de fábrica**).

**Cómo funciona (determinista, reutiliza el parser de C2):**

1. Se captura `wazuh-logtest -v` de un conjunto corto de **eventos sintéticos**
   derivados de las **señales esperadas** de la técnica (p. ej. una línea `audit`
   de `execve` del `audit_exe` esperado), **con el ruleset base desplegado** (0
   reglas propias). La captura se versiona (`c0_logtest_*.txt`).
2. El chequeo **C0 offline** consume esa captura (`--logtest-base-c0`) y, para cada
   evento, parsea la **regla ganadora** (`parse_logtest_detalle`, que expone `id` y
   `level`).
3. Si la ganadora tiene **`level=0`** (no emite alerta) → **AVISO**:
   *"detección esperada silenciada por regla de fábrica `<id>`"*.

> **Contrato:** un **AVISO de C0 NO cambia `PASA`/`FALLA`** (el silenciador es de
> fábrica y **no** lo controlamos): añade una sección `## C0` al informe y aparece
> en la línea final como `RESULTADO: PASA (AVISOS: C0=1)`. **Sin captura C0 →
> `INCOMPLETO`** (nunca PASA en silencio), coherente con C2. Una captura C0
> **presente pero sin eventos** también es `INCOMPLETO` (no se puede concluir).

**Para qué sirve en el escalado:** el ejecutor lanza C0 **por técnica antes de
medir**; si avisa, el "0 detecciones" de esa técnica queda **explicado**, no como
sorpresa.

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

### Procedimiento operativo (con las tres fases C0/C1/C2)

`wazuh-logtest` **no puede apuntar a otro directorio de reglas** (ver
`preflight_demo_hermana.md` §1): C0 y C2 necesitan el ruleset **desplegado**. Por eso
el orden es:

```text
0) C0 base-contra-base (offline tras capturar una vez): con el ruleset base desplegado
   (0 reglas propias) capturar `wazuh-logtest -v` sobre los eventos sintéticos de la
   técnica y pasar la captura:
     python _artefactos/scripts/preflight_enmascaramiento.py --logtest-base-c0 <c0.txt>
   Sin captura C0 -> INCOMPLETO (nunca PASA en silencio).

1) C1 offline sobre los ficheros candidatos del repo (barato, sin tocar el manager):
     python _artefactos/scripts/preflight_enmascaramiento.py --logtest-base-c0 <c0.txt>
   Si C1 FALLA (o hay no resolubles) -> rediseñar. NO desplegar.

2) C2 (si C1 ha salido limpio): desplegar las reglas propias de forma
   TEMPORAL y REVERSIBLE, reiniciar el manager, capturar `wazuh-logtest -v`
   (candidato) sobre el conjunto de eventos, y RESTAURAR el estado (patrón de
   preflight_demo_hermana.md §5). Con las dos capturas:
     python _artefactos/scripts/preflight_enmascaramiento.py --logtest-base-c0 <c0.txt> --logtest-base <base.txt> --logtest-candidato <candidato.txt> --eventos <eventos.jsonl>

3) Solo si el resultado es PASA (exit 0) la regla se despliega de forma definitiva.
```

> **Atajo válido (estado actual):** con **0 reglas propias** el examen **PASA
> trivialmente** y **no exige C2** — pero **sí exige la captura C0** (es
> base-contra-base y aplica siempre). Sin captura C0 → **INCOMPLETO**.

### Ejemplo (repo, 0 reglas propias)

```bash
python _artefactos/scripts/preflight_enmascaramiento.py \
    --logtest-base-c0 _artefactos/scripts/tests/fixtures/c0_logtest_python3_ls.txt \
    --out Soporte/Wazuh/Configuracion/preflight_informe.md
# -> RESULTADO: PASA (AVISOS: C0=1)  (exit 0)  [el AVISO de C0 no bloquea]
```

---

## 4. Salida y contrato (§5)

- **Informe legible** por stdout; con `--out` se escribe además en el fichero indicado
  (el ejemplo versionado es `preflight_informe.md`). Línea final
  **`RESULTADO: PASA|FALLA|INCOMPLETO`**; si C0 emitió avisos, se añade el recuento
  **`RESULTADO: PASA (AVISOS: C0=1)`** (el AVISO **no** cambia el resultado).
- **Sin reloj** → misma entrada = informe **byte a byte** idéntico (R-13). Se
  normalizan las rutas a `/` para el mismo resultado en Windows y Linux.
- **Códigos de salida:**

  | Código | Resultado | Significado |
  |---|---|---|
  | `0` | `PASA` | se puede desplegar |
  | `1` | `FALLA` | enmascaramiento **no declarado** |
  | `2` | — | uso / entrada (fichero ausente, capturas de distinto tamaño, declaración malformada) |
  | `3` | `INCOMPLETO` | C2 no ejecutado (con reglas propias), ancestro no resoluble, **C0 no ejecutado o captura C0 sin eventos** |

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
| `--logtest-base-c0` | — | captura `wazuh-logtest -v` con el ruleset base (C0 base-contra-base) |
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
- **C0** solo marca como aviso las ganadoras de **`level=0`**; no modela otros
  solapamientos de la base (p. ej. que una señal esperada caiga en una regla base
  de nivel > 0 distinta). La captura C0 la produce el operador una vez por técnica
  (con `wazuh-logtest`, que **no** permite apuntar a otro directorio de reglas):
  fuera de esa captura, C0 no re-evalúa el ruleset.
- C0 es **base-contra-base**: mide el ruleset de fábrica, **no** depende de que
  existan reglas propias. Por eso su captura es **obligatoria** aunque RS3/RS4
  estén vacías.

---

## 7. Verificación (`tfg-tester`)

1. `pytest _artefactos/scripts/tests/test_preflight_enmascaramiento.py` → todo PASA
   (offline, sin VMs), con los **casos del `plan.md` §6** y los **golden de H1**
   (`CA-H1-a/b/c`).
2. **H1 · C0** (golden obligatorio, desde la fixture versionada
   `tests/fixtures/c0_logtest_python3_ls.txt`):
   - **`CA-H1-a`**: `python3` → ganadora `92600` (`level 0`) → **AVISA**;
     `RESULTADO: PASA (AVISOS: C0=1)` (`exit 0`).
   - **`CA-H1-b`**: `ls` (mismo `key`) → ganadora `80792` (`level 3`) → **NO avisa**.
   - **`CA-H1-c`**: sin captura C0 → **`INCOMPLETO`** (`exit 3`); C1/C2 intactos.
3. Pre-flight sobre el repo (**0 reglas propias**) **con la captura C0** → `PASA`
   (`exit 0`, con AVISO `C0=1`).
4. Determinismo: dos ejecuciones con la misma entrada → informe **byte a byte**
   idéntico.
5. Los códigos de salida coinciden con los de este documento.

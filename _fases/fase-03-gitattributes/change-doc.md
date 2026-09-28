# change-doc — Micro-bloque `fase-03-gitattributes`: finales de línea y huellas

> Cierre. Fecha: **2026-09-28**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**, tras **FALLA**).
> Plan de referencia: `plan.md` (micro-plan, `approved_by_human`; **§5** = la corrección).

---

## 1. Qué se intentó y por qué se revirtió

**Intención inicial:** ampliar `.gitattributes` a **todos** los ficheros (`* text eol=lf`) para que un
`git checkout` no reescribiera a **CRLF** los ficheros cuya **huella `sha256`** está citada
(`esperado` ↔ `audited` ↔ bitácora ↔ ficha), y así no romper la cadena.

**La verificación dio FALLA (con razón):**
- Tratar como **texto** un **binario rastreado** (`Soporte/Laboratorio/topologia.png`) → en un clon con
  `core.autocrlf=true`, un `git add` le **borra bytes internos** (uno de ellos está **dentro de la firma
  PNG**) → **el PNG deja de ser válido**. *(Reproducido por el tester en repos aislados.)*
- Y el **problema de fondo**: el repo tiene **finales de línea MEZCLADOS** y **las huellas se calcularon
  sobre los bytes del disco** → **ninguna regla única** los protege a todos: **siempre** cambia alguno.

**Decisión del humano (2026-09-28): OPCIÓN A — revertir y documentar la limitación.**

---

## 2. Qué se ha hecho

1. **Eliminado `.gitattributes`** (raíz y subdirectorios). No se aplica **ningún** atributo
   (`git check-attr` → `unspecified`). Se vuelve al estado que produjo los ficheros actuales.
2. **Documentada la limitación** (texto literal del plan §5.2) en **`README.md`** (sección
   *"⚠️ Huellas y finales de línea"*) y en **`Soporte/Ataques/piloto_procedimiento.md`** (nota).

> *"Las huellas (`sha256`) que enlazan `esperado` ↔ `audited` ↔ bitácora ↔ ficha se calculan sobre los
> **bytes del fichero en disco**. El repo tiene finales de línea **mezclados** y **no lleva
> normalización**: **evitar `git checkout` / `stash` / `reset` / clonar** sobre este repositorio sin
> **recalcular** después las huellas afectadas. Los **binarios** (p. ej. `.png`) **no** deben pasar por
> reglas de texto."*

---

## 3. Verificación (`tfg-tester`) — **PASA**

| Comprobación | Resultado |
|---|---|
| **CA1′** `.gitattributes` no existe (ni aplica atributo alguno) | ✅ `unspecified` en `.csv`/`.sh`/`.md`/`.json` |
| **CA2′** ningún dato/resultado/código modificado | ✅ 0 entradas en `Dataset/`, `Bitacora/`, `Hojas/`, `_artefactos/` |
| **CA3′** huellas | ✅ **36/36** (ver §4) |
| **CA4′** `pytest` | ✅ **77** |
| **CA5′** limitación documentada | ✅ en los 2 sitios, texto literal |
| **PNG intacto** | ✅ `git hash-object` == blob de `HEAD`; firma PNG válida |
| Sin secretos · sin commit (al verificar) · `_recursos/` intacto | ✅ |

---

## 4. 📌 Corrección del recuento de huellas (defecto de registro del plan)

El plan decía *"15 huellas (3 esperado + 6 audited + 3 scripts)"*: **subrecuento** — **solo contaba el primer piloto** (ATA002/008/013).
**El desglose real** (6 ataques: los 3 del piloto + los 3 del piloto-custom):

| Categoría | Nº | |
|---|---|---|
| `*_esperado.csv` | **6** | |
| `ATA*_ataque.sh` | **6** | |
| `-Audited.csv` | **12** | 6 × {iter1, iter2} |
| `-Revision.csv` (también citados) | **12** | 6 × {iter1, iter2} |
| **Total de huellas citadas** | **36** | 6 ataques × 6 hashes |

**Verificado 36/36 sin fallos**, y los `sha256=` de las **fichas §2** coinciden (6/6). *(Extra: los 3
`c0/ATA*_logtest.txt` también cuadran con lo citado en los `*_preflight.md`.)*

---

## 5. Riesgos residuales (declarados por el tester — **no** bloqueantes)

1. 🟠 **La nota no menciona el disparador completo:** cita `checkout`/`stash`/`reset`/clonar, pero **no**
   `git add`/commit **ni** `core.autocrlf=true` (que es lo que reescribe los finales en Windows).
   **Mejora de 2 líneas** pendiente de decidir.
2. 🟡 **La nota no dice *cómo* recalcular** las huellas ni **qué** ficheros están en la cadena.
3. 🟢 La nota es **descubrible y clara**; el PNG ya no corre riesgo (git detecta binarios por su cuenta).

---

## 6. Siguiente

- **Decidir** si se amplía la nota (§5.1/§5.2) — **2 líneas**.
- **Arreglo del diseño de las señales** (el bloque que sigue pendiente: el ancla H4 y las señales anchas).
- **Escalar** las 7 técnicas restantes del corpus.
- **Tutoría (H1/H2):** el profesor no contesta → **inviable por ahora**; no bloquea.

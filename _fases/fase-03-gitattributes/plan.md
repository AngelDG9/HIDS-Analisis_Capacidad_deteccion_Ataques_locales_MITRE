---
fase: 3
bloque: fase-03-gitattributes
nombre: Ampliar .gitattributes a todos los ficheros (proteger la cadena de huellas)
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-orchestrator
gate: aprobado por instrucción explícita del humano (2026-09-28)
---

# Plan (micro) — Ampliar `.gitattributes` a todos los ficheros

> **Micro-plan** (una línea de configuración + verificación). **No** entra: el diseño de las señales, escalar, Windows, la memoria.

## 0. Objetivo

El `.gitattributes` actual cubre solo `*.csv` y `*.json`. **Pero la cadena de huellas también referencia ficheros `.sh`** (el `ataque_sha256` de cada artefacto está citado en fichas y bitácoras) y capturas `.txt`. Con `core.autocrlf=true`, un `git checkout`/`stash`/`reset` los reescribiría a **CRLF** y **rompería esas huellas**.

**Objetivo:** proteger **todos** los ficheros.

## 1. Tarea única

Dejar `.gitattributes` (raíz) con **una sola regla global** (sustituyendo las dos actuales, que quedan subsumidas) + un comentario del porqué:

```
# Normalizar finales de línea a LF en TODOS los ficheros: con core.autocrlf=true,
# un checkout reescribiría los ficheros a CRLF y rompería la cadena de huellas
# (sha256) que enlaza esperado <-> audited <-> bitácora <-> ficha.
* text eol=lf
```

## 2. Criterios de aceptación

| # | Criterio | Comprobación |
|---|---|---|
| **CA1** | `git check-attr text eol` devuelve `text: set` / `eol: lf` para **`.csv`, `.json`, `.sh`, `.py`, `.md`, `.txt`** | `git check-attr` sobre un fichero de cada tipo |
| **CA2** | **Ningún fichero aparece como modificado** por el cambio (los blobs ya están en LF) | `git status --short` (y `git diff --stat` vacío en los ficheros de datos) |
| **CA3** | **Las huellas no cambian**: `sha256` de los 3 `esperado`, los 6 `-Audited.csv`, los 3 scripts `ATA<NNN>_ataque.sh` y las bitácoras, **idénticos** antes/después | `sha256sum` antes/después |
| **CA4** | `pytest _artefactos/scripts/tests/` en verde (**77**) | ejecución |

## 3. Cómo se verifica

Cambio **trivial y objetivo** → lo comprueba el **`tfg-tester`** por `git check-attr`, `git status` y `sha256` (lectura, sin tocar nada).

## 4. Ficheros que se tocarán

`.gitattributes` (**único**). **Ningún** fichero de datos ni de resultados.

---

## 5. ⚠️ CORRECCIÓN tras la verificación (**FALLA**) — decisión del humano: **OPCIÓN A**

La verificación del `tfg-tester` dio **FALLA**, con razón: la regla global `* text eol=lf` trata como **texto** un **binario rastreado** (`Soporte/Laboratorio/topologia.png`) → en un clon con `core.autocrlf=true` aparece como modificado y un `git add` **le borraría bytes internos** (reproducido: el PNG deja de ser válido). Además, el repo tiene **finales de línea MEZCLADOS** y **las huellas se calcularon sobre los bytes del disco** → **ninguna regla única** los protege a todos: siempre cambia alguno.

**Decisión del humano (2026-09-28): OPCIÓN A — revertir y documentar la limitación.**

### Tareas (sustituyen al §1)

1. **Eliminar `.gitattributes`** — volver al estado **sin atributos**, que es el que produjo los ficheros actuales (y con el que las huellas cuadran). *(Se elimina también la regla `*.csv`/`*.json` que se añadió antes: es la que ya dejaba latente el problema con los ficheros que hoy están en CRLF.)*
2. **Documentar la limitación** en el **`README.md`** del repo y en **`Soporte/Ataques/piloto_procedimiento.md`**:
   > *"Las huellas (`sha256`) que enlazan `esperado` ↔ `audited` ↔ bitácora ↔ ficha se calculan sobre los **bytes del fichero en disco**. El repo tiene finales de línea **mezclados** y **no lleva normalización**: **evitar `git checkout` / `stash` / `reset` / clonar** sobre este repositorio sin **recalcular** después las huellas afectadas. Los **binarios** (p. ej. `.png`) **no** deben pasar por reglas de texto.*
3. **Verificar:** `.gitattributes` **no existe**; las **15 huellas** siguen **coincidiendo** con las citadas; `pytest` **77**; `git status` sin cambios en datos/resultados.

### Criterios de aceptación (revisados)

| # | Criterio |
|---|---|
| **CA1′** | **No existe** `.gitattributes` en la raíz (ni en ningún subdirectorio) |
| **CA2′** | **Ningún** fichero de datos/resultados/código aparece modificado |
| **CA3′** | **Las 15 huellas** siguen coincidiendo con las citadas en fichas/bitácoras |
| **CA4′** | `pytest _artefactos/scripts/tests/` → **77** |
| **CA5′** | La **limitación** queda escrita en `README.md` y en el runbook (enlace/nota) |

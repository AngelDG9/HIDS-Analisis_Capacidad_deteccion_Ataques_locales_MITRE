---
fase: 3
bloque: fase-03-cabos-cierre
nombre: Cabos de cierre del bloque fase-03-cabos (verificación en vivo, 4 textos y .gitattributes)
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-orchestrator
gate: aprobado por instrucción explícita del humano (2026-09-28)
---

# Plan (micro) — Cabos de cierre de `fase-03-cabos`

> **Micro-plan**: 3 arreglos **triviales** que **no requieren diseño**. Montar un bloque completo
> (planificador + gate + cierre + carpeta) sería **más trabajo que el arreglo**. KISS.
> **Especificación de referencia:** `_fases/fase-03-cabos/change-doc.md` **§3**.

## 0. Objetivo y alcance

**Objetivo:** cerrar las **2 salvedades** del bloque `fase-03-cabos` + el **riesgo latente** detectado.

**NO entra:** el arreglo del **diseño de las señales** (otro bloque), escalar las 7 técnicas, Windows,
η (Fase 4), la memoria, y **ningún cambio de cifras**.

## 1. Tareas

**T1 — Verificar EN VIVO el hallazgo de journald (`40700`).**
Encender las VMs. En el manager:
```
sudo grep -n '<rule id="4070[0-5]"' /var/ossec/ruleset/rules/0285-systemd_rules.xml
```
Confirmar que **`40700` es `level="0"`** (y que las hijas son de **fallo**). **Registrar la salida literal**
en la ficha `Dataset/Ataques/Resultados/Wazuh/linux/ATA004_meta.md` (§8.1/§10.5), cerrando la salvedad
*"no verificado en vivo"*. Si **no** se confirma, **PARA y repórtalo** (el hallazgo cambiaría).

**T2 — Corregir los 4 textos residuales** que dicen que las PAM del operador "quedan `dudosa`"
(el comportamiento **real** es: `sin_campos`→`dudosa` **solo si** el `esperado` **no** declara campos
siempre evaluables; si los declara → **`baseline`**). Redacción **idéntica en espíritu** a la de
`politica_filtrado_ruido.md` §3.bis:
- `_artefactos/scripts/filtrar_ruido.py` — **docstring (~L15-18)** y **bloque de constantes (~L84-86)**. *(La política exige coincidencia literal código↔doc.)*
- `Soporte/Ataques/piloto_procedimiento.md` (~L361).
- `Dataset/Ataques/Comandos/T1489-Service_Stop/README.md` (~L95).

**T3 — Añadir `.gitattributes`** (riesgo `core.autocrlf=true` sin atributos → un `checkout` reescribiría
los CSV a **CRLF** y **rompería la cadena de hashes**). Contenido mínimo:
```
*.csv text eol=lf
*.json text eol=lf
```

## 2. Criterios de aceptación

| # | Criterio | Comprobación |
|---|---|---|
| **CA1** | `40700` es `level="0"` y su salida queda registrada en la ficha de ATA004 | `grep` literal + lectura de la ficha |
| **CA2** | **No queda** ninguna frase que diga que las PAM "quedan `dudosa`" **sin matizar** | `grep` en el repo sobre docstring + los 3 docs |
| **CA3** | Existe `.gitattributes` con la regla; `git check-attr text eol -- <csv>` lo confirma; **los `sha256` de los 3 `esperado` y los 6 audited NO cambian** | `git check-attr`, `sha256sum` antes/después |
| **CA4** | `pytest _artefactos/scripts/tests/` en verde (**77**) | ejecución |

## 3. Cómo se verifica

Arreglos **triviales y objetivos** → el **orquestador** comprueba por `grep`, `git check-attr` y `sha256`
(verificación directa, sin ronda de tester). Si algo no cuadra, se reporta.

## 4. Ficheros que se tocarán

`.gitattributes` (**nuevo**) · `_artefactos/scripts/filtrar_ruido.py` · `Soporte/Ataques/piloto_procedimiento.md` ·
`Dataset/Ataques/Comandos/T1489-Service_Stop/README.md` · ficha `ATA004_meta.md` (registro del `grep`).
**No se toca** ningún CSV (salvo que CA3 lo exija, y no debe) ni ningún artefacto cerrado.

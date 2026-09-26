---
fase: 3
tarea: A3.0 (H2 · R-13)
nombre: Criterio de doble iteración (regla vigente v2)
version: 2
status: vigente
fecha: 2026-09-26
autor: tfg-executor
---

# Criterio de doble iteración — regla vigente (v2)

> **Documento normativo.** Fija **la regla vigente** que decide `iguales`/`review` al comparar
> las **dos iteraciones** de un ataque. Sustituye al criterio **v1** (3 criterios formales + 2
> sanidades **bloqueantes**) del bloque `fase-03-piloto`. Origen de la decisión: `plan.md` del
> bloque `fase-03-afinado` §3 (aprobado por el humano el 2026-09-26).
>
> **Nota KISS:** hoy el criterio **se aplica a mano** (no hay script). Este documento solo fija la
> regla; un script de doble iteración es opcional y se puede añadir al escalar.

---

## 1. Regla vigente (v2)

### 1.1 Criterios que DECIDEN (bloqueantes)

Un ataque obtiene **`iguales`** si y solo si se cumplen **los tres**:

- **C1′ · mismo conjunto de `rule_id`** con `categoria=deteccion` en iter1 e iter2.
- **C2′ · recuento de `deteccion` estable:** `|n2 − n1| ≤ max(2, 10 % · n1)`.
- **C3′ · ninguna fila `dudosa` sin resolver** (se mantiene del v1).

Si falla cualquiera → **`review`**.

### 1.2 Sanidades (pasan a NO bloqueantes)

Los totales de `auto_ruido` y `ruido_conocido` **se siguen calculando y registrando**, pero su
desviación **solo se reporta como aviso** (`review_motivo`), **no** fuerza `review`.

> **Justificación:** esas dos categorías dependen del **churn de arranque** (y del régimen), no del
> ataque. En el piloto la detección fue **idéntica** entre iteraciones y aun así los 3 ataques
> quedaron en `review`: **el criterio v1 medía el ruido del arranque, no la detección.** El v2 mide
> **lo que importa: la detección.**

### 1.3 Ventana de cálculo: la ventana COMPLETA `[t0,t1]`, sin exclusiones por tiempo

Las sanidades y los criterios se calculan sobre **todas** las filas de la ventana `[t0, t1]`
(que ya está **en régimen**, ver §2).

- **No** se excluye **ningún tramo** por tiempo. En particular, **no** existe una "ventana de
  asentamiento" dentro de `[t0, t1]` (no hay recorte `[t0, t0+90 s]`).
- **Por qué es justo y comparable:** las **dos iteraciones parten del mismo estado limpio**
  (`lab-revert` → `lab-listo` + asentamiento antes de `t0`) → la diferencia que quede entre
  iteraciones es **ruido real de régimen**, no churn de arranque.
- Determinista (R-13): solo depende de los timestamps reales de la ventana.

## 2. Paso operativo: sellar `t0` **después del asentamiento**

El mecanismo **principal** para apartar el ruido de arranque es **mover `t0`**, no recortar la
ventana:

> **Sellar `t0` ≥ 60–90 s DESPUÉS de confirmar el agente `Active`.**

Así el ruido de arranque ocurre **antes de `t0`** (queda **fuera** de la ventana) y el ataque
empieza ya en régimen. Es la vía para que `[t0,t1]` sea comparable entre iteraciones **sin**
recortar la ventana a posteriori. Ver
`Soporte/Ataques/piloto_procedimiento.md` §2 (paso 2/4).

> **Restricción de coherencia:** con ventanas reales de **30–45 s** (piloto: ATA002 44/31 s,
> ATA008 39/41 s, ATA013 40/41 s), una exclusión `[t0, t0+90 s]` cubriría **la ventana entera** y
> dejaría la sanidad **sin datos**. Por eso el arranque se aparta **moviendo `t0`**, nunca
> recortando la ventana.

## 3. Prueba sobre el piloto (recalculado con v2, solo lectura)

Con la regla v2 aplicada **a los `-Audited.csv` ya cerrados**:

| ATA | detección i1/i2 | conjunto `rule_id` | C1′/C2′/C3′ | veredicto **v2** |
|---|---|---|---|---|
| ATA002 | 4 / 4 | `{80781,80790,80792}` | ✅/✅/✅ | **`iguales`** |
| ATA008 | 2 / 2 | `{80791,80792}` | ✅/✅/✅ | **`iguales`** |
| ATA013 | 0 / 0 | `{}` | ✅/✅/✅ | **`iguales`** |

## 4. Nota de coherencia v1/v2 (trazabilidad para la memoria)

> *Los 3 ataques del piloto (ATA002, ATA008, ATA013) se **evaluaron con el criterio v1** (3
> criterios formales + 2 sanidades bloqueantes) y quedaron `review` por el **ruido de arranque**.
> Con el **criterio v2** (la detección decide; las sanidades pasan a aviso) **darían `iguales`**.
> No se recalcularon porque el piloto está **cerrado y verificado**; su `review` es **histórico del
> criterio v1**, no una discrepancia de detección.*

**Decisión cerrada (aprobada por el humano):** **NO** se recalculan los 3 ataques del piloto. Se
**aplica la regla v2 solo al escalado**; los `doble_iteracion: "review"` del piloto
(`Bitacora/ATA002|008|013.json`, `Hojas/ATA_index.csv` con `estado=review`) **no se tocan**.

## 5. Referencias

- Decisión: `plan.md` bloque `fase-03-afinado` §3 (H2).
- Procedimiento de ventana: `Soporte/Ataques/piloto_procedimiento.md` (§2, §6).
- Filtro y categorías: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`.
- Resultados del piloto (histórico v1): `_fases/fase-03-piloto/change-doc.md`.

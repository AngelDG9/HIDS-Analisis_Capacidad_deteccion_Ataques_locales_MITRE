# change-doc — Bloque `fase-03-senales-ratificacion`: el humano ratifica los 17 veredictos

> Cierre. Fecha: **2026-09-28**. Estado: **CERRADO** (ejecución verificada por el orquestador sobre los artefactos).
> Plan de referencia: `plan.md` (v1, `approved_by_human` por instrucción explícita del humano).
> Resuelve la **salvedad C11** de `_fases/fase-03-senales/change-doc.md` §4.

---

## 1. La decisión del humano (2026-09-28)

De las **17** filas `dudosa` que el ejecutor había resuelto a `ruido` aplicando el criterio de 2026-09-26:

| Grupo | Nº | **Veredicto del humano** |
|---|---|---|
| **Procesos ajenos** (nuestro login: `systemctl --user`, `find` de `update-motd.d`, un `tar` watch) | **13** | ✅ **`ruido`** — ratificado |
| **Escrituras del defacement** (ATA007, `80790`/`80781`) | **4** | 🔁 **`deteccion`** — **cambio** |

**Razón del cambio (razonamiento del humano):** las escrituras **son el ataque** → llamarlas "ruido" era **falso**
(el ruido es actividad ajena). Y el temor al **doble conteo** no aplica: la ficha reporta **dos cifras**
(*alertas* y *`rule_id` distintos*), así que el número de **acciones** sigue siendo el correcto.

---

## 2. Cambio aplicado

En `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA007_iter{1,2}-Revision.csv`:

- Las **4** filas de escritura → `veredicto=deteccion`, `revisor="humano (ratificacion 2026-09-28)"`,
  con nota (*"es el ataque (la escritura del defacement); es el mismo evento ya contado por el `execve` del `cp`"*).
- Las **2** filas de *setup* (`mkdir -p public_site`) → siguen `ruido`.
- Re-plegado determinista (`filtrar_ruido.py --revision`).

**Ficheros:** `ATA007_iter{1,2}-{Audited,Revision}.csv` (regenerados) · `ATA007_meta.md` · `Bitacora/ATA007.json`.

---

## 3. Verificación

| # | Comprobación | Resultado |
|---|---|---|
| **CA1** | Las 4 escrituras: `categoria=deteccion` + `veredicto_humano=deteccion` + nota + firma del humano | ✅ |
| **CA2** | Las **13** de procesos ajenos **siguen `ruido`** (ATA004/ATA012 **sin tocar**) | ✅ |
| **CA3** | ATA007 = **`deteccion=4`** por ventana (cabecera del `-Audited.csv`) | ✅ |
| **CA4** | Las **otras 5 ventanas** (ATA004 ×2, ATA012 ×2, los 3 del piloto) **byte a byte idénticas** | ✅ |
| **CA5** | `pytest` **86** · determinismo · cadena de huellas coherente | ✅ |

### ⚠️ Corrección de una cifra del plan

El plan decía *"4 alertas / **2 acciones**"*. La cifra **medible** es
**4 alertas / 3 `rule_id` distintos** (`80781`, `80790`, `80792`):

- **1 `rule_id`** (`80792`) = el `execve` del `cp` (la detección anclada), y
- **2 `rule_id`** (`80790`, `80781`) = las escrituras de ese **mismo proceso**.

👉 Las **3 vistas son el MISMO evento** (una sola acción: el `cp` sobrescribiendo la página).
El **incremento** de la ratificación es **+4 alertas / +2 `rule_id`**. *(Corregido en el `plan.md`.)*

---

## 4. Estado del recuento tras todo el bloque

| ATA | `deteccion` | de qué |
|---|---|---|
| ATA002 / ATA008 / ATA013 | 4 / 2 / 0 | **intactos** (sin ancla; retrocompatibilidad) |
| ATA004 | 3 / 3 | `systemctl` del ataque (ajenas → `ruido`) |
| **ATA007** | **4 / 4** | 1 evento: `execve` del `cp` + sus 2 escrituras (todas `deteccion`) |
| ATA012 | 6 / 7 | `find`/`tar` del ataque (ajenas → `ruido`) |

**Veredictos: 6 ataques, 5 detectados y 1 no** — sin cambios respecto al piloto.

---

## 5. Siguiente

- **Nada pendiente de este bloque.** ✔
- **Escalar** las 7 técnicas restantes del corpus (ya con el recuento limpio).
- **`push`:** los commits son locales; publicar es del humano.

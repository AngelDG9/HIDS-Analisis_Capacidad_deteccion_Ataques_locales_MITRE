# change-doc — Bloque `fase-03-cabos`: 4 arreglos de registro/documentación

> Cierre del bloque. Fecha: **2026-09-28**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA** con
> 2 salvedades no bloqueantes).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`, aprobado el 2026-09-28).
> **Bloque doc-only**: no se tocó ninguna VM, no se lanzó ningún ataque, **cero cambios de cifras**.

---

## 1. Los 4 cabos aplicados

| # | Cabo | Decisión y resultado |
|---|---|---|
| **1** | **Cita a `sha256_artefacto.txt`** en §6 de las 3 fichas… y el fichero **no existe** | **Corregir la cita** (no generarlo): §6 lista ahora lo que **realmente hay** (`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`) + nota. El `sha256` del script ya consta en la ficha §2 y en la bitácora. |
| **2** | Cabeceras de los `esperado` decían **"PENDIENTE"** | **Arreglado** → *"validado el 2026-09-26"* en los 3. Como el `sha256` del `esperado` está **incrustado en la cabecera de los 6 `-Audited.csv`**, se **regeneraron los 6** (determinista) y se actualizaron los hashes en **bitácoras y fichas**. `-Detalle` y `-Revision` **intactos**. |
| **3** | Texto que decía que las PAM quedan **`dudosa`** | **Corregido el TEXTO** (sin cambiar el diseño de H3): se describen los **dos casos reales** — (a) sin señales `rule_id` → `sin_campos`→`dudosa` (**ATA012**); (b) con `rule_id`/`rule_group` → **`baseline`** (**ATA004/ATA007**). Predicado `OPERADOR` **sin cambios**. |
| **4** | **0 alertas de journald** en ATA004 | **Hallazgo resuelto y documentado** (ficha ATA004, README de T1489, runbook §8.3): la regla de fábrica **`40700` es `level="0"`** → **la parada normal de un servicio NO alerta**; solo las hijas `40701-40705` (patrones de **fallo**). **La expectativa era estructuralmente imposible**, no "silenciada". Registrado como **cabo del escalado**. |

---

## 2. Verificación (`tfg-tester`) — **PASA**

Lo más importante, **reproducido de forma independiente**:

- **Regeneración byte a byte:** las **6/6** ventanas regeneradas coinciden con los audited del repo, y **dos pasadas dan el mismo `sha256`** (determinismo).
- **⭐ Las cifras NO cambian** (idénticas a las del `change-doc` del piloto-custom):

| Ventana | filas | deteccion | auto_ruido | ruido_conocido | dudosa |
|---|---|---|---|---|---|
| ATA004 i1 / i2 | 751 / 738 | **5 / 5** | 622 / 604 | 124 / 129 | 0 / 0 |
| ATA007 i1 / i2 | 737 / 748 | **4 / 4** | 609 / 620 | 124 / 124 | 0 / 0 |
| ATA012 i1 / i2 | 751 / 756 | **11 / 11** | 619 / 620 | 121 / 125 | 0 / 0 |

- Cada audited difiere de `HEAD` en **1 sola línea** (el `sha256` del esperado); **las filas de datos son idénticas**.
- Hashes **coherentes** ficha §2 ↔ bitácora ↔ cabecera del audited. `-Detalle`/`-Revision` **sin tocar**.
- Cabo 3 **verificado contra los 6 audited**. `pytest` **77 en verde**. Sin secretos, sin commit, `_recursos/` y `BBDD/` intactos.

---

## 3. Salvedades (del tester)

1. **⚠️ `40700 = level 0` NO verificado en vivo** (las **VMs están apagadas**). Es **consistente** con el manifiesto (`40700-40705`, n=6) y con el ruleset de fábrica, pero **falta leerlo en el manager**: `grep -n '<rule id="4070[0-5]"' /var/ossec/ruleset/rules/0285-systemd_rules.xml`. **Cierre definitivo pendiente** (1 minuto, con las VMs encendidas).
2. **Textos residuales** que siguen diciendo *"`5501`/`5502` → `dudosa`"* (mismo error que el cabo 3, en otros sitios): **2 puntos en el docstring de `filtrar_ruido.py`** (L15-18 y L84-86 — y la política exige **coincidencia literal** código↔doc), **`piloto_procedimiento.md` L361**, **`T1489/README.md` L95** y **`state.md` L156**. Ninguno cambia comportamiento. *(El plan ceñía el cabo 3 al `.md`, así que no incumple el plan.)*

---

## 4. ⚠️ Riesgo latente detectado (importante para la integridad)

**`core.autocrlf=true` sin `.gitattributes`.** Los ficheros del repo están en **LF**, pero con esa config un **`git checkout` / `stash` / `reset --hard` los reescribiría a CRLF** → **cambiaría su `sha256`** → **rompería la cadena de hashes** (esperado ↔ audited ↔ bitácora ↔ ficha). *Comprobado por el tester: el `sha256` del `ata004_esperado.csv` en LF (`a4a53a3c…`) ≠ en CRLF (`1b7388d7…`).*

**Recomendación:** añadir un **`.gitattributes`** con `*.csv text eol=lf` (o `-text`) y documentar que los hashes se calculan sobre el contenido **normalizado**.

---

## 5. Siguiente

- **Cabos de cierre (pequeños):** verificar el `40700` en vivo (VMs encendidas), corregir los **4 textos residuales** y añadir el **`.gitattributes`**.
- **Arreglo del diseño de las señales** (el bloque pendiente: el ancla H4 y las señales anchas).
- Después: **escalar** las 7 técnicas restantes.
- **Tutoría (H1/H2):** el tutor no contesta → **inviable por ahora**; no bloquea.
- **`push`:** los commits son locales; publicar es tarea del humano.

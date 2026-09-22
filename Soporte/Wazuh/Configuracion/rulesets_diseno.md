---
fase: 2
tarea: 2.7 (T-07 · R-09)
nombre: Diseño de los 4 RuleSets (RS1..RS4)
version: 1
status: approved_by_human
fecha: 2026-09-23
fecha_aprobacion: 2026-09-23
aprobado_por: humano
autor: tfg-planner
gate: G2
---

# Diseño de los 4 RuleSets — RS1..RS4 (Fase 2, tarea 2.7 · R-09)

> **Gate G2:** este documento lo aprueba el humano antes de activar reglas (tarea 2.8).
> `status: draft` → el humano lo pasa a `approved_by_human`.
> KISS: el ataque se ejecuta **una sola vez** con las 4 capas activas; cada alerta se clasifica
> por el **fichero de reglas** que la origina.

---

## 1. Principio y capas

Wazuh carga a la vez `/var/ossec/ruleset/rules/*.xml` (ruleset *default* del paquete) y
`/var/ossec/etc/rules/*.xml` (reglas propias). El **origen** de cada alerta es el fichero que
define su `rule.id`. La capa **RSn** de una alerta es la **más baja** cuyo rango contiene ese
`rule.id`. Como las 4 capas están activas simultáneamente, **no se repite el ataque**.

| RS | Nombre | Fichero(s) reales | Rango `rule.id` | Qué añade |
|---|---|---|---|---|
| **RS1** | Base (default) | `/var/ossec/ruleset/rules/*.xml` **excepto** `0365-auditd_rules.xml` | **1 – 99 999** *salvo* 80 700–80 799 | Telemetría básica: syslog, SSH, PAM, sudo, **FIM/syscheck (550–559)**, rootcheck, web |
| **RS2** | + `auditd` | `/var/ossec/ruleset/rules/0365-auditd_rules.xml` | **80 700 – 80 799** | Procesos y syscalls (`execve`, escritura de ficheros) — se activa con la config de `auditd` en el agente |
| **RS3** | + reglas propias | `/var/ossec/etc/rules/local_rules.xml` | **100 000 – 100 499** | Reglas custom del TFG (mínimas en Fase 2; crecen en Fase 3) |
| **RS4** | + externas | `/var/ossec/etc/rules/external_*.xml` | **100 500 – 101 000** | Reglas de la comunidad (**decisión abierta, §2**) |

**RS1 — subrangos reales notables** (indicativos; el manifiesto fija el min–max real de cada
fichero): FIM/syscheck **550–559**, rootcheck **510–519**, sudo **5400–5499**, PAM **5500–5599**,
sshd **5700–5799**, syslog **~1000–1999**. RS1 se define como **complemento**: todo `rule.id`
del ruleset default **que no** sea 80 700–80 799 (auditd) ni ≥ 100 000 (propias/externas).

**Fuentes de verdad:** el rango nominal de RS3/RS4 es una **reserva** (100 000–120 000 es el
rango oficial de Wazuh para reglas de usuario); el de RS1/RS2 se extrae del paquete real por
`Soporte/Wazuh/Scripts/generar_active_ruleset.sh` (tarea 2.8). **No se hardcodean** los rangos de
RS1.

---

## 2. RS4 — decisión abierta (el humano elige 1)

| Opción | Qué es | Ventajas | Inconvenientes |
|---|---|---|---|
| **A. RS4 = RS3 + 0** *(recomendada)* | Se reserva 100 500–101 000 y `external_*.xml` queda **vacío/documentado**. No se añaden reglas externas. | Cero riesgo (ni active-response, ni colisiones, ni FP nuevos); reproducible; honesto (la capa existe y se declara vacía). | RS3 ≡ RS4 en la tabla comparativa de Fase 3: capa **degenerada**; no aporta cobertura. |
| **B. Pack de comunidad** (p. ej. `socfortress/Wazuh-Rules`, commit fijado) | Reglas de detección de la comunidad Wazuh. | Reglas reales, cobertura extra, listas para usar. | Cientos de reglas **no validadas** en nuestro lab; riesgo de FP/ruido, dependencias (decoders/listas) y de `<active-response>`; IDs fuera de 100 500–101 000 → hay que **renumerar** y auditar; licencia a verificar. |
| **C. Conversión Sigma→Wazuh** (`sigma-cli` + backend comunitario p. ej. *SigWaz*, o Uncoder) | Convertir un subconjunto Sigma a XML Wazuh. | Trazable a Sigma; corpus acotado a **nuestras** técnicas; metodológicamente limpio. | **No hay backend oficial de Wazuh en pySigma** (issue *wazuh#15451* abierto); herramientas comunitarias sin garantía; requiere conversión + validación manual (tiempo). |

**Recomendación:** **A** para Fase 2. RS4=RS3+0 se documenta y no bloquea nada. B/C se pueden
reevaluar **en Fase 3** si la tabla comparativa exige un RS4 no degenerado.
En cualquier caso (A/B/C), los ficheros de RS4 **deben** pasar la auditoría de active-response
(§5) y el control de colisiones (§4) **antes** de activarse.

> **✅ Decisión del humano (G2, 2026-09-23): Opción A.**
> RS4 queda **vacía y documentada** en Fase 2. **En Fase 3**, con el corpus de ataques ya fijado,
> se **probará** introducir un conjunto **pequeño y curado** de reglas externas orientadas a esas
> técnicas concretas (no volcado masivo), **midiendo su aporte y su ruido** contra el baseline.
> Si aportan y no ensucian, se quedan; si ensucian, se revierten (se dispone del snapshot
> `lab-listo` como red de seguridad) y se declara el resultado en la memoria.

---

## 3. RS3 — esqueleto propio (Fase 2)

- **Fichero en el repo:** `Soporte/Wazuh/Reglas/local_rules.xml` → se despliega en
  `/var/ossec/etc/rules/local_rules.xml` del manager.
- **Rango reservado:** **100 000–100 499**. Convención: cada regla nueva de Fase 3 toma el
  siguiente ID libre dentro del rango; cabecera XML con comentario de la reserva.
- **Regla de ejemplo (la única de Fase 2)** — *smoke test* RS3 reutilizando la telemetría ya
  verificada (`rule.id 5710`, login SSH con usuario inexistente):

```xml
<!-- RS3 · rango reservado 100000-100499 · reglas propias del TFG -->
<group name="tfg,smoke,">
  <rule id="100000" level="3">
    <if_sid>5710</if_sid>
    <description>TFG smoke test (RS3): regla propia disparada</description>
  </rule>
</group>
```

- Dispara junto a 5710 → prueba que RS3 está activo sin cablear telemetría nueva. Es
  **temporal** (se reasigna/elimina al escribir las reglas R/E/S reales de Fase 3).

---

## 4. Mecanismo de clasificación y colisiones

**Asignación `rule.id` → RS** (rangos disjuntos; un único RS siempre):

```
r = int(rule.id)
if 100000 <= r <= 100499:  -> RS3
elif 100500 <= r <= 101000: -> RS4
elif 80700 <= r <= 80799:   -> RS2
elif 1 <= r <= 99999:       -> RS1   # RS1 excluye el subrango de RS2
else:                       -> UNKNOWN  # error: no se admite ambigüedad
```

**Detección de colisiones** (en `generar_active_ruleset.sh` y en el tester):

1. Se extraen los IDs reales por fichero (no los rangos nominales) y se agrupan por RS.
2. `RS3_ids ∩ RS4_ids ≠ ∅` → **colisión dura**.
3. Un fichero default (RS1) con IDs en 80 700–80 799 sin ser su auditd, o ≥ 100 000 → **colisión**.
4. IDs duplicados entre cualquier par de ficheros → Wazuh también avisa (*Duplicate rule ID*).
5. **Política:** ante colisión, el script **avisa y NO activa**; se **renumera** RS4 al primer
   bloque libre ≥ 100 500 (y RS3 dentro de su rango). Si persiste → abortar y escalar al humano.
   **Nunca** se resuelve en silencio.

---

## 5. Salvaguarda de detección-only (R-06) — riesgo de active-response

**Hecho confirmado:** el manager conserva **7 bloques `<command>`** de *active-response* por
defecto (p. ej. `firewall-drop`, `host-deny`, `route-null`, `disable-account`, `restart-wazuh`).
Hoy son **inertes** porque en 2.6 se eliminó **todo** `<active-response>` del `ossec.conf` y
`wazuh-execd` está parado. **El riesgo:** si una capa introdujera una regla con
`<active-response>`, Wazuh volvería a reaccionar y se rompería el modo detección-only.

**Garantías del diseño:**

- **RS1/RS2:** vienen del paquete; se **verifica** que no contienen `<active-response>`.
- **RS3 (nuestra):** por convención **prohibido** el elemento `<active-response>` dentro de `<rule>`.
- **RS4 (externa):** se **audita** (y se eliminan) antes de activar; si no se puede garantizar,
  se descarta la fuente (refuerza la opción A).
- Los `<command>` **no se eliminan** (son default e inertes); se catalogan como inertes.
- Cinturón extra: aunque fallara la regla, `wazuh-execd` parado no ejecutaría nada.

**Comprobación obligatoria (0 en todas las capas):**

```bash
grep -rl "<active-response" /var/ossec/ruleset/rules/ /var/ossec/etc/rules/   # -> sin resultados
grep -c "active-response" /var/ossec/etc/ossec.conf                            # -> 0 (ya en 2.6)
ps -eo cmd | grep '[w]azuh-execd'                                              # -> sin proceso
```
El generador **falla (exit ≠ 0)** si algún fichero de reglas contiene `<active-response>`.

---

## 6. Cómo se verifica

1. **Manifiesto:** `active_ruleset.txt` lista **cada fichero activo** con `RS`, `MIN_ID`, `MAX_ID`
   y `N_RULES`; RS1/RS2 con sus rangos **reales**; RS3/RS4 con su reserva.
2. **Sin ambigüedad:** una muestra de alertas reales (smoke test + baseline) resuelve **cada**
   `rule.id` a **un solo** RS; 0 `UNKNOWN`.
3. **Sin colisiones:** RS3 ∩ RS4 = ∅ y ningún fichero default invade 80 700–80 799 / ≥ 100 000.
4. **Smoke por capa (`wazuh-logtest`):** login SSH fallido → `5710` → **RS1**; `auditd` `execve` →
   80 7xx → **RS2**; regla 100 000 → **RS3**. (RS4 solo si §2 ≠ A.)
5. **Detección-only:** §5 con **0** `<active-response>`; `wazuh-execd` sin proceso.
6. Lo replica `tfg-tester` sobre `active_ruleset.txt` + una muestra de `alerts.json`.

---

## 7. Trazabilidad

| Requisito | Dónde se cumple |
|---|---|
| **R-09** 4 RuleSets, clasificación por origen | §1 tabla + §4 (ataque **una** ejecución → RS por `rule.id`) + `active_ruleset.txt` |
| **R-06** detección-only | §5 (0 `<active-response>` en las 4 capas; `wazuh-execd` parado) |
| **R-13** reproducibilidad | `generar_active_ruleset.sh` (2.8) + `local_rules.xml` versionado |
| **T-07** | este diseño → activación (2.8) → gate G2 (plan §8) |

---

## 8. Puntos que debe aprobar el humano (gate G2)

1. **Tabla RS1–RS3** de §1: fuentes y rangos (RS1 *default* salvo auditd = 1–99 999 ∖ 80 700–80 799;
   RS2 auditd = 80 700–80 799; RS3 propias = 100 000–100 499).
2. **Opción de RS4** de §2: **A (recomendada: RS4 = RS3 + 0)**, B (pack comunidad) o C (Sigma→Wazuh).
3. **Esqueleto RS3** de §3: rango reservado + regla *smoke test* 100 000 (temporal).
4. **Algoritmo de clasificación y política de colisiones** de §4 (renumerar y avisar; nunca en silencio).
5. **Salvaguarda active-response** de §5: 0 `<active-response>` en las 4 capas + `wazuh-execd`
   parado; los 7 `<command>` permanecen (inertes).

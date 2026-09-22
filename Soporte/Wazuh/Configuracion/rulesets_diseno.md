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
define su `rule.id`. La capa **RSn** de una alerta se determina **por el fichero de origen** que
define su `rule.id` (no por el valor numérico del ID); los rangos de la tabla siguiente son
**indicativos/informativos**. Como las 4 capas están activas simultáneamente, **no se repite el
ataque**.

> **✏️ Enmienda de criterio (2026-09-23) — afecta a §1 y §4.** El diseño original clasificaba
> `rule.id` **por rango numérico** (RS1 = el resto de IDs por debajo de la reserva de usuario,
> etc.). **Eso es imposible con el ruleset default
> real de Wazuh 4.14.7**, que incluye ficheros legítimos con IDs **> 100 000** (`0780-fireeye`
> 150 100+, `0330-sysmon` 184 665+, `0335-unbound` 500 000+): el rango nominal marcaba esos
> ficheros como colisión y **abortaba** la generación del manifiesto. La clasificación pasa a ser
> **por fichero de origen**, lo que **preserva** el principio de §1 ("el origen de una alerta es el
> fichero que la define"). Detalle del ajuste y verificación: `rulesets_activacion.md` **§7.1**
> (tarea 2.8).

| RS | Nombre | Fichero(s) reales | Rango `rule.id` (indicativo) | Qué añade |
|---|---|---|---|---|
| **RS1** | Base (default) | `/var/ossec/ruleset/rules/*.xml` **excepto** `0365-auditd_rules.xml` | *indicativo* **1 – 500 102** (real **por fichero**; puede incluir IDs > 100 000) | Telemetría básica: syslog, SSH, PAM, sudo, **FIM/syscheck (550–559)**, rootcheck, web |
| **RS2** | + `auditd` | `/var/ossec/ruleset/rules/0365-auditd_rules.xml` | **80 700 – 80 799** | Procesos y syscalls (`execve`, escritura de ficheros) — se activa con la config de `auditd` en el agente |
| **RS3** | + reglas propias | `/var/ossec/etc/rules/local_rules.xml` | **100 000 – 100 499** | Reglas custom del TFG (**0 en Fase 2**: la *smoke* `100000` se **retiró** el 2026-09-23, ver §3; crecen en Fase 3) |
| **RS4** | + externas | `/var/ossec/etc/rules/external_*.xml` | **100 500 – 101 000** | Reglas de la comunidad (**decisión abierta, §2**) |

**RS1 — subrangos reales notables** (indicativos; el manifiesto fija el min–max real de cada
fichero): FIM/syscheck **550–559**, rootcheck **510–519**, sudo **5400–5499**, PAM **5500–5599**,
sshd **5700–5799**, syslog **~1000–1999**. RS1 se define **por origen**: todo fichero del ruleset
default (`/var/ossec/ruleset/rules/*.xml`) **excepto** `0365-auditd_rules.xml` (que es RS2); un
fichero de RS1 puede tener cualquier `rule.id` del paquete, **incluidos los > 100 000**.

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

> **✏️ Enmienda (2026-09-23) — la regla *smoke* `100000` se RETIRÓ.** Al ser **hija** de `5710`
> (`<if_sid>`), Wazuh emite **una sola alerta** y la hija **sustituye** a la base → **enmascaraba la
> detección de RS1**. Como el **baseline** (tarea 2.10) es el **catálogo de ruido normal**, grabarlo
> con la regla puesta habría dejado el catálogo **sesgado** (infravaloraba `5710` y metía `100000`
> como si fuera ruido de RS1). Por decisión del orquestador se retiró **antes** del baseline. En
> consecuencia, **en Fase 2 RS3 = 0 reglas** y el esqueleto del repo queda **NO desplegable**.
> Evidencia y detalle: `rulesets_activacion.md` **§11**.

- **Fichero en el repo:** `Soporte/Wazuh/Reglas/local_rules.xml` → **esqueleto documentado**, con la
  regla `100000` **comentada** (ejemplo histórico). **NO se despliega** en `/var/ossec/etc/rules/`
  mientras no tenga reglas reales (un `<group>` vacío rompe el manager; ver
  `rulesets_activacion.md` §6).
- **Rango reservado:** **100 000–100 499**. Convención: cada regla nueva de Fase 3 toma el
  siguiente ID libre dentro del rango; cabecera XML con comentario de la reserva.
- **Regla *smoke* (histórica, RETIRADA el 2026-09-23)** — *smoke test* RS3 que reutilizaba la
  telemetría ya verificada (`rule.id 5710`, login SSH con usuario inexistente):

```xml
<!-- RETIRADA 2026-09-23 (enmascaraba 5710; ver norma §9). NO desplegar. -->
<group name="tfg,smoke,">
  <rule id="100000" level="3">
    <if_sid>5710</if_sid>
    <description>TFG smoke test (RS3): regla propia disparada</description>
  </rule>
</group>
```

- Disparaba junto a `5710` → probaba que RS3 estaba activo sin cablear telemetría nueva, pero
  **enmascaraba `5710`** (la hija **sustituye** a la madre). **Ya retirada** (ver arriba y §9): las
  reglas R/E/S reales de Fase 3 **no** repetirán ese patrón (`<if_sid>` de una base RS1).

---

## 4. Mecanismo de clasificación y colisiones

**Asignación `rule.id` → RS** (**por fichero de origen**; un único RS siempre):

```
fichero = fichero_que_define(rule.id)               # ruta del XML que define la regla
if   fichero == ".../ruleset/rules/0365-auditd_rules.xml": -> RS2
elif fichero == ".../etc/rules/local_rules.xml":           -> RS3
elif fichero == ".../etc/rules/external_*.xml":            -> RS4
elif fichero startswith ".../ruleset/rules/":              -> RS1  # resto del default, cualquier ID
else:                                                      -> UNKNOWN  # error: no se admite ambigüedad
```

> **✏️ Enmienda (2026-09-23):** se sustituye el pseudocódigo **por rango numérico** del diseño
> original por este criterio **por fichero de origen**, porque el ruleset default real de 4.14.7
> tiene `rule.id` **> 100 000** (fireeye/sysmon/unbound) — ver `rulesets_activacion.md` §7.1. Los
> rangos de §1 quedan como **informativos**; la asignación efectiva de cada alerta la da el fichero
> que la define.

**Detección de colisiones** (en `generar_active_ruleset.sh` y en el tester) — **acotada a la
reserva de usuario (100 000–101 000) y al subrango de RS2 (80 700–80 799)**; los IDs default
`> 101 000` **no** son colisión (son del paquete):

1. Se extraen los IDs reales por fichero (no los rangos nominales) y se agrupan por RS.
2. `RS3_ids ∩ RS4_ids ≠ ∅` → **colisión dura** (ambas capas usan la reserva de usuario).
3. Un fichero default (RS1) con IDs en **80 700–80 799** (sin ser `0365-auditd_rules.xml`) o en la
   **reserva de usuario 100 000–101 000** → **colisión**.
4. IDs duplicados entre cualquier par de ficheros → Wazuh también avisa (*Duplicate rule ID*).
5. **Política:** ante colisión, el script **avisa y NO activa**; se **renumera** RS4 al primer
   bloque libre ≥ 100 500 (y RS3 dentro de su rango). Si persiste → abortar y escalar al humano.
   **Nunca** se resuelve en silencio.

---

## 5. Salvaguarda de detección-only (R-06) — riesgo de active-response

**Hecho confirmado:** el manager conserva **7 bloques `<command>`** de *active-response* por
defecto (p. ej. `firewall-drop`, `host-deny`, `route-null`, `disable-account`, `restart-wazuh`).
Hoy son **inertes** porque en 2.6 se eliminó **todo** `<active-response>` del `ossec.conf` (y no hay
ninguno en los ficheros de reglas). **La garantía NO es que `wazuh-execd` esté parado:** al
**reiniciar el manager** (o al arrancar la VM) **`wazuh-execd` vuelve a arrancar**; hoy puede estar
**corriendo**, pero es **inerte** porque **no hay ningún `<active-response>` que disparar**. **El
riesgo:** si una capa introdujera una regla con `<active-response>`, Wazuh volvería a reaccionar y
se rompería el modo detección-only.

**Garantías del diseño:**

- **RS1/RS2:** vienen del paquete; se **verifica** que no contienen `<active-response>`.
- **RS3 (nuestra):** por convención **prohibido** el elemento `<active-response>` dentro de `<rule>`.
- **RS4 (externa):** se **audita** (y se eliminan) antes de activar; si no se puede garantizar,
  se descarta la fuente (refuerza la opción A).
- Los `<command>` **no se eliminan** (son default e inertes); se catalogan como inertes.
- **`wazuh-execd`:** puede estar **corriendo** tras un reinicio del manager; es **inerte** (no hay
  nada que ejecutar). Su estado **no** es la garantía; la garantía es la ausencia de
  `<active-response>`.

**Comprobación obligatoria (0 en todas las capas):**

```bash
grep -rl "<active-response" /var/ossec/ruleset/rules/ /var/ossec/etc/rules/   # -> sin resultados
grep -c "active-response" /var/ossec/etc/ossec.conf                            # -> 0 (ya en 2.6)
```
El generador **falla (exit ≠ 0)** si algún fichero de reglas contiene `<active-response>`.

### 5.1 Invariante tras reinicio del manager (checklist verificable)

**Invariante R-06:** *tras **cualquier reinicio del `wazuh-manager`*** (o arranque de la VM) deben
seguir existiendo **0 `<active-response>`** en `ossec.conf` **y** en los ficheros de reglas. Si
algún día se introduce una regla con `<active-response>`, la secuencia **"reinicio → `wazuh-execd`
arranca" reactivaría la reacción** y rompería el modo detección-only.

Checklist **ejecutable tal cual** (en `wazuh-server`; los `grep` sobre `/var/ossec/...` requieren
`root` — sin `sudo`, `angel` recibe *Permission denied*). Comando → resultado esperado:

| # | Comando | Resultado esperado |
|---|---|---|
| 1 | `sudo grep -c '<active-response' /var/ossec/etc/ossec.conf` | `0` |
| 2 | `sudo grep -rl '<active-response' /var/ossec/ruleset/rules/ /var/ossec/etc/rules/` | sin resultados |
| 3 | `pgrep -a -x wazuh-execd` (o `sudo pgrep -a -x wazuh-execd`) | *(informativo)* puede aparecer → es **inerte**, **no es fallo** |

> `grep` devuelve **exit 1** cuando cuenta **0** coincidencias: con `grep -c` la salida es `0` y el
> código 1 **no** es un error (significa "sin coincidencias"). El **invariante** son **#1 y #2**;
> **#3** es solo el estado del proceso y **no** es vinculante.

Salida real (ejecutada el **2026-09-23** en `wazuh-server`, **literal**):

```
$ sudo grep -c '<active-response' /var/ossec/etc/ossec.conf
0
(exit=1)
$ sudo grep -rl '<active-response' /var/ossec/ruleset/rules/ /var/ossec/etc/rules/
(exit=1)
$ sudo pgrep -a -x wazuh-execd
7393 /var/ossec/bin/wazuh-execd
(exit=0)
```

> `wazuh-execd` **aparece corriendo** (PID 7393, relanzado al reiniciar el manager tras la retirada
> de `100000` el 2026-09-23) y es **inerte**: el invariante #1/#2 se cumple (`0` `<active-response>`).

---

## 6. Cómo se verifica

1. **Manifiesto:** `active_ruleset.txt` lista **cada fichero activo** con `RS`, `MIN_ID`, `MAX_ID`
   y `N_RULES`; RS1/RS2 con sus rangos **reales**; RS3/RS4 con su reserva.
2. **Sin ambigüedad:** una muestra de alertas reales (smoke test + baseline) resuelve **cada**
   `rule.id` a **un solo** RS; 0 `UNKNOWN`.
3. **Sin colisiones:** RS3 ∩ RS4 = ∅ y ningún fichero default invade el subrango **80 700–80 799**
   ni la **reserva de usuario 100 000–101 000**. (Los IDs default **> 101 000** —fireeye/sysmon/
   unbound— **no** son colisión: son del paquete, no de la reserva.)
4. **Smoke por capa (`wazuh-logtest`):** login SSH fallido → `5710` → **RS1**; `auditd` `execve` →
   80 7xx → **RS2**; regla 100 000 → **RS3** *(la regla *smoke* `100000` se **retiró** el
   2026-09-23, antes del baseline → **en Fase 2 RS3 = 0 reglas**; ver §3 y §9)*. (RS4 solo si §2 ≠ A.)
5. **Detección-only:** §5 con **0** `<active-response>` en `ossec.conf` y en las 4 capas
   (invariante §5.1); `wazuh-execd` puede estar corriendo pero es **inerte**.
6. Lo replica `tfg-tester` sobre `active_ruleset.txt` + una muestra de `alerts.json`.

---

## 7. Trazabilidad

| Requisito | Dónde se cumple |
|---|---|
| **R-09** 4 RuleSets, clasificación por origen | §1 tabla + §4 (ataque **una** ejecución → RS por `rule.id`) + `active_ruleset.txt` |
| **R-06** detección-only | §5 (0 `<active-response>` en las 4 capas y en `ossec.conf`; invariante §5.1; `wazuh-execd` inerte) |
| **R-13** reproducibilidad | `generar_active_ruleset.sh` (2.8) + `local_rules.xml` versionado |
| **T-07** | este diseño → activación (2.8) → gate G2 (plan §8) |

---

## 8. Puntos que debe aprobar el humano (gate G2)

1. **Tabla RS1–RS3** de §1: fuentes y **criterio por fichero de origen** (RS1 = todo
   `/var/ossec/ruleset/rules/*.xml` **excepto** `0365-auditd_rules.xml`, con **cualquier**
   `rule.id` del paquete —incluidos los > 100 000—; RS2 = `0365-auditd_rules.xml`;
   RS3 = `etc/rules/local_rules.xml`, reserva 100 000–100 499). Los rangos de §1 son
   **indicativos**: la asignación efectiva de cada alerta la da el **fichero que define** su
   `rule.id` (§4). *(Sustituye al criterio por rango numérico del diseño original.)*
2. **Opción de RS4** de §2: **A (recomendada: RS4 = RS3 + 0)**, B (pack comunidad) o C (Sigma→Wazuh).
3. **Esqueleto RS3** de §3: rango reservado + regla *smoke test* 100 000 *(**retirada** el
   2026-09-23, antes del baseline → RS3 = 0 reglas; ver §3/§9)*.
4. **Algoritmo de clasificación y política de colisiones** de §4 (renumerar y avisar; nunca en silencio).
5. **Salvaguarda active-response** de §5: 0 `<active-response>` en las 4 capas y en `ossec.conf`;
   `wazuh-execd` puede estar **corriendo** tras un reinicio pero es **inerte** (invariante
   verificable §5.1); los 7 `<command>` permanecen (inertes).

---

## 9. Convención anti-enmascaramiento (Fase 3)

> **✅ Aprobada por el humano el 2026-09-23.** Es una **enmienda/norma nueva**: no cambia nada de
> §1–§8, sino que **obliga** en Fase 3. *(Reforzada el 2026-09-23 con los puntos 6–8; el punto 4 ya
> se ejecutó: la regla `100000` fue **retirada** antes del baseline.)*

**Problema (verificado en vivo, tarea 2.8):** en Wazuh, cuando una regla **hija** (`<if_sid>`) casa,
**sustituye** a la alerta de la regla **madre**: el mismo evento produce **una** alerta (la hija).
Comprobado con la regla *smoke* `100000` (hija de `5710`, login SSH fallido): tras activarla, el
evento ya **no genera `5710`** → **enmascara la detección de RS1**. Si en Fase 3 se escriben las
reglas R/E/S como **hijas de reglas base**, se **infravaloraría RS1 sistemáticamente** y se
falsearía la comparativa de RuleSets.

**Premisa explícita (por qué el problema es *inherente*):** Wazuh emite **una sola alerta por
evento**. Por tanto, cuando una regla propia casa el **mismo evento** que una base, el
**solapamiento RS1/RS3 es inherente**. No basta con evitar `<if_sid>`: una regla propia **hermana**
(sin `<if_sid>`, colgando de la misma base) que case ese mismo evento **también** suprime/menoscaba
la detección base — **es falso** que "sin `if_sid` = sin enmascaramiento". Las alternativas
(`if_group`, `<match>`) **solo** funcionan si la regla base **no** casa ese mismo evento; hay que
**verificarlo caso por caso**.

**Norma (obligatoria para toda regla propia, RS3 — y extensible a RS4):**

1. **Prohibido** que una regla propia (RS3) sea **hija (`<if_sid>`) de una regla base (RS1)** cuando
   se quiera **conservar** la detección base (la hija la suprimiría).
2. Si una regla propia necesita la **telemetría base**, usar alternativas que **NO supriman** la
   detección de origen —p. ej. `if_group` (grupo en vez de `if_sid`), coincidencia sobre **campos o
   log crudo** (`<match>`/`<regex>`), o **nivel distinto**— y **verificarlo**.
3. **Verificación obligatoria antes de dar por buena cualquier regla propia:** comprobar con
   `wazuh-logtest -v` que la **detección base sigue emitiéndose**. Si la hija la suprime →
   **rediseñar** la regla. Si el solapamiento se acepta conscientemente, debe quedar **declarado**
   en la metodología.
4. **Consecuencia operativa (hecho ya ejecutado):** la regla *smoke* `100000` (hija de `5710`) se
   **retiró el 2026-09-23, antes del baseline**, porque **enmascaraba `5710`** y habría sesgado el
   catálogo de ruido. Constancia explícita aquí y en §3; evidencia en `rulesets_activacion.md` §11.
5. **Declaración en la memoria:** el solapamiento RS1/RS3, **si existiera**, se **declara**; no se
   oculta.
6. **Regla de recuento (obligatoria si hay solapamiento):** si la base queda suprimida, hay que
   definir **cómo se cuenta** en la tabla de resultados. Convención: marcar el evento como
   **`RS1∩RS3`** y calcular la **cobertura de RS1 con y sin** la regla propia, para que el sesgo
   quede **visible** en lugar de oculto. Sin esta regla, el sesgo vuelve.
7. **Ámbito:** la norma aplica también a **RS4** (reglas externas de Fase 3) y a **cadenas `if_sid`
   de varios niveles** (una regla que cuelga de otra hija puede suprimir toda la cadena, incluidas
   detecciones de RS1/RS2).
8. **Trazabilidad obligatoria:** guardar la salida de `wazuh-logtest -v` **por cada regla propia** y
   un **pre-flight** que detecte si una regla RS3 declarada con `<if_sid>` cuelga de una base RS1
   (y **falle**, salvo que el solapamiento esté **declarado**).

**Regla de oro:** *conservar la detección base* tiene prioridad sobre *etiquetar* el evento como RS3.

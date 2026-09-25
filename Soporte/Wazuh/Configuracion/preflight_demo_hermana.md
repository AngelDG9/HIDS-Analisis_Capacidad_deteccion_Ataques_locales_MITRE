---
fase: 3
tarea: A2.2 (§9.8 · R-09/R-13)
nombre: Evidencia — caso "regla hermana" y herramientas de wazuh-logtest
version: 1
status: implementada
fecha: 2026-09-25
autor: tfg-executor
---

# Demo del caso "hermana" y reconocimiento de `wazuh-logtest` (paso 0 de A2.2)

> Evidencia del **paso 0** del bloque `fase-03-preflight` (`plan.md` §1).
> Se ejecutó el **2026-09-25** en `wazuh-server` (192.168.65.128), Wazuh **4.14.7**.
> El experimento es **autorizado, temporal y reversible**: al terminar se restauró el
> estado EXACTO del manager (ver §5).

## 1. `wazuh-logtest` — existencia, root y directorio de reglas

| Pregunta (plan §1.1) | Respuesta verificada |
|---|---|
| ¿Existe? | **Sí**: `/var/ossec/bin/wazuh-logtest` (wrapper Python → `framework/scripts/wazuh_logtest.py`) |
| ¿Requiere root? | **Sí**: `-rwxr-x--- root:wazuh`. Como `angel` da `Permission denied` (exit 126); con `sudo` funciona |
| Versión | `Wazuh v4.14.7` |
| ¿Carga solo las reglas desplegadas? | **Sí**. Habla por el socket `queue/sockets/logtest` con `wazuh-analysisd`, que tiene en memoria el ruleset **desplegado** (`/var/ossec/etc/rules/*.xml` + `/var/ossec/ruleset/rules/*.xml`) |
| ¿Se puede apuntar a **otro directorio** de reglas? | **NO.** `-h` solo ofrece `-h -V -d -U -l -q -v`; **no hay** opción de directorio. `-U` remite a `ruleset/testing/runtests.py`, que **no está instalado** (`/var/ossec/ruleset/testing/` no existe). ⇒ para probar un candidato hay que **desplegarlo y recargar** el manager |

Ayuda completa volcada en `_artefactos/scripts/tests/fixtures/preflight_logtest_ayuda.txt`:

```text
usage: wazuh_logtest.py [-h] [-V] [-d] [-U rule:alert:decoder] [-l location]
                        [-q] [-v]

Tool for developing, tuning, and debugging rules.

options:
  -h, --help            show this help message and exit
  -V                    Version and license message
  -d                    Execute in debug mode
  -U rule:alert:decoder
                        Unit test. Refer to ruleset/testing/runtests.py
  -l location           Use custom location. Default "stdin"
  -q                    Quiet execution
  -v                    Verbose (full) output/rule debugging
```

**Consecuencia para el pre-flight:** la captura "candidato" de C2 **exige** desplegar
las reglas propias y reiniciar el manager; no hay atajo. El paso 0 lo hace una vez y
versiona las capturas para reutilizarlas offline.

## 2. Forma real de `<if_sid>` / `<if_matched_sid>` / `<if_group>` (plan §1.4)

Sobre los **168 ficheros** `*.xml` de `/var/ossec/ruleset/rules/` (167 de RS1 +
`0365-auditd_rules.xml` de RS2), Wazuh 4.14.7:

| Forma | Hecho verificado |
|---|---|
| `<if_sid>` | **3.868** apariciones; **236** con varios ids |
| Separador de ids múltiples | **coma `,`**, con o sin espacio (`20100, 20101` y `150101,150102`) |
| Separador `\|` | **no se usa** (0 apariciones) |
| `<if_sid>` multilínea | **no existe** |
| `<if_matched_sid>` | id **único** (no se observaron multi-id) |
| `<if_group>` | se usa **sin** `<if_sid>`, acompañado de `<match>` |

Muestras reales (con fichero y línea) en
`_artefactos/scripts/tests/fixtures/preflight_ruleset_muestra.xml`.

## 3. Conjunto curado de eventos y captura "base"

Se derivó un conjunto **pequeño y curado** de 12 eventos de `full_log` de
`Dataset/Muestras/baseline_muestra.jsonl` (uno por `rule.id` distinto, 11 reales) más
**una** línea sshd de usuario inexistente (`5710`, sintética, formato syslog idéntico
al del lab). Está versionado en
`_artefactos/scripts/tests/fixtures/preflight_eventos.jsonl`.

Captura "base" = `wazuh-logtest -v` **sin** reglas propias
(`preflight_logtest_base.txt`). Ganadoras por evento:

`80792, 80790, 80791, 80781, 80780, 80730, 5715, 5501, 5502, 5403, 591, 5710`

## 4. Demostración del caso "hermana"

### 4.1 Regla temporal desplegada

Regla **hermana** mínima (**sin `<if_sid>`**), en `/var/ossec/etc/rules/preflight_temp_sister.xml`,
id RS3 `100000`:

```xml
<group name="tfg,preflight_temp,">
  <rule id="100000" level="5">
    <if_group>sshd</if_group>
    <match>Invalid user</match>
    <description>TFG preflight TEMP (RS3): Invalid user (regla hermana)</description>
  </rule>
</group>
```

Despliegue: copia + `chown root:wazuh` + `systemctl restart wazuh-manager` (→ `active`).
Sin errores de carga en `ossec.log`.

### 4.2 Captura "candidato" y comparación

Misma lista de eventos, con la regla hermana activa
(`preflight_logtest_candidato.txt`). Diferencial (C2):

| # | evento | ganadora BASE | ganadora CANDIDATO | ¿cambia? |
|---|---|---|---|---|
| 1 | E01 audit ejecutado | 80792 | 80792 | – |
| 2 | E02 audit creado | 80790 | 80790 | – |
| 3 | E03 audit borrado | 80791 | 80791 | – |
| 4 | E04 audit write | 80781 | 80781 | – |
| 5 | E05 audit write | 80780 | 80780 | – |
| 6 | E06 audit selinux | 80730 | 80730 | – |
| 7 | E07 sshd login OK | 5715 | 5715 | – |
| 8 | E08 PAM open | 5501 | 5501 | – |
| 9 | E09 PAM close | 5502 | 5502 | – |
| 10 | E10 sudo | 5403 | 5403 | – |
| 11 | E11 log rotated | 591 | 591 | – |
| 12 | E12 **Invalid user** | **5710** | **100000** | **SÍ** |

**Resultado: el evento que ganaba la base `5710` (RS1) pasa a ganarlo la propia
`100000` (RS3).** Queda **demostrado empíricamente** que una regla **sin `<if_sid>`**
que casa el mismo evento **suprime** la detección base (la premisa de
`rulesets_diseno.md` §9 deja de ser solo razonada).

Extractos literales de `wazuh-logtest -v` para el evento E12:

```text
# BASE (sin reglas propias)
**Phase 3: Completed filtering (rules).
	id: '5710'
	level: '5'
	description: 'sshd: Attempt to login using a non-existent user'
	groups: '['syslog', 'sshd', 'authentication_failed', 'invalid_login']'
	mitre.id: '['T1110.001', 'T1021.004']'
**Alert to be generated.

# CANDIDATO (con la hermana 100000)
	Trying rule: 100000 - TFG preflight TEMP (RS3): Invalid user (regla hermana)
		*Rule 100000 matched
**Phase 3: Completed filtering (rules).
	id: '100000'
	level: '5'
	description: 'TFG preflight TEMP (RS3): Invalid user (regla hermana)'
	groups: '['tfg', 'preflight_temp']'
**Alert to be generated.
```

### 4.3 Hallazgo colateral (por qué C2 es diferencial)

El evento E10 en el **baseline vivo** generó `5402`, pero en `wazuh-logtest` genera
`5403`. Causa: `5403` tiene `<if_fts />` (*first time seen*) y la sesión de `logtest`
arranca con el estado FTS vacío, mientras que en vivo ya se había visto antes. **Las
reglas con estado (`if_fts`, `frequency`, `if_matched_*`) no son idénticas entre
`logtest` y el flujo vivo.** Por eso C2 compara **base vs candidato con la misma
herramienta** (el sesgo se cancela) y no contra el baseline vivo.

## 5. Restauración del estado (verificación)

Se **eliminó** la regla temporal y se **reinició** el manager. Comprobaciones:

| Comprobación | Estado ANTES (2026-09-25T11:40Z) | Tras restaurar |
|---|---|---|
| `systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard` | `active active active` | `active active active` |
| `ls /var/ossec/etc/rules/` | 2 `.bak` (`…bak-retirada-100000`, `…bak-tfg28`) | **idéntico** (2 `.bak`) |
| `sha256` de los 2 `.bak` | `6a97ad12…bd66` / `991dc926…25f4` | **idénticos** |
| `ls /var/ossec/etc/rules/*.xml` | no existe | **no existe** (0 reglas propias desplegadas) |
| Login fallido → `wazuh-logtest` | `5710` | **`5710`** (vuelve a ganar la base) |

Los `.bak` **no** son `.xml`, por lo que Wazuh no los carga: **0 reglas propias
desplegadas**. La regla hermana `100000` **ya no existe** en el manager.

**Conclusión:** el manager quedó **exactamente** como estaba (salvo las alertas
generadas por la propia actividad de administración).

## 6. Trazabilidad

| Elemento | Fichero |
|---|---|
| Ayuda de `wazuh-logtest` | `_artefactos/scripts/tests/fixtures/preflight_logtest_ayuda.txt` |
| Eventos del experimento | `_artefactos/scripts/tests/fixtures/preflight_eventos.jsonl` |
| Captura base | `_artefactos/scripts/tests/fixtures/preflight_logtest_base.txt` |
| Captura candidato (hermana) | `_artefactos/scripts/tests/fixtures/preflight_logtest_candidato.txt` |
| Muestras de formas del ruleset | `_artefactos/scripts/tests/fixtures/preflight_ruleset_muestra.xml` |
| Fixture de la regla hermana | `_artefactos/scripts/tests/fixtures/preflight_local_hermana.xml` |
| Chequeo C2 | `_artefactos/scripts/preflight_enmascaramiento.py` (`--logtest-base/--logtest-candidato`) |

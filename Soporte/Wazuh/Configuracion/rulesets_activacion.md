# Activación de los 4 RuleSets — RS1..RS4 (Fase 2, tarea 2.8 / T-07 · R-09)

Documento de **evidencia real** de la activación de los RuleSets diseñados y aprobados en
`rulesets_diseno.md` (gate **G2**, `status: approved_by_human`). Complementa a ese diseño: aquí
solo se registra **qué se activó, cómo se verificó y los rangos reales**.

- **Fecha de ejecución:** 2026-09-22 (hora de las VMs)
- **Manager:** `wazuh-server` `192.168.65.128` · **Agente:** `victima-linux` `192.168.65.129` (ID `001`)
- **Versión:** Wazuh **4.14.7-1**
- **Manifiesto generado:** `Soporte/Wazuh/Configuracion/active_ruleset.txt`
- **Modo:** detección-only (R-06) intacto (0 `<active-response>`, `wazuh-execd` parado)

---

## 1. Qué se activó, por capa

| RS | Capa | Fichero(s) activos | Cómo se activó |
|---|---|---|---|
| **RS1** | Base (default) | `/var/ossec/ruleset/rules/*.xml` **excepto** `0365-auditd_rules.xml` | Ya venía con el paquete. Nada que hacer. |
| **RS2** | `auditd` | `/var/ossec/ruleset/rules/0365-auditd_rules.xml` | **Telemetría nueva** en la víctima: se instaló `auditd` + reglas propias y se hizo que el agente enviara `/var/log/audit/audit.log`. |
| **RS3** | Reglas propias | `/var/ossec/etc/rules/local_rules.xml` | Desplegado desde el repo (backup del original) + reinicio del manager. |
| **RS4** | Externas | *(vacía — opción A/G2)* | **No se activa nada.** El punto de carga `/var/ossec/etc/rules/external_*.xml` queda documentado (§6). |

**Resumen del principio:** las 4 capas están activas **a la vez**; el **origen** (fichero) de cada
alerta define su RS. El ataque se ejecutará **una sola vez** (Fase 3) y cada alerta se clasifica
por su `rule.id`.

---

## 2. RS2 — `auditd` en `victima-linux`

### 2.1 Instalación y reglas

- Instalados `auditd` y `audispd-plugins` (vía NAT, que **sigue conectado**).
- Reglas versionadas en `Soporte/Wazuh/Reglas/auditd_tfg.rules`, desplegadas en
  `victima-linux:/etc/audit/rules.d/tfg.rules` y cargadas con `augenrules --load`.
- Se creó la ruta del corpus `/home/angel/lab-legit` (necesaria para el `-w`).

`auditctl -l` (reglas reales cargadas en el kernel):

```
-a always,exit -F arch=b64 -S execve -F key=audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F key=audit-wazuh-c
-a always,exit -F arch=b64 -S truncate,ftruncate,rename,creat,unlink,unlinkat,renameat,renameat2 -F key=audit-wazuh-w
-w /etc -p wa -k audit-wazuh-w
-w /home/angel/lab-legit -p wa -k audit-wazuh-w
```

> **Claves `-k`:** se usan las **claves reservadas de Wazuh** (`audit-wazuh-c` = *command*,
> `audit-wazuh-w` = *write*), definidas en el manager en `/var/ossec/etc/lists/audit-keys`. Sin
> estas claves, las reglas 80780–80794 del ruleset default **no disparan**: son ellas las que
> mapean la clave a la categoría y activan RS2.

### 2.2 Telemetría al manager

Se añadió el bloque al `ossec.conf` **del agente** (con backup `ossec.conf.bak-tfg28`, edición
XML-validada; `Soporte/Wazuh/Scripts/patch_agent_audit.py`):

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

### 2.3 Verificación — RS2 DISPARA (`rule.id` 807xx)

Tras ejecutar `ls` / actividad trivial en la víctima, llegaron alertas **807xx** al manager
(`/var/ossec/logs/alerts/alerts.json`), agente `victima-linux`:

```
     13 "id":"80705"     Auditd: Configuration changed
      1 "id":"80730"     Auditd: SELinux permission check
     33 "id":"80780"     Audit: Watch - Write access
      1 "id":"80781"     Audit: Watch - Write access: <fichero>
      8 "id":"80782"     Audit: Watch - Write access: <directorio>
    116 "id":"80791"     Audit: Deleted: <fichero>
   1758 "id":"80792"     Audit: Command: <exe>          <- execve
```

Muestra real (una alerta 80792 = `execve`):

```json
{"RS": "RS2", "rule_id": "80792", "level": 3,
 "description": "Audit: Command: /usr/sbin/sshd.",
 "groups": ["audit", "audit_command"], "agent": "victima-linux"}
```

**Conclusión:** RS2 está activo y produce alertas en el rango **80700–80799**. ✔

---

## 3. RS3 — reglas propias (`local_rules.xml`)

### 3.1 Despliegue

- Fichero versionado: `Soporte/Wazuh/Reglas/local_rules.xml` (esqueleto + regla *smoke* `100000`,
  cabecera con la reserva **100000–100499**).
- Desplegado en `/var/ossec/etc/rules/local_rules.xml` del manager, con **backup** del original
  en `/var/ossec/etc/rules/local_rules.xml.bak-tfg28` (el original traía una regla-ejemplo `100001`).
- Manager reiniciado (`systemctl restart wazuh-manager`) y `wazuh-execd` vuelto a parar.
- **Sin `<active-response>`** (ver §5).

### 3.2 Verificación — RS3 DISPARA (`rule.id` 100000)

Login SSH fallido (usuario inexistente) contra la víctima → alerta **100000** (RS3):

```json
{"timestamp": "2026-09-22T22:50:21.902+0000", "rule_id": "100000", "level": 3,
 "description": "TFG smoke test (RS3): regla propia disparada",
 "groups": ["tfg", "smoke"], "agent": "victima-linux"}
```

### 3.3 Matiz importante: `100000` es hija de `5710` (la sustituye)

La regla *smoke* es **hija** de `5710` (`<if_sid>5710</if_sid>`, tal como fija el diseño §3). En
Wazuh, cuando una regla hija casa, **sustituye** a la padre: el mismo evento produce **una** alerta
(`100000`), no dos. Por eso, tras activar RS3, el contador de `5710` **no** crece con el nuevo
login fallido. `wazuh-logtest -v` demuestra que **ambas** casan en la cadena:

```
Trying rule: 5710 - sshd: Attempt to login using a non-existent user
	*Rule 5710 matched            <- RS1
	*Trying child rules
Trying rule: 100000 - TFG smoke test (RS3): regla propia disparada
	*Rule 100000 matched          <- RS3
**Phase 3: Completed filtering (rules).
	id: '100000'
```

Es decir: el login SSH fallido **pasa por RS1 (5710)** y **genera alerta de RS3 (100000)**. La
regla `5710` (RS1) se conserva y sigue siendo la base de la telemetría; los `5710` ya presentes en
`alerts.json` son la evidencia de RS1 (§4).

---

## 4. RS1 — base (default)

RS1 no se "activa": viene con el paquete. Su evidencia es la alerta `5710` (login SSH con usuario
inexistente), que es el sustrato sobre el que se apoya RS3:

```json
{"RS": "RS1", "rule_id": "5710", "level": 5,
 "description": "sshd: Attempt to login using a non-existent user",
 "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
 "agent": "victima-linux"}
```

---

## 5. Salvaguarda de detección-only (R-06) — verificado tras la activación

```
$ grep -rl '<active-response' /var/ossec/ruleset/rules/ /var/ossec/etc/rules/
(sin resultados)
$ grep -c 'active-response' /var/ossec/etc/ossec.conf
0
$ ps -eo cmd | grep '[w]azuh-execd'
(sin proceso)
$ systemctl is-active wazuh-manager
active
```

El **generador aborta** (`exit 2`) si algún fichero de reglas contiene el elemento de respuesta
activa. Nota: durante el despliegue, el propio **comentario** de cabecera de `local_rules.xml`
contenía la cadena literal y la guarda saltó (comportamiento correcto); se reformuló el comentario
para que la comprobación `grep -rl '<active-response'` dé **0** en las 4 capas.

Los **7 bloques `<command>`** del manager (`disable-account`, `restart-wazuh`, `firewall-drop`,
`host-deny`, `route-null`, `win_route-null`, `netsh`) **se conservan** y son **inertes** (no hay
ninguna regla que los invoque). Ver corrección en `deteccion_only.md` §1.2.

---

## 6. RS4 — externas (vacía, opción A del gate G2)

- **No se descarga ni activa ninguna regla externa.**
- El **punto de carga** es el directorio `/var/ossec/etc/rules/`: en Fase 3 bastará con dejar ahí un
  `external_<nombre>.xml` con reglas reales (IDs **100500–101000**) y sin respuesta activa.
- El repo incluye `Soporte/Wazuh/Reglas/external_reserved.xml` como **comentario de reserva**
  (no define reglas).
- **Hallazgo (por qué no se deja un fichero vacío desplegado):** Wazuh 4.14.7 **rechaza** un fichero
  de reglas sin ninguna regla. Un `<group>` vacío provoca:

  ```
  wazuh-analysisd: ERROR: Group 'group' without any rule.
  wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/external_reserved.xml'.
  ```

  y **el manager no arranca**. Por eso RS4 se deja **solo documentada** (el diseño ya lo permitía:
  "basta documentarlo"). El placeholder del repo está marcado como **NO desplegable** en Fase 2.

---

## 7. Manifiesto `active_ruleset.txt` — rangos reales y control de colisiones

Generado por `Soporte/Wazuh/Scripts/generar_active_ruleset.sh` (ejecutado en el manager, copiado
al repo). Es **determinista y re-ejecutable** (`exit 0` = sin colisiones).

**Resumen real por RuleSet:**

| RS | Nombre | MIN_ID | MAX_ID | N_RULES | N_FICHEROS |
|---|---|---:|---:|---:|---:|
| RS1 | base(default) | **1** | **500102** | 4471 | 167 |
| RS2 | auditd | **80700** | **80794** | 44 | 1 |
| RS3 | propias | **100000** | **100000** | 1 | 1 |
| RS4 | externas | – | – | 0 | 0 *(reserva 100500–101000)* |

**Control de colisiones (diseño §4):**

```
duplicate_ids          : ninguna
rs2_out_of_range       : ninguna
rs3_out_of_range       : ninguna
rs4_out_of_range       : ninguna
default_in_rs2_range   : ninguna
default_in_user_range  : ninguna
rs3_inter_rs4          : vacío
unknown_origin         : ninguno
RESULTADO: SIN COLISIONES
```

### 7.1 Ajuste necesario del algoritmo de clasificación (realidad vs. diseño)

El diseño §4 definía RS1 como `1 ≤ rule.id ≤ 99999` y trataba como **colisión** un fichero default
con IDs `≥ 100000`. **Eso no se sostiene con el ruleset real de 4.14.7:** el paquete default incluye
ficheros legítimos con IDs altos —

| Fichero default | Rango de IDs |
|---|---|
| `0780-fireeye_rules.xml` | 150100–150150 |
| `0330-sysmon_rules.xml` | 184665–185013 |
| `0335-unbound_rules.xml` | 500000–500102 |

Aplicar el diseño al pie de la letra marcaría estos 3 ficheros como **colisión** y **abortaría** la
activación (imposible generar el manifiesto). **Ajuste aplicado (mínimo, fiel a la intención):** la
clasificación es **por ORIGEN de fichero** (que es la fuente de verdad de §1):

- `0365-auditd_rules.xml` → **RS2**;
- `etc/rules/local_rules.xml` → **RS3**;
- `etc/rules/external_*.xml` → **RS4**;
- **resto** de `/var/ossec/ruleset/rules/*.xml` → **RS1** (incluidos los IDs altos del paquete).

La **detección de colisiones** se mantiene para lo que de verdad es un choque: IDs duplicados entre
ficheros, ficheros default que **invaden** `80700–80799` o la reserva de usuario `100000–101000`, y
`RS3 ∩ RS4`. Los IDs default `> 101000` **no** son colisión (son del paquete, no de la reserva).
Esto **no** afecta a la resolución de la muestra pedida: `5710→RS1`, `807xx→RS2`, `100000→RS3`.

> **Recomendación para el planner/tester:** actualizar §4 de `rulesets_diseno.md` para reflejar el
> criterio **por origen** (RS1 = complemento real del paquete) y acotar la regla de colisión a la
> reserva de usuario, evitando el falso positivo con fireeye/sysmon/unbound.

---

## 8. Verificación final (salidas reales)

```
############ 1) GUARDA ACTIVE-RESPONSE (ficheros de reglas) ############
(sin resultados)

############ 2) DETECCION-ONLY ############
active-response en ossec.conf : 0
bloques <command> (inertes)   : 7
wazuh-execd                    : sin proceso (OK)
wazuh-manager                  : active

############ 3) MUESTRA DE ALERTAS RESUELTAS A RS ############
rule.id distintos en alerts.json : 35
resueltos a un RS                : 35
UNKNOWN                          : 0
{"RS": "RS1", "rule_id": "5710",   "description": "sshd: Attempt to login using a non-existent user"}
{"RS": "RS2", "rule_id": "80792",  "description": "Audit: Command: /usr/sbin/sshd."}
{"RS": "RS3", "rule_id": "100000", "description": "TFG smoke test (RS3): regla propia disparada"}
```

- **0 `<active-response>`** en las 4 capas; `wazuh-execd` sin proceso. ✔
- Muestra de alertas resuelta **sin ambigüedad**: `5710→RS1`, `807xx→RS2`, `100000→RS3`; **0 UNKNOWN**. ✔
- `active_ruleset.txt` **sin colisiones**, con rangos **reales** de RS1/RS2. ✔

---

## 9. Ficheros creados / modificados (Fase 2 · 2.8)

**En el repo (versionados):**

| Fichero | Estado |
|---|---|
| `Soporte/Wazuh/Reglas/local_rules.xml` | **nuevo** (RS3: esqueleto + smoke 100000) |
| `Soporte/Wazuh/Reglas/auditd_tfg.rules` | **nuevo** (RS2: reglas de auditoría) |
| `Soporte/Wazuh/Reglas/external_reserved.xml` | **nuevo** (reserva RS4, solo documentación) |
| `Soporte/Wazuh/Scripts/generar_active_ruleset.sh` | **nuevo** (manifiesto + colisiones + guarda) |
| `Soporte/Wazuh/Scripts/deploy_rs2_auditd.sh` | **nuevo** (despliegue RS2) |
| `Soporte/Wazuh/Scripts/deploy_rs3_rs4.sh` | **nuevo** (despliegue RS3 + reserva RS4) |
| `Soporte/Wazuh/Scripts/patch_agent_audit.py` | **nuevo** (localfile audit en el agente) |
| `Soporte/Wazuh/Configuracion/active_ruleset.txt` | **nuevo** (manifiesto generado) |
| `Soporte/Wazuh/Configuracion/rulesets_activacion.md` | **nuevo** (este documento) |
| `Soporte/Wazuh/Configuracion/deteccion_only.md` | **corregido** §1.2 (7 `<command>` inertes) |

**En las VMs (fuera del repo):**

| Ruta | Máquina | Nota |
|---|---|---|
| `/etc/audit/rules.d/tfg.rules` | `victima-linux` | copia de `auditd_tfg.rules` |
| `/var/ossec/etc/ossec.conf` | `victima-linux` | + `<localfile>` audit |
| `/var/ossec/etc/ossec.conf.bak-tfg28` | `victima-linux` | backup previo |
| `/var/ossec/etc/rules/local_rules.xml` | `wazuh-server` | copia de RS3 |
| `/var/ossec/etc/rules/local_rules.xml.bak-tfg28` | `wazuh-server` | backup del original |

---

## 10. Reversión

```bash
# RS3 (manager): volver al local_rules.xml original
sudo cp /var/ossec/etc/rules/local_rules.xml.bak-tfg28 /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager

# RS2 (víctima): quitar reglas de auditoría y localfile
sudo rm -f /etc/audit/rules.d/tfg.rules && sudo augenrules --load
sudo cp /var/ossec/etc/ossec.conf.bak-tfg28 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
# (opcional) sudo apt-get remove --purge auditd audispd-plugins
```

> La reversión **no** toca la red ni el modo detección-only.

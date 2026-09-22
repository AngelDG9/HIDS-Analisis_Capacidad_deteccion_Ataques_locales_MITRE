# Modo detección-only (Fase 2, tarea 2.6 / T-07 · requisito R-06)

Deja el laboratorio Wazuh en **modo detección-only**: Wazuh **detecta pero NO reacciona**
(no ejecuta *active response*). Este documento contiene la **evidencia real** (comandos y
salidas) y no incluye credenciales ni claves.

- **Fecha de ejecución:** 2026-09-22 (hora de las VMs)
- **Manager:** `wazuh-server` `192.168.65.128`
- **Agente:** `victima-linux` `192.168.65.129` (ID `001`)
- **Versión:** Wazuh **4.14.7-1** (manager y agente)

---

## 1. Cambios aplicados

### 1.1 Manager (`wazuh-server`)

Se hizo **backup** de `/var/ossec/etc/ossec.conf` y se dejó el fichero **sin ninguna referencia
a `active-response`**. En la config por defecto de 4.14.7 había:

1. un bloque `<active-response>` **de ejemplo** ya comentado con `<!-- ... -->` (no con `#`),
2. un `<localfile>` que solo monitorizaba `/var/ossec/logs/active-responses.log`.

Ambos restos se **eliminaron** (el humano autorizó "comentados o eliminados") para que la
config sea inequívoca y la verificación dé **0**. El `<localfile>` eliminado solo ingería el log
de *active response*, que en detección-only **nunca se escribe** ⇒ no se pierde telemetría real.

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak   # backup
```

Edición (Python, XML-safe): elimina el bloque-ejemplo `<active-response>` comentado y el
`<localfile>` de `active-responses.log`.

> ⚠️ **Nota de validación XML:** el `ossec.conf` de Wazuh tiene **dos bloques raíz
> `<ossec_config>`** (líneas 7–312 y 314–326). Por eso el comando `xml.dom.minidom.parse()`
> **sobre el fichero completo falla también con el original** ("junk after document element").
> La validación correcta es envolver el contenido en un root sintético; hecha así, **el `.bak`
> y el nuevo fichero son XML bien formado** (2 bloques `ossec_config` cada uno).

### 1.2 `wazuh-execd` — hallazgo real en 4.14.7

**En 4.14.7 `wazuh-execd` NO existe como unidad systemd.** Es un **daemon *interno* del manager**
arrancado por `/var/ossec/bin/wazuh-control`, que forma parte de
`/usr/lib/systemd/system/wazuh-manager.service` (`Type=forking`, `ExecStart=wazuh-control start`).
Pruebas:

```
$ systemctl list-unit-files | grep -i execd
(ninguna unidad execd)
$ systemctl is-enabled wazuh-execd   ->  not-found
$ systemctl is-active  wazuh-execd   ->  inactive
```

`wazuh-control status` lo lista entre sus daemons y, tras el arranque, el proceso existe:

```
$ ps -eo pid,cmd | grep '[w]azuh-execd'
65770  /var/ossec/bin/wazuh-execd
```

Por tanto, el comando que proponía el plan (`systemctl stop/disable wazuh-execd`)
**no es aplicable** y no existe `enable|disable` por daemon (el `wazuh-control enable|disable`
solo acepta `debug`). El "medio que corresponde" a esta realidad para **dejarlo parado** es
detener el proceso del daemon:

```bash
sudo pkill -TERM -x wazuh-execd     # parada limpia (SIGTERM)
```

> **¿Por qué el objetivo (no reaccionar) se cumple igual?** Porque, aunque `wazuh-execd` se
> volviera a arrancar al reiniciar el manager, **no tiene nada que ejecutar**: no hay **ningún
> bloque `<active-response>`** en el manager (`grep -c active-response` → **0**), el `agent.conf`
> compartido no define respuestas activas y el agente las tiene explícitamente deshabilitadas
> (§1.3). `execd` sin configuración de AR **no puede reaccionar**. Parar el proceso es una
> capa extra de evidencia, no la garantía.
>
> **Corrección (2026-09-23, tarea 2.8):** una versión anterior de este apartado afirmaba que el
> manager no tenía bloques `<command>`. **Es falso.** El manager **sí conserva 7 bloques
> `<command>`** por defecto —`disable-account`, `restart-wazuh`, `firewall-drop`, `host-deny`,
> `route-null`, `win_route-null`, `netsh`— (evidencia: `grep -c '^ *<command>$'
> /var/ossec/etc/ossec.conf` → **7**). Son **inertes** en detección-only: un `<command>` solo se
> ejecuta si alguna **regla** lo referencia mediante `<active-response>`, y en 2.6 se eliminó
> **todo** `<active-response>` de la config y **ningún** fichero de reglas contiene ese elemento
> (verificado en 2.8: `grep -rl '<active-response' /var/ossec/ruleset/rules/ /var/ossec/etc/rules/`
> → sin resultados). Es decir: **`<command>` = catálogo inerte; `<active-response>` = el que
> dispara; y no hay ninguno de estos últimos.** Los 7 `<command>` se **conservan** a propósito
> (son del paquete y su presencia es la del estado de fábrica).
>
> *(Contexto de versión: en 4.x `wazuh-execd` sigue en el manager por compatibilidad; Wazuh 5.0
> lo elimina del manager. Confirmado en la documentación/issue de Wazuh.)*

### 1.3 Agente (`victima-linux`)

**El plan asumía que la config por defecto del agente ya no ejecuta respuestas activas; no es
cierto.** El `ossec.conf` de fábrica de 4.14.7 trae un bloque **activo** con `<disabled>no</disabled>`:

```xml
<active-response>
  <disabled>no</disabled>
  <ca_store>etc/wpk_root.pem</ca_store>
  <ca_verification>yes</ca_verification>
</active-response>
```

Se aplicó el **método oficial** para desactivarlo (`<disabled>yes</disabled>`), con backup previo
y validación XML (root sintético):

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
# edición: <disabled>no</disabled> -> <disabled>yes</disabled> dentro de <active-response>
sudo systemctl restart wazuh-agent
```

Resultado:

```xml
<active-response>
  <disabled>yes</disabled>
  <ca_store>etc/wpk_root.pem</ca_store>
  <ca_verification>yes</ca_verification>
</active-response>
```

---

## 2. Verificación (salidas reales)

### 2.1 Manager — sin `active-response` en config

```
$ grep -v '^\s*#' /var/ossec/etc/ossec.conf | grep -c active-response
0
```

(Comprobación adicional XML-aware: número de etiquetas `<active-response>` = **0**; y
`grep -c active-response` sobre **todo** el fichero = **0**.)

### 2.2 Ejecutor (`wazuh-execd`) — estado puntual, **no** la garantía

En el momento de esta captura (2026-09-22) se había detenido el daemon; el estado era:

```
$ systemctl is-enabled wazuh-execd   ->  not-found
$ systemctl is-active  wazuh-execd   ->  inactive
$ ps -eo pid,cmd | grep '[w]azuh-execd'
(sin proceso wazuh-execd)
$ sudo /var/ossec/bin/wazuh-control status | grep execd
wazuh-execd not running...
```

> **⚠️ No es una garantía permanente.** Al **reiniciar el `wazuh-manager`** (o al arrancar la VM),
> `wazuh-execd` **vuelve a arrancar** y puede estar corriendo. Es **inerte** porque no hay ningún
> `<active-response>` que ejecutar. La garantía real es **0 `<active-response>`** (§2.1), **no** el
> estado del proceso. Invariante verificable tras cada reinicio: `rulesets_diseno.md` **§5.1**.

### 2.3 Manager activo

```
$ systemctl is-active wazuh-manager
active
```

### 2.4 Sigue detectando (prueba end-to-end con `rule.id` 5710)

Se provocó un login SSH fallido con **usuario inexistente** desde el manager contra la víctima:

```bash
ssh -o BatchMode=yes -o PreferredAuthentications=publickey -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 baduser_tfg@192.168.65.129 true
# -> Permission denied (publickey,password).
```

Conteo de alertas `5710` en `/var/ossec/logs/alerts/alerts.json`: **antes = 2**, **después = 3**.
Alerta real recibida (recortada):

```json
{"timestamp":"2026-09-22T22:21:18.342+0000",
 "rule":{"level":5,"description":"sshd: Attempt to login using a non-existent user","id":"5710",
         "mitre":{"id":["T1110.001","T1021.004"],"tactic":["Credential Access","Lateral Movement"]},
         "groups":["syslog","sshd","authentication_failed","invalid_login"]},
 "agent":{"id":"001","name":"victima-linux","ip":"192.168.65.129"},
 "full_log":"Sep 22 22:21:17 victima-linux sshd[8153]: Invalid user baduser_tfg from 192.168.65.128 port 34058",
 "location":"journald"}
```

⇒ Tras pasar a detección-only, **la detección sigue funcionando** (el agente sigue `Active`
en el manager: `agent_control -i 001` → `Status: Active`).

---

## 3. Backups creados

| Fichero | Máquina | Ruta |
|---|---|---|
| Config original del manager | `wazuh-server` | `/var/ossec/etc/ossec.conf.bak` |
| Config original del agente | `victima-linux` | `/var/ossec/etc/ossec.conf.bak` |

---

## 4. Reversión

```bash
# Manager
sudo cp /var/ossec/etc/ossec.conf.bak /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager        # también vuelve a arrancar wazuh-execd

# Agente
sudo cp /var/ossec/etc/ossec.conf.bak /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

> Revertir **reactivaría** la capacidad de respuesta activa (el agente volvería a
> `<disabled>no</disabled>`). No hacerlo durante la fase de captura (baseline/ataques).

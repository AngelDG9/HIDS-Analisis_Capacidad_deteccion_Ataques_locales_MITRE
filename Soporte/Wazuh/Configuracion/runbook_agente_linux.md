# Runbook — Agente Wazuh en `victima-linux` (Fase 2, tarea 2.5 / T-05)

Documenta la instalación **real** del agente Wazuh en la víctima Linux, su registro en el
manager y la verificación de que **llega telemetría real**. No incluye credenciales ni claves.

- **Fecha de ejecución:** 2026-09-22
- **Host:** `victima-linux` `192.168.65.129` (Ubuntu Server 24.04.5 LTS, 2 vCPU / 3 GB)
- **Manager:** `wazuh-server` `192.168.65.128` (misma versión) — comunicación **por host-only**
- **Versión del agente:** **4.14.7-1** (misma que el manager)
- **Agent ID asignado:** **001**

> ⚠️ La comunicación agente↔manager va **siempre por la IP host-only `192.168.65.128`**, nunca
> por la IP del NAT. La regla de oro del NAT desconectado (baseline/ataques) está en
> `runbook_instalacion_wazuh.md`.

---

## 1. Instalación desde el paquete `.deb` oficial

Se descargó el `.deb` de la **misma versión** que el manager y se instaló pasando el manager
y el nombre del agente por variables de entorno (las lee el postinst):

```bash
cd /home/angel
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.7-1_amd64.deb
sudo WAZUH_MANAGER='192.168.65.128' WAZUH_AGENT_NAME='victima-linux' \
     dpkg -i ./wazuh-agent_4.14.7-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

Salida relevante:

```
Unpacking wazuh-agent (4.14.7-1) ...
Setting up wazuh-agent (4.14.7-1) ...
Created symlink /etc/systemd/system/multi-user.target.wants/wazuh-agent.service -> /usr/lib/systemd/system/wazuh-agent.service
```

---

## 2. Configuración resultante

`/var/ossec/etc/ossec.conf`:

```xml
<server>
  <address>192.168.65.128</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>
```

Versión del agente:

```
$ /var/ossec/bin/wazuh-control info
WAZUH_VERSION="v4.14.7"
WAZUH_REVISION="rc1"
WAZUH_TYPE="agent"
```

---

## 3. Congelado de repositorios del agente

El agente se instaló desde el `.deb` local, por lo que **no se creó** ningún repositorio de
Wazuh en `/etc/apt/sources.list.d/` (`ls -l` solo muestra `ubuntu.sources` y su `.curtin.orig`).
**No hay nada que congelar**; queda documentado para que no se confunda con un olvido.

> Si en el futuro se añadiera el repo, congelarlo con
> `sudo sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list`.

---

## 4. Verificación del registro en el manager

### 4.1 Servicio local

```bash
systemctl is-active wazuh-agent   # -> active
```

### 4.2 En el manager (`wazuh-server`)

```bash
sudo /var/ossec/bin/agent_control -l
```

```
   ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: victima-linux, IP: any, Active
```

```bash
sudo /var/ossec/bin/agent_control -i 001
```

```
   Agent ID:   001
   Agent Name: victima-linux
   Status:     Active
   Client version: Wazuh v4.14.7
   Syscheck last started at: ... / last ended at: ...
```

### 4.3 Vía API (JWT) del manager

La API 4.14 no acepta Basic Auth directo: hay que autenticar y usar el token.

```bash
# extrae la contraseña del usuario API 'wazuh' SIN imprimirla
API_PW=$(tar -xOf /home/angel/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
         | awk -F"'" '/api_username/{u=$2} /api_password/{if(u=="wazuh") print $2}')
TOKEN=$(curl -sk -u "wazuh:$API_PW" -X POST \
        "https://192.168.65.128:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" \
     "https://192.168.65.128:55000/agents/summary/status?pretty=true"
```

```
"connection": { "active": 1, "disconnected": 0, "never_connected": 0, "pending": 0, "total": 1 }
```

(El recuento total es 1 porque el agente del propio manager —ID 000— no cuenta como
conexión remota; `victima-linux` es el único agente remoto.)

---

## 5. Prueba de telemetría real (extremo a extremo)

Se generó **un** login SSH fallido controlado **en la víctima**:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 nonexistent_tfg@127.0.0.1 true
# -> Permission denied (publickey,password)
```

`/var/log/auth.log` en la víctima:

```
invalid user nonexistent_tfg from 127.0.0.1 port 57832
```

Alerta recibida en el **manager** (`/var/ossec/logs/alerts/alerts.json`):

```json
{"timestamp":"2026-09-22T21:58:26.640+0000",
 "rule":{"level":5,"id":"5710",
         "description":"sshd: Attempt to login using a non-existent user",
         "mitre":{"id":["T1110.001","T1021.004"]}},
 "agent":{"id":"001","name":"victima-linux","ip":"192.168.65.129"}}
```

`agent.id=001` ⇒ la telemetría de `victima-linux` **llega y se registra** en el manager.

---

## 6. Higiene: dónde están los secretos (NUNCA al repo)

- La contraseña del usuario API `wazuh` está en `wazuh-passwords.txt`, dentro de
  `wazuh-install-files.tar`, en `/home/angel` **de `wazuh-server`** (fuera del repo).
- En este runbook solo se documenta **dónde** está y **cómo usarla sin imprimirla**; nunca
  su valor.
- Patrones de secretos cubiertos en `.gitignore` (§3.10 del plan).

---

## 7. Reversión (si hiciera falta)

```bash
sudo systemctl disable --now wazuh-agent
sudo dpkg -r wazuh-agent
# (el manager conserva el agente 001 como 'disconnected'; se puede borrar con
#  /var/ossec/bin/manage_agents -r 001 en el manager)
```

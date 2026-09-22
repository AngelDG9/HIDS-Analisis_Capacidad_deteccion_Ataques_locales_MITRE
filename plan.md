---
fase: 2
nombre: Laboratorio Wazuh (F-02)
version: 2
status: approved_by_human
fecha: 2026-09-22
fecha_aprobacion: 2026-09-22
aprobado_por: humano
autor: tfg-planner
---

# Plan — Fase 2: Laboratorio Wazuh (F-02)

> Secuencia de la fase: **T-04 → T-08 (acceso) → T-05 → T-07 → T-06 → T-08 (cierre)**
> (F-02, `requirements.md` §3). Revisión v2: el **acceso se adelanta al inicio** (ya hecho) y
> los **agentes corren en el sobremesa**; el resto del diseño no cambia.
> Este plan no implementa nada: describe qué se hará, con qué salida verificable y cómo se
> comprueba. KISS: 8/10 hecho > 10/10 sin hacer.

---

## 1. Objetivo y alcance

**Objetivo:** dejar un **laboratorio Wazuh reproducible** donde Wazuh (manager + indexer +
dashboard) recibe telemetría de `victima-linux`, opera en **modo detección-only** con **4
RuleSets (RS1..RS4)** clasificables por origen (`rule.id`), tiene grabado un **baseline
legítimo de ~4 h** y es **controlable en remoto** desde el portátil (SSH) y `vmrun`. Es el
**hito H2** del roadmap.

**Entra (In scope):**

- **T-05 [MIXTO]:** desplegar **Wazuh all-in-one** en `wazuh-server` y conectar el **agente** en
  `victima-linux` (Linux primero). Runbooks en `Soporte/Wazuh/Configuracion/`.
- **T-07 [AUTO]:** **detección-only** (R-06) + los **4 RuleSets** con **clasificación de
  alertas por origen** vía `rule.id` (R-09). Salida `active_ruleset.txt`.
- **T-06 [AUTO]:** **baseline legítimo ~4 h** sobre víctima limpia (R-08) →
  `Dataset/Legitimo/ruleids_legitimos.csv`.
- **T-08 [MIXTO]:** control remoto por **SSH** y `vmrun` →
  `Soporte/Laboratorio/ssh_setup.md` + `vmrun_config.md`.
- **T-04 [HUMANO]:** ya completada (topología + VMs). Aquí solo se **registra**.
- Red temporal: adaptador **NAT** para instalar software; **snapshots** `lab-listo`.

**NO entra (Fuera de alcance):**

- Ejecutar ataques, capturar alertas por ataque, filtrar TP/FP, calcular η (Fases 3-4).
- **Atomic Red Team** (T-09) y los artefactos `ATA<NNN>` (Fase 3).
- **Windows** como víctima: solo cuando una técnica lo exija (Fase 3+).
- **Velociraptor / tercer HIDS / Snort**: extras (R-05).
- Dashboard/alertas como servicio permanente: aquí basta con que **arranque y detecte**.
- Endurecer el laboratorio o exponerlo: red **host-only**, sin internet en operación normal.
- `Hojas/Mapeos.xlsx`, BBDD SQLite, métricas η: Fases 3-5.

---

## 2. Estado de partida (T-04 hecha) — inventario real

| Elemento | Valor |
|---|---|
| Hipervisor | VMware Workstation **Pro 26H1** en el sobremesa (Windows 10, 16 GB) |
| Carpeta de VMs | `D:\TFG-VMs` |
| Red host-only | `VMnet1` = `192.168.65.0/24` (DHCP de VMware). **Sin internet** |
| `wazuh-server` | Ubuntu Server 24.04.5 LTS · `192.168.65.128` · 2 vCPU / 6 GB / 50 GB · `angel` |
| `victima-linux` | Ubuntu Server 24.04.5 LTS · `192.168.65.129` · 2 vCPU / 3 GB / 20 GB · `angel` |
| Snapshot base | `base-limpia` en ambas |
| Documentación T-04 | `Soporte/Laboratorio/README.md` + `topologia.png` + `topologia.mmd` ✔ |
| **Acceso (remoto)** | **Portátil Windows 11 (8 GB) → sobremesa por SSH sobre Tailscale** (`100.82.127.119`, usuario `angel`, equipo `desktop-oiolopo`). OpenSSH Server en el sobremesa habilitado + regla de firewall ✔ |
| **Agentes (opencode)** | **Corren en el sobremesa** (Windows 10), junto a las VMs. Sobremesa con **opencode + VSCode + git** ✔ |
| **Acceso a las VMs** | **Local desde el sobremesa** por la red **host-only** (`VMnet1`); `vmrun` **local** (sin `-h`) |
| Pendiente | **Clonar el repo** en el sobremesa (`C:\TFG\...`) |

**Conclusión:** T-04 está **completada** y el **acceso portátil→sobremesa ya está montado**
(Tailscale + OpenSSH). Puntos abiertos que resuelve esta fase: clonar el repo en el sobremesa,
internet temporal, Wazuh, detección-only + RuleSets, baseline y **documentar el acceso** +
probar `vmrun`.

---

## 3. Diseño técnico

### 3.1 Versión de Wazuh a fijar — [HUMANO]

- **Línea fijada:** **Wazuh 4.x estable vigente**. A fecha de planificación, la línea estable
  es **4.14.x**; instalador verificado:
  `https://packages.wazuh.com/4.14/wazuh-install.sh`.
- **Parche exacto:** se fija en la tarea **2.2** (p. ej. `4.14.4`) y se registra en
  `Soporte/Wazuh/Configuracion/version_wazuh.txt` (`wazuh-manager --version`,
  `wazuh-indexer --version`, `wazuh-dashboard --version`). **Decisión [HUMANO]** (gate §8).
- **Congelado:** tras instalar, se **deshabilitan los repositorios de Wazuh** para evitar
  actualizaciones accidentales:
  `sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list && apt update` (idem repos del
  agente). Da reproducibilidad al laboratorio.

### 3.2 Método de instalación all-in-one (T-05, `wazuh-server`)

- **Método:** **asistente oficial all-in-one** (indexer + manager + Filebeat + dashboard en un
  host). Es el camino más simple y el recomendado para laboratorio:
  ```bash
  curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
  sudo bash ./wazuh-install.sh -a
  ```
- **Requisitos:** se ejecuta con **NAT conectado** (§3.6). Antes, comprobar espacio libre
  (`df -h /` ≥ 20 GB) y RAM.
- **Salida:** acceso web `https://192.168.65.128/` (usuario `admin`), credenciales en
  `wazuh-install-files.tar` (`wazuh-passwords.txt`) → **NUNCA a git** (§3.10).
- **Smoke test:** comprobar servicios `active` y un login fallido controlado que dispare una
  regla conocida (SSH → `rule.id` 5710/5760) para confirmar que el pipeline detecta.
- **Runbook:** `Soporte/Wazuh/Configuracion/runbook_instalacion_wazuh.md`.

### 3.3 Agente en `victima-linux` (T-05)

- Instalar el agente de la **misma versión** que el manager y apuntarlo al manager por la IP
  **host-only** (`192.168.65.128`), no por la IP del NAT:
  ```bash
  wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_<VER>_amd64.deb
  sudo WAZUH_MANAGER='192.168.65.128' WAZUH_AGENT_NAME='victima-linux' \
       dpkg -i ./wazuh-agent_<VER>_amd64.deb
  sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
  ```
- **Registro:** agente visible como `active` en el dashboard/API.
- **Runbook:** `Soporte/Wazuh/Configuracion/runbook_agente_linux.md`.
- **Telemetría base:** syscheck (FIM) sobre rutas de la víctima y recepción de syslog/SSH/PAM.
  `auditd` se activa como parte de **RS2** (§3.5).

### 3.4 Modo detección-only (R-06)

- **Manager:** eliminar/comentar los bloques `<active-response>` de
  `/var/ossec/etc/ossec.conf` (backup `ossec.conf.bak`) y desactivar el ejecutor:
  `sudo systemctl stop wazuh-execd && sudo systemctl disable wazuh-execd`.
- **Agente:** sin `<active-response>` en su `ossec.conf` (config por defecto ya no ejecuta
  respuestas activas; se verifica explícitamente).
- **Verificación:** `grep -v '^\s*#' /var/ossec/etc/ossec.conf | grep -c active-response` → `0`;
  `systemctl is-active wazuh-execd` → `inactive`.
- **Documentación:** `Soporte/Wazuh/Configuracion/deteccion_only.md` (con la evidencia).

### 3.5 RuleSets RS1..RS4 (R-09) — propuesta concreta

**Principio de clasificación:** el **origen** de cada alerta es el **fichero de reglas** que la
define; cada capa introduce un conjunto de ficheros y, por tanto, de `rule.id`. Las 4 capas
están **activas a la vez** (Wazuh carga todo `/var/ossec/ruleset/rules/*.xml` y
`/var/ossec/etc/rules/*.xml`), así que **el ataque se ejecuta UNA vez** y se clasifica cada
alerta por el `rule.id` que la origina. La capa **RSn** de una alerta es la **más baja** cuyo
rango contenga ese `rule.id`.

| RS | Nombre | Origen (fichero) | Rango `rule.id` (indicativo) | Qué añade |
|---|---|---|---|---|
| **RS1** | **Base (default)** | `/var/ossec/ruleset/rules/*.xml` **excepto** auditd | default (p. ej. 001–5999, 6000–80699) | Telemetría básica: syslog, SSH, PAM, sudo, **FIM** (550–559), rootcheck, web |
| **RS2** | **+ `auditd`** | `/var/ossec/ruleset/rules/0365-auditd_rules.xml` (activado por config de audit en el agente) | ~**80700–80799** | **Procesos y syscalls** (execve, escritura de ficheros) |
| **RS3** | **+ reglas propias** | `/var/ossec/etc/rules/local_rules.xml` | **100000–100499** | Reglas custom del TFG orientadas a **R/E/S** (mínimas en Fase 2; crecen en Fase 3) |
| **RS4** | **+ externas** | `/var/ossec/etc/rules/external_*.xml` | **100500–101000** | Reglas de la **comunidad** (Sigma→Wazuh u otro pack). **Fuente exacta [HUMANO]** (§8) |

- **RS2 — activación de `auditd`** en `victima-linux`: instalar `auditd`, cargar reglas de
  proceso/fichero (`-a always,exit -S execve`, watch sobre rutas del corpus) y enviar la
  telemetría al agente. Las reglas de Wazuh ya vienen en el paquete; lo que se añade es la
  **telemetría** que las dispara.
- **RS3 — reglas propias** (mínimas y honestas): en Fase 2 basta con (a) una regla "smoke test"
  y (b) el **esqueleto documentado** con el rango reservado. Las reglas R/E/S se escriben en
  Fase 3, sin tocar el diseño.
- **RS4 — externas:** se reserva el rango y se deja el **loader** preparado
  (`/var/ossec/etc/rules/`). La fuente concreta (p. ej. reglas Sigma de la comunidad convertidas
  a Wazuh) la **aprueba el humano** en el gate; si no hay fuente fiable, RS4 = **RS3 + 0**
  y se documenta (no se inventan reglas).
- **Artefacto `active_ruleset.txt`:** manifiesto generado en el manager por
  `Soporte/Wazuh/Scripts/generar_active_ruleset.sh`, que recorre los ficheros activos, extrae el
  **rango real de `rule.id`** de cada uno y lo asigna a su RS. Incluye detección de **colisiones**
  de ID entre RS3 y RS4 (si las hay, se avisa y se renumeran). Salida:
  `Soporte/Wazuh/Configuracion/active_ruleset.txt`.
- **Diseño y aprobación:** `Soporte/Wazuh/Configuracion/rulesets_diseno.md` (tabla anterior +
  justificación + fuentes) → **[HUMANO]** antes de activar.
- **Resolución RS↔`rule.id` (para Fase 3):** el manifiesto define los rangos; `tfg-tester`
  comprueba que todo `rule.id` de una muestra de alertas se resuelve a un RS.

### 3.6 Red: adaptador NAT temporal (internet para instalar)

- **Cuándo:** solo durante T-05 (instalación de Wazuh y agente) y para `apt update`. En
  operación normal (baseline/ataques) **NAT desconectado**.
- **Procedimiento (por VM):**
  1. Apagar la VM → VMware → *Settings* → *Add* → *Network Adapter* → **NAT (VMnet8)**.
  2. Arrancar; identificar la interfaz nueva: `ip -br a` (p. ej. `ens37`).
  3. Añadir netplan `/etc/netplan/60-nat.yaml`:
     ```yaml
     network:
       version: 2
       ethernets:
         ens37:
           dhcp4: true
     ```
     `sudo netplan apply`; verificar internet con `ping -c2 8.8.8.8`.
  4. Instalar Wazuh / agente. **La comunicación agente↔manager sigue por VMnet1**
     (`192.168.65.128`), no por el NAT.
- **Desconexión:** dejar el adaptador **presente pero desconectado** (*Connect at power on*
  desmarcado, o `sudo ip link set ens37 down`). Motivo: reeditable para futuras instalaciones
  (p. ej. Atomic Red Team en Fase 3) sin reconfigurar.
- **Regla de oro:** durante cualquier ataque o baseline, **solo VMnet1 activa**. Queda en el
  runbook (`Soporte/Wazuh/Configuracion/runbook_instalacion_wazuh.md`) y en `README.md`.
- **IPs estables:** convertir `192.168.65.128/129` a **estáticas** (netplan) o reservarlas por
  MAC en el DHCP de VMware, para que ni el agente ni los scripts dependan de un DHCP cambiante.

### 3.7 Estrategia de snapshots

| Snapshot | VM(s) | Momento | Para qué |
|---|---|---|---|
| `base-limpia` | ambas | Ya existe | S.O. recién instalado |
| **`lab-listo`** | **ambas** | **Tras T-07** (antes de T-06) | Arranque limpio de cada ataque (Fase 3) y de la baseline |
| `lab-baseline` (opcional) | `wazuh-server` | Tras T-06 | Conservar las alertas del baseline en el indexer |

- `lab-listo` de `victima-linux` **no** incluye los ficheros creados por la baseline → cada
  ataque parte de un estado idéntico y limpio.
- El **manager no se revierte** durante los ataques: así el baseline permanece en el indexer.
- Creación vía VMware GUI o `vmrun` (T-08):
  `vmrun -T ws snapshot "D:\TFG-VMs\victima-linux\victima-linux.vmx" "lab-listo"`.

### 3.8 Baseline legítimo ~4 h (T-06)

- **Sobre:** `victima-linux` limpia (snapshot `lab-listo`), agente conectado, RS1..RS4 activos,
  **NAT desconectado**.
- **Qué actividad (legítima y variada, KISS):** script `Soporte/Wazuh/Scripts/baseline_actividad.sh`
  que durante **4 h** repite cada ~5 min un ciclo de tareas benignas en
  `/home/angel/lab-legit/`: crear/leer/escribir ficheros, `tar` de un directorio (backup
  legítimo), `cp`/`mv`/`rm` de temporales, `find`/`grep`/`sha256sum`, lectura de `journalctl`,
  `apt list --installed`. Se suma la actividad **natural** (systemd, cron, SSH, rootcheck).
  Opcional: forzar **un scan FIM** dentro de la ventana (`agent_control -r -u <id>`), porque el
  ciclo por defecto es de 12 h.
- **Ventana temporal:** registrar `t0` y `t1` (UTC/local) en `Dataset/Legitimo/baseline_meta.md`
  (duración real, RS activos, comandos ejecutados, snapshot usado). Requisito: `t1 − t0 ≥ 4 h`.
- **Captura de `rule.id`:** script `_artefactos/scripts/extraer_alertas.py` que lee
  `/var/ossec/logs/alerts/alerts.json` del **manager** y filtra por `timestamp ∈ [t0,t1]`,
  agregando por `rule.id`. (Fallback documentado: consulta al indexer `wazuh-alerts-*`.)
  Es el **mismo script reutilizable en Fase 3** (T-10/T-11).
- **Salida:** `Dataset/Legitimo/ruleids_legitimos.csv` con
  `rule_id,rule_level,rule_description,groups,count,first_seen,last_seen,rs_origen`.
- **Uso para filtrar FP (Fase 3):** el CSV es el **catálogo de ruido normal**. En Fase 3, una
  alerta disparada por un ataque cuyo `rule.id` coincide con el baseline y **no** es atribuible
  al Data Component de la técnica se marca como **candidata a FP** (revisión humana); las
  restantes son TP. El baseline **no** etiqueta automáticamente: acota.

### 3.9 Acceso remoto: SSH (Tailscale) + `vmrun` local (T-08)

- **Esquema:** el **portátil** entra al **sobremesa** por **SSH sobre Tailscale**. Los **agentes
  (opencode) corren en el sobremesa**, junto a las VMs, de modo que acceden a las VMs por la red
  **host-only** y ejecutan **`vmrun` en local**. **Ya no hay ProxyJump** (los agentes no saltan
  desde el portátil a las VMs).
- **Ya hecho (por el humano):**
  - **OpenSSH Server** en el sobremesa (Windows 10) habilitado + regla de firewall → se entra por
    SSH desde el portátil.
  - **Tailscale** operativo: IP del sobremesa `100.82.127.119`, cuenta local `angel`
    (equipo `desktop-oiolopo`). Desde el portátil: `ssh angel@100.82.127.119` funciona.
- **`vmrun` en local** (en el sobremesa), **sin `-h`**:
  ```
  vmrun -T ws list
  vmrun -T ws start  "D:\TFG-VMs\victima-linux\victima-linux.vmx" nogui
  vmrun -T ws snapshot "D:\TFG-VMs\victima-linux\victima-linux.vmx" "lab-listo"
  vmrun -T ws listSnapshots "D:\TFG-VMs\victima-linux\victima-linux.vmx"
  ```
- **Pendiente (cierre de T-08):** documentar `Soporte/Laboratorio/ssh_setup.md` (Tailscale +
  OpenSSH + prueba de conexión) y `Soporte/Laboratorio/vmrun_config.md` (rutas reales, sintaxis,
  prueba) y **probar `vmrun`** en el sobremesa. Autenticación por **clave**; las claves privadas
  **no** van a git.
- **Prueba [MIXTO]:** el humano confirma `ssh angel@100.82.127.119` desde el portátil y un
  `vmrun listSnapshots` ejecutado **en el sobremesa**.

### 3.10 Seguridad y higiene (evitar fugas al repo)

- **No versionar:** credenciales del dashboard (`wazuh-passwords.txt`, `wazuh-install-files.tar`),
  claves privadas (`id_*`, `*.pem`, `*.key`). Añadir a `.gitignore` patrones explícitos:
  `Soporte/Wazuh/Configuracion/*password*`, `*.pem`, `*.key`, `wazuh-install-files.tar`,
  `id_rsa*`, `id_ed25519*`.
- Los runbooks solo documentan **dónde** están las credenciales, nunca su valor.
- **Nunca `git push`**: los commits los hace el humano.

---

## 4. Tareas atómicas (orden F-02)

| # | Tarea | Modo | Salida verificable |
|---|---|---|---|
| 2.1 | **T-04** — registrar topología y VMs como completadas | **[HUMANO]** (hecho) | `Soporte/Laboratorio/README.md` + `topologia.png` (✔ existen) |
| 2.2 | **T-08 (acceso)** — **SSH portátil→sobremesa sobre Tailscale** + OpenSSH Server en Windows 10 | **[HUMANO]** (hecho) | acceso `ssh angel@100.82.127.119` operativo (✔) |
| 2.3 | Preparar sobremesa (**clonar repo** en `C:\TFG\...`) + fijar **versión de Wazuh** + añadir **NAT temporal** a ambas VMs + IPs estables | **[MIXTO]** | repo clonado + `version_wazuh.txt` + `ping` OK + IPs fijas |
| 2.4 | **T-05** — instalar **Wazuh all-in-one** en `wazuh-server` | **[MIXTO]** | dashboard en `https://192.168.65.128` + `runbook_instalacion_wazuh.md` |
| 2.5 | **T-05** — instalar **agente** en `victima-linux` y registrarlo | **[MIXTO]** | agente `active` + `runbook_agente_linux.md` |
| 2.6 | **T-07** — **detección-only** (active-response off, `wazuh-execd` off) | **[AUTO]** | `deteccion_only.md` + evidencia `grep`/`systemctl` |
| 2.7 | **T-07** — diseñar y **aprobar RuleSets RS1..RS4** | **[HUMANO]** | `rulesets_diseno.md` aprobado |
| 2.8 | **T-07** — activar RuleSets (auditd, local, externas) y generar **`active_ruleset.txt`** | **[AUTO]** | `active_ruleset.txt` + `local_rules.xml` + sin colisiones |
| 2.9 | Crear **snapshot `lab-listo`** en ambas VMs | **[HUMANO]** | `vmrun listSnapshots` muestra `lab-listo` |
| 2.10 | **T-06** — baseline **~4 h** + captura de `rule.id` | **[AUTO]** | `Dataset/Legitimo/ruleids_legitimos.csv` + `baseline_meta.md` ≥ 4 h |
| 2.11 | **T-08 (cierre)** — **documentar** SSH (`ssh_setup.md`) y `vmrun` **local** (`vmrun_config.md`) + **probar `vmrun`** en el sobremesa | **[MIXTO]** | `ssh_setup.md` + `vmrun_config.md` + `vmrun listSnapshots` local |
| 2.12 | Verificación (`tfg-tester`), cierre y actualizar `state.md`/`roadmap.md`/`change-doc.md` | **[AUTO]** | informe PASA + docs actualizados |

> Nota: en F-02 el orden pasa a ser **T-04 → T-08 (acceso) → T-05 → T-07 → T-06 → T-08 (cierre)**.
> El **acceso (T-08)** se adelanta al inicio y su parte de infraestructura **ya está hecha**; solo
> queda **documentarla** y probar `vmrun` al final. El snapshot `lab-listo` (2.9) se crea **entre**
> T-07 y T-06 para que la baseline y los ataques partan del mismo estado.

---

## 5. Definition of Done (roadmap Fase 2)

> "Wazuh con agentes activos, detección-only, baseline grabado y acceso remoto verificado desde
> el portátil."

- [ ] `wazuh-server` con servicios `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard` **active**.
- [ ] Agente `victima-linux` **active** en el manager, apuntando a `192.168.65.128`.
- [ ] **Detección-only** verificado (sin `active-response`, `wazuh-execd` inactive) y documentado (R-06).
- [ ] **4 RuleSets** RS1..RS4 definidos, activos y con **`active_ruleset.txt`** que mapea
      `rule.id` → RS sin colisiones (R-09).
- [ ] **Baseline ~4 h** con `Dataset/Legitimo/ruleids_legitimos.csv` y `baseline_meta.md` (R-08).
- [ ] Snapshot **`lab-listo`** en ambas VMs.
- [ ] **Acceso** verificado: `ssh angel@100.82.127.119` (portátil→sobremesa) y **`vmrun`**
      operativo **en local** en el sobremesa (T-08).
- [ ] Runbooks en `Soporte/Wazuh/Configuracion/` y docs en `Soporte/Laboratorio/`.
- [ ] Sin credenciales ni claves en git; `_recursos/` intacto; sin `git push`.
- [ ] `tfg-tester` → **PASA**; `state.md`/`roadmap.md`/`change-doc.md` actualizados (hito H2).

---

## 6. Cómo se verifica

1. **Servicios (T-05):** `systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard` →
   `active`; API/dashboard responde en `https://192.168.65.128`.
2. **Agente (T-05):** aparece `victima-linux` con estado `active`; un evento de prueba llega al
   manager (smoke test: login SSH fallido → `rule.id` 5710/5760).
3. **Detección-only (R-06):** `grep -c active-response` en `ossec.conf` → 0; `wazuh-execd`
   `inactive`; documentado.
4. **RuleSets (R-09):** `active_ruleset.txt` lista cada fichero activo con su rango de `rule.id` y
   su RS; una muestra de alertas se resuelve unívocamente a un RS; sin colisiones RS3/RS4.
   La clasificación es **por origen**, sin repetir el ataque.
5. **Baseline (R-08):** `ruleids_legitimos.csv` con N `rule.id` distintos; `baseline_meta.md`
   demuestra `t1 − t0 ≥ 4 h`; NAT desconectado durante la ventana.
6. **Snapshots:** `vmrun listSnapshots` muestra `base-limpia` y `lab-listo`.
7. **Acceso (T-08):** desde el portátil, `ssh angel@100.82.127.119` abre shell en el sobremesa;
   **en el sobremesa** `vmrun list` enumera las VMs en marcha.
8. **Higiene:** `git status` no muestra credenciales/claves; `_recursos/` intacto.
9. **DoD:** checklist de §5 completo; lo comprueba `tfg-tester`.

---

## 7. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| **RAM insuficiente** (all-in-one con 2 vCPU / 6 GB) | Reducir heap del indexer (`-Xms1g -Xmx1g`); un solo agente; si no basta, subir la VM a 8 GB (host 16 GB) **o** migrar el dashboard a otro momento. Decisión [HUMANO] en 2.3 |
| **Sin internet** por defecto | NAT temporal (§3.6), conectado solo para instalar y **desconectado** durante baseline/ataques |
| **El NAT queda conectado** y contamina ataques | Runbook + regla de oro; verificación previa a cada ataque (Fase 3) |
| **IP dinámica (DHCP)** cambia y rompe el agente | IPs estáticas o reserva DHCP por MAC en 2.3 |
| **Credenciales/claves en git** | `.gitignore` explícito + runbooks sin secretos (§3.10) |
| **Colisión de `rule.id`** RS3 vs RS4 | Rangos reservados + comprobación en `generar_active_ruleset.sh`; renumerar si procede |
| **RS4 sin fuente fiable** | Si no hay pack externo fiable, RS4 = RS3 + 0 y se documenta; no se inventan reglas |
| **Baseline poco representativo** (actividad sintética) | Actividad scripted + natural + un scan FIM forzado; limitación declarada en `baseline_meta.md` |
| **`auditd` genera ruido** que inunda alertas | Es parte del experimento (RS2); el baseline acota el ruido y Fase 3 filtra FP |
| **Indexer lento** al indexar | Espera de 60 s + segunda consulta a 300 s antes de dar por "no detectado" (Fase 3) |
| **Actualizaciones del S.O.** rompen reproducibilidad | Deshabilitar `unattended-upgrades`; congelar versión de Wazuh |
| **`lab-listo` se toma antes de T-07** por error | El orden de tareas (2.7 antes de 2.8) es explícito y se verifica |
| **Espacio en `D:\TFG-VMs`** por snapshots | Vigilar espacio antes de crear cada snapshot |

---

## 8. Puntos de validación humana ([HUMANO])

| # | Cuándo | Qué aprueba |
|---|---|---|
| **G0** | Antes de ejecutar | **Este plan (v2)** (`status → approved_by_human`) |
| **G1** | Tarea 2.3 | **Versión de Wazuh** a fijar (línea 4.14.x y parche) y RAM final de `wazuh-server` |
| **G2** | Tarea 2.7 | **Diseño de los 4 RuleSets** (`rulesets_diseno.md`), incluida la **fuente externa** de RS4 |
| **G3** | Antes de 2.10 | **Víctima limpia**, NAT desconectado y snapshot `lab-listo` presente |
| **G4** | Cierre de fase | **Hito H2** al tutor: laboratorio Wazuh funcionando + baseline |

> El **acceso (T-08)** ya está montado por el humano → no requiere gate. Ningún paso que
> edite/ejecute arranca sin el `plan.md` aprobado (gate del flujo).

---

## 9. Trazabilidad

| Requisito / flujo | Dónde se cumple |
|---|---|
| **R-05** Wazuh único HIDS del núcleo | T-05 (§3.2, §3.3): solo Wazuh se instala; salidas en `Estudio-Wazuh/` y `Dataset/Ataques/Resultados/Wazuh/` (Fase 3) |
| **R-06** detección-only | T-07 §3.4: `active-response` off + `wazuh-execd` off, documentado y verificado |
| **R-08** baseline legítimo ~4 h | T-06 §3.8: `Dataset/Legitimo/ruleids_legitimos.csv` |
| **R-09** 4 RuleSets, clasificación por origen | T-07 §3.5: RS1..RS4 + `active_ruleset.txt`, un ataque = una ejecución |
| **R-13** reproducibilidad (soporte) | Runbooks + scripts (`extraer_alertas.py`, `generar_active_ruleset.sh`, `baseline_actividad.sh`); los artefactos `ATA<NNN>` son Fase 3 |
| **F-02** secuencia de la fase | §4: T-04 → T-08 (acceso, ya hecho) → T-05 → T-07 → T-06 → T-08 (cierre) |
| **Hito H2** | DoD §5 + G4 §8 |

---

## 10. Ficheros que se tocarán

**Fase 2 (nuevos/actualizados):**

```
plan.md                                              (este fichero)
Soporte/Wazuh/Configuracion/version_wazuh.txt        (T-05)
Soporte/Wazuh/Configuracion/runbook_instalacion_wazuh.md  (T-05)
Soporte/Wazuh/Configuracion/runbook_agente_linux.md  (T-05)
Soporte/Wazuh/Configuracion/deteccion_only.md        (T-07)
Soporte/Wazuh/Configuracion/rulesets_diseno.md       (T-07)
Soporte/Wazuh/Configuracion/active_ruleset.txt       (T-07)
Soporte/Wazuh/Reglas/local_rules.xml                 (T-07, esqueleto)
Soporte/Wazuh/Scripts/baseline_actividad.sh          (T-06)
Soporte/Wazuh/Scripts/generar_active_ruleset.sh      (T-07)
_artefactos/scripts/extraer_alertas.py               (T-06; reutilizable Fase 3)
Dataset/Legitimo/ruleids_legitimos.csv               (T-06)
Dataset/Legitimo/baseline_meta.md                    (T-06)
Soporte/Laboratorio/ssh_setup.md                     (T-08)
Soporte/Laboratorio/vmrun_config.md                  (T-08)
Soporte/Laboratorio/README.md                        (actualizar pendientes/red)
.gitignore                                           (patrones de secretos)
state.md / roadmap.md / change-doc.md                (cierre)
```

**Fuera del repo (secretos, no versionados):** `wazuh-passwords.txt`,
`wazuh-install-files.tar`, claves SSH privadas.

---

## 11. Supuestos y decisiones abiertas

- Se asume que el **sobremesa** puede permitir la operación de 2 VMs (9 GB) simultáneas con Wazuh
  activo; si va justo, se aplica la mitigación de RAM (§7).
- **Decisión abierta [HUMANO]:** parche exacto de Wazuh (G1) y fuente externa de RS4 (G2).
- **Decisión abierta [HUMANO]:** ¿se elimina el adaptador NAT tras las instalaciones o se
  mantiene desconectado? (Recomendación: mantener desconectado, §3.6).

---

## 12. Erratas detectadas durante la ejecución (2026-09-23)

> Se conserva el texto aprobado tal cual; estas notas lo corrigen **sin alterar el diseño**.

1. **`wazuh-execd` (§3.4, §5, §6.3, §8, §9):** el plan asume que es una **unidad systemd** que se puede
   `stop`/`disable`. En Wazuh 4.14.7 **no existe como unidad**: es un **daemon interno** del manager,
   arrancado por `wazuh-control` dentro de `wazuh-manager.service` (`Type=forking`), y **vuelve a
   arrancar en cada reinicio del manager**. La garantía real de detección-only es que **no exista
   ningún `<active-response>`** (ni en `ossec.conf` ni en los ficheros de reglas); el proceso parado es
   evidencia adicional, **no** la garantía. Ver `deteccion_only.md` §1.2 y `rulesets_diseno.md` §5/§5.1
   (checklist post-reinicio).
2. **`<active-response>` del agente (§3.4):** el `ossec.conf` de fábrica del agente **sí trae** un bloque
   `<active-response>` con `<disabled>no</disabled>`; se pasó a `<disabled>yes</disabled>`.
3. **Algoritmo de clasificación de RuleSets (§3.5):** el criterio **por rango numérico** era imposible:
   el ruleset default tiene `rule.id` **> 100000** (fireeye 150100+, sysmon 184665+, unbound 500000+).
   Se clasifica **por fichero de origen** (lo que preserva el principio del plan). Ver `rulesets_diseno.md`
   §1/§4, **enmendados**.
4. **Disco de `wazuh-server` (§3.2, §7):** el LV raíz tenía 24 GB (16 GB libres, por debajo del mínimo de
   20 GB del plan) → se amplió a **48 GB** sobre el mismo disco de 50 GB, sin pérdida. Desviación fuera del
   encargo, **aceptada** y documentada en `runbook_instalacion_wazuh.md`.
5. **Regla *smoke* `100000` (§3.5, tarea 2.8):** se retiró **antes del baseline** (2026-09-23) porque, al ser
   **hija de `5710`**, **enmascaraba** la detección de RS1 y habría sesgado el catálogo de ruido normal.
   RS3 queda **definida y vacía** en Fase 2 (se puebla en Fase 3). Ver `rulesets_diseno.md` §9 (norma
   anti-enmascaramiento, aprobada por el humano el 2026-09-23).

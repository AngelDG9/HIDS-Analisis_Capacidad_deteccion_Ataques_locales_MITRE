# state.md — Estado vivo del proyecto

> Memoria externa del `tfg-orchestrator`. Al retomar el TFG, lo primero que se lee es este
> fichero. Se actualiza en cada transición (no se reescribe la historia: se edita el estado).

---

## Estado actual

- **Fase:** 2 — Laboratorio Wazuh (F-02), plan **v2 aprobado**. Tareas **2.3 a 2.8 hechas** y **verificadas (PASA)**.
- **Paso:** Wazuh 4.14.7 en `wazuh-server` + agente `victima-linux`; **modo detección-only** verificado; **4 capas (RS1..RS4)** activas y clasificables (`active_ruleset.txt`, sin colisiones; **RS4 vacía** por decisión G2).
- **Siguiente acción:** **2.9** (desconectar el NAT de forma persistente + snapshot `lab-listo`) → **2.10** (baseline ~4 h) → **2.11/2.12** (cierre de fase + hito H2).
- **G1/G2 fijados:** **Wazuh 4.14.7** (heap del indexer 1 GB); RuleSets aprobados con **RS4 vacía** (en Fase 3 se probarán reglas externas **curadas** contra los ataques del corpus, con el snapshot como red de seguridad).
- **Desviaciones registradas:** resize del LV de `wazuh-server` (24→48 GB, fuera del encargo, sano → aceptada); el plan asumía mal que el agente no traía `<active-response>` de fábrica y que `wazuh-execd` era una unidad systemd; **el algoritmo de clasificación del diseño §4 era imposible** (el ruleset default tiene `rule.id` > 100000: fireeye 150100+, sysmon 184665+, unbound 500000+) → reclasificado **por fichero de origen**, lo que **preserva el principio** del diseño. **Pendiente enmendar §1/§4** de `rulesets_diseno.md` (documento aprobado en G2).
- **⚠️ Riesgo metodológico ALTO para Fase 3:** en Wazuh una regla **hija** (`<if_sid>`) **sustituye** a la padre (un login fallido con la regla `100000` ya no genera `5710`). Si escribimos reglas propias hijas de reglas base, **taparemos detecciones de RS1** y falsearemos el recuento. **Hay que fijar la convención antes** de escribir reglas de ataque.
- **⚠️ Reloj:** las VMs marcan **2026-09-22** y hoy es **2026-09-23** → **verificar hora/zona/NTP antes del baseline** (las ventanas `t0`/`t1` dependen de ello).
- **⚠️ Regla de oro:** el **NAT sigue conectado** → se desconecta en **2.9**, antes del snapshot y del baseline.
- **⚠️ Sin commitear** desde 2.6: `state.md`, `Soporte/Laboratorio/README.md` y los artefactos de 2.7/2.8.
- **Reconocimiento (2026-09-22, sesión 5):** repo en el sobremesa limpio (`git status` sin cambios); `vmrun` en `C:\Program Files\VMware\VMware Workstation\vmrun.exe` (⚠️ el plan cita la ruta `(x86)`: corregir en los docs); **0 VMs en marcha**; `Soporte/Wazuh/{Configuracion,Reglas,Scripts}` y `Dataset/Legitimo/` **vacíos** (Fase 2 sin ejecutar).
- **Pendiente de Fase 1:** presentar el **hito H1** al tutor.
- **Decisiones humanas fijadas (2026-09-19):**
  - Interpretación **amplia** del filtro inverso (DC de red no elegibles pero no anulan host; T1039).
  - **T1046 = híbrida/válida** (ratificada; caso red pura → T1595).
  - **STIX en gitignore** + commit de URL/`.sha256` (repo ligero).
  - `Hojas/Mapeos.xlsx` **diferido** a Fase 3/5.
  - **Corpus = 13 técnicas** (7 Impact / 3 Exfiltration / 3 Collection).

## Fase 0 — CERRADA ✔

- Commit local: `865ee17 Fase 0: arquitectura de agentes del TFG y planificacion slim`.
- Arquitectura de agentes y roadmap slim revisados por el humano. Sin push.

## Fase 1 — Corpus MITRE — CERRADA ✔

- Entregables: `_artefactos/mitre/enterprise-attack-v19.1.json` (+ `.sha256`),
  `_artefactos/scripts/extraer_tecnicas_host.py` + tests, `Hojas/corpus_host.csv`
  (697 técnicas; **625 host-eligible**), `Hojas/lista_tecnicas_validas.md`,
  `Hojas/ATA_index.csv` (**13 técnicas**).
- Verificación `tfg-tester`: **PASA** (15 tests, reproducibilidad byte a byte). Detalle en `change-doc-fase1.md`.
- **Commit local:** `cfeaa3a Fase 1: corpus MITRE v19.1 (filtro inverso host) y 13 tecnicas seleccionadas`.
- Pendiente: **hito H1** al tutor (el `push` lo hace el humano).

## Fase 2 — Laboratorio Wazuh (en preparación)

- **Hipervisor:** VMware Workstation **Pro 26H1** en el sobremesa (Windows 10, 16 GB, VMs en `D:\TFG-VMs`).
- **Red host-only:** `VMnet1` = `192.168.65.0/24` (las VMs se ven entre sí y con el host).
- **VMs** (Ubuntu Server **24.04.5 LTS**, usuario `angel`, snapshot `base-limpia`):

  | VM | IP | vCPU | RAM | Disco |
  |---|---|---|---|---|
  | `wazuh-server` | `192.168.65.128` | 2 | 6 GB | 50 GB |
  | `victima-linux` | `192.168.65.129` | 2 | 3 GB | 20 GB |

- **Documentación T-04:** `Soporte/Laboratorio/README.md` + `topologia.png` + `topologia.mmd` ✔
- **Verificado:** ping cruzado entre VMs OK; snapshots `base-limpia` hechos.
- **Acceso:** portátil → sobremesa por **SSH sobre Tailscale** (`100.82.127.119`, usuario `angel`); los **agentes (opencode) corren en el sobremesa**. OpenSSH Server en Windows 10 habilitado ✔
- **Pendiente:** clonar el repo en el sobremesa (`C:\TFG\...`).
- ⚠️ **Sin internet todavía** (host-only): añadir adaptador **NAT** para instalar Wazuh.

## Tareas transversales pendientes

- [ ] (Más adelante) Redactar la **declaración de uso de IA** para la memoria (ver `Soporte/Normativa_IA.md`).

## Cortes / incidencias

- (ninguno)

## Historial de sesiones

- **Sesión 1:** diseño del planteamiento y ejecución de la Fase 0 (docs slim + agentes).
- **Sesión 2:** revisión de la Fase 0 + limpieza (nombres y restos heredados) + investigación de
  las políticas de IA de la ETSI/US.
- **Sesión 3:** Fase 1 completa — STIX v19.1, script de filtro inverso + tests, corpus (697 →
  625 host-eligible) y **selección humana de 13 técnicas**; verificación PASA y cierre.
- **Sesión 4:** montaje del laboratorio (2 VMs Ubuntu + snapshots) y **acceso remoto**
  (Tailscale + OpenSSH en Windows 10); decisión de que los **agentes corran en el sobremesa**;
  `plan.md` de Fase 2 → **v2** (pendiente de aprobación).
- **Sesión 5:** retomada **en el sobremesa (Windows 10)**: plan v2 **aprobado** (commit `afeb1d6`),
  repo **clonado y limpio**, recon del laboratorio (`vmrun` localizado, VMs apagadas). Siguiente:
  tarea **2.3** (versión Wazuh + NAT temporal + IPs fijas).
- **Sesión 6:** permisos de los agentes pasados a **V2** (allow por defecto + lista negra concreta;
  el campo heredado `temperature` los invalidaba en silencio). **Tarea 2.3** hecha (NAT + IPs
  fijas + internet verificado). **T-05 (2.4/2.5)** hecha: **Wazuh 4.14.7** all-in-one y agente
  `victima-linux` **active**, con smoke test `rule.id 5710` OK. **Verificación del tester: PASA**
  (con matices: resize del LV fuera de encargo, `unattended-upgrades` sin decidir, basura `NUL`).
  G1 fijado: 4.14.7 + heap del indexer a 1 GB.

# state.md — Estado vivo del proyecto

> Memoria externa del `tfg-orchestrator`. Al retomar el TFG, lo primero que se lee es este
> fichero. Se actualiza en cada transición (no se reescribe la historia: se edita el estado).

---

## Estado actual

- **Fase:** 2 — Laboratorio Wazuh (F-02), plan **v2 aprobado**. Tareas **2.3, 2.4 y 2.5 hechas** y **verificadas (PASA)**.
- **Paso:** **Wazuh 4.14.7** desplegado en `wazuh-server` (manager + indexer + dashboard **active**) y agente **`victima-linux` active** (ID 001) enviando telemetría. Red del laboratorio lista (**NAT temporal** + **IPs fijas** `192.168.65.128/129`).
- **Siguiente acción:** **2.6** (detección-only) → **2.7** (diseño de los 4 RuleSets RS1..RS4 → **gate G2: decisión humana**) → 2.8 (activar RuleSets) → 2.9 (snapshot `lab-listo`) → 2.10 (baseline ~4 h) → 2.11/2.12 (cierre).
- **G1 fijado (2026-09-22):** **Wazuh 4.14.7**, `wazuh-server` con 6 GB y **heap del indexer a 1 GB**.
- **⚠️ Decisiones humanas pendientes:** (a) `unattended-upgrades` (deshabilitar o no); (b) aceptar la **desviación del resize del LV** de `wazuh-server` (16→48 GB, fuera del encargo, técnicamente sano); (c) limpiar el fichero basura `NUL` y commitear el lote de T-05.
- **⚠️ Regla de oro pendiente:** el **NAT está conectado** en ambas VMs → hay que **desconectarlo antes** del baseline (2.10) y de los ataques (Fase 3).
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

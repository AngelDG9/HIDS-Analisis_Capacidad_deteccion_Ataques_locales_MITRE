# state.md — Estado vivo del proyecto

> Memoria externa del `tfg-orchestrator`. Al retomar el TFG, lo primero que se lee es este
> fichero. Se actualiza en cada transición (no se reescribe la historia: se edita el estado).

---

## Estado actual

- **Fase:** 2 — Laboratorio Wazuh (F-02), plan **v2 aprobado**. Tareas **2.3 a 2.9 hechas** y **verificadas**; **2.10 con las 2 ventanas lanzadas**.
- **Paso:** **🔴 VENTANA 2 DEL BASELINE CORRIENDO** en `victima-linux` (PID 3108, `setsid nohup`). **`t0 = 2026-09-23T12:00:01Z`** (14:00 CEST) · 240 min → **`t1` previsto `2026-09-23T16:00:01Z`** (18:00 CEST). Scan FIM forzado a `12:01:05Z`. Víctima revertida a `lab-listo` y script con **sha256 idéntico** al de la v1 (homogeneidad ✔). Primeros 10 min: pico 572 al arrancar y luego **~12/min en reposo** — **perfil idéntico a la v1**; disco 25 GB libres.
- **Ventana 1 (cerrada, extraída y verificada — PASA):** `00:45:00Z`→`04:45:00Z`; **6.837 alertas, 12 `rule.id`, 0 UNKNOWN** · RS1=46 (5 reglas) · RS2=6.791 (7) · RS3/RS4=0. **El 54% del ruido es auto-ruido del HIDS** (`80791` = `wazuh-agentd` reescribiendo su estado cada ~5 s, 88,9%; `80792` incluye hijos de `wazuh-syscheckd`). El mantenimiento diario (~04:25Z) **no tiene firma propia**.
- **Siguiente acción (tras las 18:00):** 1) confirmar `END` en `/home/angel/lab-legit/baseline_log.txt`; 2) **extraer la ventana 2** (`extraer_alertas.py --desde 2026-09-23T12:00:01Z --hasta <t1>`); 3) **comparar** v1 vs v2 (estabilidad del ruido: ¿mismos `rule.id`? ¿ritmos parecidos?); 4) agregar el catálogo final y **cerrar la fase** (2.11/2.12 + hito **H2**).
- **✅ Corregido:** la atribución errónea del 2º foco de auto-ruido en `baseline_meta.md` §10.4 (es `wazuh-syscheckd`, no `wazuh-agentd`).
- **Decisión humana (2026-09-23):** baseline en **DOS ventanas de 4 h en horas distintas** (noche + tarde) para cubrir mejor el ciclo diario y poder medir la **estabilidad del ruido**. La 1ª incluye el mantenimiento diario (~06:25); la 2ª no.
- **G1/G2 fijados:** **Wazuh 4.14.7** (heap del indexer 1 GB); RuleSets aprobados con **RS4 vacía** (en Fase 3 se probarán reglas externas **curadas**, con `lab-listo` como red de seguridad).
- **Desviaciones y erratas registradas:** ver `plan.md` **§12** — resize del LV (24→48 GB, **aceptada**); el agente **sí** traía `<active-response>` de fábrica; **`wazuh-execd` no es unidad systemd** (daemon interno; vuelve en cada reinicio del manager, pero es **inerte**); el algoritmo de clasificación por rango era imposible → **por fichero de origen**; la regla *smoke* `100000` **retirada antes del baseline** por enmascarar RS1.
- **Verificado antes de la ventana 1:** el *vulnerability-detector* del manager **no puede descargar CVE** (sin NAT) pero **solo produce errores de log, 0 alertas** → se deja intacto y documentado (no contamina el catálogo).
- **⚠️ Norma anti-enmascaramiento (aprobada 2026-09-23, `rulesets_diseno.md` §9):** Wazuh emite **una alerta por evento**; una regla propia que case el mismo evento (**hija o hermana**) **suprime** la detección base. Prohibido `<if_sid>` sobre base que se quiera conservar; verificación obligatoria con `wazuh-logtest -v`; recuento `RS1∩RS3` declarado; aplica también a RS4 y cadenas multinivel.
- **🔴 PENDIENTE OBLIGATORIO antes de escribir la primera regla de Fase 3:** construir el **pre-flight** del §9.8 (script que detecta si una regla RS3 con `<if_sid>` cuelga de una base RS1 y **falla** salvo solapamiento declarado). Hoy es **solo un compromiso escrito**: el script **no existe**. Y, si se quiere certeza, **comprobar empíricamente el caso "regla hermana"** (hoy solo está razonado, no demostrado en el laboratorio).
- **⚠️ Timestamps de Wazuh en UTC** (`+0000`) aunque las VMs estén en Madrid → las ventanas `t0`/`t1` y `extraer_alertas.py` deben trabajar en **UTC**.
- **⚠️ Detalle del snapshot:** `lab-listo` se tomó **antes** de alinear `/etc/timezone` (la zona efectiva ya era correcta) → ese fichero legacy dice `Etc/UTC` dentro del snapshot; **sin efecto práctico**.
- **⚠️ EL REPOSITORIO ES PÚBLICO** (confirmado por el humano el 2026-09-23): extremar la **higiene de secretos**. Auditoría del **historial completo** (2026-09-23): la contraseña del laboratorio, claves privadas y ficheros de credenciales **nunca** se han versionado ✔. Aun así: **jamás** escribir secretos en ficheros del repo.
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
- **Sesión 7:** **T-07 completo (2.6/2.7/2.8)** y **2.9**. Modo **detección-only** verificado y
  **actualizaciones automáticas desactivadas**. Gate **G2 aprobado** (RuleSets RS1..RS4; **RS4 vacía**,
  a probar en Fase 3 con reglas externas curadas). `active_ruleset.txt` **sin colisiones**.
  **NAT desconectado** de forma persistente, relojes alineados y **snapshot `lab-listo`** en ambas VMs.
  Hallazgos importantes: el agente **sí** traía `<active-response>` de fábrica; `wazuh-execd` **no** es
  unidad systemd; el algoritmo de clasificación por rango era **imposible** → **por fichero de origen**;
  y **la regla *smoke* `100000` enmascaraba `5710`** → **retirada antes del baseline** y norma
  **anti-enmascaramiento** escrita (`rulesets_diseno.md` §9). Erratas registradas en `plan.md` §12.

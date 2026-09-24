# change-doc — Fase 2: Laboratorio Wazuh (F-02)

> Cierre de fase. Fecha: **2026-09-23**. Estado: **CERRADA** (verificación del `tfg-tester`:
> **PASA con matices**, resueltos).
> Plan de referencia: `plan.md` (v2, `status: approved_by_human`). Erratas de ejecución: **`plan.md` §12**.

---

## 1. Qué se ha hecho

Dejar un **laboratorio Wazuh reproducible** que recibe telemetría de una víctima Linux, opera en
**modo detección-only** con **4 RuleSets clasificables por origen**, tiene grabado un **baseline de
actividad legítima** y es controlable en remoto. Es el **hito H2** del roadmap.

| Tarea | Resultado |
|---|---|
| **2.1 — T-04** Topología + VMs | ✔ (hecha por el humano con anterioridad; registrada) |
| **2.2 — T-08 (acceso)** SSH portátil→sobremesa sobre Tailscale + OpenSSH | ✔ (hecho por el humano) |
| **2.3** Repo en el sobremesa + versión Wazuh + NAT temporal + IPs estáticas | ✔ `version_wazuh.txt`, `red_lab.md`; IPs fijas `.128`/`.129`, internet verificado |
| **2.4 — T-05** Wazuh all-in-one en `wazuh-server` | ✔ **4.14.7-1** (manager + indexer + dashboard + filebeat `active`); heap del indexer a 1 GB |
| **2.5 — T-05** Agente en `victima-linux` | ✔ agente **001 `active`** → `192.168.65.128:1514`; telemetría confirmada |
| **2.6 — T-07** Detección-only + actualizaciones automáticas off | ✔ `0` `<active-response>`; `wazuh-execd` inerte; `unattended-upgrades`/timers `disabled` |
| **2.7 — T-07 [HUMANO]** Diseño de los 4 RuleSets (**gate G2**) | ✔ `rulesets_diseno.md` aprobado |
| **2.8 — T-07** Activación de RS1..RS4 + manifiesto | ✔ `auditd` (RS2) operativo, reglas propias (RS3) y `active_ruleset.txt` **sin colisiones** |
| **2.9** Relojes + **NAT desconectado persistente** + snapshot `lab-listo` | ✔ `ethernet1.startConnected="FALSE"`; snapshot en ambas VMs |
| **2.10 — T-06** Baseline legítimo | ✔ **2 ventanas × 4 h**; catálogo agregado |
| **2.11 — T-08 (cierre)** Documentar acceso y `vmrun` | ✔ `ssh_setup.md` + `vmrun_config.md` |
| **2.12** Verificación, cierre y documentación | ✔ `tfg-tester` **PASA**; este documento |

---

## 2. Entregables (ficheros)

| Fichero | Estado |
|---|---|
| `Soporte/Wazuh/Configuracion/version_wazuh.txt` | creado (4.14.7-1) |
| `Soporte/Wazuh/Configuracion/runbook_instalacion_wazuh.md` | creado |
| `Soporte/Wazuh/Configuracion/runbook_agente_linux.md` | creado |
| `Soporte/Wazuh/Configuracion/deteccion_only.md` | creado (R-06) |
| `Soporte/Wazuh/Configuracion/rulesets_diseno.md` | creado y **aprobado** (G2) + §9 norma anti-enmascaramiento |
| `Soporte/Wazuh/Configuracion/rulesets_activacion.md` | creado |
| `Soporte/Wazuh/Configuracion/active_ruleset.txt` | creado (sin colisiones) |
| `Soporte/Wazuh/Configuracion/red_lab.md` | creado (NAT + IPs fijas) |
| `Soporte/Wazuh/Reglas/` | `auditd_tfg.rules`, `local_rules.xml` (esqueleto **no desplegable**), `external_reserved.xml` |
| `Soporte/Wazuh/Scripts/` | `generar_active_ruleset.sh`, `deploy_rs2_auditd.sh`, `deploy_rs3_rs4.sh`, `baseline_actividad.sh` |
| `Soporte/Laboratorio/ssh_setup.md`, `vmrun_config.md` | creados (2.11) |
| `Soporte/Laboratorio/README.md` | actualizado (red, snapshots, reloj) |
| `Dataset/Legitimo/ruleids_legitimos.csv` | **entregable R-08** (catálogo agregado) |
| `Dataset/Legitimo/ruleids_legitimos_v{1,2}.csv` + `baseline_log_ventana{1,2}.txt` | evidencia por ventana |
| `Dataset/Legitimo/baseline_meta.md` | ficha del baseline (completa) |
| `_artefactos/scripts/extraer_alertas.py` | reutilizable en Fase 3 |
| `.gitignore` | patrones de secretos §3.10 |
| `plan.md` / `state.md` / `roadmap.md` | actualizados |

---

## 3. Resultados

### 3.1 Laboratorio

- **Wazuh 4.14.7-1** all-in-one en `wazuh-server` (192.168.65.128); agente **001 `victima-linux`**
  (192.168.65.129) `active`. Detección-only verificado. Red **host-only** operativa y **NAT
  desconectado**.
- **4 capas**: RS1 (ruleset default, 167 ficheros / 4.471 `rule.id`) · RS2 (auditd, 44) ·
  **RS3 vacía** y **RS4 vacía** en Fase 2 (decisiones: la *smoke* `100000` se retiró por
  enmascarar RS1; RS4 vacía por decisión G2 opción A). **Sin colisiones.**

### 3.2 Baseline (R-08)

| | Ventana 1 (noche) | Ventana 2 (tarde) |
|---|---|---|
| Ventana (UTC) | `00:45:00Z` → `04:45:00Z` | `12:00:01Z` → `16:00:01Z` |
| Alertas | **6.837** | **6.737** |
| `rule.id` distintos | **12** | **12** (los mismos) |
| Reparto | RS1=46 (5) · RS2=6.791 (7) | RS1=35 (5) · RS2=6.702 (7) |
| Sin clasificar | **0** | **0** |
| Ciclos del script | 48 (sin fallos) | 48 (sin fallos) |

- **Catálogo agregado: 12 `rule.id`, 13.574 alertas.**
- **El ruido es ESTABLE**: mismos tipos, ritmo de régimen ≈24–25/min en ambas, y la alerta
  dominante da 3.239 vs 3.242 (Δ=2).
- **Hallazgo principal: ~54 % del ruido es auto-ruido del propio HIDS** — `80791` de
  **`wazuh-agentd`** reescribiendo su fichero de estado cada ~5 s (≈2.877/ventana) y `80792` de
  hijos de **`wazuh-syscheckd`** y **`wazuh-logcollector`** (cwd `/var/ossec`, ≈806). Es la cifra
  válida como base de filtrado de FP (el **88,6 %** es solo la *cuota* de esas dos reglas).
- El **mantenimiento diario** (~04:25Z) **no tiene firma propia** (69 alertas vs 67 de un ciclo
  normal, sin `rule.id` nuevos).

---

## 4. Decisiones humanas

| # | Fecha | Decisión |
|---|---|---|
| **G1** | 2026-09-22 | **Wazuh 4.14.7**; `wazuh-server` con 6 GB y **heap del indexer a 1 GB** |
| **G2** | 2026-09-23 | **RuleSets**: RS4 = **vacía** (opción A). En Fase 3 se probará un conjunto **curado** de reglas externas contra las técnicas del corpus, con `lab-listo` como red de seguridad |
| — | 2026-09-23 | **Deshabilitar actualizaciones automáticas** en ambas VMs (reproducibilidad) |
| — | 2026-09-23 | **Retirar la regla *smoke* `100000`** antes del baseline (enmascaraba RS1) |
| — | 2026-09-23 | **Baseline en 2 ventanas de 4 h** en horas distintas (noche + tarde) para medir la **estabilidad del ruido** |
| — | 2026-09-23 | Aceptar la **desviación del resize del LV** de `wazuh-server` (24→48 GB, sano, documentado) |

---

## 5. Verificación (`tfg-tester`)

**Veredicto final: PASA con matices** (matices resueltos antes de cerrar). Se verificó de forma
independiente, entre otras cosas: Wazuh 4.14.7 y servicios `active`; agente `active` y telemetría
extremo a extremo; `0` `<active-response>` y naturaleza real de `wazuh-execd`; `active_ruleset.txt`
sin colisiones; **recuento del baseline recomputado al dígito** (6.837 / 6.737 / 0 UNKNOWN);
atribución del auto-ruido con `audit.exe`/`cwd`; snapshots; `_recursos/` intacto; y **auditoría del
historial de git sin secretos** (la contraseña del laboratorio, claves privadas y ficheros de
credenciales **nunca** se versionaron).

---

## 6. Erratas y desviaciones (resumen)

Registradas en detalle en **`plan.md` §12**:

1. **`wazuh-execd` no es una unidad systemd** (daemon interno del manager; vuelve a arrancar en cada
   reinicio, pero es **inerte**). La garantía de detección-only es **0 `<active-response>`**.
2. **El agente sí traía `<active-response>` de fábrica** (`<disabled>no</disabled>`) → se pasó a `yes`.
3. **El algoritmo de clasificación por rango numérico era imposible** (el ruleset default tiene
   `rule.id` > 100.000) → clasificación **por fichero de origen**, que preserva el principio.
4. **El plan no preveía ampliar el disco**: el LV raíz tenía 24 GB → 48 GB sobre el mismo disco de
   50 GB. Desviación aceptada y documentada.
5. **La regla *smoke* `100000` enmascaraba `5710`** → retirada, y se escribió la **norma
   anti-enmascaramiento** (`rulesets_diseno.md` §9) antes de escribir reglas de Fase 3.

---

## 7. Deudas y siguientes pasos

- **🔴 Pre-flight anti-enmascaramiento** (§9.8 de `rulesets_diseno.md`): **solo está escrito, el
  script no existe**. **Obligatorio antes de escribir la primera regla RS3 de Fase 3.**
- **Autenticación por clave en el nivel 1** (portátil→sobremesa): hoy funciona **por contraseña**;
  `administrators_authorized_keys` no existe. Decidir si se habilita por clave o se declara así.
- **Hito H1** (Fase 1) **sigue pendiente** de presentar al tutor.
- **Hito H2**: preparar y presentar (laboratorio + baseline).
- **Fase 3 — Ataques y detección**: empezar con el piloto (2-3 técnicas R/E/S).
- **`push`**: los commits son locales; publicar es tarea del humano.

---

## 8. Riesgos abiertos

| Riesgo | Nota |
|---|---|
| **Enmascaramiento RS1 por reglas propias** | Norma escrita (§9) y *smoke* retirada; **falta la herramienta** de comprobación |
| **Auto-ruido del HIDS (~54 %)** | Catalogado; el filtro de FP de Fase 3 debe descontarlo por `rule.id` |
| **Baseline sintético** | Declarado: servidor sin usuario humano; 2×4 h; el catálogo es un **superconjunto** del ruido esperable en un ataque |
| **`vulnerability-detector` sin internet** | Solo produce errores de log (**0 alertas**) → no contamina; documentado |
| **Revertir `wazuh-server` por error** | Nunca debe revertirse (perdería las alertas acumuladas); documentado en `vmrun_config.md` |
| **Disco del manager** | 25 GB libres (48 GB, 46 %); vigilar al acumular alertas de Fase 3 |

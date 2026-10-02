---
bloque: fase-02b-diseno
tarea: T-W1
nombre: Estudio Windows 10 vs Windows 11 (con evidencias)
version: 1
status: propuesta (la decisión final es del humano)
fecha: 2026-10-02
autor: tfg-executor
---

# Estudio Windows 10 vs Windows 11 — víctima Windows del laboratorio

> **Tarea T-W1 del bloque `fase-02b-diseno`.** Documento de **estudio** (no se ha
> instalado ni descargado nada). Por cada criterio: **dato → fuente/cita → consecuencia
> para el laboratorio**. Cierra con una **tabla comparativa** y una **recomendación
> razonada**. **La decisión final la toma el humano** tras leer este estudio (es la
> única cuestión abierta del bloque, `plan.md` D2).
>
> **Dato de partida:** la fecha de evaluación es **2026-10-02**. Todos los hechos
> externos se citan con su fuente; lo que no se ha podido verificar se marca
> **«a confirmar»** (no se inventa).

---

## C1 — Vigencia / fin de soporte (EOL)

**Datos:**

| S.O. | Estado a 2026-10-02 | Fecha EOL | Fuente |
|---|---|---|---|
| **Windows 10 Home/Pro 22H2** | **Fuera de soporte** | **2025-10-14** | Microsoft Learn, *Windows 10 – release information*: "On October 14, 2025, Windows 10 reached end of support"; *Windows 10 Home and Pro – Microsoft Lifecycle*: "reached end of support on October 14, 2025" (`learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro`). |
| **Windows 10 ESU (consumidor)** | Pago / con condiciones | **2026-10-12 o 2027** ⚠️ **a confirmar** | Microsoft: las ESU de consumo se anunciaron inicialmente hasta **2026-10-13** y hubo una ampliación posterior; Microsoft Learn (*end-of-support*) cita **2027-10-12** para consumidor y hasta **2028-10-10** para empresas. **Las tres cifras aparecen en fuentes oficiales y no son concluyentes → «a confirmar»**. |
| **Windows 11 24H2** | Soportado (hasta 2026-10-14 en Home/Pro) | **2026-10-14** | Microsoft Learn, *Windows 11 Home and Pro – Microsoft Lifecycle*: Version 24H2 (start 2024-10-01, end **2026-10-14**). |
| **Windows 11 25H2** | Soportado | **2027-10-13** (Home/Pro) | Microsoft Learn, *Windows 11 Home and Pro – Microsoft Lifecycle*: Version 25H2 (start 2025-09-30, end **2027-10-13**). |

> ⚠️ **Windows 11 26H1** aparece citado en el plan y en fuentes secundarias; Microsoft
> Learn publica la versión 26H1 con **fechas de soporte aún no fijadas de forma
> concluyente** → **«a confirmar»**. Para el laboratorio, la candidata de W11 es **25H2**.

**Consecuencia para el laboratorio:**

- **Elegir W10 obliga a declarar la EOL (2025-10-14)** como **limitación acotada**: la VM
  es **aislada**, **sin NAT**, **sin datos reales** y con Defender/documentación ya
  previstos; la EOL no afecta a la medición del HIDS, pero **debe constar** en el README
  y en la memoria.
- **Elegir W11 25H2 evita la objeción de vigencia** durante la vida del TFG (soporte hasta
  **2027-10-13**), a cambio de las limitaciones de C2/C4/C5.

---

## C2 — Compatibilidad con Sysmon y con el agente Wazuh 4.14.7

**Datos:**

- **Agente Wazuh (versión real del laboratorio: 4.14.7-1)**, `Soporte/Wazuh/Configuracion/version_wazuh.txt:4-12`.
  La documentación de Wazuh indica: *"You can deploy the Wazuh agent on Windows systems
  ranging from Windows XP to the latest versions, **including Windows 11** and Windows
  Server 2022"* (`documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html`).
  → **El agente 4.14.x corre en W10 y en W11**; no hay incompatibilidad de versión.
- **Sysmon *standalone* (Sysinternals)**: corre en **Windows 10+**; no depende de la
  versión de W11. Documento oficial: `learn.microsoft.com/.../sysmon/overview`.
- **Sysmon *integrado* (built-in)**: **característica opcional de Windows 11** (no de
  Windows 10). Microsoft Learn (*Sysmon Overview*, actualizado **2026-02-24**):
  *"Built-in Sysmon is an optional Windows feature on Windows 11 and Windows Server 2025"*
  y *"Coexistence between built-in Sysmon and standalone Sysmon isn't supported"* /
  *"Standalone Sysmon must be uninstalled before enabling built-in Sysmon"*.
  El integrado apareció en builds Insider de **febrero de 2026** y en el Patch Tuesday de
  **marzo de 2026** (Build 26200.8037) según fuentes secundarias → **fecha exacta «a confirmar»**,
  pero la **incompatibilidad con el standalone es oficial**.

**Consecuencia para el laboratorio:**

- En **ambos** SO se usará **Sysmon standalone** (D4), que es el que encaja con el flujo
  de pre-staging (`sysmonconfig.xml` fijada con `sha256`).
- En **W11** hay que **verificar explícitamente** que el nuevo canal integrado está
  deshabilitado antes de instalar el standalone (el integrado **viene deshabilitado por
  defecto**, pero Microsoft recomienda `Get-Service sysmon*` para comprobarlo). Es un
  **paso de checklist** del montaje (criterio C2), no un bloqueante.
- En **W10** el integrado **no existe** → cero riesgo de conflicto. Ventaja menor para W10.

---

## C3 — Ruido de fondo / impacto en la línea base

**Datos (razonamiento con base en el propio lab y en el SO):**

- El laboratorio Linux midió que **~54 % del ruido era auto-ruido del propio HIDS**
  (`state.md:68`); es decir, **la línea base es un artefacto a domesticar**. En Windows
  la telemetría nueva (Sysmon) es **mucho más voluminosa** y exige **config curada +
  baseline** (riesgo ya previsto en `roadmap.md:160`, D4).
- **Telemetría de Microsoft/Windows** (telemetría de diagnóstico, tareas programadas,
  Windows Update en segundo plano, Defender, Windows Search, etc.) genera **eventos de
  fondo** que no existen en el servidor Linux "sintético" del laboratorio. Un escritorio
  Windows **tiene más superficie de ruido** que un Ubuntu Server.
- **Windows 11 añade capa sobre Windows 10** (widgets, Copilot, más servicios de
  telemetría e IA, notificaciones) → **más ruido de base**, aunque la mayor parte es del
  **SO**, no del HIDS.
- **Las actualizaciones automáticas** se desactivan igual en ambos (paso §6.1 nº 6 del
  plan; precedente Linux `README.md:92-118`).

**Consecuencia para el laboratorio:**

- **En los dos SO el baseline Windows es obligatorio** (D6.4): `Dataset/Legitimo/windows/`,
  2 ventanas, y **demostrar `deteccion=0`** sobre él.
- **W10 22H2 tiende a menos ruido** que W11 (menos capas de servicios/telemetría), lo que
  **abarata el baseline**. `Sysmon` domina el volumen en ambos, así que la diferencia
  W10↔W11 en ruido es **moderada, no decisiva**.

---

## C4 — Cobertura de Atomic Red Team (ART) y dependencia de `wmic`

> **Forma de contar (reproducible, offline, sobre el clon local `Soporte/Ataques/atomic-red-team/`,
> pin `388942a…`).** Se cuenta una prueba por `(Technique #, Test GUID)` en
> `atomics/Indexes/Indexes-CSV/windows-index.csv`, **subtecnicas incluidas**. Se usan
> **GUID distintos** porque el índice trae **filas duplicadas exactas** (comprobado:
> `windows-index.csv` **1587 filas → 1253 distintas**, 334 duplicados; `linux-index.csv`
> 508 → 423; `index.csv` 2371 → 1878). Conteo por filas repetidas daría el mismo
> resultado a nivel "¿tiene o no tiene prueba?", pero infla el número de tests.
>
> **Titular matizado (para no inflar):** en la piscina P1, **38** técnicas cuentan con
> prueba ART Windows si se cuentan las **sub-técnicas**; **32** si se exige un test
> **propio de la técnica exacta**. Las **6** que solo aparecen vía sub-técnica son
> **T1056, T1074, T1114, T1491, T1557 y T1567**. Desglose: **36 híbridas** (30 exactas +
> 6 solo-subtécnica) y **2 Windows-only** (ambas exactas: T1114.001, T1557.001).

**Cifras verificadas (piscina P1, 89 técnicas):**

| Conjunto | Nº |
|---|---|
| P1 host-eligible | **89** |
| P1 ∧ Linux (híbridas) | **72** |
| · híbridas **con** ≥1 prueba ART Windows | **36** |
| · híbridas **sin** prueba ART Windows | **36** |
| P1 sin Linux (Windows-only / nube-red) | **17** |
| · Windows-only **con** prueba ART Windows | **2** (T1114.001, T1557.001) |
| No factibles (nube/SaaS/IaaS/red) | **12** (+ T1213.002, SaaS, según plan §4.2) |
| **P1 con prueba ART Windows** (contando sub-técnicas) | **38** |
| · de esas, **con test propio de la técnica exacta** | **32** |

**`wmic` (dependencia de versión):**

- Microsoft: **WMIC ya no está disponible como Feature on Demand (FoD) en Windows 11 24H2
  y superiores**; en **Windows 10 22H2** sigue presente (deprecado). Fuente:
  *Features and functionality removed in Windows client*
  (`learn.microsoft.com/en-us/windows/whats-new/removed-features`). ⚠️ La **fecha exacta
  de la marca de retirada** (que una fuente secundaria situaba en **agosto de 2026**) **no
  se ha podido verificar de forma concluyente desde este bloque → «a confirmar»**; **no se
  afirma**. Lo que sí está documentado y se usa aquí es la **asociación a Windows 11 24H2+**.
- **Inspección del clon** (grep `wmic` sobre los `.yaml` de las técnicas del inventario
  con prueba ART Windows): **2 técnicas** de la piscina P1 usan `wmic` en sus tests
  Windows: **T1119** (Automated Collection) y **T1490** (Inhibit System Recovery). En
  concreto, **T1490** (el candidato de piloto W1 del plan §5) usa `wmic shadowcopy delete`
  en varios de sus tests.
- ⚠️ **Matiz «a confirmar»:** el grep detecta la **presencia** de `wmic` en el test; no
  todos los tests de una técnica lo usan, y ART puede elegir el test. En W11, los tests de
  T1490 basados en `wmic` **fallarían** o requerirían adaptación; los basados en
  `vssadmin`/`wbadmin`/`diskshadow` **seguirían corriendo**.

**Consecuencia para el laboratorio:**

- **W10 22H2 = máxima fidelidad ART** (intersección ART Windows ≡ lo que corre tal cual).
- **W11 25H2** mantiene **36/36 híbridas con prueba ART** (mismo conteo global) pero
  **pierde los tests concretos que usan `wmic`**; el impacto exacto es **pequeño pero no
  nulo** y afecta a **T1119 y T1490** (hay que adaptar o elegir otro test). Para W11,
  además, `wmic` **ya no se puede recuperar como FoD** en 24H2+.
- **La retirada de `wmic` no cambia el conteo del índice ART** (el índice es agnóstico de
  versión): siguen **36/36 híbridas** y **38 (contando sub-técnicas) / 32 (test propio de
  la técnica)**. Lo que cambia en W11 es **qué tests concretos** de T1119/T1490 pueden
  correr tal cual; por eso **no se ajusta ninguna cifra de cobertura**, solo se declara la
  pérdida de tests.
- El **estudio no invalida la recomendación preliminar**: la pérdida ART de W11 es
  **pequeña y localizada (2 técnicas)**, no masiva.

---

## C5 — Coste de montaje (Defender, requisitos, esfuerzo)

**Datos:**

- **Defender**: hay que **desactivarlo** en ambos (D3: Tamper Protection → protección en
  tiempo real → nube/comportamiento). En W11 el **Tamper Protection** y las
  configuraciones de seguridad son **más estrictas** (mayor fricción para desactivar de
  forma persistente). En ambos se aplica el **checklist previo a cada ventana**
  (E4 `defender_off.md`).
- **Requisitos de W11**: **TPM 2.0 + Secure Boot + CPU soportada + 4 GB RAM + 64 GB
  disco** — la VM debe **simular TPM/Secure Boot** (VMware Workstation Pro 26H1 lo
  soporta, pero es **un paso extra** de configuración y una fuente de fricción).
  **W10 22H2 no exige TPM/Secure Boot** → montaje más simple.
- **Recursos del host**: **16 GB** (D5/`README.md:16`); la víctima Windows pide **4 GB**
  (plan §6.1) y **no debe encenderse a la vez** que `victima-linux` (`roadmap.md:162`).
  Esto **no cambia** entre W10 y W11.
- **ISO virgen** (D2): en ambos el coste de instalación desde cero + VMware Tools +
  políticas es el mismo. La disponibilidad de la ISO de **W10 22H2** sigue existiendo en
  canales oficiales, aunque Microsoft empuja a W11.

**Consecuencia para el laboratorio:**

- **W10 es algo más barato de montar** (sin TPM/Secure Boot, Defender más domable).
- **W11 exige un poco más de esfuerzo** (TPM/Secure Boot + verificar/desactivar Sysmon
  integrado + Tamper más duro), pero **no es bloqueante** con VMware Workstation Pro 26H1.

---

## Tabla comparativa

| Criterio | **Windows 10 Pro 22H2 x64** | **Windows 11 Pro 25H2 x64** |
|---|---|---|
| **C1 Vigencia/EOL** | **EOL 2025-10-14** → limitación a declarar (ESU consumer hasta 2026/2027, «a confirmar») | **Soportado hasta 2027-10-13** (Home/Pro) |
| **C2 Sysmon + Wazuh 4.14.7** | Ambos OK; **sin** riesgo de Sysmon integrado | Ambos OK; hay que **verificar** el Sysmon integrado (viene off; no coexiste con standalone) |
| **C3 Ruido de base** | **Menor** superficie de servicios/telemetría | Algo **más** de ruido (servicios/IA/telemetría); baseline más caro (dominado por Sysmon) |
| **C4 Cobertura ART** | **Máxima fidelidad**: `wmic` presente (deprecado) → tests corren tal cual | 36/36 híbridas con prueba (38/32 global); **pierde tests con `wmic`** (T1119, T1490) y `wmic` ya no es FoD en 24H2+ |
| **C5 Coste de montaje** | **Más simple** (sin TPM/Secure Boot; Defender más fácil) | **Más esfuerzo** (TPM/Secure Boot simulados; Defender/Tamper más duros) |

---

## Recomendación

**Recomendación: Windows 10 Pro 22H2 x64 (ISO virgen).**

**Razón:** es la opción que **maximiza la fidelidad de Atomic Red Team** (los tests Windows
se escriben mayoritariamente para W10 y **2 de las técnicas P1 dependen de `wmic`**, que en
W11 24H2+ ya no está), **minimiza el ruido de base** y **abarrata el montaje** (sin
TPM/Secure Boot, Defender más fácil de domar). Es coherente con la recomendación preliminar
del plan (§3.4).

**Coste / contrapartida (a declarar):** Windows 10 está **EOL desde 2025-10-14**. Se asume
como **limitación acotada del laboratorio**: entorno **aislado**, **sin NAT**, **sin datos
reales**, **sin defender activo** y **documentado**. La EOL **no afecta a lo que se mide**
(la capacidad de detección de Wazuh sobre ataques locales), pero **debe constar** en el
README del laboratorio, en la memoria y en la declaración de limitaciones.

**Alternativa si el tutor exige un SO vigente: Windows 11 Pro 25H2.**
Coste de la alternativa:
1. **Pérdida acotada de ART**: los tests que usan `wmic` (T1119, T1490) fallan o hay que
   adaptarlos; el resto de las **36 híbridas con prueba ART** siguen disponibles.
2. **Más ruido de base** → baseline algo más caro.
3. **Montaje más duro**: TPM/Secure Boot simulados + verificar/desactivar Sysmon integrado
   + Tamper Protection más estricto.

> **Nivel de confianza:** **alto** en C2/C5 (documentación oficial) y en C4 (cifras del
> clon local); **medio** en C3 (razonamiento, no medido); **a confirmar** en las fechas
> exactas de ESU de W10 y en el calendario de 26H1. Nada de esto **obliga** a una decisión:
> **la decisión final es del humano** (gate del bloque).

---

## Lo que queda por verificar en el montaje (T-W1 → construcción)

- **Confirmar que W10 22H2 22H2 x64 es la última revisión servida por Microsoft** y su
  `sha256` de ISO (ver `pasos_montaje.md`, material).
- **W11 (si se elige):** comprobar `Get-Service sysmon*` y desactivar el Sysmon integrado
  antes de instalar el standalone.
- **W10 (si se elige):** declarar la EOL en el README y en la memoria.
- **En ambos:** que Defender queda off de forma persistente (checklist E4).

---

## Referencias

- Microsoft Learn — *Windows 10 – release information* y *Windows 10 Home and Pro – Lifecycle*
  (EOL 2025-10-14; ESU).
- Microsoft Learn — *Windows 11 Home and Pro – Lifecycle* (24H2 → 2026-10-14; 25H2 → 2027-10-13).
- Microsoft Learn — *Features and functionality removed in Windows client* (WMIC, ya no
  disponible como FoD en Windows 11 **24H2+**; fecha exacta de la marca de retirada
  **«a confirmar»**, no se afirma).
- Microsoft Learn — *Sysmon Overview* / *sysmon* (built-in en Windows 11; no coexistencia
  con standalone).
- Wazuh — *Deploying Wazuh agents on Windows endpoints* (W10/W11/Server).
- Local — clon ART `Soporte/Ataques/atomic-red-team/` (pin `388942a…`),
  `atomics/Indexes/Indexes-CSV/windows-index.csv`; `Hojas/corpus_host.csv`;
  `Hojas/inventario_p1_windows.csv`; `Soporte/Wazuh/Configuracion/version_wazuh.txt`.

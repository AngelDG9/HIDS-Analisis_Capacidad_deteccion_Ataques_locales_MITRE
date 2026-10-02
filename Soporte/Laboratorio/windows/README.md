# Laboratorio Windows — decisiones y estructura (bloque `fase-02b-diseno`)

> **Bloque de DISEÑO/ESTUDIO.** Aquí **no se ha instalado, ni descargado, ni atacado
> nada**, y **no se ha tocado Linux**. Este documento fija las **decisiones D1–D7** del
> laboratorio Windows, la **estructura de fases B** y la **convención de carpetas por SO**,
> para que `fase-02b-construccion` y `fase-03b` **nazcan ordenados**.
>
> Fuente de decisión: `plan.md` del bloque (`fase-02b-diseno`, `status: approved_by_human`).
> Documentos hermanos: `estudio_w10_vs_w11.md` (T-W1), `telemetria_windows.md` (E3),
> `defender_off.md` (E4), `pasos_montaje.md` (E5).

---

## 1. Resumen de decisiones (D1–D7)

| # | Decisión | Estado |
|---|---|---|
| **D1** | Estructura de fases: **`fase-02b`** (laboratorio Windows) y **`fase-03b`** (ataques Windows) | **Recomendada** (se valida en el gate) |
| **D2** | **ISO virgen** (no la plantilla del profesor) | **Decidida por el humano** |
| **D2-W10/W11** | **Windows 10 vs Windows 11** | ⏳ **ABIERTA** — la decide el humano tras `estudio_w10_vs_w11.md` |
| **D3** | Windows Defender: **DESACTIVAR** (control ambiental declarado) | **Decidida por el humano** |
| **D4** | Telemetría: **Sysmon curado + Seguridad 4688 + PowerShell 4104 + Syscheck** | **Decidida por el humano** |
| **D5** | Agente **Wazuh 4.14.7** MSI, offline/pre-staging, IP `192.168.65.130` | **Recomendada** |
| **D6** | Recogida y filtro: **parametrizar por perfil de plataforma** (no bifurcar) | **Recomendada** |
| **D7** | RuleSets RS1..RS4 en Windows (RS2 vacía) | **Recomendada** |

---

## 2. D1 — Estructura de fases `fase-02b` / `fase-03b`

Se adoptan las fases **`fase-02b`** (laboratorio Windows) y **`fase-03b`** (ataques
Windows); cada bloque se archiva como `_fases/fase-02b-<nombre>/` / `_fases/fase-03b-<nombre>/`.
**Este bloque = `fase-02b-diseno`**.

- Bloques previstos: `fase-02b-diseno` (este) → **`fase-02b-construccion`** (VM + red +
  agente + telemetría + snapshots) → `fase-02b-baseline`; después **`fase-03b-*`** (tandas
  de ataques).
- Orden: **`fase-02b` antes de `fase-03b`** (no se ataca sin laboratorio y baseline Windows).
- Los `ATA<NNN>` **se continúan desde `ATA055`** (no se reinician); **la misma técnica en
  otro SO = otra fila / otro `ATA`**, comparable con Linux.

### 2.1 Qué se **comparte** con Linux vs qué es **específico de Windows**

> **Regla "un dueño por cosa, sin duplicar".** Cada documento metodológico tiene **un solo
> dueño**; Windows **amplía**, no crea un criterio paralelo.

| Elemento | Dueño | Cómo |
|---|---|---|
| Criterio ART / manual / pre-staging | `Soporte/Ataques/criterio_ataques.md` | **Ampliar §D** con la concreción Windows |
| Doble iteración | `Soporte/Ataques/criterio_doble_iteracion.md` | Reutilizar **sin cambios** |
| Métrica congelada (O1 SÍ/NO + `rule_id` + evidencia · O2 acciones `k/m`) | `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` / `state.md` | **No se toca** |
| Plantilla de señales esperadas | `Soporte/Ataques/plantilla_esperado.md` | Ampliar con la tabla de campos Windows y el `ATTACK_ROOT` Windows |
| RuleSets RS1..RS4 | `Soporte/Wazuh/Configuracion/rulesets_diseno.md` | Añadir **§Windows** (ver D7) |
| Anti-enmascaramiento (preflight) | `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` | Aplica igual a RS3/RS4 Windows |
| Mapa ART | `Hojas/cobertura_atomic.csv` | Reutilizar; añadir filas de los `ATA` Windows |
| **Baseline** | `Dataset/Legitimo/windows/` | **Nuevo** subárbol (no se toca el de Linux) |
| **Resultados de ataque** | `Dataset/Ataques/Resultados/Wazuh/windows/` | **Nuevo** subárbol |
| **Artefactos/comandos** | `Dataset/Ataques/Comandos/windows/<T>-<desc>/` | **Nuevo** subárbol |
| **Agente Wazuh** | `Soporte/Wazuh/Configuracion/runbook_agente_windows.md` | **Nuevo** (espejo del de Linux) |
| **Defender / telemetría / VM** | `Soporte/Laboratorio/windows/` | **Nuevo** (este directorio) |

> **Declaración:** cada documento ampliado llevará una nota *"aplica a Linux y Windows; en
> Windows …"* para que nadie crea que hay dos métodos distintos. Los directorios `windows/`
> se crean **cuando llegue el primer dato** (`fase-02b-construccion`); **KISS: no se dejan
> carpetas vacías**.

---

## 3. D2 — S.O.: **ISO virgen** (no plantilla) y elección W10/W11

### 3.1 ISO virgen — **decidido por el humano**

- **Motivo (rigor metodológico):** una VM con software preinstalado variado (la plantilla
  del profesor `Windows10-DIT-MV.7z`, `http://ait08.us.es/MVs/Alumnos/`, `context.md:150`)
  **ensucia la línea base**: introduce procesos, servicios y ruido ajenos al laboratorio y
  hace que los resultados **no sean plenamente atribuibles al HIDS**. Una **ISO virgen** da
  un **estado de partida conocido y reproducible**.
- **Constancia del descarte:** la plantilla del profesor **se evaluó y se descartó** por ese
  motivo; **no es una opción** de este laboratorio.
- **Consecuencia asumida:** el montaje sube de coste (instalación desde cero + VMware Tools
  + parches de instalación), pero se gana **atribuibilidad** y **reproducibilidad** (misma
  línea que el Linux: SO limpio + snapshot `base-limpia`).

### 3.2 W10 vs W11 — ⏳ **ABIERTA**

El **estudio `estudio_w10_vs_w11.md`** (T-W1) cubre los 5 criterios con evidencias.
**Resumen de su recomendación:** **Windows 10 Pro 22H2 x64** (máxima fidelidad ART,
`wmic` presente, menor ruido, menos montaje), **declarando la EOL (2025-10-14)** como
limitación acotada; **alternativa: Windows 11 Pro 25H2** (vigente, pero pierde los tests
con `wmic` de T1119/T1490, más ruido y montaje más duro). **La decisión final es del humano**
(gate del bloque).

> **Cobertura ART de la piscina P1 (titular matizado):** **38** técnicas cuentan con prueba
> ART Windows si se cuentan las **sub-técnicas** (**36** híbridas + **2** Windows-only);
> **32** si se exige un **test propio de la técnica exacta** (las **6** restantes —T1056,
> T1074, T1114, T1491, T1557, T1567— solo tienen prueba en alguna sub-técnica). No son "38
> técnicas con test propio de la técnica". Reproducible en
> `Hojas/inventario_p1_windows.csv` (`_artefactos/scripts/inventario_p1_windows.py`).

> **Factibilidad alineada con el plan (§4.2):** de las 17 P1 sin Linux, las **Windows-only
> factibles** son **T1114.001, T1185 y T1557.001**; **T1114.002** (Remote Email Collection)
> queda en **baja factibilidad** (servidor Exchange/nube) y **T1213.002** (Sharepoint) es
> **no factible** (SaaS), como las **12** de nube/SaaS/IaaS/red.

---

## 4. D3 — Windows Defender: **DESACTIVAR** (control ambiental declarado)

**Decidido por el humano: Defender OFF** (Tamper Protection → protección en tiempo real →
protección en la nube / comportamiento).

**Motivo:**
1. **Cuarentena del artefacto** → el ataque no se ejecuta → **falso negativo** de Wazuh.
2. **Alertas propias de Defender** convertidas en "detecciones" → mediría al antivirus, no
   al HIDS. El manager **ya trae** `0600-win-wdefender_rules.xml` (**113 reglas**, RS1) y
   `0430-ms_wdefender` (3) que alertarían sobre eventos del antivirus (`active_ruleset.txt:116,149`).
3. **Aislamiento/corrección a mitad de ventana** → contamina `[t0,t1]` y la doble iteración.

**Cómo se trata:** **control ambiental declarado** (igual que "NAT desconectado" y
"detección-only"), con:
- **procedimiento** de desactivación (ver `defender_off.md`);
- **checklist previa a cada ventana** de que sigue apagado;
- **declaración** de que el objeto de medida es **Wazuh**;
- **trabajo futuro opcional** (fuera de alcance): repetir una técnica con Defender ON para
  comparar "Wazuh vs. antivirus nativo".

---

## 5. D4 — Telemetría de Windows (sustituto de `auditd`)

**Decidido por el humano:** **Sysmon (config curada) + Registro de Seguridad (4688) +
PowerShell (4104) + FIM (ficheros y claves)**. El detalle (capas + mapa capa→técnica) está
en **`telemetria_windows.md`**.

| Capa | Aporta | Cómo se recoge |
|---|---|---|
| **Sysmon** (config curada) | `Process Create (1)`, `Network (3)`, `File Create/Delete`, `Registry`, `ProcessAccess (10)`, `ImageLoad (7)` | Binario Sysmon (Sysinternals) + `sysmonconfig.xml` (**pre-staging**); el agente lee `Microsoft-Windows-Sysmon/Operational` |
| **Registro de Seguridad** | `4688` creación de proceso (con línea de comandos), `4624/4625` logon, `7045` servicio, cuentas | Canal `Security` vía `<localfile><log_format>eventchannel</log_format>` |
| **PowerShell 4104** | Script Block Logging | GPO + canal `Microsoft-Windows-PowerShell/Operational` (reglas `0915-win-powershell`) |
| **Syscheck / FIM** | Ficheros y **claves de registro** vigiladas | `<syscheck>` del agente (espejo del de Linux) |
| **Sysmon 12/13/14 + FIM de registro** | Modificación de claves (persistencia, T1490) | Sysmon/eventchannel |
| **Estado del agente** | Conexión/desconexión (equivale a `503`/`506`) | Reglas internas Wazuh |

> **Sysmon sin filtro genera muchísimo evento** → **config curada + baseline Windows**
> obligatorios. La config por defecto **no vale**.

---

## 6. D5 — Agente Wazuh 4.14.7 (MSI, offline / pre-staging)

- **Versión:** la **misma que el manager, 4.14.7-1** (`version_wazuh.txt:4-12`); MSI
  `wazuh-agent-4.14.7-1.msi`. Sigue la lección de sincronía repo↔manager (`state.md:64`).
- **Instalación offline (pre-staging):** el **MSI**, el **Sysmon** y la **config Sysmon**
  se traen **antes de `t0`**, con **URL + `sha256`** registradas; el NAT se activa **solo**
  para descargarlos y se **desconecta** antes de baseline/ataques
  (`Soporte/Laboratorio/vmrun_config.md:70-85`). Los binarios quedan **fuera del repo**
  (solo se versiona el sidecar con URL+`sha256`).
- **Alta en el manager:** agente `victima-windows`, IP estática **`192.168.65.130`**
  (libre en `192.168.65.0/24`), apuntando a **`192.168.65.128:1514`**. **No se revierte el
  manager** durante los ataques (`vmrun_config.md:66-68`).
- **Verificación extremo a extremo:** un intento de logon fallido controlado → alerta en el
  manager por el `agent.id` de la víctima Windows (espejo del runbook Linux).

---

## 7. D6 — Recogida y filtro: **perfil de plataforma** (no bifurcar)

**No se crea una lógica paralela.**

1. **`extraer_alertas.py`** gana un **perfil Windows**: además de `data.audit.*` /
   `syscheck.path`, emite un **esquema normalizado** `data.win.*` (p. ej. `win_image`,
   `win_parent_image`, `win_command_line`, `win_cwd`, `win_target`, `win_user`). El
   **agregado por `rule.id`/`rs_origen` no cambia**.
2. **`filtrar_ruido.py`** gana un **perfil de plataforma** (config declarativa), con las
   **mismas categorías, orden de decisión y guardarraíles**; cambian los **datos**:
   - **procesos auto-ruido**: Linux `wazuh-*`; Windows `wazuh-agent.exe` + firmas internas del manager;
   - **`ATTACK_ROOT`**: Linux `/home/angel/lab-attack/`; Windows `C:\lab-attack\<ATA>`;
   - **predicado OPERADOR**: Linux `5715`/`19004` por IP; Windows logon RDP/red desde la IP
     del host `192.168.65.1` (**a confirmar** con datos reales);
   - **evento de ejecución**: Linux grupo `audit_command`; Windows Sysmon `1` / Seguridad `4688`.
3. **Métrica congelada: intacta.**
4. **Baseline Windows obligatorio:** `Dataset/Legitimo/windows/` con el **mismo criterio**
   que Linux (2 ventanas, preferentemente en horas distintas) para poblar el catálogo de
   ruido y **demostrar `deteccion=0`** sobre la línea base.

> **Nota de honestidad (KISS):** esto es **diseño**; la implementación es de
> `fase-02b-construccion`. Aquí solo se fija la **interfaz** (perfil de plataforma).

---

## 8. D7 — RuleSets RS1..RS4 en Windows

- **RS1** = default (incluye **todo** el ruleset Windows ya activo: `0330-sysmon` (39),
  `0430-ms_wdefender` (3), `0575`–`0620-win-*`, `0800`–`0830-sysmon_id_*`,
  `0840-win_event_channel`, `0915-win-powershell` — verificado en `active_ruleset.txt:96,116,144-155,174-185`).
- **RS2 = vacía en Windows** (declararlo): el "slot" RS2 nació como capa `auditd`
  (`rulesets_diseno.md:45`); sin `auditd` no aplica. **Sysmon es telemetría** (config en la
  víctima), **no** un fichero de reglas del manager.
- **RS3** = nuestras reglas Windows (`local_rules.xml` en el manager, reserva **100 000–100 499**),
  que pasan el **preflight anti-enmascaramiento** antes de activarse.
- **RS4** = reglas externas curadas (decisión de `rulesets_diseno.md` §2), si se usan en Windows.

---

## 9. Convención de carpetas por SO (sin mover nada de Linux)

> **Regla absoluta:** **no se mueve ningún fichero de Linux.** Los datos y ficheros Linux
> actuales **se quedan donde están** (cadena de huellas intacta, `state.md:59`). Los
> subárboles `windows/` **nacen nuevos** cuando llegue el primer dato.

```
Dataset/
├── Legitimo/
│   ├── (Linux actual: baseline plano, NO se mueve)
│   └── windows/                         # NUEVO (fase-02b-baseline)
└── Ataques/
    ├── Comandos/
    │   ├── T<id>-<desc>/                # Linux actual (NO se mueve)
    │   └── windows/<T>-<desc>/          # NUEVO (fase-03b)
    └── Resultados/Wazuh/
        ├── linux/                       # Linux actual (NO se mueve)
        └── windows/                     # NUEVO (fase-03b)

Soporte/Laboratorio/windows/             # NUEVO (este directorio, fase-02b-diseno)
Soporte/Wazuh/Configuracion/runbook_agente_windows.md   # NUEVO (fase-02b-construccion)
```

- Los `ATA<NNN>` **se continúan** desde `ATA055`; la misma técnica en Windows = **otro `ATA`**.
- Los nombres de fichero de ataque siguen la convención vigente
  (`ATA<NNN>_iter{N}-Audited.csv`, `-Revision.csv`, `ATA<NNN>_esperado.csv`).

---

## 10. Lo que **no** entra en este bloque

- **No** se crean VMs, **no** se instala Windows ni el agente, **no** se descarga nada.
- **No** se ejecuta ningún ataque ni prueba ART.
- **No** se toca Linux (ni datos, ni scripts, ni huellas, ni carpetas). **No se mueve nada.**
- **No** se modifica `_recursos/` (solo lectura).
- **No** se implementan los cambios de `extraer_alertas.py` / `filtrar_ruido.py` (solo se
  diseña la interfaz).
- **No** entran las 12 P1 nube/SaaS/IaaS/red (se declaran no factibles).
- **No** se mide con Defender activo (trabajo futuro opcional).

---

## 11. Referencias

- Plan del bloque: `plan.md` (raíz) — D1–D7, T-W1, §4–§6.
- Estudio W10/W11: `estudio_w10_vs_w11.md`.
- Telemetría: `telemetria_windows.md`; Defender: `defender_off.md`; pasos: `pasos_montaje.md`.
- Inventario: `Hojas/inventario_p1_windows.csv`
  (`_artefactos/scripts/inventario_p1_windows.py`).
- Linux (no se toca): `Soporte/Laboratorio/README.md`, `vmrun_config.md`;
  `Soporte/Wazuh/Configuracion/version_wazuh.txt`, `active_ruleset.txt`, `rulesets_diseno.md`.

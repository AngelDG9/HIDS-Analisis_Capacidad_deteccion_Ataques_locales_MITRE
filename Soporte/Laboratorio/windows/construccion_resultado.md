# Construcción del laboratorio Windows — resultado de ejecución (`fase-02b-construccion`)

> **Ejecutor:** agente `tfg-executor`. **Plan:** `plan.md` (raíz, `approved_by_human`,
> 2026-10-06). **Método:** `vmrun` + VMware Tools (**sin SSH a la víctima**; SSH solo al
> manager Linux para verificar).
> **Sin secretos** y **sin commit**. Nada de Linux tocado (salvo verificación de solo lectura
> en el manager). Material en `prestaging_material.md`.
>
> **Revisión 2026-10-07 (cierre tras el `tfg-tester`, «PASA con salvedades»):** corrección de
> **reloj/zona** del invitado (**§5**), **cita** de la config Sysmon (**§3.4**) y registro de la
> **limitación aceptada** de Windows Update (**§3.1**).

---

## 1. Resultado de los 11 pasos

| # | Paso | Resultado real |
|---|---|---|
| **1** | Arrancar las 2 VMs | ✅ `wazuh-server` (`.128`) y `victima-windows` (`.130`) arrancadas; VMware Tools `running`; la víctima responde y tiene IP `192.168.65.130/24` en `Ethernet0` (VMnet1) |
| **2** | Registrar el material | ✅ `prestaging_material.md` con **URL + tamaño + `sha256` completo** de los 3 ficheros |
| **3** | Copiar a `C:\Users\angel\material\` | ✅ `wazuh-agent-4.14.7-1.msi` (5 935 104), `Sysmon.zip` (2 938 038), `sysmonconfig-export.xml` (123 257) |
| **4** | Windows Update OFF | ⚠️ Reaplicado a **`Start=4` (Disabled)** + política `NoAutoUpdate=1`/`AUOptions=1`; **Windows lo auto-repara a Manual (Trigger-start) en cada arranque** (ver §3) |
| **5** | Defender OFF | ✅ `WinDefend` **Stopped**; `DisableRealtimeMonitoring/BehaviorMonitoring/IOAV/ScriptScanning=True`, `MAPSReporting=0`, `SubmitSamplesConsent=2`, `TamperProtection=0` |
| **6** | Telemetría mínima | ✅ `AllowTelemetry=0` (2 ubicaciones) y `DiagTrack` Stopped/Disabled |
| **7** | Snapshot `base-limpia` | ✅ creado con la VM **apagada** (`victima-windows-Snapshot2.vmsn`, 33 841 B). *(El primer intento se hizo en caliente con la VM encendida; se **borró** y se repitió offline.)* |
| **8** | Sysmon + config curada | ✅ Sysmon **v15.22** servicio `Sysmon64` **Running/Automatic**; config validada (`schema 4.50/4.91`); eventos 1/4/16 generados |
| **9** | Agente Wazuh + config logs | ✅ Instalado (agent **ID 002**, `4.14.7-rc1`); `WazuhSvc` Running; canales **Security**, **Sysmon**, **PowerShell Operational**; FIM (default + `C:\lab-attack` realtime); 4688 con línea de comandos; **4104** activado. Agente **`Active`** en el manager |
| **10** | Prueba de telemetría | ✅ Logon fallido inocuo → alerta **rule `60122`** (level 5) con `agent.id=002` en el manager |
| **11** | Snapshot `lab-listo-windows` | ✅ creado con la VM apagada (`victima-windows-Snapshot3.vmsn`, 33 848 B); VM revertida a él. *(**Recreado** el 2026-10-07 → `Snapshot5`, tras corregir reloj/zona; ver §2.3 y §5.)* |

---

## 2. Evidencia clave

### 2.1 Agente en el manager
```
ID: 002, Name: victima-windows, IP: any, Active
```
### 2.2 Alerta de la prueba de telemetría (`alerts.json` del manager)
```json
{"timestamp":"2026-10-06T21:56:22.909+0000",
 "rule":{"level":5,"id":"60122","description":"Logon Failure - Unknown user or bad password"},
 "agent":{"id":"002","name":"victima-windows","ip":"192.168.65.130"},
 "data":{"win":{"system":{"eventID":"4625"},"eventdata":{"targetUserName":"NoSuchUser_TFG"}}}}
```
- `alerts.json` pasó de **739 → 834** líneas durante la prueba; hay alertas con **Sysmon**
  (66) y **PowerShell** (111) ingeridas. La alerta `60122` es la del evento `4625` generado
  a propósito.

### 2.3 Snapshots
```
Total snapshots: 2
base-limpia
lab-listo-windows
```
- `base-limpia` (`Snapshot2`): **sin cambios**. **Conserva la zona horaria antigua**
  (`Pacific Standard Time`) a propósito — es solo el **punto de retorno de la instalación**.
- `lab-listo-windows` (`Snapshot5`): **recreado** el **2026-10-07** (con la VM apagada:
  `deleteSnapshot` + `snapshot`) tras corregir la zona/reloj del invitado, para que **no
  arrastre el desfase** (ver **§5**).

### 2.4 Aislamiento (NAT)
- `.vmx`: `ethernet1.startConnected = "FALSE"` (**NAT desconectado de forma persistente**).
- En el invitado: `Ethernet1` = **Disconnected** (APIPA `169.254.x.x`), **sin ruta por
  defecto**; única red `192.168.65.0/24` por `Ethernet0` (VMnet1). `ping` y `TCP/1514`
  víctima→manager OK.

---

## 3. Desviaciones y puntos abiertos (reportados al orquestador/humano)

1. **`wuauserv` se auto-repara a Manual/Trigger-start en cada arranque** en Windows 10 22H2
   (comportamiento conocido; ocurre incluso con `WaaSMedicSvc` y `UsoSvc` en `Disabled`).
   **Se ACEPTA como limitación** (decidido con el humano, 2026-10-07): no es posible dejar el
   servicio en `Disabled` de forma **estable**. El **control efectivo de la actualización** no
   es el servicio, sino la **política `NoAutoUpdate=1`** (+ `AUOptions=1`) **y el
   aislamiento**: el **NAT está desconectado**, de modo que la VM **no tiene ruta a internet
   y no puede descargar actualizaciones**. Verificado: `wuauserv` `Running/Manual`,
   `NoAutoUpdate=1`, `Ethernet1` (NAT) `Disconnected`. El paso 4 se da por válido **a nivel de
   política + aislamiento**, no por el estado del servicio.
2. ~~**Reloj/zona horaria del invitado**~~ **RESUELTO (2026-10-07).** La víctima estaba en
   **`Pacific Standard Time`** y con el reloj **+9 h 00 m** por delante del host respecto a
   **UTC**. Corregido: zona **`Romance Standard Time`** (Madrid) y **hora del invitado
   sincronizada con la del host** (`tools.syncTime = "TRUE"` en el `.vmx` + corrección puntual
   del reloj, porque VMware Tools no autocorrigió el offset de +9 h). Evidencia **antes/después**
   en **§5**; el snapshot `lab-listo-windows` se **recreó** para no arrastrar el desfase (ver
   §2.3).
3. **`wazuh-indexer` arrancó en `failed` (timeout)** al encender el manager; se recuperó con
   un `systemctl restart wazuh-indexer` (quedó `active`). No afecta a `alerts.json` ni a la
   conexión de agentes, pero conviene vigilarlo.
4. **Procedencia de la config Sysmon (CITA CORREGIDA, 2026-10-07):** `pasos_montaje.md` citaba
   `olafhartong/sysmon-modular`, pero la config real es **`sysmonconfig-export.xml`**
   (**SwiftOnSecurity/sysmon-config**, *source version 74*, 2021-07-08). Corregida la cita en
   `pasos_montaje.md` §2 con la **fuente real y su URL**
   (`https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml`);
   es la URL fijada en `plan.md` §0 y la registrada en `prestaging_material.md`.

---

## 4. Ficheros de trabajo

- Repo (este bloque): `Soporte/Laboratorio/windows/prestaging_material.md` y este documento.
- Invitado (en `lab-listo-windows`): `C:\Users\angel\material\` con el MSI, `Sysmon\` y la
  config + `ossec.conf.original.bak`. Los ficheros temporales `_*.txt/_*.ps1` se limpiaron.
- Host (temporal, fuera del repo): evidencias `win_*.txt` en
  `C:\Users\angel\AppData\Local\Temp\opencode\`.

---

## 5. Corrección de reloj/zona del invitado (`2026-10-07`)

**Problema (detectado por el `tfg-tester`):** `victima-windows` estaba en
**`Pacific Standard Time`** (UTC−8; con DST, UTC−7) y su reloj iba **+9 h 00 m** por delante
del host respecto a **UTC**. El `timestamp` de las alertas lo pone el manager (correcto), pero
el campo interno `data.win.system.systemTime` venía desfasado.

**Medida aplicada:**
1. En el `.vmx` **con la VM apagada**: `tools.syncTime = "TRUE"` (antes `"FALSE"`).
2. En el invitado: `Set-TimeZone -Id 'Romance Standard Time'` (Madrid) y **corrección puntual
   del reloj al UTC del host**. VMware Tools **no** autocorrigió el offset de +9 h (aun con el
   *time sync* en `Enabled`), por eso se fijó la hora explícitamente.
3. **Snapshot `lab-listo-windows` recreado** (VM apagada):
   `vmrun deleteSnapshot … lab-listo-windows` → `vmrun snapshot … lab-listo-windows`
   (`Snapshot5`). `base-limpia` **no** se toca (conserva la zona antigua; punto de retorno de
   la instalación).

**Evidencia — UTC del host vs UTC del invitado:**

| Momento | UTC del **host** | UTC del **invitado** | Zona del invitado | Δ (invitado − host) |
|---|---|---|---|---|
| **Antes** | `2026-10-06T22:19:44Z` | `2026-10-07T07:19:47Z` | `Pacific Standard Time` | **+9 h 00 m** |
| **Después** | `2026-10-06T22:22:41Z` | `2026-10-06T22:22:39Z` | `Romance Standard Time` | **≈ 2 s** |

**Verificación final sobre el snapshot recreado** (revertido `lab-listo-windows` y arrancado):
- `tz = Romance Standard Time` (`base_utc = +01:00`, DST activa `+02:00`).
- `utc_now = 2026-10-06T22:26:03Z` vs host `2026-10-06T22:26:00Z` → **≈ 3 s**.
- `left_clock_files = 0` (sin ficheros temporales en el perfil).
- Servicios tras el arranque: `WazuhSvc=Running`, `Sysmon64=Running`; NAT `Disconnected`;
  IP `192.168.65.130`.

**Evidencia cruda (host, temporal, fuera del repo):**
`C:\Users\angel\AppData\Local\Temp\opencode\clock\` (`host_before.txt`, `guest_before.txt`,
`guest_fix.txt`, `guest_after2.txt`, `guest_persist.txt`, `guest_final.txt`).

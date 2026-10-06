# change-doc — Bloque `fase-02b-construccion`: montaje del laboratorio Windows

> Cierre. Fecha: **2026-10-07**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (con 4 salvedades, resueltas/declaradas).
> Plan de referencia: `plan.md` (micro-plan, `approved_by_human`). **Bloque de EJECUCIÓN en la VM Windows.**

---

## 1. Objetivo

Dejar el **laboratorio Windows** listo para medir: agente de Wazuh + telemetría (Sysmon), sistema **limpio**
(sin Defender, sin updates, telemetría mínima) y **puntos de retorno** (snapshots). **NO** se hizo la línea base.

---

## 2. Resultado: **laboratorio Windows operativo** ✅

| # | Paso | Resultado (evidencia) |
|---|---|---|
| 1 | Arrancar las 2 VMs | ✅ manager `.128` + víctima `.130` |
| 2 | **Registrar el material** (pre-staging) | ✅ `Soporte/Laboratorio/windows/prestaging_material.md` con **URL + tamaño + `sha256`** |
| 3 | Copiar el material a la VM | ✅ `C:\Users\angel\material\` (MSI, Sysmon, config) |
| 4 | **Windows Update OFF** | ⚠️ política `NoAutoUpdate=1` aplicada; el **servicio se auto-repara a Manual** (limitación aceptada, ver §4) |
| 5 | **Windows Defender OFF** | ✅ `WinDefend` **Stopped**; `DisableRealtime/Behavior/IOAV/ScriptScan=True`; **`TamperProtection=0`** |
| 6 | **Telemetría al mínimo** | ✅ `AllowTelemetry=0` + `DiagTrack` Stopped/Disabled |
| 7 | **Snapshot `base-limpia`** | ✅ (VM apagada) |
| 8 | **Sysmon v15.22** + config curada | ✅ `Sysmon64` Running/Automatic; genera eventos |
| 9 | **Agente Wazuh 4.14.7** | ✅ **ID `002` `victima-windows`**; canales **Security + Sysmon + PowerShell 4104** + **FIM** (`C:\lab-attack` realtime); **4688 con línea de comandos** |
| 10 | **Prueba de telemetría** | ✅ un logon fallido en la víctima → **alerta `60122` (evento `4625`)** en el manager |
| 11 | **Snapshot `lab-listo-windows`** | ✅ (recreado tras el fix del reloj) |

**Verificación independiente (`tfg-tester`)**: agente **`active`** · **1.121 alertas** del agente 002 en el manager
(Sysmon 108, PowerShell 25) · hashes del material **recomputados y coincidentes** · canales/FIM/4688 confirmados en el `ossec.conf` ·
**NAT desconectado** (persistente en el `.vmx`) + IP fija `.130` sin ruta por defecto · **2 snapshots** existentes.

---

## 3. 🔴 Corrección del reloj (detectada por el tester)

La víctima estaba en **`Pacific Standard Time`** con **+9 h 00 m** de desfase.
- **Arreglado**: zona **`Romance Standard Time`** + `tools.syncTime = "TRUE"` + fijado puntual del reloj.
- **Verificado**: host UTC `22:22:41Z` vs invitado `22:22:39Z` → **Δ ≈ 2 s** ✅.
- **`lab-listo-windows` RECREADO** para no arrastrar el desfase. **`base-limpia`** se conserva tal cual
 (punto de retorno de instalación; **conserva la zona antigua** → declarado).

---

## 4. ⚠️ Salvedades declaradas (ninguna bloqueante)

1. **`wuauserv` se auto-repara a `Manual`** en Win10 22H2 (self-heal de Windows). **Se ACEPTA como limitación**:
 el control efectivo es la **política `NoAutoUpdate=1`** + **el aislamiento** (NAT desconectado → sin descargas posibles).
2. **`wazuh-indexer` arrancó `failed` (timeout)** y se recuperó reiniciándolo. **Vigilar** en cada arranque del manager.
 *(No afecta a `alerts.json`.)*
3. **La config de Sysmon es de `SwiftOnSecurity`** (no `olafhartong` como citaba un documento) → **cita corregida**.
4. **`base-limpia` conserva la zona horaria antigua** (es solo un punto de retorno de instalación).

---

## 5. Entregables

| Fichero | Qué |
|---|---|
| `Soporte/Laboratorio/windows/prestaging_material.md` | **registro del material** (URL + tamaño + `sha256`) |
| `Soporte/Laboratorio/windows/construccion_resultado.md` | resultado del montaje + limitaciones |
| `Soporte/Laboratorio/windows/pasos_montaje.md` | cita de Sysmon **corregida** |
| **VM** `D:\TFG-VMs\victima-windows\` | Windows 10 Pro + agente 002 + Sysmon + **snapshots `base-limpia` y `lab-listo-windows`** |

---

## 6. Siguiente

1. **Línea base de Windows** (el "ruido normal" del sistema) — **bloque siguiente**.
2. **`fase-03b`**: ataques en Windows (piloto de ~5 técnicas: 2 con ART + 2 propias + 1-2 de comparación Linux↔Windows).
3. **Pendientes ya anotados**: normalización de finales de línea + recálculo de huellas · arreglo futuro del filtro (`19010/19011`, SCA).
4. **`push`:** los commits son locales; publicar es del humano.

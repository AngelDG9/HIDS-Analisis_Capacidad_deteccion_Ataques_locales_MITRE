# Montaje de la VM Windows — pasos para el HUMANO

> **Nota de nombre:** este fichero (`pasos_montaje.md`) **es el entregable E5** del plan (`fase-02b-diseno`), que lo cita como `pasos_humano.md`; es el mismo documento y **no se renombra**.

> **Tarea E5 del bloque `fase-02b-diseno`.** **Lenguaje sencillo.** Todo esto lo hace **el
> humano**: los agentes **no pueden crear VMs ni instalar sistemas operativos** (ni deben).
> La VM Windows **no se enciende a la vez** que `victima-linux` (el host tiene **16 GB**).
>
> Este documento **no se ejecuta** en el bloque de diseño; es la **guía** para
> `fase-02b-construccion`. Cuando algo dependa de la elección **W10/W11** (aún abierta),
> se marca con **«[según SO]»**.

---

## 0. Antes de empezar

- Hipervisor: **VMware Workstation Pro 26H1**, en el sobremesa (`D:\TFG-VMs`).
- `vmrun`: `C:\Program Files\VMware\VMware Workstation\vmrun.exe` (`vmrun_config.md`).
- Red del laboratorio: **VMnet1 = `192.168.65.0/24`** (host-only). El manager está en
  **`192.168.65.128`**; la IP libre para Windows es **`192.168.65.130`**.
- **Decisión pendiente:** **Windows 10 Pro 22H2 x64** (recomendado) **o Windows 11 Pro
  25H2**. Ver `estudio_w10_vs_w11.md`. **No empieces la descarga hasta decidirlo.**

---

## 1. Pasos de montaje (en orden)

1. **Descargar la ISO virgen** de Windows desde la web oficial de Microsoft
   (**W10 22H2 x64** o **W11 25H2**, según la decisión). Anotar **versión exacta, tamaño y
   `sha256`** (ver §2).
2. **Crear la VM** en VMware Workstation: **máquina nueva**, disco **≥ 40 GB**, **2 vCPU**,
   **4 GB RAM**. Guardarla en `D:\TFG-VMs\victima-windows\`. **Apagada.**
3. **Instalar Windows** desde la ISO (instalación **limpia**, usuario local de laboratorio).
   **No instalar software adicional.** *(Si es W11: habilitar **TPM 2.0** y **Secure Boot**
   en la configuración de la VM antes de instalar.)*
4. **Adaptador de red:** dejar **solo `VMnet1`** (host-only, `192.168.65.0/24`) activo.
   Añadir un segundo adaptador **NAT** (para descargar material), **desconectado al
   arrancar** (`ethernet1.startConnected = "FALSE"` en el `.vmx`, como en Linux).
5. **IP fija `192.168.65.130`**, hostname `victima-windows`, **sin DNS ni ruta por defecto**
   por la interfaz host-only.
6. **Desactivar las actualizaciones automáticas** de Windows (reproducibilidad).
7. **Desactivar Windows Defender** para las ventanas: **Tamper Protection → protección en
   tiempo real → nube/comportamiento**. **Verificar** que queda apagado y **anotar cómo se
   hizo**. Procedimiento detallado: `defender_off.md`.
8. **Con el NAT encendido temporalmente (pre-staging):** descargar y **fijar con URL +
   `sha256`** el **agente Wazuh 4.14.7 (MSI)**, **Sysmon** (Sysinternals) y la **config
   Sysmon curada** (ver §2). Guardar **fuera del repo**.
9. **Con el NAT apagado:** instalar el **agente Wazuh** (nombre `victima-windows`, manager
   `192.168.65.128:1514`), instalar **Sysmon** con su config, y activar las **políticas de
   auditoría** (**4688** con línea de comandos; **PowerShell Script Block Logging 4104**).
   *(Si es W11: comprobar con `Get-Service sysmon*` que el **Sysmon integrado no está
   activo** antes de instalar el standalone.)*
10. **Comprobar la telemetría:** generar un evento controlado (p. ej. un logon fallido) y
    ver la alerta en el manager por el `agent.id` de la víctima Windows.
11. **Crear los snapshots:** **`base-limpia`** (SO recién instalado) y **`lab-listo-windows`**
    (lab listo: agente activo, Sysmon, Defender off, NAT off). **Punto de partida de cada ataque.**
12. **Apagar la VM** entre sesiones. Durante los ataques, **`wazuh-server` no se revierte**
    (conserva las alertas en el indexer).

---

## 2. Material a pre-descargar (URL + `sha256`)

> **Regla del repo:** los **binarios no entran al repo** (es público, `state.md:89`);
> solo se versiona el **sidecar** con **URL + `sha256`**. Se descargan en una **ventana
> aparte** (antes de `t0`) con NAT on, y el NAT se **desconecta** antes de baseline/ataques.

| Material | Origen / URL | Cómo se fija |
|---|---|---|
| **ISO de Windows** (W10 22H2 x64 o W11 25H2 x64) | Web oficial de Microsoft (Media Creation Tool / descarga directa) | **Versión + tamaño + `sha256`** (⚠️ el `sha256` **depende de la ISO exacta**; se calcula al descargar: `certutil -hashfile iso SHA256`) |
| **Agente Wazuh 4.14.7 MSI** | `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi` | URL fijada; `sha256` **a calcular al descargar** (no se pudo verificar por hash desde aquí) |
| **Sysmon** (Sysinternals) | `https://download.sysinternals.com/files/Sysmon.zip` | URL fijada; `sha256` **a calcular al descargar** (varía con cada release de Sysinternals) |
| **Config Sysmon curada** | `olafhartong/sysmon-modular` — **releases**: `https://github.com/olafhartong/sysmon-modular/releases/latest` (commit observado 2026-09-18: `082cba5`) | **commit + `sha256` del XML** congelados al descargar |
| **VMware Tools** | Ya incluido en VMware Workstation Pro 26H1 | (versión del hipervisor) |
| **(Para `fase-03b`) módulo `Invoke-AtomicRedTeam` + `powershell-yaml` + clon ART** | Clon local `Soporte/Ataques/atomic-red-team/` (pin `388942a…`) | **commit + `sha256`** (los binarios/PowerShell se preparan en `fase-03b`) |

> ⚠️ **Sobre los `sha256`:** los de **Sysmon** y del **MSI de Wazuh** dependen del binario
> exacto que se descargue ese día; **no se inventan**. El humano (o `fase-02b-construccion`)
> los **calcula al descargar** y los **anota** en el sidecar de pre-staging. El `sha256` de
> la **ISO de Windows** depende de la edición y de la build elegida → **se calcula con
> `certutil`** y se registra. **Si un hash no es fiable, se dice** (aquí no se puede
> garantizar ninguno de los tres desde el bloque de diseño).

---

## 3. Checklist rápida antes de cada ventana de ataque

- [ ] Defender **OFF** (real-time + cloud/behavior + Tamper) y verificado.
- [ ] **NAT desconectado** (`ethernet1.startConnected = "FALSE"`).
- [ ] IP **`192.168.65.130`** correcta; `ping` al manager `192.168.65.128` OK.
- [ ] Agente Wazuh **Active** en el manager (mismo `agent.id`).
- [ ] Sysmon **corriendo** con la config curada.
- [ ] (W11) Sysmon **integrado desactivado**.
- [ ] Snapshot **`lab-listo-windows`** revertido antes de empezar.
- [ ] `victima-linux` **apagada** (RAM del host).

---

## 4. Referencias

- Estudio W10/W11: `estudio_w10_vs_w11.md`.
- Defender: `defender_off.md`; telemetría: `telemetria_windows.md`.
- Decisiones: `README.md` (este directorio); plan: `plan.md` §6.
- Linux (no se toca): `Soporte/Laboratorio/README.md`, `vmrun_config.md`,
  `Soporte/Wazuh/Configuracion/runbook_agente_linux.md`.

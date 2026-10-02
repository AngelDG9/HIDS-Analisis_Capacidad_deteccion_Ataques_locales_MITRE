# ATA055 · T1557.003 — DHCP Spoofing (señuelo local + cliente efímero, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda C** (2.º de 2). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA055** |
| Técnica | **T1557.003 — Adversary-in-the-Middle: DHCP Spoofing** |
| Táctica | Credential Access; Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1557) |
| Ejecución | usuario `angel` con **`sudo`** (`ip link` + `udhcpd`) |

## 2. Qué hace y dónde escribe

- **Qué hace:** monta un **servidor DHCP señuelo** (`busybox udhcpd`) que responde a un **cliente
  efímero** (`busybox udhcpc`) y le entrega una concesión con **gateway/DNS controlados por el
  atacante** (`10.99.0.1`) — la base del **MITM por DHCP spoofing**.
- **Topología:** **segmento local AISLADO** (par `veth` `vdhcp0`/`vdhcp1`, `10.99.0.0/24`) **dentro
  de la víctima**. El cliente emite/recibe **solo** por `vdhcp1`; **no** se emite ninguna trama en
  `VMnet1`/`ens33`.
- **Por qué no en VMnet1 (declarado):** el DHCP de VMware (`vmnetdhcp`) sirve el **mismo rango
  `.128–.254`** que las IP fijas del laboratorio; un cliente DHCP en `VMnet1` podría recibir
  `.128`/`.129` y **romper la red / el manager**. Se usa un segmento aislado: **mecanismo fiel,
  riesgo 0**, y al terminar **no queda ningún servidor DHCP activo**.
- **Capa del HIDS que ejercita:** **`execve`** (`busybox`/`ip`). El HIDS de host **no ve la red**;
  la prueba es el **lease** entregado por el señuelo.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `busybox` (`/usr/bin/busybox`; applets `udhcpd`/`udhcpc`), `ip` (`/usr/bin/ip`), `timeout` (de serie) |
| Dependencias | ninguna nueva |
| Elevación | **sí** (`sudo`; `ip link` + bind UDP/67) |
| Guardarraíl | señuelo SOLO en `vdhcp0` (`10.99.0.0/24`); prohibido `ens33`/`192.168.65.0/24`/manager; ≤ **15 s**; limpieza (kill + `ip link del`) por `trap` |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio a `/home/angel/lab-attack/ATA055/`.
2. `cd /home/angel/lab-attack/ATA055 && echo '<pw>' | sudo -S bash ATA055_ataque.sh 2>&1 | tee ejecucion.out`.
3. El propio guion crea y **retira** el segmento; no hay receptor externo.

## 5. Señales esperadas (convención H4)

`ATA055_esperado.csv` (todas `deteccion`):

- `T1557.003-S1` `audit_exe=busybox` (`80792`).
- `T1557.003-S2` `audit_exe=ip` (`80792`).
- `T1557.003-S3` `audit_cwd=/home/angel/lab-attack/ATA055/*` — ancla H4.

> **Binario real:** `busybox` → `/usr/bin/busybox`; `ip` → `/usr/bin/ip` (symlink desde `/usr/sbin/ip`).

## 6. Señuelo — cómo se monta y se retira

`busybox udhcpd -f udhcpd.conf` (solo `vdhcp0`) + `busybox udhcpc -i vdhcp1` (cliente efímero). El
`lease_script.sh` **solo registra** el lease (no configura interfaces). Al terminar: `kill` del
señuelo + `ip link del vdhcp0` → verificado `udhcpd_residual=0` y `veth_residual=0`.

## 7. Prueba de éxito (independiente de la alerta)

`lease.obtained` registra el lease entregado por el señuelo:
`ip=10.99.0.101 mask=24 router=10.99.0.1 dns=10.99.0.1 serverid=10.99.0.1 lease=120` ⇒ el cliente
efímero **aceptó el gateway/DNS del atacante** (base del MITM).

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** señuelo parado y veth borrado al terminar (0 residuos); **sin** servidor DHCP activo;
  **sin NAT**; **sin** reglas de firewall.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el mecanismo son reales** (servidor DHCP señuelo + cliente que acepta un lease con
> gateway/DNS del atacante); **el alcance es de laboratorio**: el segmento se **simula con un par
> veth aislado** (sustituto declarado de `VMnet1` para **no competir con el DHCP de VMware** ni
> romper la red), el cliente es **efímero** y el `lease_script` **no** reconfigura ninguna interfaz
> real; **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas
> por el analista**.

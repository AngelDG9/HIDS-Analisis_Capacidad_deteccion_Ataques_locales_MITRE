# `ventana_meta.md` — Ficha de la ventana legítima (L1, `legitimo_72h`)

> **Estado:** **PREPARADA** (preparación cerrada 2026-10-18). Ventana **sellada**; se completará
> con los resultados y el **veredicto de validez (V1–V8)** tras `t1` (2026-10-22T00:00:00Z).
> Métrica: `Soporte/Metrica/metrica_hids.md` v1 (`metrica_version = 1`), bóveda
> `boveda_congelacion.md` v1 (B10 se sella en `Soporte/Laboratorio/legitimo_72h/b10_sellado.md`).

## 1. Ventana (sellada, UTC)

| Parámetro | Valor |
|---|---|
| `t0` | **2026-10-19T00:00:00Z** (= 2026-10-19 02:00 local, Europe/Madrid CEST +02:00) |
| `t1` | **2026-10-22T00:00:00Z** (= 2026-10-22 02:00 local) |
| Duración | **72 h** exactas (`t1 = t0 + 259 200 s`), continuas |
| Cruce DST | **No** (el cambio de hora europeo es el 2026-10-25) |
| Fuente de alertas | **fichero diario** `/var/ossec/logs/alerts/2026/{Oct}/ossec-alerts-{19,20,21}.json` (**3 días**) |
| Denominador `M` | `archives.json` (manager), `logall_json` **ON solo en la ventana** |
| Contador de acciones | `ghosts.history_timeline` (PostgreSQL del host) |

## 2. Configuración

- **HIDS:** **solo Wazuh** 4.14.7 (`victima-linux`, agente `001`), **config virgen** `C1 = {RS1,RS2}`
  (`RS3 = RS4 = 0`). **No** se añaden reglas.
- **Instrumentación `M`:** `<logall_json>yes</logall_json>` en el manager **solo** durante `[t0,t1]`;
  **OFF** fuera (por defecto). `off` **borra** `archives.json` ⇒ **copiar antes** (§ extracción).
- **Actividad legítima:** GHOSTS v8.3.1 + "internet local" (host); cliente Linux en `victima-linux`.
  Timeline **`timeline_72h.json`** (4 handlers en bucle; franjas UTC `00:45–04:45` y `12:00–16:00`;
  `sha256` en `Soporte/Laboratorio/legitimo_72h/sha256sums.txt`).
- **Aislamiento:** NAT **desconectado**; la víctima solo habla con la "internet local" (`192.168.65.1`).
- **PC:** encendido y **sin suspensión** durante las 72 h; **cero acceso** a la víctima en `[t0,t1]`.

## 3. Evidencia operativa (a completar tras `t1`)

- **Host-side:** `Soporte/Laboratorio/legitimo_72h/legitimo_host_control.log` (UTC) — `prep`/`arm`/`stop`.
- **Vigilancia:** `Soporte/Laboratorio/legitimo_72h/vigilancia_legitimo.log` (UTC).
- **Denominador:** `denominador_M.csv` (+ `denominador/archives.json`) — `M` titular = **endpoint (001)**.
- **Acciones:** `ghosts_acciones.csv` (total + por `handler` + por hora).
- **Alertas:** `alertas_detalle.csv` (por alerta, agente `001`) + `ruleids_legitimos.csv` (+ por día).

## 4. Validez V1–V8 (a completar tras `t1`)

| # | Criterio | Resultado |
|---|---|---|
| **V1** | Cobertura de alertas del agente `001` en `[t0,t1]` (primera ≤ `t0+δ`, última ≥ `t1−δ`) | *pendiente* |
| **V2** | GHOSTS vivo: acciones distribuidas día y noche (no un pico y silencio) | *pendiente* |
| **V3** | Manager `active`; los 3 diarios existen y crecen | *pendiente* |
| **V4** | **0** logon/sesión del operador (`192.168.65.1`) atribuibles al agente `001` | *pendiente* |
| **V5** | NAT off durante la ventana (víctima solo habló con la internet local) | *pendiente* |
| **V6** | `archives.json` de `[t0,t1]` **copiado** y `M` computado antes de `logall_json off` | *pendiente* |
| **V7** | Sin cambios de config a mitad; sin tocar la víctima | *pendiente* |
| **V8** | PC sin suspensión/apagado/reinicio en `[t0,t1]` | *pendiente* |

**Veredicto:** *pendiente* (VÁLIDA / INVÁLIDA — si INVÁLIDA, se **repite entera**).

## 5. Preparación verificada (2026-10-18) — **PASA**

- [x] `timeline_72h.json` creada, versionada (`sha256`) y **probada en seco**: **209 acciones en 180 s**
      (`Command` 111 + `Curl` 87; 4/4 handlers) y **rastro en Wazuh** (`intranet.local` 93, `/usr/bin/curl` 116,
      `/usr/bin/gzip` 36, `/usr/bin/tar` 29, `/usr/bin/md5sum` 14).
- [x] Tareas del host (`TFG-Legit-{Prep,Arm,Watch,Stop}`) **`Ready`** con `NextRun` correcto
      (01:15 · 01:40 · 05:00 cada 3 h · 22/10 02:05, hora local).
- [x] Tarea del invitado (`TFG-Ghosts-Legit`, systemd timer) instalada: **`NEXT = 23:55Z = t0−5min`**.
- [x] Helper `contar_denominador.py` (+ tests) y orden **copiar-antes-de-apagar** fijados y ensayados
      (`M total=2474 / endpoint=2271` en el ensayo; `archives.json` **borrado** por `off`).
- [x] Ensayo general ejecutado (prep → arranque → verificación → `drytest` → extracción → parada → restauración).
- [x] Chequeos pre-`t0`: suspensión/hibernación **0**, snapshots **intactos**, disco del manager **22 G libres**,
      **0 VMs / 0 procesos / 0 reglas** al cierre.

> **Nota sobre `M` (volumen):** medido **≈ 43 MB/h** con actividad intensa (vs. ≈ 4,17 MB/h de fondo de L0);
> proyección a 72 h **≈ 1,2 GB** (≪ 5 GB ⇒ **no** se activa el fallback `L11`). La vigilancia registra el
> tamaño de `archives.json` para detectar desviaciones.

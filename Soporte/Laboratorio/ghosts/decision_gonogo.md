# Decisión go/no-go — bloque `legitimo-infra` (L0)

> **Fecha:** 2026-10-18 · **Autor:** ejecutor (bloque L0) · **Ámbito:** montar y probar la
> infraestructura del **legítimo** (GHOSTS + "internet local" + denominador `M`) y decidir si se
> sigue con **GHOSTS** en `L1` o se activa el **plan B**. **En L0 NO se mide** (ni FPR, ni las 72 h).

## Veredicto

> ## ✅ **GO** — se sigue con **GHOSTS** en `L1`.

Se cumplen **G1–G4** dentro del esfuerzo acotado (**G5**). GHOSTS **deja rastro en el host visible
por Wazuh** (el criterio crítico) y la "internet local" funciona **sin internet**.

---

## Criterios objetivos (§7.1 del plan)

| # | Criterio | Resultado | Evidencia |
|---|---|---|---|
| **G1 — Offline** | Toda la infraestructura funciona con **NAT off**; el manager solo recibe en sus puertos | **PASA** | `verificar_internet_local.sh` desde la víctima: web 8080 `200`, *paste* 9090 `200`, WebDAV 9092 `PUT 201`/`PROPFIND 207`; `ip route` **sin default**; `curl http://example.com` → **falla** (`exit 28`), `curl http://1.1.1.1` → **falla** (`exit 7`) |
| **G2 — Presupuesto** | Stack GHOSTS + internet local **≤ 1.5 GB**; host **≥ 1 GB libre** con las 2 VMs; VMware intacto | **PASA** | Stack medido = **361.6 MB** (API 192.1 + PostgreSQL 109 + Python 60.5); **5.56 GB libres** con 2 VMs; `vmrun list` = **2 VMs**; arrancan y responden |
| **G3 — Cliente útil** | El cliente Linux se **registra**, recibe **timeline** y ejecuta **≥ 1 acción con rastro visible por Wazuh** | **PASA** | Máquina `victima-linux` id `7c33a13a-…` registrada; **timeline entregada por el servidor** (MachineUpdate `Type=Timeline`); el cliente ejecutó **14 acciones por ciclo** (8 `Command` + 6 `Curl`) — **28 persistidas en 2 ciclos** en `history_timeline` — creando ficheros y descargando del sitio local; en el manager: **1481 alertas `80792` (`audit_command`)** hoy y alerta de ejemplo `Audit: Command: /usr/bin/tar.` (agente **001**) |
| **G4 — Control** | Arranque/parada **scriptables**; *timelines* **versionadas**; **contador de acciones exportable** | **PASA** | `start_ghosts.ps1`/`stop_ghosts.ps1` + `start_internet_local.ps1`/`stop_internet_local.ps1`; timeline `timeline_smoke.json` (fichero versionado); contador = tabla **`history_timeline`** (exportable por SQL/API) |
| **G5 — Tiempo** | Dentro de un esfuerzo acotado (**≤ 2 sesiones**) | **PASA** | Montaje, pruebas y documentación en la sesión L0 |

---

## Qué se montó (resumen)

| Componente | Dónde | Puerto | Estado |
|---|---|---|---|
| **GHOSTS API** (.NET 8, v8.3.1) | HOST `192.168.65.1` | **5000** | operativa |
| **PostgreSQL 16.15** (portable) | HOST (solo `127.0.0.1`) | **5432** | operativa |
| **Cliente GHOSTS** (Linux, *self-contained*) | `victima-linux` `.129` | — | registrado y ejecutando |
| **Web estática** (intranet + descargas) | HOST | **8080** | operativa |
| **Sink HTTP** (*paste*/C2) | HOST | **9090** | operativa (reuso) |
| **Sink WebDAV** (nube) | HOST | **9092** | operativa (reuso) |
| **Snapshot** `lab-listo-legit` | `victima-linux` | — | creado (cliente + config) |

---

## Plan B (declarado; **NO** se activa)

Si en `L1` GHOSTS fallara, el plan B es **actividad real por guion** (bash + `systemd`/cron) **con
navegador/apps reales** (no un guion plano), **con la misma internet local** (que ya se monta
igual) y **las mismas unidades** (`acción`/`hora`). Se declararía como limitación *"legítimo
guionizado, no NPC"*. **El plan B no desperdicia nada de L0** (la "internet local" y el
denominador `M` sirven igual).

---

## Riesgos / cabos para `L1` (declarados, no bloquean)

- **Duplicado de máquina** en el primer arranque del cliente (carrera SignalR/updates) → en `L1`
  **reconciliar** tras el primer alta (conservar la del `instance/id.json`).
- **Adaptaciones locales** del build (newline en `QueueSyncService` + cultura invariante): quedan
  declaradas en `README.md` §7.
- El **manager de Wazuh** quedó `failed` tras el encendido → se reinició (higiene conocida).
- **Denominador `M` (prueba de `logall_json`, acotada y revertida):**
  `archives.json` creció `1 054 756` bytes en `911 s` ⇒ ≈ **4,17 MB/h** ⇒ **≈ 300 MB a 72 h**,
  **muy por debajo** del umbral de fallback (**> 5 GB**). El titular **por evento** es **viable**;
  `logall_json` quedó **APAGADO** y el manager **restaurado** (detalle en
  `Soporte/Laboratorio/instrumentacion_denominador.md`).

## Referencias

- Plan: `plan.md` §7 (go/no-go), §10 (CA-L0-08), §11 (gate).
- Montaje: `Soporte/Laboratorio/ghosts/README.md`.
- Denominador: `Soporte/Laboratorio/instrumentacion_denominador.md`.

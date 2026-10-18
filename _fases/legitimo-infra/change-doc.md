# change-doc — Bloque `legitimo-infra` (L0): infraestructura del legítimo

> Cierre. Fecha: **2026-10-18**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (4 salvedades menores: **4 corregidas**).
> Plan de referencia: `plan.md` (raíz, `status: approved_by_human`, 506 líneas).
> **Bloque de INFRAESTRUCTURA**: monta y **prueba** (no mide). Las **72 h** son el bloque **L1**.

---

## 1. Objetivo

Montar la infraestructura con la que se medirá el **legítimo** (la parte que da las **falsas alarmas**): **GHOSTS** + **"internet local"** + la instrumentación del **denominador `M`**, con **go/no-go**.

---

## 2. Resultado: **GO** ✅

| Criterio | Evidencia |
|---|---|
| **G1 — Offline** | NAT desconectado en ambas VMs (`ethernet1.startConnected = "FALSE"`); la víctima solo ve la internet local |
| **G2 — Presupuesto** | Stack **361,6 MB**; **5,56 GB libres** con 2 VMs; VMware intacto |
| **G3 — Cliente útil** | Cliente Linux registrado (`victima-linux`, id `7c33a13a…`), timeline servida y **acciones con rastro en el host** (peticiones de `.129` a 8080/9090/9092 en los timestamps de los handlers) + **1481 alertas `80792`** |
| **G4 — Control** | Arranque/parada scriptables; timeline versionada; **contador de acciones exportable** (28 persistidas = 14 × 2 ciclos) |
| **G5 — Tiempo** | Dentro del *time-box* |

**Plan B (declarado, NO activado):** actividad real por guion con **navegador/apps reales** + la misma internet local + mismas unidades.

### ⭐ El dato clave (denominador `M`)
Prueba de `logall_json`: **`1.054.756 B` en `911 s` ⇒ ≈ 4,17 MB/h ⇒ ≈ 300 MB a 72 h** (el límite eran ~5 GB).
⇒ **El denominador "por evento" es VIABLE** (con ~17× de margen) ⇒ **no se activa el fallback**. *(Caveat honesto: la actividad GHOSTS de esa ventana duró ~17–38 s ⇒ esa tasa es esencialmente **ruido de fondo**; la proyección es, si acaso, un **ligero infravalor**.)*

---

## 3. Producto

**`Soporte/Laboratorio/ghosts/`**: `README.md` · `prestaging_material.md` (pin: **GHOSTS v8.3.1** `4d2e1608…` por tag/commit + PostgreSQL 16.15 con `URL+sha256`) · `decision_gonogo.md` · `timeline_smoke.json` · `start_ghosts.ps1` / `stop_ghosts.ps1` · `deploy_client.ps1` · `ghosts_api.py` · `client_ctl.sh` · `limpiar_cliente.sh` · `logall_json_ctl.sh` · `diag_wazuh.sh` · `arrancar_manager.sh` · `check_wazuh_host_trace.sh` · `contar_wazuh2.sh` · `client_config/{application.json,timeline.json}`.

**`Soporte/Laboratorio/internet_local/`**: `README.md` · `serve_site.py` (web estática 8080) · `start_internet_local.ps1` / `stop_internet_local.ps1` · `verificar_internet_local.sh` · `make_descargas.py` · `site/**` (con `descargas/`).
*(Reaprovecha el **sink HTTP** :9090 y la **nube WebDAV** :9092 de los ataques.)*

**Otros**: `Soporte/Laboratorio/instrumentacion_denominador.md` (cifras reales + fallback con umbral `>5 GB`) · `Soporte/Wazuh/Configuracion/logall_json_procedimiento.md` · `Soporte/Laboratorio/vmrun_config.md` (snapshot nuevo).

**Snapshot**: **`lab-listo-legit`** en `victima-linux` (cliente + config, **sin datos de medida**); los **originales intactos**.

---

## 4. Verificación (`tfg-tester`) — **PASA**

12 CA cumplidos (evidencia re-ejecutada: pin por tag/commit y `sha256` de PostgreSQL; logs de la internet local; BD de GHOSTS; aritmética del contador; snapshots; `git status` limpio; 0 VMs/procesos/firewall al cierre).

**Salvedades (todas corregidas):**
1. "14 acciones" → **"14 por ciclo; 28 persistidas"**.
2. **Caveat** añadido a la estimación del contador (actividad GHOSTS corta ⇒ tasa de fondo ⇒ infravalor).
3. `README`: cliente = `src/ghosts.client.linux` (no "Universal"); GHOSTS se fija por **tag/commit**.
4. `start_ghosts.ps1`: eliminado el `Password=ghosts` de la cadena **solo-localhost** (optics; `initdb -A trust`).

**Cabos declarados (no bloquean):** `wazuh-manager` puede arrancar `failed` → `systemctl restart` (higiene conocida) · duplicado de máquina en el primer arranque de GHOSTS (carrera SignalR↔updates) → reconciliar en L1 · el `sudo` de las VMs no es NOPASSWD (se pasa por STDIN).

---

## 5. Siguiente

1. **`legitimo-72h` (L1)**: la captura de **72 h** (cuello de botella) — revert a `lab-listo-legit`, `t0`, GHOSTS 72 h, `t1`, extracción; y **sellado de la bóveda B10**.
2. En paralelo: **`M1a`** (recorte histórico de los 55 ataques).
3. **`push`**: los commits son **locales**; publicar es del humano.

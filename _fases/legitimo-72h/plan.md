> **Nota de recuperación (2026-10-20).** Este fichero es la **reconstrucción literal** del `plan.md`
> de L1 (v1, `status: approved_by_human`, 2026-10-18) que estaba en la **raíz** del repo. La raíz se
> reutiliza para el plan del bloque siguiente (`legitimo-fix`) — el flujo dice que el plan vive en la
> raíz mientras el bloque corre — y **L1 nunca llegó a archivarse** (falló antes de cerrar), así que
> esa era su única copia. Se conserva aquí, junto al diagnóstico del fallo, **sin cambios de
> contenido**. Si el orquestador conserva una copia original, esta debe sustituirse por ella.

---
bloque: legitimo-72h
nombre: L1 — Captura de 72 h de actividad legítima (GHOSTS, Wazuh virgen) + extracción + sellado B10
version: 1
status: approved_by_human
fecha_aprobacion: 2026-10-18
aprobado_por: humano
ventana: t0 = 2026-10-19T00:00:00Z · t1 = 2026-10-22T00:00:00Z (72 h continuas)
fecha: 2026-10-18
autor: tfg-planner
depende_de: legitimo-infra (L0, cerrado 2026-10-18 con GO) · reencuadre-metrica (R2, métrica congelada) · reencuadre (R0, §7 y §10.2)
gate: |
  **APROBADO (2026-10-18).** Ventana fijada: **t0 = 2026-10-19T00:00:00Z** → **t1 = 2026-10-22T00:00:00Z** (72 h continuas; medianoche UTC = 02:00 local). Gate §11 Q1–Q7 → **SÍ**. Este bloque necesita el **PC encendido y sin tocar la VM durante 3 días**.
  Diseño propuesto: la ventana de **72 h continuas en UTC** (`t0 … t1 = t0+72h`), con **arranque/parada
  automáticos** (tareas del host + tarea del invitado, como en el baseline), **revert a `lab-listo-legit`**,
  `logall_json` **ON solo en la ventana**, "internet local" + GHOSTS arriba, y **cero acceso a la víctima**
  dentro de `[t0,t1]`. Al terminar: extracción de **alertas** (fichero diario, varios días) + **denominador `M`**
  (`archives.json`, **copiado antes de apagarlo**) + **contador de acciones** GHOSTS + **sellado B10**.
  **La fecha de arranque la decide el humano** (§3.2). Si una ventana resulta inválida → **se repite entera**.
---

# plan.md — Bloque `legitimo-72h` (L1)

> **Qué es este documento.** El **plan** del bloque **L1**: **capturar 72 h de actividad legítima** en la
> víctima Linux con **Wazuh virgen** (GHOSTS + "internet local", infraestructura ya montada en **L0**), y
> dejar los **datos listos y verificados** para el análisis. También **sella la bóveda B10** (config del legítimo).
>
> **Qué NO es.** **No analiza** (ni FPR, ni T3/T4, ni el catálogo de ruido): eso es **L2**. **No monta nada
> nuevo** (L0 ya lo montó). **No toca la métrica congelada** (`Soporte/Metrica/`). **No implementa hasta el
> gate**: tras el gate, la ejecución corre las 72 h, extrae y documenta.
>
> **Este es el cuello de botella del TFG**: 72 h de **reloj de pared** (no acelerables) ⇒ **arrancarlo cuanto
> antes** (`R0 §10.3`).

## Anclas

- `(R0 §X.Y)` = `_fases/reencuadre/plan.md` (v2, aprobado): **§7** (plan del legítimo), **§10.2/§10.3**
  (secuencia y cuello de botella), **§11** (riesgos).
- `(R2 §X)` = `Soporte/Metrica/metrica_hids.md` (v1, **congelada**) + `boveda_congelacion.md` (v1):
  **§2** (unidad del legítimo + denominador `M` + fallback), **§6** (reglas de conteo), **§8** (ventana),
  **§9/§9.2** (`L11`, qué invalida), **§10** (unidad común entre HIDS: **acción GHOSTS / hora**).
  **B10** (config del legítimo) = **lo que este bloque sella**.
- `(L0 §X.Y)` = `_fases/legitimo-infra/plan.md` + `change-doc.md` + `reviews.md` (cerrado con **GO**).
- `(BL §X)` = `_fases/fase-02b-baseline/plan.md` (patrón de **ventana con tareas del host + del invitado**).
- `state.md` (estado vivo; `roadmap.md:73-92`).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Contexto verificado (lo que L0 dejó montado y probado)](#2-contexto-verificado-lo-que-l0-dejó-montado-y-probado)
3. [La ventana de 72 h (planificación)](#3-la-ventana-de-72-h-planificación)
4. [Preparación (antes de `t0`)](#4-preparación-antes-de-t0)
5. [Ejecución: arranque/parada automáticos, disciplina y vigilancia](#5-ejecución-arranqueparada-automáticos-disciplina-y-vigilancia)
6. [Extracción (alertas + denominador `M` + contador de acciones)](#6-extracción-alertas--denominador-m--contador-de-acciones)
7. [Sellado de la bóveda B10](#7-sellado-de-la-bóveda-b10)
8. [Validez: criterios objetivos y qué invalida la ventana](#8-validez-criterios-objetivos-y-qué-invalida-la-ventana)
9. [Riesgos y mitigaciones](#9-riesgos-y-mitigaciones)
10. [Criterios de aceptación (verificables)](#10-criterios-de-aceptación-verificables)
11. [Gate humano (lenguaje sencillo)](#11-gate-humano-lenguaje-sencillo)
12. [Ficheros que se tocarán](#12-ficheros-que-se-tocarán)
13. [Trazabilidad (fuentes y afirmaciones verificadas)](#13-trazabilidad-fuentes-y-afirmaciones-verificadas)
14. [Decisiones abiertas y lo que NO cuadra](#14-decisiones-abiertas-y-lo-que-no-cuadra)

---

## 0. Resumen ejecutivo

L1 hace **cinco cosas** y **una decisión**:

1. **Planifica la ventana**: **72 h continuas UTC** (`t0 … t1 = t0+72 h`), con **fecha elegida por el humano**.
2. **Prepara** (antes de `t0`, ~45 min): **revert a `lab-listo-legit`**, **`logall_json` ON**, "internet
   local" + GHOSTS arriba, **timeline de 72 h** armada, **tarea del invitado** (GHOSTS) y **tareas del host**
   listas, **verificación previa** (todo ANTES de `t0`).
3. **Ejecuta** las 72 h **sin tocar la víctima** (disciplina dura), con **arranque/parada automáticos** y
   **vigilancia pasiva** (GHOSTS vivo, manager vivo) que **no accede a la víctima**.
4. **Extrae**: (a) **alertas** de `[t0,t1]` del **fichero diario** (¡**varios días**!); (b) el **denominador
   `M`** desde `archives.json` (**copiado antes de `logall_json_ctl.sh off`, que lo borra**); (c) el
   **contador de acciones** GHOSTS.
5. **Sella B10** (versión GHOSTS + "internet local" + instrumentación del denominador).

**Decisión:** **ventana VÁLIDA / INVÁLIDA** con criterios objetivos; si es inválida → **se repite entera**.

**Datos de L0 que hacen esto viable (verificados):** GHOSTS **v8.3.1** (commit `4d2e1608…`); el contador
`logall_json` medido a **≈ 4,17 MB/h ⇒ ≈ 300 MB a 72 h** (≪ 5 GB ⇒ **denominador por evento VIABLE, sin
fallback**); snapshot **`lab-listo-legit`** creado; **`logall_json` OFF** por defecto; cliente deja **rastro
visible por Wazuh** (1481 alertas `80792` en la prueba).

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo del bloque

Producir el **dataset legítimo de 72 h** (denominador `M` + alertas + contador de acciones) que **L2**
analizará, y **sellar B10**. Es el **insumo autoritativo del ruido** (`R0 §10.4`): el juicio de FP/TN se
hace **con estas 72 h**, no con los baselines antiguos (que quedan como `histórico`).

### 1.2 Entra

- **Planificar y ejecutar** la captura de **72 h** con GHOSTS + "internet local" (infra de L0) sobre la
  víctima Linux (`victima-linux`, `.129`) revirtiendo a **`lab-listo-legit`**.
- **Instrumentar** el denominador `M` (`<logall_json>` ON **solo** en la ventana) y **extraer** `M`.
- **Extraer** las alertas del **fichero diario** en `[t0,t1]` (varios días), aisladas a la víctima.
- **Exportar** el **contador de acciones** GHOSTS.
- **Sellar B10** (resultado + hashes).
- **Evaluar la validez** y documentar la ventana (evidencia host-side y manager-side).

### 1.3 NO entra (fuera de alcance de L1)

- **El análisis**: T3/T4, FPR/TNR, catálogo de ruido por regla, pruning → es **L2** (`legitimo-analisis`).
- **El recorte de ataques** (M1a/M1b) → otros bloques.
- **Montar o cambiar** infraestructura de GHOSTS/"internet local" (L0 ya lo hizo).
- **Añadir/quitar reglas** de Wazuh (virgen preservada; C2/C3 son contingentes al gate).
- **Tocar la métrica**: `Soporte/Metrica/**`, `extraer_alertas.py`, `filtrar_ruido.py` (solo lectura).
- **Tocar** el corpus, `Hojas/`, `_recursos/`, `Dataset/` **salvo** la **carpeta nueva** de esta captura.
- **Mezclar HIDS** (la corrida legítima es **solo Wazuh**; VR es `V0`/`V1`) ni **Linux y Windows a la vez**.
- **`git commit`/`push`** (los hace el orquestador/humano).

---

## 2. Contexto verificado (lo que L0 dejó montado y probado)

| Elemento | Dónde / estado (verificado en L0) | Uso en L1 |
|---|---|---|
| **GHOSTS API** (.NET 8, `v8.3.1`, commit `4d2e1608…`) | **HOST** `192.168.65.1:5000` (`start_ghosts.ps1`) | servicio que arranca en preparación; entrega timeline y recoge acciones |
| **GHOSTS PostgreSQL 16.15** | **HOST** `127.0.0.1:5432` (solo localhost) | contador de acciones (`history_timeline`) |
| **Cliente GHOSTS** (`src/ghosts.client.linux`, *self-contained*) | **`victima-linux`** `.129`; `client_ctl.sh start|stop|status|id|log` | ejecuta la actividad legítima 72 h |
| **"Internet local"** | **HOST**: web estática `:8080` (`serve_site.py`), *paste*/sink `:9090`, nube WebDAV `:9092` (`start_internet_local.ps1`); firewall acotado a `192.168.65.0/24` | webs/descargas/nube/paste sin internet |
| **Snapshot `lab-listo-legit`** | **`victima-linux`** (cliente + config + `/etc/hosts`, **sin datos de medida**) | **punto de partida** de la ventana |
| **`logall_json`** (`logall_json_ctl.sh on|off|status|size`) | manager `.128`; **OFF** por defecto; **`off` BORRA `archives.json`** | instrumenta `M` en la ventana |
| **Timeline smoke** | `timeline_smoke.json` (**`TimeLineHandlers`** `Command`+`Curl`; `Status: Run`) | base para la **timeline de 72 h** (falta) |
| **Patrón de ventana** (baseline 02b) | host: **tareas** `TFG-Baseline-*-{Start,Stop}` + invitado: **tarea** `TFG-Baseline-Legit`; **`baseline_host_control.ps1`** | se **reutiliza el patrón** (tareas host + tarea invitado) |

> **Nota operativa (cabos de L0, no bloquean):** el **manager puede quedar `failed`** tras encender la VM
> → `systemctl restart wazuh-manager` (`arrancar_manager.sh`); el **`sudo` de las VMs no es NOPASSWD**
> (se pasa por STDIN, **nunca** en fichero); **duplicado de máquina** en el primer arranque del cliente →
> **reconciliar** antes de `t0` (`limpiar_cliente.sh`, `README.md` §8).

---

## 3. La ventana de 72 h (planificación)

### 3.1 Definición (congelada por el diseño)

| Parámetro | Valor |
|---|---|
| **Duración** | **72 h exactas** (`t1 = t0 + 259 200 s`), **continuas**, **ampliables, no reducibles** (`R0 §7.1`) |
| **Fronteras** | **instantes UTC fijos** `t0`/`t1` (`00:00:00Z` de un día → `00:00:00Z` de `D+3`) |
| **Ventana canónica del legítimo** | la ventana **es** `[t0,t1]` (la métrica §8 fija la ventana canónica por **caso**; el legítimo tiene **una sola** ventana) |
| **Actividad** | GHOSTS **continuo** día/noche (franjas de referencia `00:45–04:45Z` y `12:00–16:00Z`, **en bucle**, `L0 §5.1`) |
| **Config** | Wazuh **virgen** (`C1` = RS1+RS2, `RS3=RS4=0`) + `logall_json` **ON** **solo** en la ventana |

> **Por qué `00:00:00Z`:** (a) es un **corte UTC redondo** ⇒ el `[t0,t1]` cubre **exactamente 3 días de
> calendario** ⇒ **3 ficheros diarios** de alertas y **3 ficheros de archivo** (si rotan) — **predecible y
> auditable**; (b) evita bordes incómodos de medianoche; (c) el **reloj autoritativo es UTC** (Wazuh sella
> en UTC, `state.md:108`).

### 3.2 Fecha de arranque (la decide el humano)

- **Plantilla (propuesta):** `t0 = D 00:00:00Z` → `t1 = D+3 00:00:00Z`, donde **`D`** lo elige el humano.
- **Ejemplo orientativo** (no vinculante): `t0 = 2026-10-20T00:00:00Z` → `t1 = 2026-10-23T00:00:00Z`.
- **Requisitos de la fecha:** PC encendido y **sin suspensión** los 3 días; **sin tocar la VM**; si es
  posible, **evitar** el cambio de hora de **DST** (Europa: **2026-10-25**) — si `[t0,t1]` lo cruza, se
  **declara** (Wazuh es UTC; solo cambia la hora **local** del disparador de las tareas).

### 3.3 Cómo se sella `t0`/`t1` (sin tocar la VM en la ventana)

Igual que el baseline (`BL §1.4`): **no** se escribe `t0`/`t1` desde el invitado (eso sería "tocar la VM").
- **`t0`/`t1` = instantes UTC fijos** (§3.1).
- **Reloj del host** sincronizado; `start_utc` registrado por la **tarea del host** (≤ `t0 − 30 min`);
  `stop_utc` por la **tarea de parada** (≥ `t1`).
- **Evidencia manager-side:** primera/última alerta del agente **`001`** dentro de `[t0,t1]`.
- **Evidencia invitado-side** (recogida **después** de `t1`): log de la actividad GHOSTS y `history_timeline`.

### 3.4 Qué hace el humano (⚠️ **crítico**)

1. **Dejar el PC (sobremesa) ENCENDIDO y SIN suspensión** los **3 días** de la ventana (corriente, plan de
   energía "alto rendimiento", suspensión/hibernación **desactivadas**).
2. **NO tocar la víctima** (`victima-linux`): ni RDP/SSH, ni consola GUI, ni `vmrun … runProgramInGuest`,
   ni snapshotar, **durante `[t0,t1]`**. Cualquier acceso genera eventos y **ensucia** la ventana.
3. **No apagar/reiniciar** el PC ni cerrar VMware.
4. El humano **sí puede** estar delante (lo prohido es **interactuar** con la VM medida).

---

## 4. Preparación (antes de `t0`)

> **Ventana de preparación: `[t0 − 45 min, t0)`.** Todo lo que se haga aquí genera eventos **antes de `t0`**
> (no contaminan la medida). Se reutiliza el patrón de L0 y del baseline.

### 4.1 Secuencia (un solo script host-side + armado del invitado)

**A) Infraestructura del host (tareas del host, patrón `baseline_host_control.ps1`):**

1. **Revert** de `victima-linux` a **`lab-listo-legit`** (`vmrun revertToSnapshot`).
   *(El **manager NO se revierte**: conserva sus alertas; `vmrun_config.md` §4.)*
2. **Start** `victima-linux` (`nogui`) y **start** `wazuh-server` (`nogui`, idempotente) → `arrancar_manager.sh`
   para dejar `wazuh-manager` `active`.
3. **Start** de la "internet local" (`start_internet_local.ps1`) y del **GHOSTS servidor**
   (`start_ghosts.ps1`); **verificar** firewall `TFG-ghosts-5000` (o crear) acotado a `192.168.65.0/24`.
4. **`logall_json` ON** (`logall_json_ctl.sh on`, por SSH al manager, sudo por STDIN) → reinicia el manager
   (el churn queda **antes de `t0`**); verificar `<logall_json>yes</logall_json>`.

**B) Preparación de la víctima (antes de `t0`; aquí **sí** se puede tocar):**

5. **Verificación negativa de aislamiento** desde la víctima (NAT off): `ip route` sin `default`,
   `verificar_internet_local.sh` (8080 `200`, 9090 `200`, 9092 `201/207`), `curl` externo **falla**.
6. **Reconciliar** la máquina GHOSTS (evitar el **duplicado** del primer arranque; conservar la del
   `instance/id.json`) y comprobar que el cliente **se registra** (`ghosts_api.py wait victima-linux`).
7. **Armar la timeline de 72 h**: versionar **`timeline_72h.json`** (nueva; ver §4.2) y **entregarla** por el
   servidor (`ghosts_api.py send-timeline victima-linux --timeline …/timeline_72h.json`).
8. **Armar la tarea del invitado** (**`TFG-Ghosts-Legit`**): arranca el **cliente GHOSTS** y **lo mantiene
   vivo** (relanza si muere) durante las 72 h. Se registra **antes de `t0`**; su telemetría **se declara**.
9. **Prueba en seco** (fuera de ventana, minutos): confirmar que el cliente **ejecuta acciones** con la
   timeline de 72 h (≥ 1 acción por handler; rastro visible en Wazuh), y **anotar** el estado inicial del
   contador (`history_timeline`).

**C) Armar las tareas del host (arranque/parada/vigilancia):** ver §5.1.

**D) Verificación previa (checklist, TODO antes de `t0`):** manager `active` · agente `001` `active` ·
`<logall_json>yes` · GHOSTS API responde (`/api/machines`) · internet local responde · cliente registrado ·
timeline `Run` · tarea `TFG-Ghosts-Legit` **`Ready`** · **NAT off** · reloj UTC correcto · **suspensión
desactivada** (host y, si aplica, invitado) · snapshot `lab-listo-legit` intacto.

### 4.2 La timeline de 72 h (diseño; el fichero smoke no basta)

> El `timeline_smoke.json` de L0 solo produjo **14 acciones por ciclo** (8 `Command` + 6 `Curl`) y está
> pensado para **humo**, no para 72 h. L1 necesita una **timeline de régimen**.

- **`timeline_72h.json`** (nueva, versionada, **`sha256`**): handlers con **ventanas UTC diarias**
  (`UtcTimeOn`/`UtcTimeOff`) que cubren **día y noche** (franjas de referencia `12:00–16:00Z` y
  `00:45–04:45Z`), con **`Loop`** para repetir cada día, y **actividad variada**:
  - **Ficheros** (`Command`): crear/leer/editar/mover/comprimir/hashear en `~/Documentos`/`~/Descargas`
    (utilidades reales: `mkdir`, `echo`, `cp`, `mv`, `gzip`, `tar`, `md5sum`, `ls`).
  - **Red local** (`Curl`): visitar la web estática `:8080` (intranet/noticias), **descargar** ficheros
    de `:8080/descargas/…`, **subir** a la nube (`:9092`), **postear** al *paste* (`:9090`).
- **Regla KISS:** **no** se inventan decenas de handlers; basta con **pocos handlers en bucle** con `Delay`
  razonables para cubrir las franjas. El **realismo** lo da el **bucle día/noche**, no el número.
- **Verificación obligatoria:** en la **prueba en seco** (§4.1-B9), comprobar que la timeline **produce
  acciones en las dos franjas** y que estas **dejan rastro visible por Wazuh** (criterio G3 de L0).
- **Se versiona y entra en B10** (§7).

---

## 5. Ejecución: arranque/parada automáticos, disciplina y vigilancia

### 5.1 Arranque/parada automáticos (tareas, patrón del baseline)

> **Decisión de diseño:** **no** se usa un proceso en segundo plano (lección `vmrun_config.md` §7): se
> gobierna con el **Programador de tareas de Windows** (host) + una **tarea del invitado** (víctima).

| Tarea | Ámbito | Cuándo | Qué hace |
|---|---|---|---|
| **`TFG-Legit-Prep`** | **host** | `t0 − 45 min` | revert `lab-listo-legit` + start `victima-linux` + start `wazuh-server` + `arrancar_manager.sh` + start internet local + start GHOSTS + `logall_json` ON + log UTC |
| **`TFG-Legit-Arm`** | **host** | `t0 − 20 min` | (o **manual** con sesión delante) armar timeline + `TFG-Ghosts-Legit` + iniciar cliente + verificación previa (§4.1-D) |
| **`TFG-Ghosts-Legit`** | **invitado** | `t0 − 5 min`, durante 72 h | arranca el cliente GHOSTS y lo **mantiene vivo** (relanza si muere) |
| **`TFG-Legit-Watch`** | **host** | cada **2–3 h** en `[t0,t1]` | **vigilancia pasiva** (§5.3): GHOSTS API + manager; **sin tocar la víctima** |
| **`TFG-Legit-Stop`** | **host** | `t1 + 5 min` | `stop victima-linux soft` (el manager **sigue** encendido para la extracción) |

- Los **scripts** se crean en `Soporte/Laboratorio/legitimo_72h/` (`legitimo_host_control.ps1` con fases,
  `armar_legitimo.ps1`, `vigilancia_legitimo.ps1`), **sin secretos** (credenciales del invitado **por
  variables de entorno**, como `baseline_host_control.ps1`).
- **Probados en seco** antes de la fecha elegida (fase `-WhatIf`/dry-run y una **prueba corta** fuera de ventana).

### 5.2 Disciplina durante `[t0,t1]` (regla dura)

- **CERO** acceso a `victima-linux`: ni RDP, ni SSH, ni `vmrun … runProgramInGuest`/`copyFile*`, ni consola
  GUI, ni snapshots (paridad con `BL §1.2`).
- **No** se cambia **config** a mitad de ventana (ni Wazuh, ni GHOSTS, ni internet local).
- El **manager** puede consultarse **por SSH de solo lectura** (no es la VM medida) ⇒ sus eventos caen al
  agente `000` (manager) y se **excluyen** por filtro de agente (§6.2).
- **Prueba anti-contaminación post-hoc:** buscar logon/sesión del operador (`5715`/`PAM`, `srcip`
  `192.168.65.1`) atribuibles al agente **`001`** dentro de `[t0,t1]`; si hay → ventana **INVÁLIDA** (§8).

### 5.3 Vigilancia (que GHOSTS siga vivo y que el manager no se caiga)

> **Principio:** vigilar **sin tocar la víctima**. Se usan **señales del host y del manager**, no del invitado.

1. **GHOSTS vivo (host-side):** `TFG-Legit-Watch` consulta la **API** (`GET /api/machines` →
   `statusUp`/`lastReportedUtc`) → si el último reporte es **más viejo que un umbral** (p. ej. > 10 min),
   **anota anomalía**. *(La tarea del invitado `TFG-Ghosts-Legit` es la que **relanza** al cliente; la
   vigilancia solo **observa**.)*
2. **Manager vivo:** por SSH de **solo lectura**: `systemctl is-active wazuh-manager` + conteo de las
   **últimas alertas del agente `001`** (crecimiento del fichero diario). Si el manager está caído o el
   diario no crece → **anota anomalía**.
3. **Resultado:** **log host-side** (`vigilancia_legitimo.log`, UTC) con marca de tiempo por chequeo. Al
   cierre, **resumen de anomalías** (una anomalía **no** invalida por sí sola; se **juzga** en §8).

---

## 6. Extracción (alertas + denominador `M` + contador de acciones)

> Se ejecuta **después de `t1`**, con la víctima **parada** y el manager **encendido**. Regla vigente de
> Fase 3: **fichero diario**, **NO** `alerts.json` (`state.md:97`).

### 6.1 ALERTAS de `[t0,t1]` (varios días — ¡ojo!)

- **Fuente:** `/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`. Con `t0 = D 00:00Z` y
  `t1 = D+3 00:00Z`, son **3 ficheros diarios** (`<DD>`, `<DD+1>`, `<DD+2>`).
- **Herramienta:** `_artefactos/scripts/extraer_alertas.py` **sin modificar** (verificar `sha256` repo ==
  copia del manager antes de extraer, lección de sincronía `state.md:85`); extracción en el manager como
  `root` (sudo por STDIN).
- **Por cada día:** `--detail` (una fila por alerta) y agregado; luego **unión** de los 3 tramos.
- **Aislamiento por agente:** filtrar a **`agent_name == victima-linux`** + cruce **`agent.id == 001`**
  (snippet canónico, `BL §2.2`). El manager (`000`) y cualquier otro agente **nunca** entran.
- **Regla de medianoche:** ya cubierta por el diseño (3 ficheros) — no hay caso especial.

### 6.2 DENOMINADOR `M` (`archives.json`)

> **⚠️ Hallazgo material (condiciona el orden de operaciones):** `logall_json_ctl.sh` ejecuta
> `sudo -n rm -f "$ARCH"` **tanto en `on` como en `off`** ⇒ **`off` BORRA `archives.json`**. Por tanto:
> **la copia del archivo y el cómputo de `M` se hacen ANTES de apagar `logall_json`.**

- **Secuencia:**
  1. **Copiar** `/var/ossec/logs/archives/` (y/o `archives.json` + los ficheros diarios de archivo si
     rotan) del manager a **fuera** (`Dataset/Legitimo/legitimo_72h/denominador/` o `D:\TFG-VMs\…`).
  2. **Contar** las **líneas/entradas decodificadas con `timestamp ∈ [t0,t1]`** ⇒ **`M`**. Helper nuevo
     `contar_denominador.py` (determinista, solo lectura; **no** se toca `extraer_alertas.py`).
  3. **Registrar** tamaño total y tasa (`Δ bytes / 72 h`); **evaluar** el **disparador del fallback**
     (`> ~5 GB` ⇒ `FP/acción`+`FP/hora`, `L11`). Con L0 (**≈ 300 MB**) se espera **no** activarlo.
  4. **`logall_json` OFF** (`logall_json_ctl.sh off`) ⇒ restaura `ossec.conf` (`diff` con la copia) y
     reinicia el manager. **Se verifica** `<logall_json>no</logall_json>` y manager `active`.
- **Rotación:** **verificar antes** (en preparación) si `archives.json` rota a ficheros diarios
  (`/var/ossec/logs/archives/<AAAA>/<Mes>/…`); si rota, se **unen** los que cubran `[t0,t1]`. **Si no rota**,
  es un único fichero. Se **declara** lo observado.
- **Alcance de `M` (decisión abierta, §14):** conteo **titular** = eventos del **endpoint** (agente `001`);
  **complemento** = **total** de líneas de `archives.json` (incluye manager). Se reportan **ambos** y el gate
  decide (la métrica §2 dice "una línea de archives.json" sin restringir agente; la **unidad** es del endpoint).

### 6.3 CONTADOR DE ACCIONES GHOSTS

- **Fuente:** tabla **`history_timeline`** (PostgreSQL, host) — contador **exportable** (L0 G4).
- **Exportar** las acciones con marca temporal **dentro de `[t0,t1]`** (excluye las **28** residuales de la
  prueba de L0): `psql … "select … where createdutc >= '<t0>' and createdutc < '<t1>'"` (o **diferencia** con
  el conteo previo anotado en preparación).
- **Producto:** `Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv` (nº total, por `handler`, y por hora
  → soporta `FP/acción` y `FP/hora`).

### 6.4 Dónde queda todo

| Producto | Ruta |
|---|---|
| Alertas (detalle por alerta, agente 001) | `Dataset/Legitimo/legitimo_72h/alertas_detalle.csv` |
| Catálogo agregado por `rule.id` | `Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv` (+ `_<DD>.csv` por día) |
| Vista por origen/capa (opcional, paridad 02b) | `Dataset/Legitimo/legitimo_72h/resumen_por_origen.csv` |
| Denominador `M` + tamaño/rotación | `Dataset/Legitimo/legitimo_72h/denominador_M.csv` (+ `denominador/` con la copia) |
| Contador de acciones GHOSTS | `Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv` |
| Ficha de la ventana (t0/t1, config, validez, evidencia) | `Dataset/Legitimo/legitimo_72h/ventana_meta.md` |
| Evidencia operativa host-side + logs de vigilancia | `Soporte/Laboratorio/legitimo_72h/` (`resultado.md`, `*.log`) |
| Scripts (host/invitado, extracción, vigilancia, timeline) | `Soporte/Laboratorio/legitimo_72h/` |

- **Cabecera obligatoria (regla `R2 §6.7`):** cada CSV lleva `metrica_version` (`1`), `boveda_version`, y
  los **`sha256` de todas las entradas**; sin esa cabecera **la cifra no es válida**.

---

## 7. Sellado de la bóveda B10

> **B10 = config del legítimo** (GHOSTS + "internet local" + instrumentación del denominador). Hoy está
> **pendiente** (`boveda_congelacion.md` B10). **Lo cierra L1.**

**Contenido del sello (valores + `sha256`):**

| Elemento | Valor / huella |
|---|---|
| **GHOSTS** | `v8.3.1`, commit `4d2e160860f508f699f935472b5515358f534844` (pin por tag/commit) |
| **Timeline** | `timeline_72h.json` (+ `sha256`) |
| **"Internet local"** | `serve_site.py` (+ `sha256`), `site/**` (+ `sha256`), puertos `8080/9090/9092`; sinks `sink_http.py`/`sink_webdav.py` (huellas) |
| **Instrumentación `M`** | `<logall_json>yes</logall_json>` ⇒ `archives.json`; `logall_json_ctl.sh` (+ `sha256`) |
| **Config de la ventana** | `t0`/`t1`, sobres; `C1` virgen (`RS1+RS2`, `RS3=RS4=0`) |

- **Dónde:** L1 **no puede tocar `Soporte/Metrica/`** (protegido). Se escribe un **sidecar**
  `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` con los valores y huellas; **el humano/orquestador**
  aplica la actualización a **`Soporte/Metrica/boveda_congelacion.md` (B10)** y recalcula
  `boveda_congelacion.sha256`. **Punto de coordinación declarado** (igual que L0).
- **Consecuencia:** el sellado de B10 con los valores reales es **parte del cierre de L1** (CA-L1-08).

---

## 8. Validez: criterios objetivos y qué invalida la ventana

### 8.1 Criterios de `ventana VÁLIDA` (se cumplen **todos**)

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **V1 — Cobertura** | Las alertas del agente `001` cubren `[t0,t1]`: primera ≤ `t0 + δ` y última ≥ `t1 − δ` (δ pequeño, p. ej. ≤ 30 min), con **huecos** entre alertas **acotados** | detalle filtrado + serie temporal por hora |
| **V2 — GHOSTS vivo** | Hay **acciones** distribuidas a lo largo de **toda** la ventana (día **y** noche), no un pico y silencio | `ghosts_acciones.csv` por hora + `statusUp`/`lastReportedUtc` del log de vigilancia |
| **V3 — Manager vivo** | `wazuh-manager` `active` en los chequeos; el **fichero diario** de los 3 días existe y **crece** | log de vigilancia + tamaño de los 3 diarios |
| **V4 — 0 contaminación** | **0** eventos de logon/sesión del **operador** (`192.168.65.1`) atribuibles al agente **`001`** en `[t0,t1]` | prueba anti-contaminación (`BL §4.2`) |
| **V5 — Aislamiento** | NAT off durante la ventana; la víctima solo habló con la "internet local" | `ip route` (pre/post) + logs de la internet local |
| **V6 — `M` obtenido** | `archives.json` de `[t0,t1]` **copiado** y `M` computado; tamaño/tasa registrados | fichero + `denominador_M.csv` |
| **V7 — Sin cambios a mitad** | No se cambió config (Wazuh/GHOSTS/internet local) ni se tocó la víctima | `git status` + log de tareas + auditoría |
| **V8 — PC sin suspensión** | El host **no** se suspendió/apagó/reinició en `[t0,t1]` | uptime/eventos del host + log de tareas |

### 8.2 Qué invalida la ventana (`→ se repite ENTERA`, paridad `BL §4.3`)

- La **víctima** se apaga/crashea o el agente `001` pierde conexión dentro de `[t0,t1]`.
- El **manager** se cae o **no** escribe los ficheros diarios de algún día.
- **Cualquier acceso del operador** a la víctima dentro de `[t0,t1]` (la contaminación **no se resta**).
- **GHOSTS deja de producir actividad** una parte **significativa** de la ventana (p. ej. > 1 ciclo día/noche).
- El **PC se suspende/apaga/reinicia**.
- `archives.json` de `[t0,t1]` **se pierde** (p. ej. si se apaga `logall_json` **antes** de copiarlo).
- Un **fallo de la herramienta** de extracción: se **re-extrae** (idempotente) ⇒ **sigue válida** si el dato
  fuente está íntegro (matiz: solo la **herramienta**, no el dato).

> **Regla:** una ventana **parcial o dudosa no vale**; se **repite desde cero** (snapshot fresco + 72 h
> nuevas). Las incidencias se **registran** (no se maquillan). El **umbral** de "significativo" en V2 y el
> **veredicto** los **firma el humano** con la evidencia delante.

---

## 9. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **PC se suspende/apaga** en 3 días | Ventana inválida | Plan de energía "alto rendimiento", suspensión/hibernación off, en corriente; verificar antes de `t0`; V8 |
| **GHOSTS muere** a mitad | Hueco de actividad | **Tarea del invitado** `TFG-Ghosts-Legit` (relanza); vigilancia host-side; si hueco significativo → repetir |
| **Manager se cae / `failed`** | No hay telemetría | `arrancar_manager.sh` en preparación; vigilancia (V3); reinicio **fuera** de ventana si hiciera falta |
| **`archives.json` se borra** (por `logall_json_ctl.sh off`) | Se pierde `M` | **Copiar el archivo ANTES** de `off` (§6.2); orden de operaciones explícito |
| **Disco del manager lleno** | Escritura rota | `archives.json` ≈ **300 MB** (≪ 50 GB de disco); monitorizar espacio (vigilancia); alerta temprana |
| **La ventana cruza días** (varios ficheros diarios) | Extracción incompleta | Diseño `t0 = D 00:00Z` ⇒ **3 diarios**; unión controlada; regla de medianoche documentada |
| **`archives.json` rota** (se desconoce) | `M` incompleto | **Verificar la rotación** en preparación; unir ficheros si rota; declarar lo observado |
| **Duplicado de máquina GHOSTS** (cabos L0) | Contador impuro | **Reconciliar** antes de `t0`; contar por `createdutc ∈ [t0,t1]` |
| **Timeline de 72 h no rinde** (solo se probó el humo) | Actividad pobre | **Prueba en seco** obligatoria (§4.2); ajustar `Loop`/franjas antes de `t0` |
| **`sudo` no NOPASSWD** (VMs) | Scripts se atascan | Contraseña **por STDIN**, **nunca** en fichero (regla dura) |
| **DST** si `[t0,t1]` cruza `2026-10-25` | Disparador local desfasado | Preferir fechas antes; si cruza, **declarar** (Wazuh es UTC) |
| **Contaminación por nuestro acceso** | Medida invalidada | Disciplina dura (§5.2) + prueba anti-contaminación (V4) |
| **Fuga de secreto** | Seguridad | La contraseña del laboratorio **nunca** en ficheros; `git status` como control |
| **`_recursos/`/corpus tocados** | Rompe disciplina | Solo lectura; `Dataset/` solo la carpeta nueva |

---

## 10. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-L1-01** | Ventana **72 h** sellada en UTC (`t1 = t0+72 h`), con **arranque/parada automáticos** (tareas host + tarea invitado) **probados en seco**. | fichero de ventana + scripts + log de tareas |
| **CA-L1-02** | **Preparación**: revert a **`lab-listo-legit`** (snapshot citado), **`logall_json` ON** (verificado), internet local + GHOSTS arriba y **verificados desde la víctima**; todo **antes de `t0`**. | log host-side + salida de la víctima |
| **CA-L1-03** | **`timeline_72h.json`** versionada (`sha256`), produce acciones en **día y noche** (prueba en seco). | fichero + huella + evidencia |
| **CA-L1-04** | **0 contaminación**: 0 logon/sesión del operador (`192.168.65.1`) del agente `001` en `[t0,t1]`. | prueba anti-contaminación |
| **CA-L1-05** | **Alertas** extraídas del **fichero diario** (3 días), filtradas a `victima-linux` (cruce id `001`); **`extraer_alertas.py` sin cambios** (`sha256`). | CSVs + `sha256` |
| **CA-L1-06** | **`M`** obtenido (eventos decodificados en `[t0,t1]`), **copiado antes** de `logall_json off`; tamaño/tasa y **disparador de fallback** evaluados (`>5 GB` ⇒ no). | `denominador_M.csv` + copia + `logall_json_ctl.sh status` = `no` |
| **CA-L1-07** | **Contador de acciones** GHOSTS exportado (total + por hora, en `[t0,t1]`). | `ghosts_acciones.csv` |
| **CA-L1-08** | **B10 sellado**: sidecar con versiones + `sha256`; aplicado a `boveda_congelacion.md` B10 por humano/orquestador. | `b10_sellado.md` + B10 actualizado |
| **CA-L1-09** | **Validez evaluada** (V1–V8) con **veredicto** VÁLIDA/INVÁLIDA; si inválida → **repetida entera**. | `ventana_meta.md` |
| **CA-L1-10** | **Sin secretos**; `_recursos/`, corpus, `Hojas/`, `Soporte/Metrica/` sin tocar; `Dataset/` solo la carpeta nueva; manager **restaurado**; NAT off; snapshots originales intactos; **sin commit/push**. | `git status` + auditoría de texto |
| **CA-L1-11** | Cada CSV lleva cabecera `metrica_version`/`boveda_version` + `sha256` de entradas (`R2 §6.7`). | cabeceras de los CSV |
| **CA-L1-12** | **Gate humano**: `plan.md` en `status: approved_by_human` **antes** de ejecutar; **PC encendido sin suspensión** confirmado. | Frontmatter + confirmación |
| **CA-L1-13** | **Vigilancia** registrada (GHOSTS vivo, manager vivo) con log host-side, **sin acceso a la víctima**. | `vigilancia_legitimo.log` + `resultado.md` |

---

## 11. Gate humano (lenguaje sencillo)

> Aprobar **antes** de arrancar las 72 h.

1. **Qué voy a hacer.** Dejar la víctima Linux **funcionando sola durante 3 días** con la actividad
   "de oficina" de **GHOSTS** (ya montada y probada), mientras **Wazuh** (en su configuración de fábrica)
   registra todo. Al final, recojo: las **alertas**, el **número total de eventos** (el denominador) y
   el **número de acciones** que hizo GHOSTS.
2. **⚠️ Lo que necesito de ti.** El **PC encendido y sin suspensión 3 días**, y **no tocar la máquina
   víctima** en ese tiempo (ni entrar por remoto ni abrir su ventana). Si el PC se apaga/se suspende o
   entro en la víctima, la ventana **no vale** y **se repite entera**.
3. **Cuándo.** La **fecha la eliges tú** (propongo una plantilla: 3 días completos, de `00:00` a `00:00` UTC).
4. **Arranque/parada automáticos.** Se enciende/apaga solo con **tareas programadas** (como en el baseline):
   tú no tienes que hacer nada durante los 3 días.
5. **Conteo de eventos (`M`).** Para el % de falsas alarmas necesito el **total de eventos**; activo el
   contador de Wazuh **solo** en la ventana y lo **apago** al terminar. **Detalle delicado:** el apagado
   **borra** el fichero del contador, así que **lo copio antes** de apagarlo (ya contemplado).
6. **Sellado de la bóveda.** Dejo escritas (con huellas) las versiones exactas de GHOSTS y la "internet
   local". El cambio en el documento congelado lo aplicas tú/el orquestador (ese fichero está protegido).
7. **¿Todo de acuerdo?** ¿Y si la ventana sale inválida, la repito **entera** (no parcheo)?

---

## 12. Ficheros que se tocarán

**Nuevos (en ejecución, tras el gate):**

- `Soporte/Laboratorio/legitimo_72h/` → `README.md` · `legitimo_host_control.ps1` (fases) ·
  `armar_legitimo.ps1` · `vigilancia_legitimo.ps1` · `timeline_72h.json` ·
  `exportar_denominador.sh` · `exportar_acciones.sh` · `resultado.md` · `b10_sellado.md` · logs.
- `Dataset/Legitimo/legitimo_72h/` → `alertas_detalle.csv` · `ruleids_legitimos.csv` (+ por día) ·
  `resumen_por_origen.csv` · `denominador_M.csv` (+ `denominador/`) · `ghosts_acciones.csv` ·
  `ventana_meta.md`.
- `_artefactos/scripts/contar_denominador.py` (+ tests) — helper nuevo (solo lectura; **no** se toca
  `extraer_alertas.py`).
- `_fases/legitimo-72h/` → `plan.md`/`reviews.md`/`change-doc.md` (al archivar).

**Modificados (mínimo / coordinado):**

- `Soporte/Metrica/boveda_congelacion.md` (**B10**) + `boveda_congelacion.sha256` → **lo aplica el
  humano/orquestador** (L1 no toca `Soporte/Metrica/`).
- `Soporte/Laboratorio/vmrun_config.md` (si hace falta registrar el uso de `lab-listo-legit` en L1).
- `state.md`, `roadmap.md` (los cierra el orquestador).

**Reutilizados sin modificar:** `Soporte/Laboratorio/ghosts/*` (arranque/parada/cliente/contador) y
`Soporte/Laboratorio/internet_local/*`; `_artefactos/scripts/extraer_alertas.py`.

**Prohibido tocar:** `_recursos/**` (solo lectura), el **corpus**, `Hojas/`, `Soporte/Metrica/**`
(salvo la coordinación de B10), `_artefactos/scripts/extraer_alertas.py` y `filtrar_ruido.py`,
`Dataset/**` (salvo la carpeta nueva).

**Nada de `git commit`/`push`.** 🔑 **La contraseña del laboratorio nunca en ficheros.**

---

## 13. Trazabilidad (fuentes y afirmaciones verificadas)

| Afirmación | Cita verificable |
|---|---|
| **L1** = `legitimo-72h`: captura 72 h + denominador + sellado B10; depende de **L0** | `roadmap.md:73-76`; `state.md:19`; `_fases/reencuadre/plan.md` §10.2 |
| El **legítimo** = GHOSTS + **72 h** + internet local; **ampliable, no reducible** | `_fases/reencuadre/plan.md` §7.1 |
| **Cuello de botella** = 72 h de reloj; arrancar pronto | `_fases/reencuadre/plan.md` §10.3; `roadmap.md:91-92` |
| **Unidad** = evento decodificado; **`M`** con `<logall_json>`; **fallback** `FP/acción`+`FP/hora` si >~5 GB | `Soporte/Metrica/metrica_hids.md` §2 (y §9.2 `L11`) |
| **Reglas de conteo** (auto-alerta = FP; doble conteo; nada en silencio; cabecera con `sha256`) | `Soporte/Metrica/metrica_hids.md` §6 |
| **Unidad común entre HIDS** = acción GHOSTS / hora | `Soporte/Metrica/metrica_hids.md` §10 |
| **B10 pendiente** = GHOSTS + internet local + `logall_json` | `Soporte/Metrica/boveda_congelacion.md` B10 |
| **Datos L0**: GHOSTS v8.3.1; **≈4,17 MB/h ⇒ ≈300 MB a 72 h** (≪5 GB, sin fallback); `lab-listo-legit`; rastro `80792` | `_fases/legitimo-infra/change-doc.md` §2; `decision_gonogo.md`; `instrumentacion_denominador.md` §3 |
| **Patrón de ventana** (tareas host + tarea invitado; no acceso en ventana; ventana inválida → repetir) | `_fases/fase-02b-baseline/plan.md` §1.3-1.5, §4.3; `Soporte/Laboratorio/windows/baseline_host_control.ps1` |
| **Regla vigente**: extracción del **fichero diario**, NO `alerts.json` | `state.md:97`; `_fases/fase-02b-baseline/plan.md` §2.1 |
| **`logall_json_ctl.sh off` BORRA `archives.json`** (`rm -f` en `on` **y** `off`) | `Soporte/Laboratorio/ghosts/logall_json_ctl.sh` (líneas 14-26) |
| **Manager no se revierte**; NAT off; `sudo` no NOPASSWD (STDIN) | `Soporte/Laboratorio/vmrun_config.md` §4; `ghosts/README.md` §8 |
| **Cabos L0**: duplicado de máquina; `wazuh-manager` puede quedar `failed`; timeline solo *smoke* | `_fases/legitimo-infra/change-doc.md` §4; `ghosts/README.md` §8-9 |

---

## 14. Decisiones abiertas y lo que NO cuadra

### 14.1 Decisiones abiertas (las lleva el humano/orquestador)

1. **Fecha de arranque `t0`** (la decide el humano; plantilla `D 00:00:00Z → D+3 00:00:00Z`) y si se
   **evita** el DST (`2026-10-25`).
2. **Alcance titular de `M`**: ¿**endpoint** (agente `001`) como titular + **total** como complemento
   (propuesta), o **total de `archives.json`** como titular? (la métrica §2 no restringe agente; la unidad
   es del endpoint).
3. **Sellado B10**: ¿quién aplica el cambio en `Soporte/Metrica/boveda_congelacion.md` (protegido)?
   Propuesta: **humano/orquestador**, con el sidecar de L1 (§7).
4. **Keep-alive del cliente GHOSTS** (tarea del invitado que relanza si muere): su telemetría **se declara**;
   ¿se aprueba?
5. **Rotación de `archives.json`**: se **desconoce** si rota a diario; se **verifica en preparación** y se
   **declara** (afecta a cómo se une `M`).
6. **Umbral de "hueco significativo"** de V2 (GHOSTS parado) — fijarlo con el humano antes de `t0`.

### 14.2 Lo que NO cuadra (declarado, para el revisor)

1. **`archives.json` vs `alerts.json`**: la **regla vigente** obliga al **fichero diario** de **alertas**;
   el **denominador `M`** vive en `archives.json` (**no** diario por defecto). Son **dos fuentes distintas**;
   L1 lo declara y **verifica** la rotación del archivo.
2. **`logall_json_ctl.sh off` borra `archives.json`** ⇒ el orden de operaciones es **crítico** (§6.2). Si se
   descuida, **`M` se pierde** y la ventana sería inválida.
3. **La timeline de 72 h no existe** (L0 solo probó *smoke*): **hay que crearla y probarla** (§4.2). Riesgo
   real de que GHOSTS genere **menos** actividad de la prevista ⇒ la **prueba en seco** es obligatoria.
4. **GHOSTS 72 h sin incidencias no está garantizado** (duplicado de máquina, cuelgues): por eso hay
   **keep-alive** + **validez** que puede **invalidar** la ventana y obligar a **repetir**.
5. **`M` por evento es per-HIDS y no comparable** con Velociraptor (`metrica_hids.md` §2/§10): la
   comparación se hará por **acción/hora** en L2/VR; aquí solo se **produce** el dato.
6. **L1 no analiza**: si al abrir los datos algo no cuadra (p. ej. `dudosa`), **no** se arregla aquí; se
   resuelve en **L2** con la métrica congelada.
7. **El "significativo" de V2 y el veredicto de validez** requieren **juicio humano** con la evidencia:
   el plan **no** finge un umbral automático mágico.

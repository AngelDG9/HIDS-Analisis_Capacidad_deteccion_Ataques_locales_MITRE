---
bloque: legitimo-infra
nombre: L0 — Infraestructura del legítimo (GHOSTS + "internet local" + denominador M) con go/no-go
version: 1
status: approved_by_human
fecha: 2026-10-18
fecha_aprobacion: 2026-10-18
aprobado_por: humano
autor: tfg-planner
depende_de: reencuadre (R0, cerrado) · reencuadre-docs (R1, cerrado) · reencuadre-metrica (R2, métrica congelada)
gate: |
  **APROBADO (2026-10-18).** Respuestas del humano al gate (§11): Q1 montar GHOSTS + internet local → **SÍ** · Q2 dónde corre cada cosa (host + víctima; Wazuh intacto salvo la prueba) → **SÍ** · Q3 contador `logall_json` solo en la prueba y apagado después → **SÍ** · Q4 plan B (actividad real con navegador/apps) → **SÍ** · Q5 sin Docker (host-native o VM pequeña) → **SÍ** · Q6 en L0 solo se monta y se prueba (las 72 h son L1) → **SÍ**.
---

# plan.md — Bloque `legitimo-infra` (L0)

> **Qué es este documento.** El **plan** del bloque **L0** del programa del reencuadre: **montar la
> infraestructura** con la que se medirá el **legítimo** (la parte que produce las **falsas
> alarmas**) — **GHOSTS** (servidor API + cliente(s)), la **"internet local"** (webs, descargas,
> nube, *paste*) y la **instrumentación del denominador `M`** — más la **decisión go/no-go** (con
> **plan B declarado**).
>
> **Regla dura (R2).** La métrica y las tablas están **congeladas**; L0 **no las cambia**. L0
> **prepara** lo que `L1` (`legitimo-72h`) medirá. **L0 NO mide** (la captura de 72 h es L1).
>
> **Este bloque NO implementa** hasta el gate: este fichero es **diseño**. Tras el gate, la
> ejecución monta, prueba y documenta la infraestructura.

## Anclas

- `(R0 §X.Y)` = `_fases/reencuadre/plan.md` (v2, **aprobado**, 2026-10-16). En especial **§7** (plan
  del legítimo), **§9** (internet), **§10** (secuencia; L0 depende de R2), **§11** (riesgos).
- `(R2 §X.Y)` = `Soporte/Metrica/metrica_hids.md` (`version: 1`, **congelada**) y
  `_fases/reencuadre-metrica/plan.md` (v2). En especial **§2.2** (unidad del legítimo + denominador
  `M` + fallback) y **§8** (unidad común entre HIDS: **acción GHOSTS / hora**).
- `(R1)` = `context.md` / `requirements.md` / `roadmap.md` (v2, vigentes).
- `state.md` — resumen del reencuadre (arriba del fichero).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Contexto verificado (lo que existe y lo que se ha comprobado)](#2-contexto-verificado-lo-que-existe-y-lo-que-se-ha-comprobado)
3. [Arquitectura propuesta (qué corre dónde)](#3-arquitectura-propuesta-qué-corre-dónde)
4. [El "internet local" (reuso + añadido)](#4-el-internet-local-reuso--añadido)
5. [La actividad legítima (GHOSTS): roles, timeline y recuento](#5-la-actividad-legítima-ghosts-roles-timeline-y-recuento)
6. [La instrumentación del denominador `M`](#6-la-instrumentación-del-denominador-m)
7. [El go/no-go y el plan B](#7-el-gono-go-y-el-plan-b)
8. [Higiene de medida (fuera vs dentro de ventana)](#8-higiene-de-medida-fuera-vs-dentro-de-ventana)
9. [Riesgos y decisiones abiertas](#9-riesgos-y-decisiones-abiertas)
10. [Criterios de aceptación (verificables)](#10-criterios-de-aceptación-verificables)
11. [Gate humano (lenguaje sencillo)](#11-gate-humano-lenguaje-sencillo)
12. [Ficheros que se tocarán](#12-ficheros-que-se-tocarán)
13. [Trazabilidad (fuentes y afirmaciones verificadas)](#13-trazabilidad-fuentes-y-afirmaciones-verificadas)
14. [Lo que NO cuadra (declarado, para el revisor)](#14-lo-que-no-cuadra-declarado-para-el-revisor)

---

## 0. Resumen ejecutivo

L0 monta **tres piezas** y toma **una decisión**:

1. **GHOSTS** (CMU-SEI) — **servidor API + PostgreSQL** (fuera de las VMs víctima) y **cliente en la
   víctima Linux**; camino a Windows **preparado** (no desplegado). Genera **actividad legítima real
   (NPCs)**.
2. **"Internet local"** — los servicios que GHOSTS necesita (webs que visitar, ficheros que
   descargar, nube, *paste*) **reaprovechando** lo ya construido para los ataques
   (`sink_http.py`, `sink_webdav.py`) **+ un servidor web estático** (stdlib) que **no existe hoy**.
3. **Instrumentación del denominador `M`** — dejar **listo y probado** el `<logall_json>` del
   manager (mide el nº de eventos decodificados), **sin activarlo durante las medidas de ataque**;
   con **estimación de tamaño a 72 h** y **disparador del fallback** (`R2 §2.2`).
4. **Go/no-go** — criterios objetivos; si GHOSTS no es viable en tiempo/presupuesto → **plan B
   declarado** (acciones reales por guion con navegador/apps reales, no un guion plano).

**Hallazgos de la inspección (2026-10-18) que condicionan el diseño:**

- El **host** es **Windows 10 Home**, ~**16 GiB** de RAM, con **.NET SDK 8** únicamente, **sin
  Docker** y **sin** distro WSL → **evitar Docker Desktop** (exigiría WSL2/*Virtual Machine
  Platform*, que **puede chocar con VMware** y con la víctima Windows; y Win10 Home no soporta
  Hyper-V completo).
- GHOSTS **v9** pide **API .NET 10 + PostgreSQL 16** (los clientes son Universal/.NET 9 · Lite/.NET 8
  · Windows/.NET 4.6.2). El **SDK del host (v8)** **no** basta para el API v9 ⇒ **decisión de
  *pin* de versión** (§9, abierta 1).
- GHOSTS es **más pesado que "un script"**: es un **bloque** con servidor, base de datos y clientes
  (`(R0 §1.2.6)`).

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo del bloque

Dejar **construida, probada y documentada** la infraestructura con la que `L1` capturará **72 h de
actividad legítima** (cuello de botella del TFG) y **decidir go/no-go** con criterios objetivos.

### 1.2 Entra

- Desplegar **GHOSTS servidor** (API + PostgreSQL) y **cliente Linux** en `victima-linux`; **preparar
  (sin desplegar aún)** el camino Windows.
- Montar la **"internet local"** (webs, descargas, nube, *paste*) y **verificarla sin internet**.
- Dejar **listo y probado** el **denominador `M`** (`<logall_json>`), **apagado** por defecto.
- **Go/no-go** documentado + **plan B** declarado.
- **Snapshots** nuevos para `L1` (`lab-listo-legit` en la víctima) y **pre-staging** con `URL+sha256`.
- La documentación de montaje/operación en `Soporte/Laboratorio/`.

### 1.3 NO entra (fuera de alcance de L0)

- **Medir**: la captura de **72 h**, el FPR, T3/T4 → es **L1** y **L2**. L0 **no produce cifras de
  resultado** (solo **pruebas de humo** de la infraestructura).
- **Activar `logall_json` durante ventanas de ataque** (solo **prueba acotada** y se **apaga**).
- **Añadir reglas/artifacts propios** (Wazuh `+propias`/`+externas`, VR `+custom`): **contingentes a
  gate** (`R0 §10.2`).
- **Velociraptor** (`V0`) y **ataques Windows** (`B1`).
- **Tocar** el corpus, `Hojas/`, `Dataset/`, `Soporte/Metrica/`, `_recursos/` (solo lectura) ni el
  manager **salvo** la **prueba acotada** de `logall_json` (que se **revierte**).
- **Mezclar HIDS**: la corrida legítima es **solo Wazuh** (Q10/Q11, `R0 §10.3`).

---

## 2. Contexto verificado (lo que existe y lo que se ha comprobado)

### 2.1 Lo que **ya existe** y se **reaprovecha**

| Elemento | Dónde | Estado (verificado) | Uso en L0 |
|---|---|---|---|
| **`sink_http.py`** | `Soporte/Ataques/receiver/sink_http.py` | HTTP en `192.168.65.1:9090`; `do_POST`/`do_PUT` **genérico** (registra ruta+IP+len+`sha256`) | Sirve de **"paste"** (`POST /paste`), **C2/sink** (`POST /c2/beacon`) y *health check* (`GET`) |
| **`sink_webdav.py`** | `Soporte/Ataques/receiver/sink_webdav.py` | WebDAV mínimo (OPTIONS/PROPFIND/MKCOL/PUT/GET/HEAD/DELETE), `192.168.65.1:9090` | **"Nube"** de la internet local (cliente `rclone`) |
| **Pre-staging** (patrón) | `Soporte/Laboratorio/windows/prestaging_material.md` | URL + tamaño + `sha256`; material fuera del repo | Patrón para fijar el material de GHOSTS |
| **Laboratorio** | `victima-linux` `.129` (2 vCPU/3 GB) · `wazuh-server` `.128` (2 vCPU/6 GB) · `victima-windows` `.130` · host `.1` | VMnet1 `192.168.65.0/24`; **NAT off**; snapshots `base-limpia`/`lab-listo` | Base de L0 y de L1 |
| **`vmrun` + snapshots** | `Soporte/Laboratorio/vmrun_config.md` | Revert/start/stop; NAT off persistente | Snapshot nuevo para L1 |
| **Wazuh virgen** | `Soporte/Wazuh/Configuracion/active_ruleset.txt` | RS1 4.471 · RS2 44 · **RS3=RS4=0**; 4.14.7 | Sujeto de la medida de FP (virgen) |
| **Métrica/denominador** | `Soporte/Metrica/metrica_hids.md` v1 + `boveda_congelacion.md` **B10** | `M` = eventos decodificados (`archives.json`); **B10 pendiente** | Lo que L0 debe **preparar** para sellar |

### 2.2 Lo que **NO existe** (lo que L0 añade)

- **GHOSTS** (ni servidor ni cliente) y su **material fijado** (URL+`sha256`).
- Un **servidor web estático** local con **contenido creíble** (webs a visitar, ficheros a
  descargar) — hoy solo hay *sinks* triviales.
- El **denominador `M`** instrumentado y **medido** (solo especificado en R2).
- El **snapshot** de la víctima con el cliente GHOSTS listo (`lab-listo-legit`).

### 2.3 Hallazgos de la inspección del host (2026-10-18, solo lectura)

| Comprobación | Resultado | Implicación |
|---|---|---|
| SO | Windows 10 **Home**, build 19045 | **Sin Hyper-V completo**; Docker Desktop usaría **WSL2** |
| RAM | ~16 GiB (17.1 GB) | Presupuesto ajustado: 2 VMs (6+3 GB) + host |
| `.NET` | **SDK 8.0.403** (sin 9/10) | No basta para el **API de GHOSTS v9** (necesita .NET 10) |
| Docker | **ausente** | Habría que instalarlo → **riesgo Hyper-V/WSL2 ↔ VMware** |
| WSL | stub **sin distro** | Igual riesgo si se activa la plataforma de VM |
| Python | 3.13 presente | Sirve para el **servidor web estático** (stdlib) |

> **Consecuencia de diseño:** **no** se propone Docker Desktop. Se proponen **dos rutas** (§3) y el
> **go/no-go** decide.

---

## 3. Arquitectura propuesta (qué corre dónde)

### 3.1 Tabla de componentes

| Componente | Tecnología | Dónde corre | Puertos (VMnet1) | Por qué ahí |
|---|---|---|---|---|
| **GHOSTS API** | .NET (según *pin*, ver §9) | **Host** `192.168.65.1` *(recomendado)* o VM dedicada `ghosts-server` *(alternativa)* | **5000** (API) | Fuera de las VMs medidas; no contamina al detector; evita 3.ª VM |
| **GHOSTS PostgreSQL** | PostgreSQL 16 | **Host** (escucha **solo en localhost**) | **5432** (no expuesto) | Persistencia de NPCs/timelines; no debe ser visible a la víctima |
| **GHOSTS cliente (Linux)** | Universal (.NET 9) **o** Lite (.NET 8) | **`victima-linux`** `.129` | — | Es el **endpoint medido** (donde corre el agente Wazuh) |
| **GHOSTS cliente (Windows)** | Windows (.NET 4.6.2) | **`victima-windows`** `.130` — **preparado, NO desplegado** | — | Camino a `B1`; solo se deja documentado/construido |
| **Internet local — web estática** | `python -m http.server` (stdlib) **NUEVO** | **Host** `.1` | **8080** | Webs a visitar + ficheros a descargar |
| **Internet local — *paste*/sink/C2** | `sink_http.py` (**reuso**) | **Host** `.1` | **9090** | Ya existe y ya se usó en ATA008/009/010/043/050 |
| **Internet local — nube (WebDAV)** | `sink_webdav.py` (**reuso**) | **Host** `.1` | **9092** | Ya existe (ATA049); puerto distinto para coexistir con 9090 |
| **Wazuh manager** | 4.14.7 | `.128` | 1514/1515/55000/443 | **No se toca** (solo `<logall_json>` en la prueba) |
| **Manager VM** | — | `.128` | — | **Aislado**: nunca se ejecuta GHOSTS/internet-local aquí |

### 3.2 Red y puertos — **no interferir con el manager**

- **Toda** la infraestructura nueva se enlaza a **`192.168.65.1`** (host en VMnet1), **igual que los
  *sinks*** de los ataques. **Nunca** se ocupa `1514/1515/55000/443` (Wazuh).
- **Firewall del host:** reglas **acotadas** a `192.168.65.0/24`, una por puerto
  (`TFG-ghosts-5000`, `TFG-web-8080`, `TFG-sink-9090`, `TFG-webdav-9092`), **retirables** (patrón
  `TFG-sink-9090` ya documentado).
- **`/etc/hosts` de la víctima:** alias de "dominios" creíbles → `.1` (p. ej. `intranet.local`,
  `portal.local`, `nube.local`) para que las URLs parezcan reales sin DNS real. **Declarado** como
  simulación.

### 3.3 Pre-staging (qué se descarga en el host y se copia)

Todo el material se fija con **URL + tamaño + `sha256`** en
`Soporte/Laboratorio/ghosts/prestaging_material.md` (patrón `prestaging_material.md` de Windows),
**fuera del repo** (`D:\TFG-VMs\material-ghosts\`). **Nunca** la contraseña del laboratorio.

| Material | Origen | Destino |
|---|---|---|
| **Release de GHOSTS** (tag fijado) | GitHub `cmu-sei/GHOSTS` (tag/commit) | Host (build/run) |
| **SDK/runtime .NET** necesario para el *pin* | `dotnet.microsoft.com` | Host (si falta) |
| **PostgreSQL 16** | `postgresql.org` | Host (si ruta host-native) |
| **Cliente Linux compilado** (*self-contained*, si aplica) | build en el host | `victima-linux` (vía `scp`, **sin instalar runtime**) |
| **(Si Universal + navegador) Firefox + Xvfb** | paquetes `.deb` | `victima-linux` (offline `dpkg -i`, patrón ya usado en ataques GUI) |

> **Regla:** en la **víctima** no se instala nada que requiera NAT (el cliente se publica
> *self-contained* o se instala **offline**). El NAT sigue **desconectado**.

### 3.4 Presupuesto de recursos (host de 16 GiB)

- **VMs medidas** (obligatorias en L1): `wazuh-server` 6 GB + `victima-linux` 3 GB = **9 GB**.
- **GHOSTS + internet local en el host**: objetivo **≤ 1.5 GB** (API + PostgreSQL + web estática).
- **Criterio de aceptación de RAM:** con las 2 VMs arriba y la infraestructura corriendo, el host
  conserva **≥ 1 GB libre** y las VMs **arrancan y responden** (VMware intacto).
- **Alternativa (VM dedicada `ghosts-server`)**: solo si el go/no-go la elige y el presupuesto se
  cumple (sería una **3.ª VM ligera**, 2 GB) — **declarada como riesgo de RAM**.

---

## 4. El "internet local" (reuso + añadido)

### 4.1 Qué se reaprovecha y qué se añade

| Servicio | ¿Nuevo? | Implementación | Puerto |
|---|---|---|---|
| **Webs que visitar** | **NUEVO** | Servidor estático stdlib sirviendo un sitio pequeño y creíble (intranet/portal/noticias) con HTML/CSS/JS e imágenes | 8080 |
| **Ficheros que descargar** | **NUEVO** (mismo server) | Rutas con ficheros (`/descargas/*.zip`, `*.pdf`, `*.csv` de juguete) | 8080 |
| **Nube** | **Reuso** | `sink_webdav.py` | 9092 |
| ***Paste*** | **Reuso** | `sink_http.py` `POST /paste` (ya genérico) | 9090 |
| **C2 / sink** | **Reuso** | `sink_http.py` `POST /c2/beacon` | 9090 |

> **KISS:** el servidor estático es `python -m http.server` (biblioteca estándar, **cero
> dependencias**), apuntando a una carpeta de sitio en (`Soporte/Laboratorio/internet_local/site/`
> o, si es pesado con imágenes, fuera del repo con un enlace). **No** se monta una "nube real".

### 4.2 Cómo se apunta GHOSTS a la internet local

- En las **timelines** de GHOSTS, las actividades de red usan **URLs locales** (`http://192.168.65.1:8080/…`,
  `…:9090/paste`, `…:9092/…`) y/o los **alias** de `/etc/hosts` (`intranet.local` → `.1`).
- **No** se configura ninguna URL de internet real.
- El **cliente** apunta al **API**: `http://192.168.65.1:5000/api` (o la IP de la VM servidor).

### 4.3 Verificación de que funciona **sin salir a internet**

1. **NAT off** en la víctima: `ip route` **sin** `default`; `ens37` DOWN.
2. Desde la víctima: `curl -sS http://192.168.65.1:8080/` → **200**; `GET` a `/descargas/x.zip` →
   descarga OK; `POST /paste` y `PUT` WebDAV → **200/201** con `sha256` en el `sink.log`.
3. **Prueba negativa:** `curl --max-time 3 http://example.com` → **falla** (timeout/DNS); confirma el
   aislamiento.
4. **Evidencia** guardada (logs del host + salida de la víctima) **fuera** de la ventana de L1.

---

## 5. La actividad legítima (GHOSTS): roles, timeline y recuento

> **L0 no ejecuta las 72 h**: define **qué** hará GHOSTS, **cómo se cuenta** y **cómo se registra**,
> y lo **prueba** (humo, no medida).

### 5.1 Qué hará GHOSTS (roles y timeline)

- **Roles/NPCs** en `victima-linux` (y, en el camino Windows, en `.130`): un usuario "de oficina"
  con actividad variada a lo largo del **día y la noche** (reutilizando las franjas ya validadas
  `00:45–04:45Z` y `12:00–16:00Z`, ahora **continuas** 72 h).
- **Actividades** (*handlers* que dejen **rastro en el host** — es lo que el HIDS ve):
  - **Ficheros**: crear/editar/leer/mover documentos en `~/Documentos`, `~/Descargas`.
  - **Red local**: visitar las webs locales (8080), **descargar** ficheros, **subir** a nube
    (WebDAV), **postear** al *paste*.
  - **Procesos**: ejecutar utilidades reales (compresión, visualización, edición) — **cada acción
    es un `execve`** que auditd ve.
  - *(Opcional, según go/no-go)* **navegador real** (Firefox vía **Xvfb**) contra el sitio local.
- **Duración**: diseñado para **72 h ampliables** (no reducibles) — la ejecución es de **L1**.

### 5.2 Cómo se cuentan las acciones (unidad común para comparar HIDS)

- **Unidad = "acción GHOSTS"** = **una acción/handler ejecutado y registrado** por GHOSTS.
- **Se cuenta** (para T3 meta y complementos de `R2 §2.2`): `n_acciones_ghosts`, y se derivan
  **`FP/acción`** y **`FP/hora`** (la unidad **común** Wazuh↔Velociraptor, `R2 §8`).
- **Requisito de L0:** verificar que **GHOSTS permite exportar el nº de acciones** (BD PostgreSQL o
  log del cliente). Si **no** fuese exportable → **se cuenta en el plan B** desde el log del guion.

### 5.3 Cómo se registra

- GHOSTS persiste actividades en **PostgreSQL**; además, **envoltorio propio** que marca **`t0`/`t1`**
  (UTC) y guarda el **contador de acciones**.
- Los **timelines** se **versionan** (fichero + `URL`/`sha256` del *pin*) — entran en la **bóveda B10**.
- La clasificación posterior reutiliza **`filtrar_ruido.py --modo baseline`** (`R2 §6.3`), **sin
  reimplementar** el filtro.

---

## 6. La instrumentación del denominador `M`

> **Especificación congelada:** `R2 §2.2`. L0 la deja **lista y probada**, **no** en régimen.

### 6.1 Cómo se activa/verifica `logall_json`

- **Dónde:** en el **manager** (`wazuh-server`, `.128`), bloque `<global>` de
  `/var/ossec/etc/ossec.conf`: `<logall_json>yes</logall_json>`.
- **Qué hace:** Wazuh escribe **todos** los eventos **decodificados** (hayan disparado o no una
  regla) en `archives.json`. **No cambia el ruleset** ⇒ **virgen preservada**; se **declara**.
- **Alternativa declarada** (si `archives.json` no fuese viable): **contar en el origen**
  (auditd/Sysmon/FIM).
- **Procedimiento (prueba, en L0):**
  1. Activar `logall_json` en el manager; **reiniciar** el manager.
  2. Generar **actividad acotada** en la víctima (p. ej. **30–60 min** de acciones GHOSTS/plan B).
  3. Medir **tamaño y tasa** de `archives.json` (bytes/hora).
  4. **Estimar** el tamaño a **72 h**.
  5. **Desactivar** `logall_json` (`no`) y **reiniciar** → vuelve el estado **normal**.
- **Higiene:** la prueba va **fuera** de toda ventana; el manager se **restaura** y se **verifica**.

### 6.2 Tamaño estimado y disparador del fallback

- **Disparador del fallback (`R2 §2.2`, literal):** si `archives.json` de 72 h **> ~5 GB** **o** la
  decodificación no es fiable ⇒ el **titular cae a `FP/acción` + `FP/hora`** y se **documenta como
  limitación** (caso **L11**).
- **L0 entrega** el **número medido** (tasa y proyección a 72 h) para que **L1** decida con dato, no
  con intuición.
- Se **declara** que la instrumentación **no** altera el ruleset ni el recuento de detecciones.

---

## 7. El go/no-go y el plan B

### 7.1 Criterios objetivos (GO = se cumplen **todos**)

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **G1 — Offline** | Toda la infraestructura funciona con el **NAT off** en las VMs; el manager solo recibe en sus puertos. | `ip route` sin default; servicios responden desde la víctima; `curl` externo **falla** |
| **G2 — Presupuesto** | El *stack* GHOSTS + internet local usa **≤ 1.5 GB** de host; con las 2 VMs arriba, host **≥ 1 GB libre**; **VMware intacto** (sin Hyper-V/WSL2). VMs arrancan y responden. | `Get-CimInstance`/`Get-Process` + `vmrun list` + ping VMs |
| **G3 — Cliente útil** | El cliente Linux **se registra**, recibe una **timeline** y ejecuta **≥ 1 acción que deje rastro en el host** visible por Wazuh (evento en `archives.json`/alerta). | Log del cliente + evento en el manager |
| **G4 — Control** | **Arranque/parada scriptables**; **timelines versionadas** (URL+`sha256`); **contador de acciones exportable**. | Scripts + fichero de *pin* + export del contador |
| **G5 — Tiempo** | Se logra dentro de un **esfuerzo acotado** (declarado: **≤ 2 sesiones de trabajo**). | Registro del bloque |

> **Si G1–G4 se cumplen → GO** (se sigue con GHOSTS en L1). Si **cualquiera falla dentro de G5** →
> **NO-GO** y se activa el **plan B**.

### 7.2 Plan B declarado (si NO-GO)

> **Acciones reales por guion** (bash + `systemd` timer/cron en la víctima), **con navegador/apps
> reales** — **no** un guion plano como el baseline antiguo. Mismo patrón de actividad (§5.1) y
> **mismas unidades** (`acción`/`hora`). Se **declara** como limitación ("legítimo guionizado, no
> NPC"). Requiere solo la **internet local** (que ya se monta igual) ⇒ **el plan B no desperdicia
> L0**.

### 7.3 Qué se hace si el **API** v9 no es viable en el host (sub-decisión)

- **Priorizar** un *pin* de GHOSTS **compatible con .NET 8** (SDK ya instalado) → **menos descargas**;
  si solo hay releases .NET 10 → **instalar el SDK correspondiente** en el host (**pre-staging**).
- **Alternativa** (si host-native no cuadra por RAM/versión): **VM dedicada `ghosts-server`**
  (Ubuntu, 2 GB, VMnet1) — **declarada** como 3.ª VM ligera.

---

## 8. Higiene de medida (fuera vs dentro de ventana)

| Fase | Ventana | Qué se hace | Qué **NO** se hace |
|---|---|---|---|
| **L0 (este bloque)** | **FUERA** de toda ventana | Descargas, instalación, montaje, **pruebas de humo**, prueba de `logall_json`, snapshots | **No** se captura legítimo; **no** se mide FP |
| **L1 (`legitimo-72h`)** | **DENTRO** | Revert a `lab-listo-legit`, `t0`, GHOSTS 72 h, `t1`, extracción | **No** se monta nada; **no** se cambia config a mitad |

- **Antes de L1:** revertir la víctima a **`lab-listo`** y **crear** el snapshot
  **`lab-listo-legit`** (cliente GHOSTS + alias `/etc/hosts` + config; **sin** datos de medida).
- Los snapshots **originales** (`base-limpia`, `lab-listo`, `lab-listo-windows`, …) **no se tocan**.
- **`logall_json`** queda **OFF** por defecto; se activa **solo** en la ventana de L1 (no en ataques).
- El manager **no se revierte** (conserva alertas); la extracción usa el **fichero diario** en
  `[t0,t1]` (regla vigente de Fase 3).

---

## 9. Riesgos y decisiones abiertas

### 9.1 Riesgos (con mitigación)

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **Docker/WSL2 ↔ VMware** (Win10 Home) | Rompe el laboratorio | **No** usar Docker Desktop; API **host-native** o **VM Linux**; **verificar** que las VMs siguen arrancando (G2) |
| **`pin` de GHOSTS vs .NET** | Bloquea el despliegue | Elegir release compatible con **.NET 8** si es posible; si no, instalar el SDK (pre-staging); **time-box** (G5) |
| **RAM (16 GiB) con 2–3 VMs + infra** | L1 no cabe | Infra en host (≤1.5 GB); **nunca** 3.ª VM pesada; medir G2 |
| **GHOSTS no deja rastro en el host** | FPR poco informativo | Elegir **Universal** con handlers de host; validar **G3** (evento visible) antes de L1 |
| **`archives.json` enorme** | `M` no publicable | **Medir** la tasa en L0; **fallback** `FP/acción`+`FP/hora` (L11) |
| **Sobre-medida / contaminar** | Medida inválida | Montaje y pruebas **fuera** de ventana; snapshots limpios |
| **Conflicto de puertos con el manager** | Detección rota | Puertos **distintos** y **acotados**; nunca `443/1514/1515/55000` |
| **Fuga de secreto** | Seguridad | La contraseña del laboratorio **nunca** en ficheros |
| **`_recursos/` / corpus tocados** | Rompe disciplina | **Solo lectura**; `git status` como control |

### 9.2 Decisiones abiertas (las lleva el humano/orquestador)

1. **`pin` de GHOSTS y runtime .NET** (¿release v8-era compatible con .NET 8, o v9 con .NET 10?).
2. **Dónde corre el servidor** (host-native recomendado vs VM dedicada `ghosts-server`) → lo decide
   el **go/no-go** con G2.
3. **Cliente Linux: Universal vs Lite** (rastro en host vs ligereza) → lo decide G3/§5.1.
4. **¿Navegador real (Xvfb+Firefox)** o solo handlers de red/ficheros/procesos?
5. **Sellado de la bóveda B10** (`boveda_congelacion.md`): L0 **no toca `Soporte/Metrica/`**; el
   sellado con los valores reales (versión GHOSTS + internet local + instrumentación) lo hace **L1**
   (o el humano). **Punto de coordinación.**
6. **Ventana de L1**: fecha de arranque de las 72 h (cuello de botella) y si es **ampliable**.
7. **Alcance del firewall** (reglas por puerto, acotadas a `192.168.65.0/24`).
8. **¿Se cuenta `M` con `logall_json` o en origen?** (tras el dato de tamaño de L0).

---

## 10. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-L0-01** | Existe `Soporte/Laboratorio/ghosts/` con **README**, **scripts de arranque/parada**, **timelines** y ***pin*** del material (**URL+`sha256`**). | Ficheros + huellas |
| **CA-L0-02** | La **"internet local"** (8080 web + 9090 *paste*/sink + 9092 nube) **responde** desde la víctima. | Logs del host + salida de la víctima |
| **CA-L0-03** | **Prueba negativa**: la víctima **no** sale a internet (NAT off, sin default route, `curl` externo falla). | `ip route` + salida de `curl` |
| **CA-L0-04** | El **cliente GHOSTS** se **registra**, recibe timeline y ejecuta **≥1 acción con rastro en el host**. | Log del cliente + evento en el manager |
| **CA-L0-05** | El **contador de acciones** GHOSTS es **exportable** (nº de acciones). | Export/consulta |
| **CA-L0-06** | Prueba de **`logall_json`**: medida la **tasa/tamaño** de `archives.json`, **estimación a 72 h**, y **desactivado** después (manager **restaurado**). | Fichero + `ossec.conf` con `no` |
| **CA-L0-07** | **Disparador del fallback** documentado con el **umbral numérico** (>~5 GB ⇒ fallback). | `instrumentacion_denominador.md` |
| **CA-L0-08** | **Go/no-go decidido** por escrito (GO/NO-GO + motivo); si NO-GO, **plan B declarado** y listo. | `Soporte/Laboratorio/ghosts/decision_gonogo.md` |
| **CA-L0-09** | Snapshot **`lab-listo-legit`** creado; snapshots **originales intactos** (`listSnapshots`). | `vmrun listSnapshots` |
| **CA-L0-10** | **Sin secretos**; `_recursos/`, corpus, `Hojas/`, `Dataset/` y `Soporte/Metrica/` **sin tocar**; manager **restaurado** tras la prueba. | `git status` + auditoría de texto |
| **CA-L0-11** | **Presupuesto RAM** cumplido (G2) y **VMs arrancan** tras el montaje. | Medición + `vmrun list` |
| **CA-L0-12** | **Gate humano**: `plan.md` con `status: approved_by_human` antes de ejecutar. | Frontmatter |

---

## 11. Gate humano (lenguaje sencillo)

> Aprobar **antes** de instalar/montar nada.

1. **Qué voy a montar.** Para medir las **falsas alarmas** necesito **actividad humana real** en la
   víctima. Voy a instalar **GHOSTS** (un simulador de usuarios de la Universidad Carnegie Mellon):
   un **servidor** y un **cliente** en la máquina víctima Linux. Además, como el laboratorio está
   **aislado**, monto una **"internet local"** (unas webs, unas descargas, una "nube" y un "paste"
   locales) **reutilizando** lo que ya usamos en los ataques.
2. **¿Dónde corre cada cosa?** El servidor y la "internet local" en el **ordenador** (host), **fuera**
   de las máquinas que se miden; el cliente en la **víctima**. **No** toco el servidor de Wazuh
   (salvo una **prueba** corta para contar eventos, que luego apago).
3. **El contador (denominador).** Para calcular el % de falsas alarmas necesito **cuántos eventos
   normales** hubo: activo un contador de Wazuh (`logall_json`) **solo en la prueba**, mido cuánto
   ocupa en 72 h y lo **dejo apagado**. Si es demasiado grande, uso el **recuento por acción/hora**
   (ya previsto).
4. **¿Y si GHOSTS no sale?** Tengo un **plan B**: la misma actividad pero con un **guion que usa
   navegador y programas reales** (no un guion plano). Declarado.
5. **Riesgo técnico.** El ordenador tiene **Windows 10 Home** y **no** puede llevar Docker sin
   tocar la virtualización que usa VMware. Por eso **no** uso Docker: instalo el servidor "a pelo"
   (o, si no cabe, en una máquina virtual pequeña aparte). Lo **mido** antes de seguir.
6. **Nada se mide en este paso**: solo se **monta y se prueba**. Las **72 horas** son el bloque
   siguiente.

---

## 12. Ficheros que se tocarán

**Nuevos (en ejecución, tras el gate):**

- `Soporte/Laboratorio/ghosts/` → `README.md`, scripts de arranque/parada, timelines,
  `prestaging_material.md` (**URL+`sha256`**), `decision_gonogo.md`.
- `Soporte/Laboratorio/internet_local/` → `README.md`, script del servidor web estático y carpeta
  `site/` (contenido de juguete).
- `Soporte/Laboratorio/instrumentacion_denominador.md` → procedimiento de `logall_json` + medida.
- `_fases/legitimo-infra/` → `plan.md`/`reviews.md`/`change-doc.md` (al archivar).

**Modificados (mínimo):**

- `Soporte/Laboratorio/vmrun_config.md` (añadir el snapshot **`lab-listo-legit`** y su reversión).
- `state.md`, `roadmap.md` (marcar L0) y el `change-doc` del bloque (al cerrar).
- `Soporte/Wazuh/Configuracion/` → **solo** el procedimiento de `logall_json` (documentado;
  `ossec.conf` del manager se **restaura**).

**Reutilizados sin modificar:**

- `Soporte/Ataques/receiver/sink_http.py` y `sink_webdav.py` (**se usan**, no se editan).

**Prohibido tocar:**

- `_recursos/**` (solo lectura), el **corpus**, `Hojas/`, `Dataset/**`, `Soporte/Metrica/**`, el
  manager (salvo la prueba de `logall_json`, **revertida**), `_artefactos/scripts/extraer_alertas.py`.

**Snapshots (fuera del repo, en `D:\TFG-VMs`):** crear `lab-listo-legit`; **no** borrar los
existentes.

---

## 13. Trazabilidad (fuentes y afirmaciones verificadas)

| Afirmación | Cita verificable |
|---|---|
| **L0** = `legitimo-infra`; monta GHOSTS + internet local; **go/no-go**; depende de **R2** | `_fases/reencuadre/plan.md` §10.2 (fila L0); `roadmap.md` §4 |
| El **legítimo** es **cuantificar el error** con **GHOSTS + 72 h + internet local** | `_fases/reencuadre/plan.md` §7; `context.md` §8 |
| **Unidad** = evento decodificado; **`M`** ≥ con **`<logall_json>`**; **fallback** `FP/acción`+`FP/hora` si >~5 GB | `_fases/reencuadre-metrica/plan.md` §2.2; `Soporte/Metrica/metrica_hids.md` §2 (L11) |
| **Unidad común entre HIDS** = **acción GHOSTS / hora** + por técnica | `_fases/reencuadre-metrica/plan.md` §8; `_fases/reencuadre/plan.md` §4.6 |
| **Lab**: `victima-linux` `.129` · `wazuh-server` `.128` · `victima-windows` `.130` · host `.1`; VMnet1; **NAT off** | `Soporte/Laboratorio/README.md` §3–4; `vmrun_config.md` |
| **Servicios locales** (`sink_http` 9090, `sink_webdav`) en el **host** | `Soporte/Ataques/receiver/README.md`; `Dataset/Ataques/Comandos/T1567.002…/README.md`; `T1567.003…/README.md` |
| **Pre-staging** (URL+`sha256`, fuera del repo) | `Soporte/Laboratorio/windows/prestaging_material.md` |
| **GHOSTS** = API central + clientes (Windows/Universal/Lite) + PostgreSQL; clientes → `:5000/api` | README de `github.com/cmu-sei/GHOSTS` (v9) — `_recursos/reuniones/03/ghost.txt` |
| **B10 pendiente** = GHOSTS + internet local + `logall_json` | `Soporte/Metrica/boveda_congelacion.md` B10 |
| **Host**: Win10 Home · ~16 GiB · .NET SDK 8 · sin Docker · WSL sin distro | **Inspección directa 2026-10-18** (esta sesión) |

---

## 14. Lo que NO cuadra (declarado, para el revisor)

1. **La versión de GHOSTS y el runtime no están fijados**: el API de **v9** exige **.NET 10** y el
   host solo tiene **.NET 8**; **no** se decide aquí la versión (abierta 1, con *time-box* en L0).
2. **Docker Desktop queda descartado *a priori*** por el **riesgo Hyper-V/WSL2 ↔ VMware** en
   **Win10 Home**; se documenta la alternativa (VM Linux) para no cerrar puertas.
3. **No se puede garantizar** que los *handlers* de GHOSTS dejen **suficiente rastro en el host**
   (es lo que decide el FPR útil): por eso **G3** es criterio de **go/no-go**, no un supuesto.
4. **El tamaño de `archives.json` a 72 h es desconocido** hasta la prueba de L0; el disparador del
   fallback está **congelado** (L11) pero el **dato** lo pone L0/L1.
5. **El sellado de la bóveda B10** (que R2 dejó "para L0/L1") **no lo hace L0** porque L0 tiene
   prohibido tocar `Soporte/Metrica/`: se **coordina** con el orquestador/humano (abierta 5).
6. **"Internet local" ≠ internet real**: no se prueban C2/dominios reales; la **alternativa híbrida**
   (NAT temporal para un C2 real) queda **documentada, no descartada** (`R0 §9`).
7. **Windows** se **prepara** (build/documentación) pero **no** se despliega ni mide en L0 (es `B1`).
8. **El plan B no es "peor"**: si GHOSTS no sale, el guion con apps reales **cubre el mismo objetivo**
   con una limitación declarada; por eso L0 **no apuesta todo** a GHOSTS.

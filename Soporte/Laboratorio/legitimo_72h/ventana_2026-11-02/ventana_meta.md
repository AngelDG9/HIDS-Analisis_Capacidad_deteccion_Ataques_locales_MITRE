# `ventana_meta.md` — Ficha de la ventana legítima `legitimo-v3` (`legitimo_72h`)

> **Estado: VÁLIDA CON INCIDENCIA** (incidencia única: **orden de extracción invertido**, V6;
> fuente diaria íntegra y `M` re-extraído). Veredicto global y criterio V1–V9 en
> **`veredicto_validez.md`** (mismo directorio).
>
> `metrica_version = 1` · **`boveda_version = 2`** · `receptor_navegador = none`.
> Sellado: `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` (**v3**) y
> `Soporte/Metrica/boveda_congelacion.md` (**v2**, B10).
> Fecha de cierre: **2026-11-05**.

## 1. Ventana (UTC)

| Parámetro | Valor |
|---|---|
| `t0` | **2026-11-02T00:00:00Z** (= 2026-11-02 01:00 local, Europe/Madrid CET +01:00) |
| `t1` | **2026-11-05T00:00:00Z** (= 2026-11-05 01:00 local) |
| Duración | **72 h** exactas (`t1 = t0 + 259 200 s`), continuas |
| Cruce DST | **No** (el cambio de hora es el 2026-10-25, anterior a `t0`) |
| Días | lunes `d1` → martes `d2` → miércoles `d3` (recetas v2: 163 / 178 / 163 acciones) |
| Fuente de alertas | ficheros diarios `/var/ossec/logs/alerts/2026/{Nov}/ossec-alerts-{02,03,04}.json` (**3 diarios**) |
| Denominador `M` | `archives.json` del manager (`logall_json` **ON solo** en `[t0,t1]`) |
| Contador de acciones | `ghosts.history_timeline` (PostgreSQL del host) |
| Cosecha | **2026-11-05T00:08:22Z** (`cosecha.done`, 43 ficheros + `MANIFEST.tsv`) |
| Parada de la víctima | **2026-11-05T00:09:16Z** (soft, tras `cosecha.done`) |

## 2. Configuración medida

- **HIDS:** **Wazuh `4.14.7-1`** (manager/indexer/dashboard + agente **`001` `victima-linux`**),
  **config virgen `C1 = {RS1, RS2}`**, **`RS3 = RS4 = 0`**. **No** se añadieron reglas.
  Ruleset por defecto: `sha256 64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b`
  (`Soporte/Wazuh/Configuracion/active_ruleset.txt`, idéntico a B2 de la bóveda).
- **Actividad legítima:** **GHOSTS v8.3.1** (`4d2e160860f508f699f935472b5515358f534844`), cliente
  Linux *self-contained* en `/home/angel/ghosts-client`, arrancado con **`cwd = /home/angel`**
  (`TFG_CWD_BASE=/home/angel`; `0` filas con `audit_cwd` = `.../ghosts-client`).
  Binario desplegado: `ghosts.client.linux` `sha256 3e1a73a49f7e95fc52864a4c52e89e5af38a0644791bee2115a7ac96b742c659`
  (72 520 B) + `ghosts.client.linux.dll` `sha256 7405f546d168754e1e745d87a1400593ee24d80c485f771199f89cab40986977`.
- **Receta:** v2 (`TFG_RECETA_VERSION=2`), `sha256` de `d1.json` `0b2fa91cdbc7f16cfc3e59e3ace7b67269d78de4279b641f4fbfae221b50c7df`,
  `d2.json` `0e0329cc979797f5fa63420a79a9d5d5af26ae6d4d6cec7dd961ed31adddc58a`,
  `d3.json` `885a80b2f698ed2e6cc4a249a5f36bdd6756a246352b01dc52953638db611345`.
- **Calendario:** `bloques.env` `sha256 ee43ff463a2faa20e0565afdc2fd8bcc3475505c86770e28bc1781fadbdb64fd`
  (B1 08:00–08:12 · B2 08:12–10:00 · P1 10:00–10:20 · B3 10:20–13:00 · P2 13:00–14:00 ·
  B4 14:00–16:15 · B5 16:15–17:00 · **B6 17:05–17:50 = campaña declarada**).
- **Campaña de falsos positivos (dentro de la ventana):** **11 casos no mutantes** (`C-01…C-12`, sin
  `C-04`), 63 acciones, 22 marcas, inicios `d1 17:06Z / d2 17:17Z / d3 17:11Z`.
  `casos.md` `sha256 2003c9cc71624c40ca8a70931027b552bed15a17b9cc0044720c5801c99f2a49`
  (firmado **antes** de `t0`). **0 mutación** (`crontab -l` → `rc=1` antes y después).
- **Snapshot de trabajo:** **`lab-listo-legit-v3`** (6 snapshots en total; `lab-listo-legit-v2`
  intacto). Deploy idempotente (`deploy_client.ps1`, 2 aplicaciones = mismo `sha256`).
- **Aislamiento:** víctima en `192.168.65.129`, solo `192.168.65.0/24`; **`ip route` sin `default`**.
- **Navegador:** **descartado** (`receptor_navegador = none`; `browser_eval.md`, DT-B0 FAIL).
- **Sin `sudo`** en la actividad legítima (declarado; `E0-1` registrado).

## 3. Denominador `M` (medido)

| Concepto | Valor |
|---|---|
| **`M` endpoint (agente `001`)** | **342 966** eventos |
| `M` total (incluye manager `000`) | **394 739** eventos |
| Cobertura endpoint | `2026-11-02T00:00:04Z .. 2026-11-04T23:59:56Z` |
| Ficheros | **4**: `ossec-archive-{02,03,04}.json.gz` + `ossec-archive-05.json` (vivo) |
| `sha256` de entradas | `0adf47b8…6242` (02) · `ed39daf0…eb99` (03) · `78f504ae…0a4c2` (04) · `ae53465c…a850` (05) |
| `--estricto` | **sin solapes**, **`exit 0`** |
| Duplicados (`sha256`) / sin `ts` / JSON malo | **0 / 0 / 0** |
| Eventos endpoint por día | **114 118 / 114 660 / 114 188** |
| Eventos totales por día | **131 252 / 131 894 / 131 593** |
| Tasa endpoint | **4 763,4 eventos/h** (total: 5 482,5/h) |
| Bytes copiados | 3 `.gz` = **43 567 376 B** (41,55 MiB) + vivo **4 888 764 B** (0 eventos en ventana) |
| Tasa de fichero | **0,61 MB/h** comprimido (≈ **43,6 MB** en 72 h) |

> El fichero vivo (`ossec-archive-05.json`) contiene **solo eventos posteriores a `t1`**
> (`2026-11-05T00:00:02.995Z .. 00:09:36.908Z`), por eso **aporta 0** a `M`. Se copia y se declara
> (regla de borde `[t0,t1]` inclusivo). **Un solo `M`**: no hay cifra alternativa.

## 4. Alertas (medido)

- **294 253** alertas del agente `001` en `[t0,t1]` (98 064 / 98 254 / 97 935 por día).
- Primer `timestamp_utc`: `2026-11-02T00:00:04.676Z`; último: `2026-11-04T23:59:56.971Z`.
- **Hueco máximo entre alertas: 62,554 s** (≈ 1 min; umbral V1: 30 min).
- **11 `rule_id`** distintos (suma de `count` = 294 253):

| `rule_id` | nivel | descripción (muestra) | `groups` | `count` | RS |
|---|---|---|---|---|---|
| `80792` | 3 | Audit: Command: `/usr/bin/bash.` | `audit\|audit_command` | **236 277** | RS2 |
| `80791` | 3 | Audit: Deleted: `var/run/.` | `audit\|audit_watch_delete` | **55 649** | RS2 |
| `80780` | 3 | Audit: Watch - Write access. | `audit\|audit_watch_write` | **1 871** | RS2 |
| `80782` | 3 | Audit: Watch - Write access: `/.` | `audit\|audit_watch_write` | **227** | RS2 |
| `80781` | 3 | Audit: Watch - Write access: `/etc/.pwd.lock.` | `audit\|audit_watch_write` | **93** | RS2 |
| `80730` | 3 | Auditd: SELinux permission check. | `audit\|audit_selinux` | **72** | RS2 |
| `591` | 3 | Log file rotated. | `ossec` | **47** | RS1 |
| `80790` | 3 | Audit: Created: `…/informes/adjunto_1_2026-11-02.tar.gz.` | `audit\|audit_watch_create` | **11** | RS2 |
| `554` | 5 | File added to the system. | `ossec\|syscheck\|syscheck_entry_added` | **3** | RS1 |
| `80711` | **10** | Auditd: Process ended abnormally. | `audit\|audit_anom` | **2** | RS2 |
| `11` | 4 | *(sin descripción)* — alerta interna de estadísticas del agente | `stats` | **1** | **UNKNOWN** |

- **Filtrado post-cosecha declarado:** el volcado inicial tenía **297 477** filas; se descartaron
  **3 224** del **manager** (`wazuh-server`, agente `000`; reglas `5402/5501/5502/5715`) y **0** por
  ventana. Las **294 253** conservadas son byte a byte idénticas al original. Detalle en
  `incidencias.md`.
- **`rule 11` = UNKNOWN:** alerta `stats` emitida por el **agente `001`** (1 fila). No se le asigna
  RuleSet; su tratamiento como auto-ruido corresponde al filtro de la métrica, no a este recorte.

## 5. Acciones (medido)

| Concepto | Valor |
|---|---|
| Acciones GHOSTS en `[t0,t1]` | **504** (handler `Command` 504) |
| Por día | **163 / 178 / 163** |
| Receta por día (jornada + campaña) | 147+16 / 153+25 / 141+22 = **163 / 178 / 163** |
| Cumplimiento | **100 % / 100 % / 100 %** (umbral V2: ≥ 90 %) |
| Acciones/hora (media) | **7,0** |
| Horas con acciones | 08–12 y 14–17 UTC los 3 días (**sin** 13:00 = P2; **sin** 00–07 ni 18–23) |
| Acciones fuera de bloque | **0** a resolución horaria; la hora 17:00 es **B6** (campaña declarada) |

> **Limitación declarada:** el producto `ghosts_acciones.csv` es **agregado por hora** (así lo
> genera `exportar_acciones.sh`); la BD de GHOSTS ya estaba parada al cerrar, así que **no se
> dispone de granularidad por acción**. La comprobación de “0 fuera de bloque” es **a resolución
> horaria** + marcas de campaña. Ver `veredicto_validez.md` (V2).

## 6. Campaña de falsos positivos (tabla propia, 11/11)

`campana_fp.csv` — **11/11 `SI`** (todos ejecutados, con `hecho.txt`); **0 alertas `N ≥ 7`** (todas
las alertas de las ventanas son de nivel **3**, `80780/80791/80792`, y en C-11 también
`80730/80781/80782`). La campaña **está dentro** de `M`; su tabla **no** genera una segunda cifra.

| Caso | Día | `ini` (UTC) | `fin` | Alertas | `rule_id` | Nivel | Esperado |
|---|---|---|---|---|---|---|---|
| C-01 | d1 | 17:06:00 | 17:06:40 | 160 | 80780;80791;80792 | 3 | **SI** |
| C-02 | d1 | 17:15:20 | 17:15:49 | 127 | 80780;80791;80792 | 3 | **SI** |
| C-03 | d1 | 17:24:40 | 17:25:09 | 151 | 80780;80791;80792 | 3 | **SI** |
| C-05 | d2 | 17:17:00 | 17:17:45 | 158 | 80780;80791;80792 | 3 | **SI** |
| C-06 | d2 | 17:25:30 | 17:26:15 | 175 | 80780;80791;80792 | 3 | **SI** |
| C-07 | d2 | 17:33:11 | 17:33:40 | 134 | 80780;80791;80792 | 3 | **SI** |
| C-08 | d2 | 17:41:21 | 17:41:57 | 155 | 80780;80791;80792 | 3 | **SI** |
| C-09 | d3 | 17:11:00 | 17:11:42 | 159 | 80780;80791;80792 | 3 | **SI** |
| C-10 | d3 | 17:19:32 | 17:20:08 | 220 | 80780;80791;80792 | 3 | **SI** |
| C-11 | d3 | 17:27:12 | 17:27:49 | 241 | 80730;80780;80781;80782;80791;80792 | 3 | **SI** |
| C-12 | d3 | 17:35:42 | 17:36:01 | 113 | 80780;80791;80792 | 3 | **SI** |

> `n_acciones` queda **vacío** en las 11 filas: la BD de GHOSTS estaba parada al rehacer la tabla y
> el runner no pudo contar acciones por caso (los **eventos** y las **alertas** sí están). Se
> declara; no se rellena a mano.

## 7. Incidencias declaradas

1. **Orden de extracción invertido (V6).** El `cleanup` (que incluye `logall_json off`) arrancó a
   las **00:09:16Z** y apagó `logall_json` a las **00:12:15Z**; la copia del denominador quedó
   cerrada a las **00:15Z**. **Los 3 ficheros diarios `.gz` estaban intactos** (rotados a las
   00:00Z) y el fichero vivo solo tenía eventos **posteriores a `t1`**. `M` se **re-extrajo** desde
   la fuente íntegra: **342 966** endpoint, `--estricto` **`exit 0`**, `sha256` idénticos. **No
   invalida** (§9.2: fallo de extracción con fuente íntegra ⇒ se re-extrae).
2. **4 `AVISO` de rotación de medianoche** (03/11 00:00 y 00:30; 04/11 00:00 y 00:30): `sin_df` y
   delta negativo por el cambio de fichero diario. **Transitorio y esperado**; se recupera solo.
   **0 `ALARMA`** en toda la ventana.
3. **Filtrado de 3 224 alertas del manager** (post-cosecha): no pertenecen al endpoint medido.
   Recuentos y `sha256` en `incidencias.md`.
4. **`TFG-Legit-Stop` desactivada** el 04/11 16:59Z para evitar la carrera con la cosecha manual.
   No toca la víctima ni la medida (la ventana acaba en `t1`).
5. **`rule 11` UNKNOWN** (1 alerta `stats` del agente): ver §4.
6. **`n_acciones` vacío** en la tabla de campaña: ver §6.
7. **WU re-pausado 13 veces** por el `watch` (`reps=si`): acción del **host**, no toca la víctima
   (protege V8). `wuauserv` terminó `Stopped/Disabled`.

## 8. Validez V1–V9 (resumen; detalle literal en `veredicto_validez.md`)

| # | Criterio | Veredicto | Evidencia (una línea) |
|---|---|---|---|
| **V1** | Cobertura | **PASA** | primera `00:00:04.676Z` (t0+4,7 s) · última `23:59:56.971Z` (t1−3,0 s) · hueco máx. **62,554 s** |
| **V2** | Actividad | **PASA** | **163/178/163** = **100 %** de la receta los 3 días · **0** horas fuera de bloque · 17:00 = **B6** declarada |
| **V3** | Manager y diarios | **PASA** | **144/144** `mgr=active/2` · **144/144** `ag=Active` · **3 diarios** con `sha256` OK y eventos |
| **V4** | 0 contaminación | **PASA** | **0** `srcip=192.168.65.1` · **0** `srcip`/`srcuser` no vacíos · **0** reglas `5715/5501/5502/5402/550` · solo `victima-linux` |
| **V5** | Aislamiento | **PASA** | `ip route`: solo `192.168.65.0/24 … src 192.168.65.129`; **sin `default`** |
| **V6** | `M` | **VÁLIDA CON INCIDENCIA** | **342 966** endpoint · `--estricto` **`exit 0`** · `MANIFEST` con `sha256` OK · incidencia: orden invertido con fuente íntegra |
| **V7** | Sin cambios a mitad | **PASA** | `sha256sums` **143/143** · ruleset `64213db7…` · `CONFIG_IDENTICA` (00:12:17Z) · `git status` solo rutas permitidas |
| **V8** | Host estable | **PASA** | `LastBootUpTime` **2026-10-29T20:25:02Z** < `t0` · **0** `Kernel-Power` 42/107 en `[t0,t1]` |
| **V9** | Recuperaciones/rotaciones/arranques | **PASA** | recuperaciones **0** · rotaciones **2** (d2 y d3, `resultado=ok`) · arranques del cliente **3** (≤ 3) |

**Veredicto global: VÁLIDA CON INCIDENCIA** (una sola, V6, con fuente íntegra y `M` re-extraído).
La ventana es **publicable** (§9.2) y **promovible** a `Dataset/`: la incidencia **no** está entre
los supuestos invalidantes de §9.3 y la fuente del denominador era **íntegra**.

## 9. Límites declarados (no defectos)

- **El manager queda excluido del endpoint.** `M` = **342 966** (agente `001`); el total
  (**394 739**) incluye el manager y **no** se usa como denominador.
- **4 `AVISO` de rotación** de medianoche (declarados; **0 `ALARMA`**).
- **Orden de extracción invertido** (V6; fuente diaria íntegra, `M` re-extraído).
- **`rule 11` UNKNOWN** (1 alerta; sin RuleSet).
- **Granularidad horaria** en `ghosts_acciones.csv` (no por acción).
- **`n_acciones` vacío** en `campana_fp.csv` (BD de GHOSTS parada).
- **Sin navegador** (`receptor_navegador=none`): la sesión web es *browser-like* con `curl`.
- **Swap de ~1,9 GB** en la víctima (declarado; no se toca la VM).
- **La campaña está dentro de `M`**: se publica en tabla aparte y **no** se fabrica un FPR
  alternativo.

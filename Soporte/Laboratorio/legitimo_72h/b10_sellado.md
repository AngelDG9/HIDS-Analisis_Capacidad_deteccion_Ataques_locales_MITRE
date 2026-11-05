# `b10_sellado.md` — sidecar del **sellado B10** (config del legítimo) — **v3**

> **Qué es.** Los **valores reales y las huellas** con los que se sella la **bóveda B10**
> (`Soporte/Metrica/boveda_congelacion.md`, apartado “Config del legítimo”): GHOSTS + “internet
> local” + instrumentación del denominador + **la ventana medida**.
>
> **Versión 3** (cierre de `legitimo-v3`, **2026-11-05**): sustituye a la v2 (sidecar de
> `legitimo-fix`, 2026-10-21) y **rellena B10 con datos medidos**, no con la configuración
> prevista. La bóveda pasa a **`version: 2`** (bump aprobado en el gate Q8: cambia la config del
> legítimo respecto de la v1).
>
> Huellas completas: `Soporte/Laboratorio/legitimo_72h/sha256sums.txt`. Productos de la ventana:
> `Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/`.

## B10 — Contenido del sello (v3, medido)

### 1. Ventana

| Elemento | Valor |
|---|---|
| `t0` / `t1` | **2026-11-02T00:00:00Z** → **2026-11-05T00:00:00Z** (72 h, lunes→jueves, medianoche UTC) |
| Días | `d1` lunes · `d2` martes · `d3` miércoles (`TFG_MAPA_DIAS=2026-11-02:1,2026-11-03:2,2026-11-04:3`) |
| Cosecha / parada | **00:08:22Z** (`cosecha.done`, 43 ficheros) / **00:09:16Z** (soft) |
| `logall_json` | **ON solo en `[t0,t1]`**; **`off` a las 00:12:15Z**; `CONFIG_IDENTICA` a las 00:12:17Z |
| Veredicto | **VÁLIDA CON INCIDENCIA** (V6: orden de extracción invertido; fuente diaria íntegra, `M` re-extraído) |

### 2. Versiones

| Elemento | Valor |
|---|---|
| **GHOSTS** | `github.com/cmu-sei/GHOSTS` **v8.3.1** → commit `4d2e160860f508f699f935472b5515358f534844`; .NET 8; PostgreSQL **16.15** (portable, `127.0.0.1`) |
| **Cliente Linux** | `ghosts.client.linux` (*self-contained*) en `/home/angel/ghosts-client`; **`sha256 3e1a73a49f7e95fc52864a4c52e89e5af38a0644791bee2115a7ac96b742c659`** (72 520 B) |
| Cliente (DLL) | `ghosts.client.linux.dll` **`sha256 7405f546d168754e1e745d87a1400593ee24d80c485f771199f89cab40986977`** (257 024 B) |
| **Wazuh** | **`4.14.7-1`** (manager/indexer/dashboard + agente `001 victima-linux`); ruleset por defecto **`sha256 64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b`** (`RS1 4.471 · RS2 44 · RS3 0 · RS4 0`) |
| Config | **`C1 = {RS1, RS2}` virgen**; sin reglas propias ni de terceros |
| `cwd` de arranque | **`/home/angel`** (`TFG_CWD_BASE`); `0` alertas con `audit_cwd` = `.../ghosts-client` |
| Navegador | **`receptor_navegador = none`** (descartado con evidencia: `browser_eval.md`, DT-B0 FAIL) |

### 3. Receta ejecutada (v2)

| Elemento | Valor |
|---|---|
| Versión de receta | `TFG_RECETA_VERSION=2` |
| `d1.json` | `sha256 0b2fa91cdbc7f16cfc3e59e3ace7b67269d78de4279b641f4fbfae221b50c7df` — **163 acciones** (147 jornada + 16 campaña) |
| `d2.json` | `sha256 0e0329cc979797f5fa63420a79a9d5d5af26ae6d4d6cec7dd961ed31adddc58a` — **178** (153 + 25) |
| `d3.json` | `sha256 885a80b2f698ed2e6cc4a249a5f36bdd6756a246352b01dc52953638db611345` — **163** (141 + 22) |
| `calendario.json` | `sha256 14463efd9ddf1897b40cefce81e78a480d03225b20948a038a02df9ae47826a7` |
| `bloques.env` | `sha256 ee43ff463a2faa20e0565afdc2fd8bcc3475505c86770e28bc1781fadbdb64fd` — B1 08:00–08:12 · B2 08:12–10:00 · P1 10:00–10:20 · B3 10:20–13:00 · P2 13:00–14:00 · B4 14:00–16:15 · B5 16:15–17:00 · **B6 17:05–17:50 (campaña)** |
| Ritmo | jitter fijo determinista; hueco máx. **22 min**; 2 pausas largas/día; **0 pipes**; **0 `random`** |
| Errores | **10/día** con `exit≠0` + reintento correcto; `errores.log` (copia) `sha256 ae684c50e8abaced661abe41993ee3f806bb3a17ac2df8fd2848182f600f00a6` — **60 líneas = 30 `error` + 30 `reintento`** |
| Cobertura de binarios | receta v2 **23/50**; receta + campaña **25/50** (umbral ≥ 22) |

### 4. Campaña de falsos positivos (dentro de la ventana)

| Elemento | Valor |
|---|---|
| Casos | **11** no mutantes (`C-01…C-03`, `C-05…C-12`; `C-04` retirada) |
| Pre-registro | `campana/casos.md` `sha256 2003c9cc71624c40ca8a70931027b552bed15a17b9cc0044720c5801c99f2a49` (**firmado antes de `t0`**) |
| Comandos literales | `campana/campana_casos.csv` `sha256 3b4b8f15c6d2b800ec96c867f7a9c5f81886a3e9d903090505d6a6116fe6169d` (11 filas) |
| Marcas | 22 (`inicio`/`fin`) → `campana_ventanas.tsv` `sha256 6b07a3506e51211d1a82941145a844f2dfc24c616269eea1d4109f9d6e3e7323` |
| Inicios (UTC) | `d1 17:06` · `d2 17:17` · `d3 17:11` (jitter fijo dentro de B6) |
| Resultado | **11/11 `SI`** (`campana_fp.csv` `sha256 f41ea4ee9bcf9acbdd8ad4bc2d5c8ffbc0d2828dec872a6efc01ff68fc579d20`); **0 alertas `N ≥ 7`**; todas de nivel 3 |
| Mutación | **0** (`crontab -l` → `rc=1` antes y después; estado solo bajo `~/Documentos/campana_fp/C-XX/`) |
| Relación con `M` | **dentro** de `M`; tabla propia, **sin** segunda cifra de FPR |

### 5. Instrumentación `M`

| Elemento | Valor |
|---|---|
| Mecanismo | `<logall_json>yes</logall_json>` → `/var/ossec/logs/archives/archives.json`; rotación diaria `ossec-archive-<DD>.json.gz` |
| Control | `Soporte/Laboratorio/ghosts/logall_json_ctl.sh` `sha256 8c7cc874c68c7ad0cfaad80798b1c21543b4b8034148fd264163e0fe02cd5669` |
| Copia | `exportar_denominador.sh copiar-ventana` (3 `.gz` + vivo + `MANIFEST.tsv` + dedupe `sha256`), **fuera del repo** en `D:\TFG-VMs\legitimo-2026-11-02\denominador\` |
| Contador | `contar_denominador.py --estricto --manifest` → **`exit 0`**, sin solapes, 0 duplicados, 0 sin `ts`, 0 JSON malo |
| Regla de borde | `[t0,t1]` **inclusivo**; `.gz` = `[t0,t1)`; el vivo solo aporta `timestamp = t1` |
| **`M` endpoint (001)** | **342 966** eventos |
| `M` total (incluye manager 000) | 394 739 eventos (el manager **no** se usa como denominador) |
| Cobertura | `2026-11-02T00:00:04Z .. 2026-11-04T23:59:56Z` |
| Ficheros | `ossec-archive-{02,03,04}.json.gz` (14 524 310 / 14 557 318 / 14 485 748 B) + `ossec-archive-05.json` (4 888 764 B, **0 eventos en ventana**) |
| `sha256` de entradas | `0adf47b8…6242` · `ed39daf0…eb99` · `78f504ae…0a4c2` · `ae53465c…a850` |
| **Volumen** | **43 567 376 B** (41,55 MiB) en 3 `.gz` → **0,61 MB/h** comprimido (≈ 43,6 MB/72 h) |
| **Eventos/h** | **4 763,4** endpoint (5 482,5 total) |
| **Acciones/día** | **163 / 178 / 163** (504 en total; 7,0 acciones/h) |
| **Alertas** | **294 253** (98 064 / 98 254 / 97 935); **11 `rule_id`** |

### 6. Lo que actuó dentro (real, no previsto)

| Elemento | Valor |
|---|---|
| **Recuperaciones** | **0** |
| **Rotaciones** | **2** (día 2: `2026-11-03T07:45:27Z`; día 3: `2026-11-04T07:45:08Z`), ambas `resultado=ok` |
| **Arranques del cliente** | **3** (1 inicial + 2 por rotación) — tope 3 |
| `rotacion.estado` | `2026-11-04` |
| Vigilancia | **144 chequeos** (48/día), **140 OK + 4 AVISO** (`sin_df` de la rotación de medianoche), **0 `ALARMA`**, `mgr=active/2` y `ag=Active` en **144/144** |
| Incidencia V6 | **orden de extracción invertido**: `off` a las 00:12:15Z, copia cerrada a las 00:15Z; **3 diarios intactos**, `M` re-extraído = 342 966 (`exit 0`) |

### 7. Despliegue y política del cliente

| Elemento | Valor |
|---|---|
| Deploy | `Soporte/Laboratorio/ghosts/deploy_client.ps1` `sha256 98099e284490be87aa2181cfca18e89796ba9f7c94efeb0566d5935104316200` (idempotente: 2 aplicaciones = mismo `sha256`; reversible) |
| `client_ctl.sh` | `sha256 020e6bca556dae4e7f199f396d561bbd78865617a19e97b54bbf8c826d354b22` (tope `client.out` 20 MB + `client.out.1` → máx. 40 MB) |
| `nlog.config` | `sha256 d8f5f1d1154601360e5d81c752ea50b034e915e10f9545625f4a5732352221fb` (consola `Warn`, `app.log` 1 MB × 20) |
| Keepalive | `guest/tfg_keepalive.sh` `sha256 c1241001831f4da0d2e4f5b1fc4876798c4e0579b3e30ae8fc256b8c919f8f9b` (v3: heartbeat por `lastReportedUtc`, `STALE=30`, `GRACIA=15`, `CONFIRMA=5`, `MAX_RECUP=2`, `MAX_ARRANQUES=3`, `ROTACION_UTC=07:45`) |
| Snapshot | **`lab-listo-legit-v3`** (6 en total; `lab-listo-legit-v2` **intacto**) |
| “Internet local” | web `8080` (`internet_local/serve_site.py`) · paste/C2 `9090` (`sink_http.py`) · nube WebDAV `9092` (`sink_webdav.py`); firewall acotado a `192.168.65.0/24` |
| `sudo` | **no se usa** en la actividad legítima (declarado; E0-1 registrado) |
| Aislamiento | `ip route` **sin `default`**; solo `192.168.65.0/24` |

### 8. Versiones de medida

- **`metrica_version = 1`** (métrica congelada, `metrica_hids.md` v1).
- **`boveda_version = 2`** (bump aplicado en los 3 sitios: `boveda_congelacion.md`, su `.sha256` y
  `_artefactos/scripts/metrica_hids.py` `VERSION_BOVEDA = 2`).
- **`receptor_navegador = none`**.

## Lo que declara este bloque (para que B10 no maquille nada)

1. **El denominador es el endpoint**, no el manager: **342 966** (001) frente a 394 739 totales.
   Las **3 224** alertas del manager se descartaron y se declaran en `incidencias.md`.
2. **Orden de extracción invertido** (V6): `off` antes de cerrar la copia. La fuente diaria estaba
   íntegra y `M` se re-extrajo con `--estricto exit 0`. **Válida con incidencia**, no inválida.
3. **4 `AVISO` de rotación de medianoche** (`sin_df`): transitorios, esperados, **0 `ALARMA`**.
4. **`rule 11` = UNKNOWN** (1 alerta `stats` del agente `001`): sin RuleSet; su tratamiento como
   auto-ruido es del filtro de la métrica.
5. **Granularidad horaria** en `ghosts_acciones.csv`; **`n_acciones` vacío** en `campana_fp.csv`
   (la BD de GHOSTS estaba parada al rehacer la tabla).
6. **La campaña está dentro de `M`**: se publica en tabla aparte y **no** se fabrica un FPR
   alternativo.
7. **Sin navegador** (`receptor_navegador=none`): sesión web *browser-like* con `curl` (UA fija,
   cookie jar, `Referer`, descarga real del PDF).
8. **Swap ~1,9 GB** en la víctima (declarado; no se toca la VM).
9. **GHOSTS pierde el reporte de comandos con `|`**: la receta no usa pipes (0 en el validador).
10. **`TFG-Legit-Stop` desactivada** el 04/11 16:59Z para cosechar a mano sin carrera; no toca la
    víctima ni la medida (la ventana termina en `t1`).

- **Trazabilidad:** L0 montó y *pinneó* la infra; L1 falló por el stdout sin tope
  (`fallo_2026-10-19/`); `legitimo-fix` selló la **v2** (config prevista); `legitimo-v3` **mide**
  (T1–T4 + 72 h) y sella la **v3** con los valores reales.

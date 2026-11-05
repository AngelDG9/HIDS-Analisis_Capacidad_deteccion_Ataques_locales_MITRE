# `veredicto_validez.md` — V1–V9 de la ventana `legitimo-v3` (2026-11-02 → 2026-11-05)

> **Veredicto global: VÁLIDA CON INCIDENCIA.**
> La única incidencia es **V6** (orden de extracción invertido respecto del plan) y **no invalida**
> la ventana: la fuente diaria estaba **íntegra**, `M` se **re-extrajo** y coincide exactamente
> (`342 966`, `--estricto exit 0`). Criterio aplicado: plan §9.2 (“fallo de la herramienta de
> extracción con fuente íntegra ⇒ se re-extrae”) y §9.3 (nada de lo observado está en la lista de
> invalidantes).
>
> **Nada de esto se ha recalculado “a mano” sobre la víctima**: todo sale de los productos ya
> extraídos y de los ficheros de evidencia. **No se han arrancado VMs.**
>
> Reproducible con:
>
> ```bash
> python _artefactos/scripts/verificar_validez_ventana.py
> ```
>
> (El script solo lee; V8 se comprueba aparte con WMI/`Get-WinEvent`, ver §V8.)

---

## V1 — Cobertura · **PASA**

**Criterio:** primera alerta del `001` ≤ `t0+10 min`; última ≥ `t1−10 min`; ningún hueco > 30 min.

```text
V1 filas=294253 primera=2026-11-02T00:00:04.676000Z (+0.08 min de t0)
   ultima=2026-11-04T23:59:56.971000Z (0.05 min antes de t1) hueco_max=62.554s
   por dia: {'2026-11-02': 98064, '2026-11-03': 98254, '2026-11-04': 97935}
```

- Primera: **`t0 + 4,676 s`** (≪ 10 min). Última: **`t1 − 3,029 s`** (≪ 10 min).
- Hueco máximo: **62,554 s ≈ 1,04 min** (≪ 30 min). Es el hueco natural entre dos acciones de la
  receta, no una caída del agente.
- **294 253** filas, **0** fuera de ventana (el filtro `[t0,t1]` inclusivo ya está aplicado y
  declarado en la cabecera del CSV).

## V2 — Actividad · **PASA**

**Criterio:** cada día ≥ 90 % de su receta (contra los `--check` congelados); 0 acciones fuera de
los bloques de `bloques.env` (con **B6 17:05–17:50** declarado).

```text
V2 total_acciones=504
   por_dia={'2026-11-02': 163, '2026-11-03': 178, '2026-11-04': 163}
   receta={'2026-11-02': {'total': 163, 'jornada': 147, 'campana': 16},
           '2026-11-03': {'total': 178, 'jornada': 153, 'campana': 25},
           '2026-11-04': {'total': 163, 'jornada': 141, 'campana': 22}}
   cumplimiento_pct={'2026-11-02': 100.0, '2026-11-03': 100.0, '2026-11-04': 100.0}
   horas_con_acciones=[08,09,10,11,12,14,15,16,17] × 3 días
   horas_fuera_de_bloques=[]
```

Comprobación de la receta (conteo de `TimeLineEvents`):

```text
> python -c "import json;print([sum(len(h['TimeLineEvents']) for h in json.load(open('Soporte/Laboratorio/legitimo_72h/recetas/'+d+'.json',encoding='utf-8'))['TimeLineHandlers']) for d in ('d1','d2','d3')])"
[163, 178, 163]
```

- **100 %** los tres días (163/163, 178/178, 163/163) — umbral 90 %.
- Horas con acciones: **08–12 y 14–17** los tres días. **Ninguna** en 00–07 ni 18–23; **ninguna**
  en la hora 13 (P2, comida). La hora **17** es **B6 (campaña declarada, 17:05–17:50Z)**, no
  jornada de trabajo.
- **Explicación de lo que cae fuera de `[07:55, 17:10]`:** la hora 17 agrupa el final de **B5**
  (hasta 17:00) y **B6** (17:06–17:50). Las acciones posteriores a **17:10** son de **B6**, el
  bloque de campaña **declarado en `bloques.env`** (22 marcas, 11 casos). **No** hay ninguna acción
  antes de **07:55** (no existe ningún bucket 00–07) ni después de **17:50** (no existe bucket 18+).
- **Limitación declarada:** `ghosts_acciones.csv` es un agregado **por hora** (es lo que produce
  `exportar_acciones.sh`); con la BD de GHOSTS ya parada no hay granularidad por acción. La
  comprobación es **a resolución horaria** + las **22 marcas** de campaña (`campana_ventanas.tsv`),
  todas dentro de B6. No hay ninguna hora fuera de bloque que explicar.

## V3 — Manager y diarios · **PASA**

**Criterio:** manager `active` en todos los chequeos; los 3 diarios existen y crecen.

```text
V3 chequeos=144 estados={'OK': 140, 'AVISO': 4} mgr_active_2=144 ag_Active=144
   primero=2026-11-02T00:00:03Z ultimo=2026-11-04T23:30:06Z
   diario ossec-archive-02.json.gz: bytes=14524310 existe=True sha_ok=True
   diario ossec-archive-03.json.gz: bytes=14557318 existe=True sha_ok=True
   diario ossec-archive-04.json.gz: bytes=14485748 existe=True sha_ok=True
   diario ossec-archive-05.json: bytes=4888764 existe=True sha_ok=True
```

Eventos por diario (recuento del `--estricto`, ver V6):

```text
ossec-archive-02.json.gz: total=131252 endpoint=114118 rango=2026-11-02T00:00:04Z .. 2026-11-03T00:00:01Z
ossec-archive-03.json.gz: total=131894 endpoint=114660 rango=2026-11-03T00:00:03Z .. 2026-11-04T00:00:00Z
ossec-archive-04.json.gz: total=131593 endpoint=114188 rango=2026-11-04T00:00:02Z .. 2026-11-04T23:59:56Z
ossec-archive-05.json:    total=0      endpoint=0      rango=sin eventos en ventana
```

- **144/144** chequeos con `mgr=active/2` y **144/144** con `ag=Active`.
- **140 OK + 4 AVISO**; los 4 AVISO son **`sin_df`** en la rotación de medianoche (03/11 00:00 y
  00:30; 04/11 00:00 y 00:30). **0 `ALARMA`** en la ventana.
- Los **3 diarios** existen, con `sha256` correcto y **> 0 eventos** cada uno. El vivo (05) es
  posterior a `t1` y aporta **0**.

## V4 — 0 contaminación · **PASA**

**Criterio:** 0 filas con `srcip = 192.168.65.1`; 0 sesiones del operador en el endpoint.

```text
V4 srcip_192.168.65.1=0 srcip_no_vacia=0 srcuser_no_vacio=0
   reglas_sesion={'5715': 0, '5501': 0, '5502': 0, '5402': 0, '550': 0}
   agentes=['victima-linux']
```

- **0** accesos del host a la víctima (`srcip` vacío en **todas** las filas).
- **0** alertas de sesión PAM/SSH/sudo (`5715`, `5501`, `5502`, `5402`, `550`).
- **Todas** las alertas son del agente **`victima-linux`** (001). Las **3 224** del manager
  (`wazuh-server`) se descartaron post-cosecha y están documentadas en `incidencias.md`.

## V5 — Aislamiento · **PASA**

**Criterio:** `ip route` sin `default`.

```text
V5 tiene_default=False rutas=['192.168.65.0/24 dev ens33 proto kernel scope link src 192.168.65.129']
```

- Solo la ruta de enlace de `VMnet1` (`192.168.65.0/24`), **sin puerta de enlace por defecto**.
- La víctima solo puede hablar con la “internet local” del host (`192.168.65.1`), como estaba
  declarado.

## V6 — `M` · **VÁLIDA CON INCIDENCIA**

**Criterio:** copiado antes de `off`; `--estricto` con `exit 0`; `MANIFEST` con `sha256`; un solo
`M` sobre `[t0,t1]`.

Re-ejecución literal del contador sobre la copia fuera del repo:

```bash
python _artefactos/scripts/contar_denominador.py \
  --desde 2026-11-02T00:00:00Z --hasta 2026-11-05T00:00:00Z \
  --agent-id 001 --agent-name victima-linux \
  --metrica-version 1 --boveda-version 2 --estricto \
  --out C:/Users/angel/AppData/Local/Temp/opencode/M_recheck.csv \
  D:/TFG-VMs/legitimo-2026-11-02/denominador/ossec-archive-02.json.gz \
  D:/TFG-VMs/legitimo-2026-11-02/denominador/ossec-archive-03.json.gz \
  D:/TFG-VMs/legitimo-2026-11-02/denominador/ossec-archive-04.json.gz \
  D:/TFG-VMs/legitimo-2026-11-02/denominador/ossec-archive-05.json
echo "EXIT=$LASTEXITCODE"
```

```text
  ossec-archive-02.json.gz: total=131252 endpoint=114118 rango=2026-11-02T00:00:04Z .. 2026-11-03T00:00:01Z
  ossec-archive-03.json.gz: total=131894 endpoint=114660 rango=2026-11-03T00:00:03Z .. 2026-11-04T00:00:00Z
  ossec-archive-04.json.gz: total=131593 endpoint=114188 rango=2026-11-04T00:00:02Z .. 2026-11-04T23:59:56Z
  ossec-archive-05.json: total=0 endpoint=0 rango=sin eventos en ventana
M total=394739 endpoint=342966 no_ts=0 bad_json=0 ficheros=4 duplicados=0
cobertura endpoint: 2026-11-02T00:00:04Z .. 2026-11-04T23:59:56Z
--estricto: sin solapes entre ficheros únicos
EXIT=0
```

```text
V6 endpoint=342966 total=394739
   cobertura=['2026-11-02T00:00:04Z', '2026-11-04T23:59:56Z']
   ficheros=4 sha_coinciden=True bytes_coinciden=True
```

`denominador_M.csv` (producto):

```text
metrica_version,boveda_version,ambito,eventos,primer_ts,ultimo_ts
1,2,total,394739,2026-11-02T00:00:04Z,2026-11-04T23:59:56Z
1,2,endpoint,342966,2026-11-02T00:00:04Z,2026-11-04T23:59:56Z
```

### La incidencia (y por qué la ventana sigue siendo válida)

- **Qué pasó.** El `cleanup` (que incluye **`logall_json off`**, y `off` **borra**
  `archives.json`) arrancó a las **2026-11-05T00:09:16Z** y aplicó el `off` a las **00:12:15Z**
  (`legitimo_host_control.log`). La copia del denominador quedó cerrada a las **00:15Z**. Es decir,
  **el orden planificado se invirtió** respecto de §8 (“copiar → contar `M` → `off`”).
- **Por qué no destruye el dato.** Los **3 ficheros diarios** (`ossec-archive-{02,03,04}.json.gz`)
  ya estaban rotados a las **00:00Z** y **estaban intactos**: contienen el **100 %** de `[t0,t1]`.
  El único fichero que podía perderse era el **vivo** (`archives.json`), y su contenido es
  **exclusivamente posterior a `t1`** (`2026-11-05T00:00:02.995Z .. 00:09:36.908Z`, 2 550 eventos):
  **aporta 0** a `M`. La copia incluye un `ossec-archive-05.json` de 4 888 764 B que, por sus
  eventos, tuvo que capturarse **antes** del `off`.
- **Qué se hizo.** Se **re-extrajo** `M` desde la copia íntegra con `--estricto` (**`exit 0`**,
  sin solapes, `0` duplicados, `sha256` de entrada idénticos al `MANIFEST`). El resultado
  **coincide** con el producto publicado: **342 966** endpoint / **394 739** total.
- **Criterio.** §9.2: “fallo de la herramienta de extracción con **fuente íntegra** (se
  re-extrae)” ⇒ **válida con incidencia**. §9.3 no se cumple en ninguno de sus 8 puntos
  (no hay acceso del operador, ni caída del agente, ni `M` no recuperable, ni reinicio, ni cambio
  de configuración no declarado…).
- **Huella exacta del desorden:** la secuencia precisa de las dos copias (manager→`/tmp` y
  `scp`→`D:`) **no es reconstruible** con los logs disponibles (la sesión manual no se registró en
  `legitimo_host_control.log`). Se declara. Lo que **sí** está verificado es lo que importa para la
  validez: **fuente íntegra + `M` re-derivado idéntico + `exit 0`**.

## V7 — Sin cambios a mitad · **PASA**

**Criterio:** `sha256sums.txt` coherente antes/después; `CONFIG_IDENTICA`; ruleset con la misma
huella; `git status` solo rutas permitidas.

```text
V7 sha256sums ok=143 bad=0 missing=0
   ruleset_sha256=64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b
   CONFIG_IDENTICA(ultimo)=CONFIG_IDENTICA
```

Tras **regenerar** `sha256sums.txt` con las fichas, productos y scripts del cierre
(`python _artefactos/scripts/verificar_validez_ventana.py`):

```text
V7 sha256sums ok=169 bad=0 missing=0
   ruleset_sha256=64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b
   CONFIG_IDENTICA(ultimo)=CONFIG_IDENTICA
   git status:
      M Dataset/Legitimo/legitimo_72h/ventana_meta.md
      M Soporte/Laboratorio/legitimo_72h/b10_sellado.md
      M Soporte/Laboratorio/legitimo_72h/exportar_acciones.sh
      M Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/MANIFEST.md
      M Soporte/Laboratorio/legitimo_72h/sha256sums.txt
      M Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/incidencias.md
      M Soporte/Metrica/boveda_congelacion.md
      M Soporte/Metrica/boveda_congelacion.sha256
      M _artefactos/scripts/metrica_hids.py
     ?? Dataset/Legitimo/legitimo_72h/PROMOCION.md
     ?? Dataset/Legitimo/legitimo_72h/alertas_detalle.csv
     ?? Dataset/Legitimo/legitimo_72h/campana_fp.csv
     ?? Dataset/Legitimo/legitimo_72h/campana_ventanas.tsv
     ?? Dataset/Legitimo/legitimo_72h/denominador_M.csv
     ?? Dataset/Legitimo/legitimo_72h/ghosts_acciones.csv
     ?? Dataset/Legitimo/legitimo_72h/ruleids_legitimos.csv
     ?? Soporte/Laboratorio/legitimo_72h/campana/campana_ventanas.tsv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/alertas_detalle.csv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/campana_fp.csv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/denominador_M.csv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/evidencia/
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/ghosts_acciones.csv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/ruleids_legitimos.csv
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/ventana_meta.md
     ?? Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/veredicto_validez.md
     ?? _artefactos/scripts/filtrar_ventana_alertas.py
     ?? _artefactos/scripts/promover_ventana_legitimo.py
     ?? _artefactos/scripts/tests/test_filtrar_ventana_alertas.py
     ?? _artefactos/scripts/verificar_validez_ventana.py
```

- **143/143** entradas del manifiesto **de la ventana** coinciden (`bad=0`, `missing=0`); tras el
  cierre, **169/169** (incluye fichas, productos, scripts y copias promovidas).
- Ruleset **idéntico** a B2 (`64213db7…`), antes y después.
- `CONFIG_IDENTICA` en el `cleanup` de cierre (**00:12:17Z**): `ossec.conf == ossec.conf.tfg-bak`.
- `git status` acotado a rutas permitidas: **MC-1** (`exportar_acciones.sh`), manifiesto de huellas,
  fichas, productos de la ventana, `campana_ventanas.tsv`, scripts nuevos, **B10 v3 / bóveda v2**,
  `metrica_hids.py` y la **promoción declarada** a `Dataset/Legitimo/legitimo_72h/`.
  **Nada** en `_recursos/`, corpus, `Hojas/`, ruleset ni snapshots.
- **Excepciones declaradas** (§9.1): ficheros que crean/borran los casos bajo `campana_fp/`; **una
  línea** de journal de C-11; `web_access.log` de la intranet (fuera de la víctima).

## V8 — Host estable · **PASA**

**Criterio:** `LastBootUpTime` < `t0`; 0 eventos `Kernel-Power` 42/107 en `[t0,t1]`.

```powershell
$os = Get-CimInstance Win32_OperatingSystem
"LastBootUpTime_utc=$($os.LastBootUpTime.ToUniversalTime().ToString('o'))"
$t0=[datetime]::Parse('2026-11-02T00:00:00Z').ToUniversalTime()
$t1=[datetime]::Parse('2026-11-05T00:00:00Z').ToUniversalTime()
"boot_lt_t0=$($os.LastBootUpTime.ToUniversalTime() -lt $t0)"
(Get-WinEvent -FilterHashtable @{LogName='System'; Id=42,107; StartTime=$t0; EndTime=$t1} -ErrorAction SilentlyContinue |
    Measure-Object).Count
```

```text
LastBootUpTime_local=2026-10-29T21:25:02.1868740+01:00
LastBootUpTime_utc=2026-10-29T20:25:02.1868740Z
t0=2026-11-02T00:00:00.0000000Z t1=2026-11-05T00:00:00.0000000Z
boot_lt_t0=True
KernelPower_42_107_en_ventana=0
```

- Arranque **3 días 3 h 35 min antes de `t0`** ⇒ **sin reinicio** dentro de la ventana.
- **0** eventos `Kernel-Power` **42** (suspensión) y **107** (reanudación) en `[t0,t1]`.

## V9 / V2bis — Recuperaciones, rotaciones y arranques · **PASA**

**Criterio:** recuperaciones **0**, rotaciones **2** (declaradas), arranques del cliente **≤ 3**.

```text
V9 recuperaciones=0 rotaciones=2 rotaciones_fallidas=0 arranques_cliente=3 rotacion_estado=2026-11-04
```

`recovery.log` (evidencia):

```text
2026-11-03T07:45:27Z accion=rotacion dia=2 sha_timeline=0e0329cc huella=dbbf3b32 pid_nuevo=272565 resultado=ok
2026-11-04T07:45:08Z accion=rotacion dia=3 sha_timeline=885a80b2 huella=89ed004a pid_nuevo=462962 resultado=ok
```

- **0 recuperaciones** (el keepalive no tuvo que reiniciar el cliente por caída).
- **2 rotaciones** (día 2 y día 3), ambas `resultado=ok`; el día 1 se salta porque el `sha` ya
  coincide. `rotacion.estado = 2026-11-04`.
- **3 arranques** del cliente (1 inicial + 2 por rotación) = **≤ 3**.
- `keepalive.txt`: **436** líneas (1 `inicio` + muestras cada 10 min) de
  `2026-11-01T23:55:02Z` a `2026-11-05T00:06:06Z`; **0** líneas `RECUPERACION` y **2** `ROTACION`
  (coinciden con `recovery.txt`).

---

## Veredicto global

**VÁLIDA CON INCIDENCIA.**

- **8 de 9** criterios **PASA** sin salvedades.
- **V6** es **válida con incidencia**: el orden de extracción se invirtió, pero la **fuente diaria
  estaba íntegra**, `M` se **re-extrajo** y coincide (`342 966`, `--estricto exit 0`, `sha256` de
  entrada idénticos). Ninguno de los 8 supuestos invalidantes de §9.3 concurre.
- Consecuencia: la ventana es **publicable** y **promovible** a `Dataset/` (§9.2, CA-21), con la
  incidencia **declarada en la ficha** y en `incidencias.md`.

### Lo que NO invalida (repasado contra §9.3)

| Supuesto invalidante | ¿Concurre? | Dato |
|---|---|---|
| Acceso del operador a la víctima en `[t0,t1]` | **No** | 0 `srcip=192.168.65.1`, 0 sesiones PAM/SSH/sudo |
| Agente caído o hueco > 60 min | **No** | 144/144 `ag=Active`; hueco máx. de alertas 62,6 s |
| Manager caído > 30 min o falta un diario | **No** | 144/144 `mgr=active/2`; 3 diarios con `sha256` OK |
| `M` no recuperable | **No** | re-extraído: 342 966, `exit 0` |
| Un bloque de trabajo entero sin acciones | **No** | 100 % de la receta los 3 días |
| Reinicio / suspensión / cierre de sesión | **No** | boot 29/10 20:25Z; 0 `Kernel-Power` 42/107 |
| Cambio de configuración no declarado | **No** | `CONFIG_IDENTICA`; ruleset `64213db7…` |
| > 2 recuperaciones o `ALARMA` de disco/agente | **No** | 0 recuperaciones; 0 `ALARMA` |

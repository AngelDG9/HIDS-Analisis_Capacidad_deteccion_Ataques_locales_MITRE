# T3 — ruido real del operador (ventana legítima Windows v2)

> **Bloque:** `windows-legit-prep` · **Plan:** `plan_w3bis.md` v2 `approved_by_human`
> (`4237a16`) · **Tanda:** T3 (§4 y §8).
> **Ejecución:** 2026-11-11 por `tfg-executor`.
> **Sin ventana de 72 h, sin ataques, sin snapshot, sin commits. Sin secretos.**
> Snapshot usado: **v1** `lab-listo-windows-legit` (7 snapshots; ninguno nuevo).

## 1. Qué se midió y cómo

| Elemento | Valor |
|---|---|
| Manager | VM `wazuh-server` (arrancada 15:03Z), `logall_json=no`, `CONFIG_IDENTICA` |
| Víctima | `victima-windows` (revert a v1 + `prep` + deploy 8.3.1, `MANIFIESTO_OK`) |
| Servicios de actividad | GHOSTS API `192.168.65.1:5000` + PostgreSQL `127.0.0.1:5432` (host) |
| Cliente GHOSTS | 8.3.1 (`Domain 8.2.7.90`, `exe 8.2.2.0`), `win_user=angel`, 1 proceso |
| Keepalive | **1 proceso** (`powershell.exe` + `conhost`), `-Loop`, mutex, 1 instancia |
| Chivato | sink `192.168.65.1:9095` → `heartbeat.jsonl` (`seq` encadenado) |
| **`t_a` (medida)** | **2026-11-11T15:11:00Z** (tras cerrar la última sesión SSH de *setup*) |
| **`t_b` (medida)** | **2026-11-11T15:52:30Z** |
| **Duración** | **41,5 min** (≥ 30 min exigidos) |
| Fuente de alertas | `ossec-alerts-11.json` del manager, agente **`002`**, `[15:00:00Z, 16:10:00Z]` |
| Extractor | `_artefactos/scripts/extraer_alertas_windows.py` (1.433 alertas en la franja extraída) |

### 1.1 Desviación declarada: no se ejecutó `arm`

`arm` habría ejecutado `construir_receta_legitima_windows.py --t0 2026-11-11`, que
**reescribe** `Soporte/Laboratorio/windows/recetas/calendario_windows.json` y
`bloques_windows.env` (comprobado: `w1/w2/w3.json` salen **idénticos**, pero el
calendario y el `.env` cambian). Ambos están en la lista de **no tocar** de esta tanda.
Se aplicaron **solo los efectos no destructivos de `arm`** que importan para el ruido:

1. `armado.flag` creado en el invitado;
2. `schtasks /run /tn TFG-WinLegit-Actividad` (cliente real, `win_user=angel`).

**`logall_json` se quedó en `no`** (no hay ventana ⇒ no hay `M` que medir; `T3` no
calcula FPR). No se abrió ninguna ventana y no se generó ningún `crudo`: el
`crudo.done` de `D:\TFG-VMs\legitimo-windows-2026-11-11\` es el **crudo de prueba de
T2b-2** y **no** se ha usado.

## 2. Resultado — alertas del agente `002`

| Fase | Franja UTC | Alertas totales | **Del operador** | % |
|---|---|---:|---:|---:|
| `prep` + *setup* (SSH del operador) | 15:00:00 – 15:10:59 | 1.068 | **213** | 19,94 % |
| **Ventana de medida** | **15:11:00 – 15:52:30** | **365** | **0** | **0,0000 %** |
| Posterior | 15:52:30 – 16:10:00 | 0 | 0 | — |

> **0 de 365 alertas del operador en 41,5 min ⇒ 0,0000 %**, frente al umbral **5 %**
> (`CA-W3b-13`). **PASA.**

Las **213** alertas del operador de la fase de `prep` **no** son ruido de ventana: son
las **sesiones SSH del propio `prep`/deploy** (que en la operación real viven **antes de
`t0`**). Desglose por motivo (`etiquetar_operador_legit.py`):

| Motivo | Filas | Qué eran |
|---|---:|---|
| `logon_operador` | 163 | `60106/60137/67023/67024/67028` de las sesiones SSH del host durante `prep` |
| `watch` | 45 | `verificar_windows.ps1` lanzado por SSH en `prep` (**no** por el `watch` v4) |
| `keepalive` | 4 | arranque del bucle (§3) |
| `vmware_tools` | 1 | un hijo de `vmtoolsd.exe` durante `prep` (G-W8 lo cuenta) |

> **T3b (corrección de etiqueta):** `67028` (4672) ya **no** se marca por
> `win_user=angel` a secas. En `prep` había **34** filas de 4672 con `win_user=angel` y
> **sin** `logon_type`/IP (`4672` no trae `logon_type`): se dejan como ruido del sistema
> (lado seguro). Recuento del operador: **247 → 213** (`logon_operador` 197 → 163). La
> **ventana (365/0) no cambia**.

Tras `t_a` **no hay ni una fila** de `logon_operador`, `watch`, `keepalive`,
`vmware_tools`, `latido` ni `logs_operador`.

## 3. Ruido del keepalive (`ruido_keepalive.csv`)

El bucle arrancó **dos veces fuera de la medida** (una al arrancar el invitado y otra
al reiniciarlo el `deploy` con `schtasks /run`). **No hay un número fijo de alertas por
arranque: se midieron 1–3** según el arranque (`67027` proceso y `92029` «Powershell
executed script from suspicious location», nivel 6, por la ruta del script):

| Arranque | UTC | Alertas | Reglas |
|---|---|---:|---|
| 1.º (al iniciar el invitado) | 15:05:53 | **1** | `92029` |
| 2.º (`deploy`) | 15:07:16 y 15:07:45 | **3** | `67027`(×2) + `92029` |

- **Dentro de la ventana: 0** alertas del keepalive: el bucle **arranca en `prep`**
  (antes de `t_a`), así que en la ventana solo late (0 arranques dentro).
- **Proyección 72 h:** 0 si el bucle arranca antes de `t0` y no hay recuperaciones
  (caso normal, igual que Linux con su servicio persistente); **1–3 por recuperación**
  (máximo declarado `RestartCount=3` ⇒ **≤ 9** en el peor caso patológico).
- `heartbeat.jsonl`: **11 latidos** (`seq` 1→11, 15:07:56→15:55:01), **1 solo `ka_pid`
  (1456)**, `ka_instancias=1` en **11/11**, cadena `INICIO` + 10 `OK`, `Δ` máx **3,381 s**
  (primer latido tras el arranque). En la ventana: **8/8 latidos con Δ ≤ 0,567 s**.
- **Parada ordenada:** `stop.flag` a las 15:55:07 ⇒ `KA_PROCS=0` a las 16:01 (≤ 6 min).

## 4. Ruido del chivato y del `watch` (`ruido_watch.csv`)

- **`:9095` no genera ni una alerta**: `185001` (Sysmon 3) es **nivel 0** y no aparece
  en `ossec-alerts-11.json`; **0** ocurrencias de `"9095"` en el log de alertas.
  El único tráfico del chivato es el `POST` del propio bucle.
- **3 chequeos del `watch`** (15:10:18, 15:28:15, 15:51:31), todos `fallos=0`,
  `SSH_INVITADO=0`, `HB_EDAD_MIN` ≤ 3,2 min, `ka_instancias=1`.
- **`skip=1` en los 3 chequeos — es `G-W7`** (`logall_json` según `[t0,t1]`): no había
  `ventana_actual.json` porque **no se ejecutó `arm`** (§1.1), así que `G-W7` sale
  **SKIP declarado** (`ok=8 fallos=0 skip=1`). No es un fallo; `T4` lo probará en el
  **ensayo del cierre** (con `arm` real y ventana). Los otros 8 checks dan `OK`.
- **Frecuencia ad hoc, no 30 min:** los 3 chequeos son de `T3` a mano, separados
  **18 y 23 min** (15:10→15:28 = 17:57; 15:28→15:51 = 23:16). El `watch` en operación
  real va a **30 min**; aquí se lanzó ad hoc para muestrear la ventana corta.
- **Alertas nuevas del operador en la franja de cada chequeo:** **0** en los dos
  chequeos de la ventana (15:28 y 15:51). El chequeo de 15:10 se marca `setup` porque su
  franja ±60/120 s incluye la **sesión SSH con la que se arrancó la actividad** (no la
  abre el `watch`); se deja en el CSV con la nota, sin maquillar.

## 5. Ruido del sistema (lo que sí alerta, y no es del operador)

Top de reglas en la ventana de medida (365 alertas):

| `rule_id` | Alertas | Qué es |
|---|---:|---|
| `67027` | 296 | «A process was created» (actividad legítima + servicios) |
| `92213` | 28 | ejecutable creado en carpeta de usuario |
| `92052` | 13 | cmd lanzado por proceso «anormal» |
| `92200` | 9 | scripting file en Temp/User |
| `92032` | 3 | cmd sospechoso |
| `91823`/`91820` | 2/2 | PowerShell `Invoke-Command` / búsqueda recursiva |
| `61104` | 2 | cambio de tipo de arranque de servicio |

Es **ruido de la actividad legítima y del sistema** (WU, servicios, Sysmon), no del
operador. Es exactamente el material que el FPR debe contar; el etiquetador lo deja
`operador_legit=0 / sin_operador=1`.

## 6. Etiquetador `sin_operador`

`_artefactos/scripts/etiquetar_operador_legit.py` (+ 20 tests en
`tests/test_etiquetar_operador_legit.py`):

- Marca por **evidencia estrecha** y determinista: comando del keepalive, `win_target`
  `192.168.65.1:9095`, rutas de sus logs, hijos de `vmtoolsd.exe`, logon del operador
  (predicado canónico `OPERADOR_WIN` importado de `filtrar_ruido_windows.py`) y, opcional,
  intervalos horarios **solo** con `rule_id` declarados.
- **Nunca** marca por `win_user=angel` a secas (es el usuario legítimo) ni
  `powershell.exe`/`cmd.exe` genéricos ni rutas del usuario.
- **T3b — `67028` (4672):** además del predicado canónico se exige **contexto de red o
  SSH en la propia fila** (`logon_type=3`, `srcip=192.168.65.1` o cuenta `sshd_<pid>`).
  El autologon de consola (`logon_type=2`) **no** se marca. Hay test para ambos lados.
- Salida: el CSV de entrada + `operador_legit`, `sin_operador`, `motivo_operador`,
  `evidencia_operador`; y una **auditoría JSON** con cada fila marcada y su porqué.
- Sobre esta medida (tras T3b): `filas=1433 operador=213 sin_operador=1220`
  (`por_motivo={'keepalive': 4, 'logon_operador': 163, 'vmware_tools': 1, 'watch': 45}`),
  `alerta_diseno=True` **solo por el `watch` de `prep`** (SSH de `verificar_windows`),
  no por el `watch` v4. Determinista: dos ejecuciones con el mismo CSV y el mismo nombre
  de salida dan **bytes idénticos**.

## 7. Doble FPR — plantilla (no se calcula la ventana)

Unidad **la misma que Linux**: `FP_uni` = **línea de `archives`** con ≥ 1 alerta;
`M` = líneas de `archives` del endpoint (`metrica_hids.md:45-54, 86-96`).

```text
FPR_canonico     = FP_uni / M
FPR_sin_operador = (FP_uni - operador_uni) / M
```

`operador_uni` se cuenta **en líneas de `archives`** cruzando `(timestamp, rule_id)` de
las alertas marcadas con el crudo (`--archives`); sin crudo el script declara
`unidad=alerta_provisional` y **no** publica FPR. El denominador **no cambia** (mismo
criterio que la sensibilidad «sin auto-ruido» de Linux).

> **Ojo con los nombres (no son sinónimos):** el **0,664693** de Linux es
> `sin auto-ruido` (`227.967 / 342.966`; descuenta las 66.285 líneas de ruido del
> **propio HIDS**, `80791`), **no** `sin_operador`. El `sin_operador` de Linux sería
> **0,857963** (`294.252 / 342.966`): el operador de Linux **no se ve** por la
> telemetría (**H-COMP-1**, 0/294.257 alertas), así que **no hay nada que descontar**.
> En Windows, en cambio, el operador **sí** deja rastro y se descuenta con
> `operador_uni`; esa es la comparación honesta entre plataformas.

`--plantilla` imprime la fórmula; `--fpr M FP OP` la evalúa; los tests la prueban con
datos sintéticos (`M=1000, FP=200, OP=4 ⇒ 0,2 y 0,196`). **No se calcula el FPR de la
ventana de Windows: no existe todavía.**

## 8. Ficheros y `sha256`

| Fichero | Bytes | `sha256` |
|---|---:|---|
| `alertas_detalle.csv` (detalle del extractor) | 406.424 | `01e33556770a5136962adfe6d4ee5f949dcc493fa9abdea22c68ec9ffaf40789` |
| `alertas_detalle_operador.csv` (etiquetado, **T3b**) | 436.788 | `b0aa210675654b887f8ae847e0bb33decebb7a8c6ef7a4bded6d0613922b2879` |
| `operador_auditoria.json` (qué y por qué, **T3b**) | 56.661 | `048f74eed332eb1adeca2bce750edb4cfd591909d12a79d0b03ee4a253777b37` |
| `ruido_keepalive.csv` | 1.552 | `bfab00eec94ec1f356327e6b2616708d54129920e183ae14ea9e2d5bda350673` |
| `ruido_watch.csv` | 471 | `82f0f5b2b77c0868631942760221e7be94e7550eeedb9fc7a94ad57f0c4ff72c` |
| `ruleids.csv` (agregado por regla) | 5.062 | `06e704a248a08161c632be2fc894a07b25700ef184d2e26e43487ed954332fa3` |

Fichero crudo de alertas del manager (fuera del repo, no versionable):
`D:\TFG-VMs\legitimo-windows-2026-11-11\t3\ossec-alerts-11.json`
(29.304.172 bytes, `sha256=0f333984d13d6263a87c64c345df69d6702666622caf2fa73b4048a6b9fca9ed`).

## 9. Cierre

- **0 VMs** (`vmrun list` = 0), sink `:9095` **parado**, GHOSTS API **0 procesos**,
  PostgreSQL **sin respuesta** (`pg_isready rc=2`).
- **0 tareas `TFG-*`** en el invitado (las 2 borradas) y **0 tareas `TFG-*`** en el host.
- **Borrado del invitado = evidencia fuera del log de control:** las **2 tareas `TFG-*`**
  del invitado y el `armado.flag` se borraron por **SSH** al cerrar. El
  `windows_legit_host_control.log`/`vigilancia_windows.log` de T3 **no registran ese
  borrado** (el `watch` solo anota su chequeo; el `cleanup` no se ejecutó). Queda
  **declarado aquí** y **T4 lo capturará** en su ensayo de cierre (log del `cleanup` con
  las tareas y el flag ya retirados).
- Manager: `logall_json=no` + `CONFIG_IDENTICA` verificados **antes** de apagarlo.
- Variables `TFG_MANAGER_PW`/`TFG_GUEST_PW` **no** se escribieron en ningún fichero ni
  se dejaron en el entorno de ningún proceso persistente.
- No se creó snapshot; los 7 existentes siguen intactos.

## 10. Veredicto T3 / T3b

> **T3 PASA.** Ruido del operador medido: **0/365 = 0,0000 %** (umbral **5 %**),
> keepalive **1 proceso / 1 instancia / 0 alertas en ventana**, chivato **0 alertas**,
> `watch` **0 SSH**, doble FPR **definido en la unidad de Linux** y **probado con
> sintéticos**. Lo único que queda para T4 es la **ventana real** (2 h + snapshot v2)
> y, con ella, `M`/`FP_uni`/`operador_uni` sobre el crudo.
>
> **T3b PASA (corrección de etiqueta):** `67028` ya no se marca por usuario a secas;
> recuento `prep` **247 → 213** (`logon_operador` 197 → 163), **ventana 365/0 intacta**,
> etiquetador determinista y `pytest` **419**. Se declaran aquí el keepalive **1–3 por
> arranque**, el `skip=1` de `G-W7` (sin `arm`), la frecuencia **ad hoc 18/23 min** y que
> el **0,664693** es `sin auto-ruido` (no `sin_operador`; Linux `sin_operador` =
> **0,857963**).

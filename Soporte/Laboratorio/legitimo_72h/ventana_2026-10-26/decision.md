# decision.md — aborto de la ventana `legitimo-72h-v2`

| | |
|---|---|
| **Bloque** | `legitimo-72h-v2` (`plan.md` v1, `status: approved_by_human`, §5.5 «Aborto temprano») |
| **Fecha de la decisión** | **2026-10-27** |
| **Hora local (Europe/Madrid, UTC+1)** | **16:53** (inicio del cierre) · 17:04 (fin del cierre) |
| **Hora UTC** | **15:53Z** (inicio) · **16:04Z** (fin) |
| **Ventana prevista** | `t0 = 2026-10-26T00:00:00Z` → `t1 = 2026-10-29T00:00:00Z` (72 h) |
| **Tiempo transcurrido en el aborto** | **≈ 39 h 53 min** (40,08 h hasta el fin del cierre) — quedaban ≈ 32 h de ventana |
| **Quién decide** | el humano (orquestador del TFG) |
| **Autorización** | `plan.md` §5.5: «el humano puede **abortar** para no gastar 2 días: `registrar_tareas -Eliminar` + `cleanup` (**host-side**, sin entrar en la víctima) y se reprograma. **Se registra el motivo** (no se «arregla» la ventana)» |

> **La decisión se tomó ANTES de analizar resultados.** No se ha extraído, contado, abierto ni
> analizado ningún dato de la ventana (ni denominador `M`, ni alertas, ni acciones GHOSTS). No se ha
> ejecutado `exportar_denominador.sh`, `contar_denominador.py`, `extraer_alertas.py` ni
> `exportar_acciones.sh`. El estado de las señales que sí se conocía (registro de vigilancia y
> `incidencias.md`) es el de **operación**, no el de resultados.

## 1. Motivo

La ventana **no se aborta por invalidez** (no se había observado ninguna condición invalidante de
§7.3: agente vivo, manager vivo, ficheros diarios presentes, bloques con acciones). Se aborta porque
el humano decide **rehacer la ventana con un diseño mejor** antes de gastar las 32 h restantes:

1. **Actividad más realista** — la receta actual produce un patrón demasiado regular (bloques fijos,
   acciones cada pocos minutos en las mismas horas), lo que hace la ventana poco representativa de
   actividad legítima real y facilita que el resultado dependa del patrón y no del HIDS.
2. **Campaña dirigida de falsos positivos** — se quiere añadir, **fuera** de esta ventana, una campaña
   explícita de acciones legítimas «ruidosas» (las que se sospecha que disparan reglas) para poder
   medir falsos positivos con denominador suficiente, en vez de esperar a que aparezcan por azar.

Consecuencia: **los datos de esta ventana no se van a usar** para la métrica. No se promocionan a
`Dataset/` (no hay nada que promocionar: no se extrajo nada). La ventana se repetirá **entera** con
un plan nuevo (nuevo `plan.md`, nuevo gate humano).

## 2. Qué se ha hecho (orden ejecutado)

| # | Paso | Comando | Resultado |
|---|---|---|---|
| 1 | **Parar la vigilancia** (primero, para que `watch` no corra durante el cierre) | `registrar_tareas.ps1 -Eliminar` | `rc=0`; eliminadas `TFG-Legit-Prep`, `-Arm`, `-Watch`, `-Stop`. Verificado: **0 tareas `TFG-Legit-*`** |
| 2 | **Preservar evidencia del manager** (antes de apagar `logall_json`, que borra `archives.json`) | `ssh`+`sudo -S` **solo lectura** al manager `192.168.65.128` → copia a `D:\TFG-VMs\legitimo-2026-10-26-piloto\` | `rc=0`; 6 ficheros + `MANIFEST.tsv` + `df-root.txt` (ver §3) |
| 3 | **Parar la víctima** (soft; el manager seguía arriba) | `legitimo_host_control.ps1 -Phase stop -T0 2026-10-26T00:00:00Z -T1 2026-10-29T00:00:00Z` | `rc=0`; `vmrun stop … soft -> rc=0`; `vmrun list` → **1 VM** (solo el manager) |
| 4 | **Cierre** | `legitimo_host_control.ps1 -Phase cleanup -T0 … -T1 …` | `rc=0`; `logall_json` → **no**, `CONFIG_IDENTICA`, manager abajo, reglas `TFG-*` retiradas, **0 VMs** |
| 5 | **Verificación final** | `vmrun list` / `listSnapshots` / `Get-ScheduledTask` / `Get-NetFirewallRule` / `Get-Service` | ver §5 |

Detalles de operación:

- `logall_json off` (16:02:17Z) reinició el manager; `wazuh-apid` requirió 2 intentos (`manager=active`
  en el intento 2) y `agent_control=OK`. Estado registrado tras el apagado:
  `conf: <logall_json>no</logall_json>` · `manager=active` · `daemons_remoted_analysisd=2`.
- `diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf` → **`CONFIG_IDENTICA`**.
- `cleanup` incluye un `client_ctl.sh stop` por SSH a la víctima: la VM ya estaba apagada desde el
  paso 3, la conexión **no llegó a establecer** (el intento agotó el tiempo de TCP, 15:59:19Z →
  16:02:17Z) y **no se ejecutó nada en el invitado**. El cierre del invitado fue el `stop soft` del
  paso 3, como manda el plan.
- El `stop soft` de la víctima dejó la VM **apagada con sus cambios** (no se revierte el snapshot:
  la próxima `prep` revierte a `lab-listo-legit-v2`).
- **No se ha restaurado Windows Update** (la próxima ventana lo necesita pausado). Su estado se anota
  en §5.

## 3. Evidencia preservada (fuera del repo)

Ruta: **`D:\TFG-VMs\legitimo-2026-10-26-piloto\`** (fuera de `D:\TFG\…`).

| Fichero | Bytes | SHA-256 |
|---|---|---|
| `ossec-archive-26.json.gz` | 14 651 172 | `9377b285ad1f5a6fe48abcf531fde816af0990b6ce10c471fbfbe179c5e3daec` |
| `ossec-archive-26.json.sum` | 641 | `d4a98b75b1758bf1ae4951a8735169ec86fe36075aa039f45ad06a04829fe42b` |
| `ossec-archive-27.json` | 167 168 486 | `930aba80ba8fa69ced947c3cb218a7ea5ca086eeaed01a7493b33cc048a90eff` |
| `ossec-alerts-26.json.gz` | 12 201 350 | `4e85c735714cd9a2886539da5efa22b0c7464da9b06ce9419e57977265d133a1` |
| `ossec-alerts-26.json.sum` | 623 | `105ec2f0ff3f98cf5bb44f2de08375b89ee1607d9aedb7c0db87f2626c98b8a6` |
| `ossec-alerts-27.json` | 153 710 947 | `21ee2f623328dc8704b90e96e4a29f6b200896057704cdf1913808957a59d9ac` |

**Total: 6 ficheros, 347 733 219 bytes (331,6 MiB).**

Metadatos de la copia (mismo directorio):

- `MANIFEST.tsv` — `ruta`, `bytes`, `sha256` de los 6 ficheros (formato TSV, la tabla de arriba).
- `_sha256_remoto_dia26.txt` — `sha256sum` **calculado en el manager** de los dos ficheros
  **estáticos** del día 26: **coinciden byte a byte** con los locales (`archive-26` y `alerts-26`).
- `df-root.txt` — `df -h /` del manager: `48G` total, `26G` usados, **`19G` disponibles (58 %)**.
- `_inventario_remoto.txt` — `ls -l --time-style=full-iso` de `logs/archives/2026/Oct` y
  `logs/alerts/2026/Oct` (estado en el momento del cierre).
- `_copias.stderr` — trazas de `sudo`/`ls` de las copias (sin secretos).

Notas de fidelidad:

- `ossec-archive-27.json` y `ossec-alerts-27.json` son los **ficheros vivos** del día 27 (hardlink de
  `archives.json`), **en crecimiento** durante la copia (~30 KB/s). Los bytes y `sha256` de la tabla
  corresponden **al instante de la copia**, no a un fichero cerrado: en el manager, a las 15:58:49Z,
  el fichero ya medía 167 583 447 B. **No existe `.gz` del día 27** (rota a las 01:00 local), igual
  que en el plan se preveía para el día 28.
- Los nombres reales en el manager son `ossec-archive-NN.json[.gz]` (singular «archive»), no
  `ossec-archives-NN…` como decía el encargo. Se copiaron con su **nombre real**.
- Se añadieron los dos `.sum` del día 26 (no pedidos expresamente, mismo directorio, coste 1,3 KB):
  son la huella que el propio Wazuh deja del fichero rotado y sirven para verificar la copia.

## 4. Qué se descarta (y por qué)

- **`archives.json` del manager (166 685 184 B, hardlink del día 27): BORRADO** por
  `logall_json_ctl.sh off` (`rm -f archives.json`, línea 53 del script), como estaba previsto en el
  plan. Es la razón de que la copia del paso 2 fuera **antes** del `cleanup`. Lo único que se conserva
  de ese fichero son los **167 168 486 B copiados** en `D:\TFG-VMs\legitimo-2026-10-26-piloto\`.
  Comprobación posterior en el manager: `ls -l /var/ossec/logs/archives/` → solo `2026/` y
  `archives.log` (0 B); **no hay `archives.json`**.
- **Los datos de la ventana no se van a analizar ni a usar**: no se ha extraído nada (ni `M`, ni
  alertas, ni acciones). En `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/` solo quedan
  documentos de **operación**: este `decision.md`, el `incidencias.md`, y dos anexos de la copia
  (`MANIFEST_preservado.tsv` y `manager_df_root.txt`, copias literales de los del directorio de
  evidencia). **No** se promociona nada a `Dataset/`.
- La evidencia preservada **no se borra**: queda como testigo de lo que hizo el laboratorio
  (útil para dimensionar disco: `archives` del manager creció a ~5 MB/h con la receta actual, y el
  `/` del manager se quedó en 19 GB libres).

## 5. Estado final verificado (2026-10-27T16:04Z)

| Comprobación | Esperado | Obtenido | ✔ |
|---|---|---|---|
| VMs encendidas | 0 | `Total running VMs: 0` | ✔ |
| Tareas `TFG-Legit-*` | 0 | 0 (`registrar_tareas.ps1 -Verificar` → «NO hay tareas») | ✔ |
| Reglas de firewall `TFG-*` | 0 | 0 (retiradas `TFG-ghosts-5000`, `TFG-web-8080`, `TFG-sink-9090`, `TFG-webdav-9092`) | ✔ |
| `logall_json` | `no` | `<logall_json>no</logall_json>` (último `status` antes de apagar el manager) | ✔ |
| `ossec.conf` vs `.tfg-bak` | idéntica | `CONFIG_IDENTICA` | ✔ |
| Snapshots de `victima-linux` | 5 (incl. `lab-listo-legit-v2` **intacto**) | 5: `base-limpia`, `lab-listo`, `lab-listo-legit`, `fallo-2026-10-19-disco-lleno-NO-USAR`, **`lab-listo-legit-v2`** | ✔ |
| Snapshot `lab-listo-legit-v2` no tocado | metadatos sin cambios | `victima-linux.vmsd` mtime **2026-10-21 07:51**, su disco `victima-linux-000005.vmdk` mtime **2026-10-21 07:50** (anteriores a la ventana) | ✔ |
| `TFG_GUEST_PW` | conservada | presente como variable **de usuario** (`User`); `TFG_MANAGER_PW` no existe (se usa el fallback) | ✔ |
| Procesos del lab (GHOSTS / PostgreSQL / internet local) | 0 | 0 (`stop_ghosts.ps1` y `stop_internet_local.ps1` correctos) | ✔ |
| Disco `D:` del host | holgado | **181,3 GB libres** | ✔ |
| `wuauserv` (**no se restaura**) | se anota | **`Running` / `Manual`** ⇒ **NO está pausado**: el servicio se auto-reparó, como ya se documentó en `incidencias.md` (26/10 09:40 local). La **política** `NoAutoUpdate=1` + `NoAutoRebootWithLoggedOnUsers=1` no se ha tocado. **La próxima `prep` debe re-pausarlo** (P-1 / G-10, `pausar_windows_update.ps1 pausar`) | ⚠ anotado |

Snapshots del manager (informativo): 2 — `base-limpia`, `lab-listo`. No se han tocado.

## 6. Las 4 `ALARMA` de borde (todas falsas)

Todas del **mismo patrón**, ya declarado en `incidencias.md` §«Patrón conocido»: la vigilancia
comprueba a las `:00:02`/`:30:02` y dos bloques de la receta empiezan **en punto** (`08:00Z`, `14:00Z`);
en ese chequeo exacto la señal 1 (`doing>30m`) compara con la última acción del bloque **anterior**,
antes de que ocurra la primera del nuevo. **Ninguna es persistente** (el chequeo siguiente siempre da
`OK`), así que **ninguna invalida** la ventana (§7.2). Son falsos positivos **del instrumento de
vigilancia**, no del HIDS.

| Fichero | UTC | Señal | `doing_age` | Chequeo siguiente |
|---|---|---|---|---|
| `ALARMA_2026-10-26T080002Z.txt` | 26/10 08:00:02Z | `doing>30m` | 6654 m | 08:30Z → `OK`, 4 m |
| `ALARMA_2026-10-26T140005Z.txt` | 26/10 14:00:05Z | `doing>30m` | 62 m | 14:30Z → `OK`, 5 m |
| `ALARMA_2026-10-27T080007Z.txt` | 27/10 08:00:07Z | `doing>30m` | 902 m | 08:30Z → `OK`, 3 m |
| `ALARMA_2026-10-27T140004Z.txt` | 27/10 14:00:04Z | `doing>30m` | 62 m | 14:30Z → `OK`, 3 m |

Los 4 ficheros `ALARMA_*.txt` se **conservan** en `Soporte/Laboratorio/legitimo_72h/` como evidencia
de operación. **Corrección para la próxima ventana:** el umbral de `doing` debe ignorar el primer
chequeo de cada bloque (o desplazar la vigilancia 2 min), para no generar 6 falsas alarmas de
instrumento en 72 h.

## 7. Lo que queda para la próxima ventana (no se hace ahora)

- Diseñar un `plan.md` nuevo (actividad más realista + campaña dirigida de falsos positivos) y pasar
  su gate humano. **No se repite nada con este plan.**
- **Re-pausar Windows Update** (hoy `Running`/`Manual`, §5) antes de `prep`.
- Decidir si el instrumento de vigilancia se corrige (§6).
- La víctima se queda **apagada, con los cambios de la ventana abortada**; la próxima `prep`
  revierte a `lab-listo-legit-v2`.
- Nada se ha commiteado ni se ha hecho `push`: este `decision.md` y la evidencia quedan sin sellar.

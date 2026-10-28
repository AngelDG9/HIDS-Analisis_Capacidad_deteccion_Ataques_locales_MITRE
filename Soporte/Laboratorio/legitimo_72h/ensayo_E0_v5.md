# Ensayo E0 (v5) — armado de punta a punta antes de `t0`

> **Bloque:** `legitimo-v3` · **Plan:** `plan.md` §6 (E0-1…E0-10) · **Gate:** `approved_by_human`
> (2026-10-27). **Este E0 es un ENSAYO con `T0` falso**: **no fija la ventana** (regla §3.2), **no
> registra tareas** y **no deja fecha** en la receta (al final se regeneró con `mapa_dias` **vacío**).
>
> **Ejecución:** **2026-10-28, 21:54:49Z → 22:59:25Z** (≈ **64 min**; hora local CET = UTC+1).
> **Host:** `angel` (D: 181 GB libres, `wuauserv` re-pausado). **Snapshot:** `lab-listo-legit-v3`.
> **Veredicto: PASS**, con **11 salvedades/hallazgos** declarados (§5: **H-1…H-8** y **S-1…S-3**),
> ninguno achacable al mecanismo de la ventana. **H-6** (Windows Update **se auto-repara y vuelve a
> `Manual` en 3–10 min**) queda cubierto por una **mitigación obligatoria en el `watch`** (§5.1):
> **re-pausar justo antes de `t0` no basta**. Las **desviaciones respecto del plan** están
> declaradas, una por una, en **§4.1**.
>
> **Disciplina de acceso:** entre el inicio y el fin de cada tramo **no se abrió ninguna sesión SSH
> a la víctima** (evidencia: `/var/log/auth.log`, §4.5). La colocación de la timeline y la recogida
> son anteriores/posteriores al tramo.

---

## 1. Tabla de pasos (duración real / tope / resultado)

| # | Paso | Inicio → fin (UTC) | **Duración** | **Tope** | **Resultado** |
|---|---|---|---|---|---|
| **0** | `cleanup` de partida (estado conocido) | 21:54:49 → 21:55:03 | **14 s** | 10 min | **PASS** (rc=0; 0 VMs; `CONFIG_IDENTICA`) |
| **1** | Receta con **T0 falso** (`--t0 2026-10-28`) | 21:55:2x | **< 1 s** | 2 min | **PASS** (`RESULT=PASS`; mapa 28→d1/29→d2/30→d3) |
| **2** | `prep -T0 2026-10-28T22:30:22Z -T1 …+72 h` | 21:55:52 → 21:59:27 | **215 s** | 15 min | **PASS** (rc=0; G-1…G-12 OK) |
| **3** | Comprobaciones en el invitado | 21:59:4x | **~2 s** | 5 min | **PASS con hallazgo** (12/12 binarios; `sudo -n` rc=1 esperado; `app.log` aún no existe) |
| **4** | `arm -T0 2026-10-28T22:24:46Z` | 21:59:49 → 22:00:07 | **18 s** | 5 min | **PASS** (timer `NEXT=22:19:46Z`=`T0−5`; 1 proceso; `recovery.log` vacío) |
| **5a** | **P1**: jornada d1 comprimida (147 acciones) | 22:05:00 → 22:11:33 | **393 s** de ejecución | 10 min | **PASS** (147/147; 0 pipes) |
| **5b** | **P2**: campaña B6 comprimida (63 acciones / 11 casos) | 22:16:00 → 22:54:07 | **2 287 s** de ejecución | 45 min | **PASS** (63/63; 22 marcas; 11 `hecho.txt`; 33 ficheros) |
| **5** | *(conjunto del paso: setup + P1 + P2 + recogida)* | 22:01:07 → 22:56:34 | **≈ 55 min** | **25 min (⚠, tope del encargo)** | **PASS**, **tope superado** — ver **H-4** |
| **6** | `stop` + `cleanup` | 22:57:17 → 22:58:24 | **67 s** (`stop` 3 s + 3 s de enlace + `cleanup` 61 s) | 10 min | **PASS** (0 procesos; `logall_json=no`; `CONFIG_IDENTICA`; 0 VMs; 0 reglas) |
| **7** | `revert` a `lab-listo-legit-v3` + `verificar_arreglos.sh` | 22:58:25 → 22:59:20 | **≈ 55 s** | 5 min | **PASS** (6 snapshots; `RESULT=PASS`; 0 VMs) |

**Ningún paso quedó colgado.** Todos los comandos SSH llevaron `-o BatchMode=yes -o
ConnectTimeout=10` y, cuando podían tardar, `timeout` remoto + tope del lanzador con **kill del
árbol** (`taskkill /T /F`) y **stdin desde NUL** (así un `ssh`/`sudo` que pidiera credenciales
recibe EOF en vez de esperar 6 h).

---

## 2. Salidas literales por paso (recortadas)

### 2.1 Paso 0 — `cleanup` de partida (14 s, rc=0)

```text
[21:54:50Z] [cleanup] === START cleanup ===
[21:54:50Z] [cleanup] cleanup: victima_en_marcha=True manager_en_marcha=True
[21:54:51Z] [cleanup] cleanup: cliente parado (fase remota de la victima hecha)
[21:54:52Z] [cleanup] bash /tmp/logall_json_ctl.sh off
ssh.exe : bash: /tmp/logall_json_ctl.sh: No such file or directory      <-- ver H-8
[21:54:52Z] [cleanup] sudo -S -p '' diff /var/ossec/etc/ossec.conf.tfg-bak /var/ossec/etc/ossec.conf ... 
CONFIG_IDENTICA
[21:54:55Z] [cleanup] vmrun -T ws stop ...victima-linux.vmx soft -> rc=0
[21:54:59Z] [cleanup] vmrun -T ws stop ...wazuh-server.vmx soft -> rc=0
[21:55:03Z] [cleanup] vmrun -T ws list -> rc=0 Total running VMs: 0
[21:55:03Z] [cleanup] === END cleanup ===
```

> **`p0_cleanup.err.txt` es inocuo.** El `stderr` de este paso solo contiene
> `pg_ctl: el archivo de PID «D:/TFG-VMs/material-ghosts/pgdata/postmaster.pid» no existe —
> ¿Está el servidor en ejecución?` y el `rc` fue **0**: PostgreSQL **no estaba levantado**
> (el `cleanup` de la tanda anterior ya lo había parado), así que no había nada que parar.
> No hay ningún efecto sobre la ventana ni sobre el estado del laboratorio.

### 2.2 Paso 1 — receta con fecha falsa (solo para el ensayo)

```text
$ python _artefactos/scripts/construir_receta_legitima.py --t0 2026-10-28
d1.json  147 acciones de jornada + 16 de B6 ... sha256=e711bc93…
d2.json  153 acciones de jornada + 25 de B6 ... sha256=216a747b…
d3.json  141 acciones de jornada + 22 de B6 ... sha256=86057a15…
mapa_dias=2026-10-28:1,2026-10-29:2,2026-10-30:3
RESULT=PASS
```

> Las timelines `d1/d2/d3` **no cambian** con la fecha (mismo `sha256` que sin fecha); solo cambian
> `calendario.json` y `bloques.env` (`mapa_dias`). Al final se **regeneró sin fecha** (§6).

### 2.3 Paso 2 — `prep` (215 s, rc=0)

```text
[21:55:52Z] [prep] === START prep t0=2026-10-28T22:30:22Z t1=2026-10-31T22:30:22Z ===
[21:55:52Z] [prep] G-1 OK: snapshot 'lab-listo-legit-v3' presente | Total snapshots: 6 …
[21:55:52Z] [prep] G-10: D_libre_gb=181 wuauserv_StartType=Disabled sesion=angel
[21:55:53Z] [prep] G-4 --check: … RESULT=PASS
[21:55:53Z] [prep] G-4 OK: d1=e711bc93 d2=216a747b d3=86057a15 mapa=2026-10-28->d1,2026-10-29->d2,2026-10-30->d3
[21:56:10Z] [prep] G-12: ram_free_mb=2528 swap_mb=1915 ram_min_mb=1500
[21:56:10Z] [prep] G-12 AVISO (declarado): swap_mb=1915 != 0
Despliegue completado (cliente + nlog.config + d1/d2/d3 + calendario + carpetas).
[21:57:27Z] [prep] G-2: df_free_mb=4512 inodos_libres_pct=84
[21:57:28Z] [prep] G-3 verificar_arreglos: … RESULT=PASS   (rc=0; campana_fp=OK; carpetas_cwd=OK; client_cwd=/home/angel)
[21:58:50Z] [prep] G-7: conf: <logall_json>yes</logall_json> manager=active daemons_remoted_analysisd=2
[21:59:16Z] [prep] servidor GHOSTS lanzado
[21:59:17Z] [prep] firewall: regla TFG-ghosts-5000 creada (TCP 5000 desde 192.168.65.0/24)
[21:59:22Z] [prep] G-8: 8080/9090/9092 OK; example.com FALLA (ok, aislado); 1.1.1.1 FALLA (ok, aislado); sin `default via`
# (aqui "OK" = "puerto a la escucha"; el GET / del host contra 9092 da 404 - esperado, ver la nota de G-8)
[21:59:23Z] [prep] G-5: agentd_procs=1 | … Status: Active …
[21:59:23Z] [prep] G-11: machineids de victima-linux = 7c33a13a-fe89-4a56-bf3c-fcd499e1e557
[21:59:25Z] [prep] prep: timeline activa = e711bc93 (esperado d1=e711bc93)
[21:59:25Z] [prep] prep: rotacion.estado = 2026-10-28 (día 1 ya colocado; no se rota el día 1)
[21:59:26Z] [prep] G-6 OK: muestras 'df -P' del agente 001 en archives.json
[21:59:26Z] [prep] H1(b) estado del watch sembrado: archives=133559091B alerts=201197200B df_edad_min=-1
[21:59:27Z] [prep] === END prep (laboratorio LISTO, cliente PARADO) ===
```

**Guardarraíles:** G-1, G-2, G-3, G-4, G-5, G-6, G-7, G-8, G-10, G-11, **OK**; **G-12 OK con aviso
declarado** (swap 1 915 MB, ya documentado); G-9 informativo y vacío (no había `.gz` previo).
**Ningún código de aborto.**

**G-8 — declarado con precisión (9092 en local).** La comprobación **del host** que hace
`start_internet_local.ps1` deja `8080 → 200`, `9090 → 200` y **`9092 → 404`** («sin respuesta» en su
traza). Ese **404 local es el esperado**: el servicio WebDAV no sirve un `GET /` del host; **la
comprobación válida es la del invitado**, que es la que cierra G-8 y la del registro literal de
arriba: **`9092 put: 201`** y **`9092 propfind: 207`** (crear y listar, que es lo que hace la
actividad legítima). El resultado de G-8 es **PASS**; lo que **no** se afirma es «9092 responde 200».

**Idempotencia (E0-3):** el **`lab-listo-legit-v3`** ya contiene el **mismo deploy** (se construyó
desde `v2` aplicándolo, `snapshot_v3.md`, 2026-10-28 02:47:51Z UTC — 03:47 local). Esta aplicación de `prep` deja
**exactamente los mismos `sha256`** (`d1/d2/d3`, `nlog.config`, `client_ctl.sh`, `tfg_keepalive.sh`)
y `verificar_arreglos.sh` da `RESULT=PASS` con los hashes esperados ⇒ **deploy idempotente**
(no hizo falta snapshot nuevo).

### 2.4 Paso 3 — comprobaciones en el invitado

```text
/usr/bin/xargs   /usr/bin/timeout  /usr/bin/sed   /usr/sbin/ip
/usr/bin/openssl /usr/bin/tee      /usr/bin/free  /usr/bin/logger
/usr/bin/seq     /usr/bin/rsync    /usr/bin/shred /usr/bin/wget        <-- 12/12
---SUDO---
sudo_n_rc=1                       <-- "sudo: a password is required" (esperado: C-2)
---CAMPANA---
drwxrwxr-x 2 angel angel 4096 Oct 28 03:45 /home/angel/Documentos/campana_fp
ficheros=0                        <-- existe y VACÍA
---APPLOG---
ls: cannot access '/home/angel/ghosts-client/logs/app.log': No such file or directory
```

> `app.log` **no existe antes del primer arranque** del cliente (el deploy no lo crea). Se comprobó
> **después** de `arm`: existe, en `~/ghosts-client/logs/app.log`, y **creció** durante P1 hasta
> **172 567 B** (§4.3). Eso **cierra R3**: NLog resuelve `logs/app.log` contra el **directorio del
> exe**, no contra el `cwd` (`/home/angel`).

### 2.5 Paso 4 — `arm` (18 s, rc=0)

```text
T0=2026-10-28T22:24:46Z  ->  OnCalendar=2026-10-28 22:19:46 UTC
== timers ==  NEXT Wed 2026-10-28 23:19:46 CET  LEFT 19min  tfg-ghosts-legit.timer -> tfg-ghosts-legit.service
== unit-files == tfg-ghosts-legit.service disabled / tfg-ghosts-legit.timer enabled
== ExecStart ==  ExecStart=/home/angel/ghosts-client/tfg_keepalive.sh 74 2026-10-28T22:24:46Z
== fecha UTC de la victima == Wed Oct 28 21:59:52 UTC 2026  (CET 22:59:52)
rc=0
[22:00:05Z] [arm] GHOSTS: maquinas victima-linux=1 | up=Up | last=2026-10-28T22:00:03.357839
[22:00:05Z] [arm] cliente:                                    <-- ver H-1 (falso negativo, YA CORREGIDO en T4-a)
[22:00:07Z] [arm] === END arm ===
```

- `NEXT` = **`T0_falso − 5 min` = 22:19:46Z** (la hora de `systemctl` sale en CET: 23:19:46) ✅
- **1 proceso** del cliente ✅ (`pgrep`: `16493 /home/angel/ghosts-client/ghosts.client.linux`).
- **`recovery.log` vacío** ✅ (no existía; lo crea el keepalive solo si actúa).
- **`keepalive.log` no existía** (el timer aún no había disparado).

### 2.6 Paso 5 — ejecución de los dos tramos comprimidos

**Setup P1** (22:01:07Z): cliente parado, `timeline.json` = P1 (`sha b4735ceb…`, 147 eventos), cliente
arrancado (`pid 17383`, `cwd=/home/angel`).

**Setup P2** (22:13:18Z): cliente parado (`no corria` → `arrancado pid=18118`), `timeline.json` = B6
(`sha 010e58bf…`, 63 eventos). El cliente estuvo **parado** entre tramos, así que **no hubo recarga
en caliente**.

### 2.7 Paso 6 — `stop` + `cleanup` (67 s, rc=0)

```text
[22:57:20Z] [stop] victima parada (soft). El manager SIGUE encendido para la extraccion.
[22:57:24Z] [cleanup] victima_en_marcha=False manager_en_marcha=True
[22:57:24Z] [cleanup] victima APAGADA -> se omite la fase remota (H1c, sin SSH)
valor aplicado:     <logall_json>no</logall_json>
conf:     <logall_json>no</logall_json>
manager=active
daemons_remoted_analysisd=2
CONFIG_IDENTICA
[22:58:17Z] [cleanup] vmrun -T ws stop ...wazuh-server.vmx soft -> rc=0
[22:58:24Z] [cleanup] firewall: regla TFG-ghosts-5000 retirada
[22:58:24Z] [cleanup] vmrun -T ws list -> rc=0 Total running VMs: 0
```

> **Duración:** `stop` **3 s** (22:57:17→22:57:20) + **3 s** entre el fin de `stop` y el arranque de
> `cleanup` + `cleanup` **61 s** (22:57:23→22:58:24) = **67 s** de tramo (22:57:17→22:58:24).
> `stderr` de `cleanup` **vacío** (`p6_cleanup.err.txt`, 0 B) y `rc=0`.

### 2.8 Paso 7 — revert a `lab-listo-legit-v3` (≈ 55 s)

```text
revert_rc=0
Total snapshots: 6
base-limpia / lab-listo / lab-listo-legit / fallo-2026-10-19-disco-lleno-NO-USAR / lab-listo-legit-v2 / lab-listo-legit-v3

$ bash /tmp/verificar_arreglos.sh <nlog> <d1> <d2> <d3> <keepalive>
nlog_console=Warn · nlog_sha=d8f5f1d1… · nlog_applog_archive=20 · client_ctl_cap=20 · keepalive_v3=1
recetas=e711bc93,216a747b,86057a15 · timeline_activa=e711bc93 · timeline_huella=f1c769c7
client_cwd=/home/angel · keepalive_cwd=/home/angel · carpetas_cwd=OK · campana_fp=OK · campana_fp_casos=0
RESULT=PASS
Total running VMs: 0
```

---

## 3. Las 6 comprobaciones de ejecución (evidencia literal)

### 3.1 `history_timeline`: **147/147** y **63/63** (0 pipes, 0 pérdidas)

```text
# comparación multiconjunto timeline JSON vs BD (script e0_cmp.py)
P1 → timeline 147 db 147 faltan 0 sobran 0
     db_con_pipe=0
P2 → timeline 63 db 63 faltan 0 sobran 0
     db_con_pipe=0
```

```text
$ psql -c "select count(*) from history_timeline where createdutc >= '2026-10-28 22:04:50' and createdutc <= '2026-10-28 22:12:40'"
147
$ psql -c "select handler, count(*) … group by handler"
Command|147
$ psql -c "select count(*) … between '22:15:50' and '22:55:00'"
63
```

> **H-1 (v3) sigue cerrado**: 0 comandos con `|` en la BD y **multiconjunto exacto** en los dos
> tramos. La campaña ejecuta **63/63** aunque haya casos con `exit≠0` (C-09, `RC_FALLO=28`).

### 3.2 `errores.log`: **20 líneas × 5 campos**, `rc` real

```text
lineas=20
lineas_mal=0                                   # awk -F'\t' 'NF!=5'
rc_distintos=rc=0 rc=1 rc=2                    # rc real, no constante
--- head -2 (cat -A)
2026-10-28T22:05:09Z^Ierror^Iruta_mal^Ils -la /home/angel/Documentos/informe^Irc=2$
2026-10-28T22:05:10Z^Ireintento^Iruta_mal^Ils -la /home/angel/Documentos/informes^Irc=0$
--- tail -2 (cat -A)
2026-10-28T22:10:35Z^Ierror^Igzip^Igzip -d /home/angel/Documentos/informes/informe.bak^Irc=2$
2026-10-28T22:10:38Z^Ireintento^Igzip^Igzip -kf /home/angel/Documentos/informes/informe.bak^Irc=0$
```

### 3.3 `audit_cwd`: **0 con `ghosts-client`**, **13** y **18** carpetas distintas

```text
# P1 (archives.json del manager, ventana 22:04:50–22:12:45)
eventos_audit_con_cwd=832
cwd_distintos=13
  cwd=/home/angel n=233 · cwd=/ n=217 · cwd=/home/angel/Documentos/informes n=140
  cwd=/var/ossec n=104 · cwd=/home/angel/Descargas n=61 · cwd=/home/angel/Documentos n=20
  cwd=/home/angel/Documentos/copias/informes n=20 · cwd=…/actas n=13 · cwd=…/copias n=11
  cwd=…/correo n=7 · cwd=/home/angel/.cache/tfg-web n=3 · cwd=/root n=2 · cwd=/usr/lib/sysstat n=1
cwd_ghosts_client=0
binarios: bash:152 · wazuh-agentd:95 · dash:79 · date:55 · ghosts.client.linux:39
          xargs:37 · cat:32 · curl:25 · rsync:21 · shred:21 · cp:20 …

# P2 (ventana 22:15:30–22:55:30)
eventos_audit_con_cwd=916
cwd_distintos=18
  cwd=/var/ossec n=532 · cwd=/home/angel n=123 · cwd=…/campana_fp/C-10 n=70 · cwd=/ n=43
  cwd=…/campana_fp/C-06 n=24 · cwd=…/campana_fp n=22 · cwd=…/C-09 n=16 · cwd=…/C-07 n=12
  cwd=…/C-01 n=10 · cwd=…/C-05 n=10 · cwd=…/C-03 n=9 · cwd=…/C-08 n=9 · cwd=…/C-02 n=8
  cwd=…/C-11 n=7 · cwd=…/C-12 n=5 · cwd=…/C-07/destino n=3 · cwd=/root n=9 · cwd=/usr/lib/sysstat n=4
cwd_ghosts_client=0
binarios: wazuh-agentd:480 · bash:63 · ghosts.client.linux:60 · rm:58 · xargs:37 …
```

> **CA-05 / R3:** **0** acciones con `cwd=/home/angel/ghosts-client`. En P2 aparecen además las
> carpetas de cada caso (`C-01`…`C-12`) ⇒ el `cwd` por acción funciona también en la campaña.
> Los `rm`/`xargs` de P2 son **de la propia campaña** (verificado: `rm` en C-01/02/03…, `xargs` en
> C-10 a las 22:46:32Z), no residuos del tramo anterior.

### 3.4 `auth.log`: **0 accesos del host durante la ejecución**

```text
# /var/log/auth.log (hora local +01:00 = UTC+1) — líneas sshd del periodo
23:00:05 … 23:01:25   Accepted publickey for angel from 192.168.65.1   <-- 22:00:05–22:01:25Z: prep/arm
23:12:33 … 23:13:18   Accepted publickey … (5 sesiones)                <-- 22:12:33–22:13:18Z: recogida P1 y setup P2
23:56:32 … 23:56:34   Accepted publickey … (2 sesiones) + sudo grep   <-- 22:56:32–22:56:34Z: recogida P2

# Ventanas de ejecución (NO hay ninguna línea entre estos límites)
P1 [22:05:00Z, 22:11:40Z]  -> 0 sesiones
P2 [22:16:00Z, 22:54:10Z]  -> 0 sesiones
```

> Recuento: **8** sesiones del host en toda la hora del ensayo — **1** en `prep/arm`, **5** en la
> recogida de P1 + setup de P2 (22:12:33–22:13:18Z) y **2** en la recogida de P2 (22:56:32–22:56:34Z).
> **Cero** dentro de las ventanas de ejecución.

### 3.5 Campaña: **22 marcas**, **11 `hecho.txt` con `RESULTADO=OK`**, **33 ficheros**

```text
casos=11
ficheros=33
hecho_ok=11
marcas=22
marcas_con_formato_mal=0
C-01 2026-10-28T22:16:00Z 2026-10-28T22:16:40Z 3
C-02 2026-10-28T22:19:50Z 2026-10-28T22:20:19Z 3
C-03 2026-10-28T22:23:29Z 2026-10-28T22:23:58Z 3
C-05 2026-10-28T22:27:08Z 2026-10-28T22:27:53Z 3
C-06 2026-10-28T22:31:03Z 2026-10-28T22:31:48Z 3
C-07 2026-10-28T22:34:58Z 2026-10-28T22:35:27Z 3
C-08 2026-10-28T22:38:37Z 2026-10-28T22:39:13Z 3
C-09 2026-10-28T22:42:23Z 2026-10-28T22:43:05Z 3
C-10 2026-10-28T22:46:15Z 2026-10-28T22:46:51Z 3
C-11 2026-10-28T22:50:01Z 2026-10-28T22:50:38Z 3
C-12 2026-10-28T22:53:48Z 2026-10-28T22:54:07Z 3
```

### 3.6 No mutación de la campaña (E0-9)

```text
$ crontab -l
no crontab for angel
crontab_rc=1                    <-- idéntico a antes del ensayo (no hay crontab)

# listado de ficheros modificados durante la hora del ensayo, SOLO dentro de $HOME
# (fuera de campana_fp/ y de ghosts-client/):
#   SOLO los artefactos declarados de la receta (Documentos/, Descargas/, .cache/tfg-web/…)
#   0 ficheros en $HOME/.config ni en $HOME/.local/state
```

> **Alcance real del listado (declarado):** el inventario **solo cubre `$HOME`**. **No** se
> enumeró nada **fuera de `$HOME`** (`/etc`, `/var`, unidades systemd, spool de cron), así que este
> apartado **no** afirma «0 cambios en el sistema»: la no mutación se apoya en (a) el listado de
> `$HOME`, (b) el `crontab -l` idéntico y (c) que la campaña **no usa `sudo`** (E0-1, `rc=1`). El
> inventario de rutas de sistema es una **cobertura pendiente**, no un resultado.

---

## 4. Lo que se ha verificado (resumen frente a E0-1…E0-10)

| E0 | Comprobación | Resultado |
|---|---|---|
| **E0-1** | `sudo -n true` | **rc=1** (`sudo: a password is required`) → **confirmado**: la receta **no** puede usar `sudo`; la campaña es sin `sudo` |
| **E0-2** | 12 binarios nuevos (`command -v`) | **12/12** presentes (`xargs timeout sed ip openssl tee free logger seq rsync shred wget`) — **no** se comprobó el total **36/36** del plan: **desviación D2 (§4.1)** |
| **E0-3** | `prep` con receta v2 + deploy | **`Res=0`**, G-1…G-12 OK; **idempotente** (2.ª aplicación = mismos `sha256`) |
| **E0-4** | `cwd` real + `app.log`/`client.out` | `cwd=/home/angel` en el cliente; `app.log` en `~/ghosts-client/logs` y **creciendo** (172 567 B); `audit_cwd` **0** con `ghosts-client` |
| **E0-5** | `arm` | timer `NEXT=T0−5` **UTC**; **1** proceso; `recovery.log` **vacío** |
| **E0-6** | acciones + `exit≠0` + campaña | 147/147 y 63/63; 20 errores/10 reintentos (**no corta** la ráfaga); 22 marcas; 11 `hecho.txt` OK — **día comprimido y 11 casos** (el plan pedía 20 min reales + 3 casos): **desviación D3 (§4.1)** |
| **E0-7** | borde del `watch` y primer chequeo | **no repetido aquí** (ya probado en T3 con la misma versión; el estado se sembró en `prep`: `archives=133559091B alerts=201197200B`) — salvedad **S-3** y **desviación D4 (§4.1)** |
| **E0-8** | `stop` + `cleanup` con la VM apagada | **sin SSH** (`victima_en_marcha=False`); 0 procesos; `logall_json=no`; `CONFIG_IDENTICA` |
| **E0-9** | no mutación de la campaña | `crontab -l` idéntico; 0 estado fuera de `campana_fp/` (salvo efectos declarados de la receta) |
| **E0-10** | revert y apagado | **6 snapshots**; **0 VMs**; `verificar_arreglos.sh` = **PASS** — revert a **`lab-listo-legit-v3`**, no a `v2`: **desviación D5 (§4.1)** |

### 4.1 Desviaciones respecto del plan (declaradas, una por una)

El plan (`plan.md` §6) se escribió **antes** de T3; el ensayo se ejecutó **después**. Estas son las
**5** diferencias, con su motivo y su efecto. **Ninguna** cambia el veredicto del E0.

| # | E0 | El plan decía | Se hizo | Motivo / efecto |
|---|---|---|---|---|
| **D1** | — | Snapshot de trabajo **`lab-listo-legit-v2`** (5 snapshots) | **`lab-listo-legit-v3`** (6 snapshots) | La **v3** se creó en **T3** (`snapshot_v3.md`, 2026-10-28 **02:47:51Z UTC** — 03:47 local) porque el deploy **no** entraba idempotente en la v2. El `plan.md` en ese punto está **obsoleto**. `v2` **intacta** como red de seguridad. |
| **D2** | **E0-2** | `command -v` de **22 de la lista blanca + 14 nuevos = 36/36** | **12/12 binarios nuevos** | El ensayo comprobó **solo los nuevos**. Los **22** de la lista blanca no se pre-comprobaron con `command -v`: **se ejercitaron ese mismo día** en P1 (147 acciones verificadas en la BD, §3.1), así que su existencia quedó probada *por uso*, no *por sondeo*. Si faltara alguno, ese tramo habría fallado. |
| **D3** | **E0-6** | **20 min** de receta real + **un día comprimido de campaña con 3 casos** (6 marcas) | **Día comprimido** (147 acciones en **393 s**) + los **11 casos** de la campaña (63 acciones, **22 marcas**) | El día comprimido sustituye a los 20 min reales (es el mismo código de la receta, con el reloj comprimido) y la campaña se corrió **entera** en vez de 3 casos: más cobertura, mismo coste de preparación. **No se perdió ninguna comprobación**; se hizo más. |
| **D4** | **E0-7** | Repetir el **borde del `watch`** y el **primer chequeo** | **No se repitió**: lo cubre **T3** | T3 validó el borde con **la misma versión** del script (21→OK, 26→AVISO, 36→ALARMA) y `prep` **sembró** el estado del `watch` (`H1(b)`), que es lo que el primer chequeo necesitaba. Repetirlo en E0 no añadía información. **Ver S-3.** |
| **D5** | **E0-10** | Revert a **`lab-listo-legit-v2`**, **5 snapshots** | Revert a **`lab-listo-legit-v3`**, **6 snapshots** | Consecuencia de **D1**. El estado limpio del ensayo es el de la v3, que es también el punto de retorno de la ventana. |

> **Aparte de D1-D5:** el **timer del invitado no llegó a disparar** en el ensayo (se paró y
> deshabilitó tras verificar `NEXT`, **H-5**). Eso deja **una prueba pendiente para T4-b**: que el
> `tfg-ghosts-legit.timer` dispare de verdad a `t0−5` y que el keepalive arranque el cliente.
> `NEXT` correcto ≠ disparo correcto.

---

## 5. Hallazgos y salvedades (ninguna invalida el E0)

| # | Tipo | Qué | Efecto |
|---|---|---|---|
| **H-1** | **Hallazgo (cosmético) — CORREGIDO** | `arm` registra **`cliente: `** vacío y **«cliente NO esta vivo»** aunque el cliente **sí** está vivo. Causa: `Get-ClientEstado` pasaba **comillas dobles anidadas** dentro de una cadena PowerShell (`"pgrep -af "(^|/)…""`): Windows PowerShell se comía las comillas y el remoto recibía un `pgrep` roto (`El término '^' no se reconoce…`, `p4_arm.err.txt`). **Corregido** (1 línea, L193): el patrón va entre **comillas simples**, el mismo de `client_ctl.sh:35`. | **Ninguno** en la ventana. El `arm` real ya **no** intentará el `start` redundante ni dejará el aviso falso. **Re-probar `arm` en T4-b** (aquí no se ha lanzado ninguna VM). |
| **H-2** | **Hallazgo (esperado)** | `sudo -n true` → **rc=1**. | **Ninguno**: confirma **C-2**; la receta y la campaña **no usan `sudo`**. |
| **H-3** | **Hallazgo** | `logs/app.log` **no existe antes del primer arranque** del cliente. Tras `arm` existe y crece. | **Ninguno**: cierra **R3** (NLog usa el directorio del exe). |
| **H-4** | **Contradicción del encargo** | **El tope de 25 min para el paso 5 lo fija el encargo del orquestador de la tanda T4-a**, no `plan.md` (el §6 del plan solo pide «20 min de receta real + un día comprimido de campaña con 3 casos» y **no pone tope**). Con ese tope, **P1 (~7 min) + B6 (~5 min)** es imposible: `prueba_b6_comprimida.py` **no puede** hacerlo en 5 min porque la separación mínima entre casos es **> 180 s** (la exige `extraer_campana.comprobar_ventanas`) ⇒ **10 × 190 s = 31,7 min** mínimo. El ensayo real tardó **2 287 s (38 min)**. | **Tope superado por diseño** (≈ 55 min en total), **no por cuelgue**. Se dividió en **P1 (tope 10 min)** y **B6 (tope 45 min)**. *No se tocó el helper.* **Acción:** el tope del paso 5 debe reescribirse (≥ 50 min) en el encargo de T4-b. |
| **H-5** | **Desviación declarada** | Tras verificar `NEXT`, se **paró y deshabilitó** el timer del invitado (`systemctl stop/disable` vía `sudo -S` con la contraseña por **STDIN**) para que el **keepalive no arrancara a mitad de los tramos comprimidos**. | **Ninguno**: lo que E0-5 exige (timer con `NEXT` correcto) se verificó **antes**. **Pero el timer no llegó a disparar**: `NEXT` correcto **no** prueba que el disparo funcione (unit, `ExecStart`, permisos, reloj). **Queda como prueba obligatoria de T4-b.** |
| **H-6** | **Hallazgo importante (host) — CORREGIDO** | **`wuauserv` se auto-repara y vuelve a `Manual` en 3–10 min**, no en «~70 min» ni en «~6 h 13 min». El **Visor de eventos** (**System, evento 7040**: cambio de tipo de inicio del servicio) da las latencias reales, medida a medida: `15:36:32→15:46:44 (10m12s)` · `21:49:32→21:56:04 (6m32s)` · `20:44:12→20:47:07 (2m55s)` · `21:39:02→21:47:08 (8m06s)` · `22:12:36→22:17:11 (4m35s)` · `23:12:00→23:17:24 (5m24s)`. Las cifras anteriores eran **el intervalo entre dos observaciones** (nadie miró en medio), no la latencia de reparación. | **Conclusión: re-pausar justo antes de `t0` NO BASTA; la pausa se deshace antes de `t0`.** **Mitigación obligatoria (C-3):** el `watch` **re-pausa Windows Update en cada chequeo** (~30 min) y lo registra (§5.1). Es una acción del **host**, declarada; **no toca la víctima ni altera la medida**. |
| **H-7** | **Hallazgo (procedimiento)** | En el **primer intento** de P1 se copió `timeline.json` **con el cliente vivo** (el `stop` no llegó a ejecutarse por el orden del comando): el cliente detectó el `FileWatcher`, **recargó en caliente** y **murió**. Se rehízo **con el cliente parado** (verificado con `pgrep`) y funcionó. | **Ninguno** en el resultado (P1 se ejecutó limpio desde 22:05). Refuerza lo ya sabido: **nunca** se cambia la timeline con el cliente vivo (**salvo** la rotación del keepalive, que para el cliente antes). |
| **H-8** | **Hallazgo menor** | Tras **revertir el snapshot**, `/tmp` del manager **pierde** `logall_json_ctl.sh` etc. El `cleanup` del paso 0 avisó `No such file or directory` al intentar `logall_json off`. | **Ninguno** (la config ya era `CONFIG_IDENTICA`). En la ventana los scripts se copian en `prep`. |
| **S-1** | Salvedad | `swap_mb=1915` (el plan asumía 0). | **Declarada** desde L1-fix; no se toca la VM. |
| **S-2** | Salvedad | `T0` **falso** (`22:30:22Z` en `prep`, `22:24:46Z` en `arm`, ~5 min de diferencia por el tiempo entre pasos). | **Ninguno**: es un ensayo; `rotacion.estado` (2026-10-28) impide la rotación y `recovery.log` quedó vacío. |
| **S-3** | Salvedad | **E0-7** (borde del `watch` y primer chequeo) **no se repitió** en esta tanda: se validó en T3 con **la misma versión** del script (21→OK, 26→AVISO, 36→ALARMA) y el estado se **sembró** en `prep` (`H1(b)`). | **Ninguno**; queda como cobertura de T3, no de E0-v5. |

### 5.1 Mitigación obligatoria de Windows Update (host) — C-3

**Qué se añade.** En la fase `watch` de `legitimo_host_control.ps1` (cada ~30 min en la ventana):

1. **Lee** `wuauserv` (estado y `StartType`), `NoAutoUpdate`, `NoAutoRebootWithLoggedOnUsers` y
   `LastBootUpTime` (helper `Get-WuHostEstado`, **solo lectura**).
2. **Si `StartType != Disabled`** ejecuta `pausar_windows_update.ps1 pausar` y **registra**
   `[watch] WU re-pausado (<estado previo>)` en `legitimo_host_control.log`.
3. **Registra en la línea del `watch`**: `wu=<estado>/<tipo> au=<0|1> noreb=<0|1> boot=<último
   arranque> reps=<si|no>`, así que cada chequeo deja la prueba en `vigilancia_legitimo.log`.
4. **Idempotente**: si ya está `Disabled`, **no hace nada** (`reps=no`). Un `watch` repetido no
   cambia el estado ni escribe dos veces la pausa.
5. **No toca la víctima.** Es una acción del **host** y está declarada: **no altera la medida**.
   *"Protege V8 (sin reinicio); WU es del host, no del sistema medido."*
6. **No cambia los umbrales** de `doing_age` (**25/35** siguen igual) ni añade señales al recuento
   de 9: la re-pausa **no** entra en `$nivel`, solo en la línea de registro.

**Por qué es obligatoria.** Con las latencias reales de H-6 (3–10 min), la pausa de `t0` se
deshace **antes** de `t0`; sin la re-pausa, Windows Update puede instalar y programar un reinicio
en mitad de las 72 h, y eso **invalida V8** (host sin reinicio).

**Cómo se prueba sin VM.** El bloque es código de host: se compila el fichero entero con el parser
de PowerShell (0 errores), se extrae el helper y el bloque y se ejecutan con `-DryRunWu` (lee el
estado, decide y registra, **sin** ejecutar `pausar_windows_update.ps1`), con dos estados
simulados: `Running/Manual` → `WU re-pausado (Running/Manual)` + `reps=si(dryrun)`; y
`Stopped/Disabled` → **no actúa** (`reps=no`, idempotencia). La prueba de fuego real (re-pausa
efectiva) es **T4-b**.

---

## 6. Estado final verificado

```text
Total running VMs: 0
Total snapshots: 6   (base-limpia, lab-listo, lab-listo-legit, fallo-…-NO-USAR, lab-listo-legit-v2, lab-listo-legit-v3)
Tareas TFG-Legit-*: 0
Reglas de firewall TFG-*: 0
<logall_json>no</logall_json>   ·   CONFIG_IDENTICA
wuauserv: Stopped / Disabled   (re-pausado a las 22:59:25Z; ver H-6 y §5.1)
TFG_GUEST_PW: presente (10 caracteres) en el ENTORNO DE USUARIO (HKCU\Environment),
              NO "solo en memoria": las tareas TFG-Legit-* corren sin sesion interactiva
              y la necesitan; se borra al cerrar la ventana
Procesos postgres/dotnet/python del lab: 0
```

- **Receta regenerada SIN fecha**: `mapa_dias=(vacío: se fija en T4 con --t0)`; `--check` → `RESULT=PASS`;
  `d1/d2/d3` con los **mismos `sha256`** de siempre (`e711bc93 / 216a747b / 86057a15`).
- **`sha256sums.txt`** (`Soporte/Laboratorio/legitimo_72h/`): **100 entradas, 0 desincronías** tras
  el cierre de T4-a. Respecto de las **62** del ensayo: **38 nuevas** (este informe + sus **37**
  evidencias en `ensayo_E0_v5/`) y **1 huella que cambia**, la de `legitimo_host_control.ps1`
  (es el script corregido: **H-1** y el bloque de WU). **Ninguna otra** entrada se ha movido.
- **La VM quedó revertida a `lab-listo-legit-v3` y apagada.**
- **`TFG_GUEST_PW` se borra al cerrar la ventana.** Mientras dure el armado vive en el **entorno de
  usuario** (`HKCU\Environment`) porque las tareas `TFG-Legit-*` se ejecutan **sin sesión
  interactiva** y lo leen de ahí; **no** está en ningún fichero del repo, **no** está en `sha256sums`
  y **no** aparece en los logs (se pasa a los scripts remotos por `stdin`).
- **No** se registraron tareas, **no** se fijó fecha, **no** se hizo commit, **no** se tocaron
  `_recursos/`, corpus, `Hojas/`, `Dataset/`, `Soporte/Metrica/` ni el ruleset.

---

## 7. Consecuencia

**E0 = PASS** con los artefactos finales (`deploy` v5 + receta v2 + campaña de 11 casos + `cwd`
realista) y el laboratorio **devuelto a estado limpio**.

**Antes de armar la ventana real** quedan estas acciones, ya **con el código tocado** en T4-a:

1. **H-1 corregido** (`Get-ClientEstado`, comillas simples). **Re-probar `arm` en T4-b** para
   confirmar en vivo que registra el `cliente: <pid> <ruta>`; aquí no se ha lanzado ninguna VM.
2. **H-6 cubierto por la re-pausa del `watch`** (§5.1). **Comprobación en T4-b**: forzar
   `wuauserv` a `Manual`, correr `watch` una vez y ver `[watch] WU re-pausado (Running/Manual)` +
   `reps=si` en la línea del log. Después, **dejarlo `Disabled`** antes de `t0`.
3. **Probar el disparo real del timer** (H-5): `NEXT` correcto **no** es haber disparado.
4. **Repetir E0 si pasan > 7 días** hasta `t0` (regla §3.2.4).

**No se fija fecha**: la ventana se elige al cerrar T4 (§3.2).

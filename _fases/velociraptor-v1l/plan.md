---
nombre: Velociraptor Linux - V1-L (72 h de actividad legitima) con auditd + EBPF
version: 2 (tras la auditoria de las ventanas de Wazuh)
fecha: 2026-11-24
estado: L0-L3 EJECUTADOS Y VERIFICADOS (2026-11-24; ensayo E0 ver Soporte/Laboratorio/legitimo_72h_vr/ensayo_E0_vr.md) - plan APROBADO por el humano (fecha lun 30/11 -> jue 3/12, operador en vivo, disco externo pendiente) - falta L4 (armado el domingo 29/11)
depende_de: _fases/auditoria-ventanas-wazuh/AUDITORIA.md - _fases/velociraptor-v1/plan.md (V1 cerrada) - Dataset/Ataques/Resultados/Velociraptor/linux_ojos/RESULTADO_OJOS.md - _fases/legitimo-v3/plan.md (la ventana de Wazuh que se replica)
---

# V1-L - ventana de 72 h de actividad legitima con Velociraptor virgen (v2)

## 1. Para que
Guardar, **durante 72 h exactas de actividad normal** (la misma receta GHOSTS que con Wazuh), todo lo que ven los dos ojos de Velociraptor en Linux: **EBPF** (sensor propio) y **auditd** (mismos bytes que lee Wazuh).
**Velociraptor virgen no tiene reglas:** V1-L **no produce alertas ni cifras de falsos positivos por si sola**. Produce el **crudo legitimo completo** y el ledger de acciones; los FP saldran despues aplicando C2/C3 sobre estos datos, igual que con los ataques de V1.

## 2. Lo que se replica de Wazuh y lo que no (matriz de comparabilidad, corregida por la auditoria)
| Dimension | Wazuh (`legitimo-v3`, 2-5 nov) | V1-L | Estado |
|---|---|---|---|
| Maquina | `lab-listo-legit-v3` | `lab-listo-legit-vr` = esa misma menos Wazuh mas cliente VR (+ retencion de auditd dimensionada, §3 D2) | IGUAL salvo HIDS |
| Receta | `d1/d2/d3.json` (163/178/163 = jornada 147/153/141 + campana 16/25/22) | **los mismos `d1/d2/d3.json`, byte a byte, SIN regenerar** (no llevan fechas y ya estan dentro del snapshot). El mapa de fechas (`calendario.json`, `bloques.env`) se genera **en `recetas_vr/`** con `--out-dir`; los ficheros sellados de Wazuh no se tocan | IGUAL |
| Campana B6 | 11 casos no mutantes, 22 marcas, 17:05-17:50Z | la misma | IGUAL |
| Ventana | lun 00:00Z -> jue 00:00Z, 72 h, sin cambio de hora | lun 30/11 -> jue 3/12 (CET, sin cambio de hora) | IGUAL |
| Tareas del host | Prep t0-45 - Arm t0-20 - timer del invitado t0-5 - Watch cada 30 min - Stop t1+5 | **Watch cada 30 min como tarea del host** (sin contrasena de la VM). **Prep y Arm los ejecuta el operador en vivo** a t0-45/t0-20 y la **cosecha a t1+2**; **sin tarea de parada** (§3 D5) | ADAPTADO (por la regla de contrasenas) |
| Disciplina | 0 accesos a la victima en `[t0,t1]`; PC sin suspender; WU re-pausado por cada `watch`; tareas `TFG-Baseline-*` desactivadas | igual; el `watch` **no usa SSH** | IGUAL |
| Guest | `tfg_keepalive.sh` v3, `client_ctl.sh`, GHOSTS v8.3.1, `cwd=/home/angel`, sin sudo, sin navegador | los mismos ficheros (no mencionan Wazuh) | IGUAL |
| Servicios del PC | GHOSTS API+PostgreSQL, «internet local» (`web_access.log`) | los mismos | IGUAL |
| Cosecha | a mano (no hay script); `scp` de ~43 ficheros: `recovery.log, keepalive.log, client.out, id.json, rotacion.estado, timeline.json, errores.log, campana_fp/**/{inicio,fin,hecho}.txt, crontab, ip route, df -h /` + `cosecha.done` + MANIFEST | **script de cosecha probado en L3** con la **misma lista** (en una sola sesion) + el crudo de VR (subida de `audit.log*`, copia de `/var/log/audit/`, datastore del servidor) | IGUAL + extra |
| Orden de cierre | cosechar -> `cosecha.done` -> parar -> copiar -> contar `M` | cosechar -> `cosecha.done` -> **marca FIN y cola vacia** -> copiar -> contar -> **parar solo cuando todo esta verificado**; la fuente de VR no se borra nunca | IGUAL, mas estricto |
| Productos | `denominador_M.csv`, `ghosts_acciones.csv`, `campana_ventanas.tsv`, `campana_fp.csv`, `estabilidad_dia/hora.csv`, `auto_ruido`, `veredicto_validez.md`, `incidencias.md`, `ventana_meta.md`, sellado | **mismos nombres y columnas**; `denominador_M.csv` con un ambito por ojo; alertas y `ruleids` quedan vacios hasta C2/C3; `auto_ruido` separa keepalive / cliente VR / receta | IGUAL salvo alertas |
| Ledger de acciones | solo agregado **por hora** (se exporto tarde) | **por accion** (antes de parar GHOSTS) **y** el agregado por hora con el mismo script | MEJOR |
| Snapshot final | no hay en Linux | **snapshot disco-solo tras la cosecha verificada** | MEJOR |
| HIDS y ojos | agente Wazuh + manager encendido | cliente VR (EBPF + auditd subido); **sin manager** | INEVITABLE |
| Ruido propio | `wazuh-agentd` ~18 % de los eventos de auditd | `comm="velociraptor"` | INEVITABLE (se declara y se separa) |
| Keepalive | ~72 % de los eventos de auditd (`cut`, `date`, `df`, `pgrep`...) | **identico**; se declara la cifra real | IGUAL |
| Denominador `M` | eventos del agente en `archives.json` (342 966) | filas EBPF y eventos de auditd por hora y dia; comparables **por accion y hora**, no por cifra | INEVITABLE |
| Retencion de auditd y cola del cliente | por defecto | dimensionadas por la medida de L3 | DECLARADO |

## 3. Decisiones
| # | Decision | Por que | Descartado |
|---|---|---|---|
| D1 | Snapshot **`lab-listo-legit-vr`**, creado **desde `lab-listo-legit-v3`** quitando Wazuh e instalando el cliente VR | Es la maquina de la ventana de Wazuh salvo el HIDS | Partir de `lab-listo-vr` y reinstalar GHOSTS |
| D2 | Retencion de auditd **dimensionada con la medida de L3** (no fijada de antemano): `num_logs`/`max_log_file` tales que el tope sea **<= 1,5 GB** y **>= 2 x** el volumen proyectado a 72 h; cola del cliente VR (`local_buffer`) reducida. **Puerta: uso proyectado total de la VM (auditd + cola + logs de VR + logs de GHOSTS) <= 50 % de los 4,4 GB libres** | La VM solo tiene 9,8 GB (4,4 libres); el plan v1 (3 GB + 1 GiB) no cabia | 3 GB fijos; ampliar el disco (prohibido) |
| D3 | **Cosecha doble** de auditd: subida por VR (`Generic.Collectors.File`) **y** copia directa de `/var/log/audit/` (tar por SSH, una sola sesion), con sha256 | «Guardar todo» | Solo una |
| D4 | Fecha: **t0 = 2026-11-30T00:00:00Z -> t1 = 2026-12-03T00:00:00Z** | Misma regla que Wazuh; 5 dias para preparar | Empezar ya (cambia los dias de la semana) |
| D5 | **Sin parada automatica.** La VM sigue encendida hasta verificar la cosecha; despues se hace el snapshot y se para a mano | En Wazuh la parada a t1+5 carreraba con la cosecha; esperar no pierde nada | Tarea `Stop` |
| D6 | **Contrasena de la VM solo en memoria del operador** (nunca `-SetSecret`, nunca variable de usuario/registro). Las tareas programadas del host no la necesitan | Regla del usuario | Persistirla |
| D7 | **Servidor VR**: tarea del host cada 30 min que lo reinicia si cae (`arrancar_servidor.ps1`, idempotente) **tras cambiarlo para archivar el `server.log` anterior con sello de hora** (hoy lo sobrescribe). Si cae, el cliente guarda en su cola y entrega al volver | Hoy no arranca solo; V3 usa ese log como evidencia | Solo vigilarlo |
| D8 | **Tabla de monitorizacion cfg S** (EBPF con todos los eventos + `security_inode_rename` + `mkdir`) **fijada y verificada antes de t0** y comprobada igual al final (equivalente de `CONFIG_IDENTICA`) | No hay otra forma de saber que no cambio | Suponerla |
| D9 | Si la ventana sale **invalida se repite entera** | Igual que Wazuh | Parches |
| D10 | La **marca FIN** y la cosecha se emiten **solo despues de t1**; la marca INI solo antes de t0. **Nada por SSH dentro de `[t0,t1]`** | V4 | Marcas intermedias |

## 4. Pasos y criterios de aceptacion (fijados antes de ejecutar)
| Paso | Que | Criterio de aceptacion |
|---|---|---|
| **L0** | Host: `D:` >= 60 GB, Windows Update pausado y 4 tareas `TFG-Baseline-*` desactivadas, plan de energia sin suspension, servidor VR y GHOSTS arrancables, `git status` limpio, **segunda copia de Wazuh en `C:` hecha** | cada punto anotado |
| **L1** | **Construir `lab-listo-legit-vr`**: purgar `wazuh-agent`, instalar cliente VR (misma version y config que `lab-listo-vr`), 5 reglas de auditd (md5 `7b6f8396d13ff701990fff563aa43074`), `verificar_arreglos.sh` del invitado, snapshot **disco-solo** | 0 paquetes de Wazuh; 5 reglas; cliente inscrito; `verificar_arreglos.sh` PASS; `v3` **intacto** |
| **L2** | **Scripts `*_vr`** (los de Wazuh no se modifican; sus logs y estado **no se tocan**): control del host sin manager, con `BatchMode`, `ConnectTimeout` y **comprobando el rc** de `revert/start`; `watch_servidor_vr.py` (**solo lee el host**: edad del ultimo contacto del cliente, crecimiento del fichero diario de EBPF, servidor vivo, disco del host); `exportar_denominador_vr.py`; `cosecha_vr` (una sesion, misma lista que Wazuh); `verificar_validez_ventana_vr.py`; `arrancar_servidor.ps1` con archivo del log | pruebas en seco OK; `git diff` muestra **0 cambios** en los ficheros de Wazuh; `sha256sums_vr.txt` |
| **L3** | **Ensayo E0** (<= 7 dias antes de armar): **(a) fondo + keepalive >= 60-120 min sin acciones GHOSTS**, (b) coste por accion con la jornada d1 comprimida, (c) **arm + disparo real del timer del invitado** con un T0 falso (+25 min) y 20-30 min de keepalive real, (d) **subida de ~300 MB por un flujo de VR**, (e) cosecha completa con el script y el limite de borde entre ficheros de dos dias, (f) comprobar `USER_START/USER_LOGIN` de `cron` frente a sesiones SSH (para V4), (g) `revert` | 147/147 acciones; marcas INI/FIN; **filas EBPF/s, lineas auditd/s, MB/h y crecimiento de disco medidos por separado y extrapolados a 72 h**; **puerta D2 cumplida**; subida de 300 MB OK; cosecha OK. Si no cabe: **no se arma** y se vuelve a decidir |
| **L4** | **Armado** (domingo 29/11, operador en vivo): `prep` (t0-45) + `arm` (t0-20); receta `--check`; `recetas_vr/` y `bloques.env` **sellados antes de t0**; tabla cfg S fijada y verificada (D8) | G-1..G-12 equivalentes OK; huellas selladas; **G-5/G-6 sustituidos** por «cliente enrolado y llegan >= N filas EBPF y eventos de auditd en 5 min» (consultando el servidor, no la victima) |
| **L5** | **Ejecucion** 72 h: nadie toca la victima; `watch` cada 30 min (solo host); alarma visible; chequeo diario (uptime del host, `Kernel-Power`, `D:` >= 60 GB, WU) | V1-V9 (§5) |
| **L6** | **Cosecha y cierre** (operador en vivo, t1+2): exportar acciones (por accion y por hora) **antes** de parar GHOSTS; cosecha; **marca FIN vista despues de t1 y cola vacia**; subida de `audit.log*` por VR; copia de `/var/log/audit/`; copia integra del datastore del servidor (lee ficheros de t0 a t1+1 dia, recorta por hora del **evento**); sha256 y `MANIFEST`; **2 copias** (`D:` y `C:`); **snapshot post-ventana**; despues parada | `cosecha.done`; todo con sha256; 2 copias; snapshot |
| **L7** | **Verificacion independiente** y veredicto (§5), con script nuevo y codigo propio; `incidencias.md`, `ventana_meta.md`, sellado | veredicto escrito; todo numero sale de un script reproducible |

## 5. Validez de la ventana (adaptada de Wazuh V1-V9)
| # | Criterio | Como |
|---|---|---|
| V1 Cobertura | primera fila EBPF <= t0+10 min y ultima >= t1-10 min; **ningun hueco > 30 min** en EBPF; el `audit.log` guardado cubre `[t0,t1]` sin huecos > 30 min | crudo |
| V2 Actividad | cada dia >= 90 % de su receta (contra `--check`); **0 acciones fuera de bloques** (con B6 17:05-17:50Z) | ledger por accion + `bloques.env` |
| V3 Servidor y cliente | servidor vivo y cliente conectado en todos los chequeos; si cayo, se declara y se comprueba que no hay perdida | log del `watch` + `server.log` archivados |
| V4 0 contaminacion | **0 sesiones del operador** dentro de `[t0,t1]`: ningun `USER_LOGIN/USER_START` de `sshd`/`login`/consola (los de `cron` y `systemd` no cuentan) | `audit.log` |
| V5 Aislamiento | `ip route` sin `default`; solo trafico a la «internet local» | evidencia + `web_access.log` |
| V6 Crudo completo | todo copiado antes de parar; `MANIFEST` con sha256; 2 copias | `MANIFEST.tsv` |
| V7 Sin cambios | sha256 de `sha256sums_vr.txt` igual antes/despues; **hash de la tabla cfg S, de `auditd.conf` + reglas y de `client.config.yaml` iguales antes y despues** (leidos en el snapshot y en la cosecha, no por SSH dentro) | `diff` |
| V8 Host estable | `LastBootUpTime` < t0; 0 `Kernel-Power` 41/42/107 | WMI + `Get-WinEvent` |
| V9 Recuperaciones | recuperaciones y rotaciones del keepalive y reinicios de GHOSTS declarados (`recovery.log`, `rotacion.estado`) | cosecha |
Valida / con incidencia / invalida: mismas reglas que Wazuh (`legitimo-v3` §9.2-9.3), **incluida la clausula anti-aborto** (solo se aborta en las primeras 24 h por invalidez objetiva).

## 6. Cambios en la VM / host (declarados)
Snapshot nuevo `lab-listo-legit-vr` (los demas **intactos**) con Wazuh fuera, cliente VR dentro y retencion de auditd/cola dimensionadas (D2); snapshot post-ventana. En el host: scripts nuevos `*_vr`; `arrancar_servidor.ps1` archiva el log; tarea de reinicio del servidor VR; tarea `watch`. **Contrasena de la VM solo en memoria.**

## 7. Riesgos (tras la auditoria)
| Riesgo | Mitigacion |
|---|---|
| Disco de la VM (4,4 GB libres) | puerta D2 con medida real; el keepalive exige >= 1000 MB libres |
| Volumen de EBPF (V1: ~150-200 MB/h con ataques) | L3 mide el fondo real; `D:` tiene 640 GB; no se recorta |
| Ficheros diarios por hora de recepcion | recorte por hora del evento; marca FIN tras t1 (D10) |
| Servidor VR caido / log sobrescrito | D7 |
| PC dormido/actualizando | L0 y V8 |
| Fallo del operador en vivo (mi sesion) en t0-45, t0-20 o t1+2 | prep/arm se hacen **con holgura** (el timer del invitado admite T0 futuro); si la cosecha se retrasa **no se pierde nada** (VM y servidor siguen encendidos) |
| Cortes de luz / fallo del disco `D:` | segunda copia en `C:` y **disco externo** (pendiente del humano) |
| Contaminacion por SSH del operador | D10 y V4 |

## 8. Lo que NO es V1-L
No calcula falsos positivos (C2/C3), no incluye Windows, no toca la receta ni la metrica, no mezcla ataques (la campana B6 **si** va dentro, como en Wazuh).

## 9. Registro de ejecucion (2026-11-24)
- **L0 hecho** (host: `D:` 640 GB, suspension/hibernacion desactivadas, sin tareas antiguas, git limpio, copia de Wazuh en `C:`).
- **L1 hecho**: `lab-listo-legit-vr` creado desde `lab-listo-legit-v3` y verificado (`construir_snapshot_legit_vr.py`; evidencia `Soporte/Laboratorio/legitimo_72h_vr/evidencia_L1/`). D2: `num_logs = 120`, `max_log_file = 8` MB.
- **L2 hecho**: scripts `*_vr` generados con `generar_control_vr.py` (diff declarado en `DIFF_control_vs_wazuh.txt`; **0 ficheros de Wazuh modificados**), `legit_vr.py`, `cosecha_vr.py`, `exportar_denominador_vr.py`, `verificar_validez_ventana_vr.py`, `sellar_vr.py`, `registrar_tareas_vr.ps1` (sin contrasena). Receta: `d1/d2/d3` **identicos byte a byte** a los de Wazuh.
- **L3 hecho** (ensayo real de 7 h): ver `ensayo_E0_vr.md`. **Puerta D2 cumplida** (disco: ~385 MB en 72 h sobre 4,4 GB). Defectos encontrados y corregidos: 6 (todos en mis scripts).
- **Quedan L4-L7.** Decisiones del humano recibidas el 2026-11-24: fecha lun 30/11 -> jue 3/12, PC encendido y operador en vivo (yo), disco externo pendiente (no bloquea).

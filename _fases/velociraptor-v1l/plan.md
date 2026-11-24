---
nombre: Velociraptor Linux - V1-L (72 h de actividad legitima) con auditd + EBPF
fecha: 2026-11-24
estado: PROPUESTO - pendiente del OK del humano (fecha, compromiso de 3 dias con el PC encendido y sin tocar la victima, cambio de retencion de auditd)
depende_de: _fases/velociraptor-v1/plan.md (V1 cerrada) - Dataset/Ataques/Resultados/Velociraptor/linux_ojos/RESULTADO_OJOS.md - _fases/legitimo-v3/plan.md (la ventana de Wazuh que se replica)
---

# V1-L - ventana de 72 h de actividad legitima con Velociraptor virgen

## 1. Para que
Guardar, **durante 72 h exactas de actividad normal** (la misma receta GHOSTS que se uso con Wazuh), todo lo que los dos ojos de Velociraptor ven en Linux: **EBPF** (eventos del kernel, sensor propio de Velociraptor) y **auditd** (mismos bytes que lee Wazuh, para comparar). Es la mitad «falsas alarmas» de la comparacion.
**Importante (Velociraptor virgen no tiene reglas):** V1-L **no produce alertas ni cifras de falsos positivos por si sola**. Produce el **crudo legitimo completo** y su ledger de acciones. Los falsos positivos se calcularan despues **aplicando las reglas C2/C3 sobre estos datos guardados**, igual que se hara con los ataques de V1.

## 2. Lo que se replica de Wazuh y lo que cambia
| Igual que en Wazuh (`legitimo-v3`) | Distinto (y por que) |
|---|---|
| Receta v2 (441 acciones) + campana B6 (63): **504 acciones**, mismos `d1/d2/d3.json`, `bloques.env`, `calendario.json` (mismos `sha256`) | **Sin Wazuh**: no hay agente, ni manager, ni `logall`, ni `archives.json`. El «cliente» es Velociraptor (0.77.3) |
| Cliente GHOSTS v8.3.1 en la victima, servidor GHOSTS + PostgreSQL en el PC, `cwd=/home/angel`, sin `sudo`, sin navegador | Los **dos ojos** de V1: EBPF con todos los eventos (los de fabrica + `security_inode_rename` + `mkdir`) y subida de `audit.log*` |
| Ventana **lunes 00:00Z -> jueves 00:00Z**, 72 h exactas; victima aislada (sin ruta por defecto); cero acceso a la victima dentro de `[t0,t1]` | **Denominador `M`** = filas de EBPF y eventos de auditd (se cuentan por hora del crudo), no `archives.json` |
| Keepalive del invitado (heartbeat por la API de GHOSTS), vigilancia cada 30 min, parada ordenada tras la cosecha | Vigilancia: senales **del servidor de Velociraptor** (cliente conectado, filas EBPF/hora, disco), no del manager de Wazuh |

## 2b. Matriz de comparabilidad con la ventana de Wazuh (`legitimo-v3`, 2-5 nov 2026) - revisada tras analizarla a fondo
Regla: **todo lo que no sea el HIDS se replica tal cual**; lo que no pueda ser igual se **declara**.
| Dimension | Wazuh (lo que se hizo) | V1-L | Estado |
|---|---|---|---|
| Maquina | `lab-listo-legit-v3` | `lab-listo-legit-vr` = esa misma menos Wazuh mas cliente VR (+ retencion de auditd) | IGUAL salvo HIDS |
| Receta | `d1/d2/d3.json` (163/178/163 acciones = jornada 147/153/141 + campana 16/25/22), `bloques.env`, `calendario.json` | **mismos `d1/d2/d3.json` byte a byte** (ya dentro del snapshot; los JSON solo llevan horas, el mapa de fechas va aparte con `--t0`) | IGUAL |
| Campana B6 | 11 casos no mutantes, 22 marcas, 17:05-17:50Z | la misma | IGUAL |
| Ventana | lun 00:00Z -> jue 00:00Z, 72 h, sin cambio de hora | lun 30/11 -> jue 3/12 (CET, sin cambio de hora) | IGUAL |
| Cadencia de tareas | Prep t0-45 min (revierte VM, G-1..G-12) - Arm t0-20 - timer del invitado t0-5 - Watch cada 30 min - Stop t1+10 (tras `cosecha.done`) | **las mismas 5 tareas** con sus horas | IGUAL |
| Disciplina | 0 accesos a la victima en `[t0,t1]`; PC sin suspender; Windows Update re-pausado por cada `watch`; 4 tareas `TFG-Baseline-*` desactivadas | igual | IGUAL |
| Guest | `tfg_keepalive.sh` v3, `client_ctl.sh`, GHOSTS v8.3.1, `cwd=/home/angel`, sin sudo, sin navegador | los mismos ficheros (no mencionan Wazuh) | IGUAL |
| Servicios del PC | GHOSTS API+PostgreSQL, «internet local» (intranet, `web_access.log`) | los mismos | IGUAL |
| Cosecha (t1+2) | UNICA sesion SSH al invitado: `recovery.log, keepalive.log, client.out, id.json, rotacion.estado, timeline.json, errores.log, campana_fp/**/{inicio,fin,hecho}.txt, crontab, ip route, df -h /` + `cosecha.done` + MANIFEST | **la misma lista** + el crudo de VR (subida de `audit.log*`, copia de `/var/log/audit/`, datastore del servidor) | IGUAL + extra |
| Orden de cierre | cosechar -> `cosecha.done` -> parar -> copiar -> contar `M` -> (borrar fuente al final) | igual; **la fuente de VR no se borra nunca** | IGUAL |
| Productos | `denominador_M.csv`, `ghosts_acciones.csv`, `campana_ventanas.tsv`, `campana_fp.csv`, `alertas_detalle.csv`, `ruleids_legitimos.csv`, `estabilidad_dia/hora.csv`, `veredicto_validez.md`, `incidencias.md`, `ventana_meta.md`, sellado | **mismos nombres y columnas** salvo `alertas_*`/`ruleids_*` (se generaran al aplicar C2/C3); `denominador_M.csv` con un ambito por ojo (EBPF, auditd) | IGUAL salvo alertas |
| Validez | V1-V8, «valida / con incidencia / invalida» | las mismas reglas (adaptadas en §5) | IGUAL |
| **Mejora sobre Wazuh** | `ghosts_acciones.csv` solo **por hora** (la BD de GHOSTS ya estaba parada al cerrar) | se exporta **por accion** antes de parar GHOSTS **y** el agregado por hora con el mismo script | MEJOR (se declara) |
| HIDS y sus ojos | agente Wazuh (auditd + FIM + `df -P` cada 360 s + logcollector); manager VM encendida | cliente VR (EBPF + auditd subido); **sin manager** | INEVITABLE |
| Huella propia | el agente Wazuh genera su ruido (`df -P`, etc.) | el cliente VR genera el suyo (`comm="velociraptor"`) | INEVITABLE (se declara) |
| Denominador `M` | eventos del agente en `archives.json` (342 966 en 72 h) | filas EBPF y eventos de auditd por hora y por dia | INEVITABLE (otra definicion; comparables por **accion y hora**, no por cifra) |
| Retencion de auditd | por defecto (Wazuh lo lee en vivo) | mas alta (D2) | DECLARADO (no cambia los eventos) |
| Disco de la victima en vivo | lo daba el propio agente Wazuh | **por resolver en L2** (artifact de solo lectura o, si no existe, el guardia del keepalive + la extrapolacion de L3) | ABIERTO |

## 3. Decisiones (con su por que y alternativas descartadas)
| # | Decision | Por que | Descartado |
|---|---|---|---|
| D1 | Snapshot nuevo **`lab-listo-legit-vr`**, creado **desde `lab-listo-legit-v3`** quitando el agente de Wazuh e instalando el cliente de Velociraptor (como en `lab-listo-vr`) | Es **exactamente** la maquina de la ventana de Wazuh (GHOSTS, carpetas, herramientas, receta) salvo el HIDS | Partir de `lab-listo-vr` y reinstalar GHOSTS: mas pasos manuales y mas riesgo de que la maquina difiera |
| D2 | **Subir la retencion de auditd** (`/etc/audit/auditd.conf`: `max_log_file` 8 -> 50 MB y `num_logs` -> 60) en el snapshot nuevo | El log rota a ~8 MB y solo conserva 1-2 ficheros: en 72 h se **perderia** casi todo el auditd. Subir la retencion **no cambia los eventos**, solo evita borrarlos. Cambio declarado y reversible | Leerlo en continuo con un artifact propio (codigo propio, mas riesgo) |
| D3 | **Cosecha doble** de auditd al final: subida por Velociraptor (`Generic.Collectors.File`, el «ojo» oficial) **y** copia por `scp` de `/var/log/audit/` y de los logs de GHOSTS, con sha256 | «Guardar todo»: si una falla, queda la otra | Solo una |
| D4 | Fecha: **t0 = 2026-11-30T00:00:00Z -> t1 = 2026-12-03T00:00:00Z** (lunes -> jueves); armado el domingo 29/11 | Misma regla que Wazuh; da 5 dias para preparar y ensayar. Alternativa: otra semana si no puede dejar el PC 3 dias | Empezar ya (miercoles): cambia los dias de la semana respecto a Wazuh |
| D5 | Si la ventana sale **invalida se repite entera** (no se parchea) | Igual que en Wazuh | Parches |
| D6 | El servidor de Velociraptor se **reinicia solo** si cae (tarea del host cada 30 min con `arrancar_servidor.ps1`, que es idempotente). Mientras cae, el cliente guarda en su cola (hasta 1 GB) y entrega al volver | Hoy el servidor no arranca solo y 72 h es mucho tiempo | Solo vigilarlo |

## 4. Pasos y criterios de aceptacion (fijados antes de ejecutar)
| Paso | Que | Criterio de aceptacion |
|---|---|---|
| **L0** | Estado de partida del host: espacio en `D:` >= 60 GB, Windows Update pausado, tareas antiguas deshabilitadas, servidor VR arrancable, GHOSTS (API + PostgreSQL) arrancables, `git status` limpio | cada punto comprobado y anotado |
| **L1** | **Construir `lab-listo-legit-vr`** (D1, D2): purgar `wazuh-agent`; instalar cliente VR con la config de `lab-listo-vr` (misma version); auditd con las 5 reglas (md5 `7b6f8396d13ff701990fff563aa43074`) y la retencion nueva; `verificar_arreglos.sh` del invitado; snapshot **disco-solo** con la VM apagada | 0 paquetes de Wazuh; reglas = 5; cliente inscrito; `verificar_arreglos.sh` = PASS; `lab-listo-legit-v3` **intacto** |
| **L2** | **Adaptar el control del host** (copias con los cambios declarados en un `diff`): `legitimo_host_control_vr.ps1` (quita manager/`logall`/`diag_wazuh`, pone comprobaciones del servidor VR), `watch_servidor_vr.py` (en vez de `watch_manager.py`), `exportar_denominador_vr.py`, `registrar_tareas` con las tareas VR | pruebas en seco OK; **ningun fichero de Wazuh modificado** |
| **L3** | **Ensayo E0**: jornada d1 **comprimida** (como se hizo con Wazuh: 147 acciones en ~7 min) con los dos ojos; luego `stop`, cosecha completa y `revert` | 147/147 acciones; marcas INI/FIN llegan; filas EBPF y lineas de auditd medidas **por segundo**; crecimiento de disco en la VM extrapolado a 72 h **< 60 % del libre**; cosecha completa; revert OK. Si la extrapolacion no cabe, **no se arma** y se vuelve a decidir |
| **L4** | **Armado** (domingo 29/11): `prep` + `arm`, receta con `--check`, `sha256sums.txt` y `bloques.env` **congelados antes de t0**, tareas registradas | G-1..G-12 equivalentes en OK; huellas selladas |
| **L5** | **Ejecucion** 72 h: nadie toca la victima; vigilancia cada 30 min **solo con datos del servidor VR**; alarma visible si algo se desvia | ver V1-V8 |
| **L6** | **Cosecha y cierre** a `t1+2 min` (misma lista y mismo orden que Wazuh, §2b) (antes de apagar): subida de `audit.log*` por VR, `scp` de `/var/log/audit/` y logs de GHOSTS, ledger de acciones (`exportar_acciones.sh`), copia integra del datastore del servidor VR con `MANIFEST.tsv`; despues parada ordenada. **Segunda copia en `C:`** y subida a git de lo pequeno | `cosecha.done`; sha256 de todo; 2 copias |
| **L7** | **Verificacion independiente** y veredicto de validez (§5), con un script nuevo y codigo propio sobre el crudo | veredicto escrito; todo numero sale de un script reproducible |

## 5. Validez de la ventana (V1..V8, adaptadas de Wazuh)
| # | Criterio | Como se comprueba |
|---|---|---|
| V1 Cobertura | primera fila EBPF <= t0+10 min, ultima >= t1-10 min; **ningun hueco > 30 min** en EBPF; el `audit.log` guardado cubre `[t0,t1]` sin huecos > 30 min | crudo EBPF + `audit.log*` |
| V2 Actividad | cada dia >= 90 % de su receta (contra `--check`); **0 acciones fuera de los bloques** congelados (con B6 17:05-17:50) | ledger de GHOSTS + `bloques.env` |
| V3 Servidor y cliente | servidor VR vivo y **cliente conectado** en todos los chequeos (si cayo, se declara y se comprueba que no hay perdida) | log de vigilancia + server.log |
| V4 0 contaminacion | **0 sesiones SSH/consola del operador** en `[t0,t1]` (registros `USER_LOGIN/USER_START` del `audit.log`) | `audit.log` |
| V5 Aislamiento | `ip route` sin `default` y solo trafico a la «internet local» | evidencia de L3/L4 + `web_access.log` |
| V6 Crudo completo | todo copiado **antes** de apagar; `MANIFEST` con sha256; 2 copias | `MANIFEST.tsv` |
| V7 Sin cambios a mitad | `sha256sums.txt` igual antes y despues; `CONFIG_IDENTICA` | recalculo + `diff` |
| V8 Host estable | `LastBootUpTime` < t0; 0 eventos `Kernel-Power` 41/42/107 | WMI + `Get-WinEvent` |
Valida **con incidencia** o **invalida** con las mismas reglas que Wazuh (`legitimo-v3` §9.2-9.3).

## 6. Cambios en la VM / host (todos declarados)
Snapshot nuevo `lab-listo-legit-vr` (los demas **intactos**); en el snapshot: Wazuh fuera, cliente VR dentro, retencion de auditd mayor. En el host: scripts nuevos `*_vr` (los de Wazuh no se tocan); tarea programada que reinicia el servidor VR si cae. Contrasena solo por `TFG_MANAGER_PW`, nunca en ficheros ni en git.

## 7. Riesgos
| Riesgo | Mitigacion |
|---|---|
| **Disco de la VM lleno** (ya paso en octubre) | L3 mide y extrapola; el keepalive exige >= 1000 MB libres; vigilancia lee el disco |
| **Volumen de EBPF** (todos los eventos, 72 h) | L3 lo mide; hay 640 GB libres en `D:`; **no se recorta** (guardar todo) |
| **PC dormido/actualizando/reiniciado** | Windows Update pausado, plan de energia sin suspension (L0), `LastBootUpTime` comprobado (V8) |
| **Servidor VR caido** | tarea de reinicio (D6) + cola del cliente de 1 GB |
| **Rotacion de auditd** | D2 + cosecha doble (D3) |
| **El operador toca la VM** | V4 lo detecta; si pasa, la ventana se repite |
| **Cortes de luz** | Sin solucion tecnica; si pasa, la ventana se repite |

## 8. Lo que NO es V1-L
No calcula falsos positivos (no hay reglas todavia: C2/C3), no incluye Windows, no toca la receta ni la metrica congelada, y no mezcla ataques con la ventana (la campana B6 de 11 casos no mutantes **si** va dentro, como en Wazuh).

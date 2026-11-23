# Sondas de mecanismo de los «ojos» de Velociraptor (Linux) — 2026-11-23

Plan: `_fases/velociraptor-ojos/plan.md` (E0 y E1a) · Script: `_artefactos/scripts/probar_ojos_velociraptor.py` · Resúmenes: `sondas/*.json` · Filas crudas (fuera del repo): `D:\TFG-VMs\ataques-velociraptor-linux-ojos\{sondas,sondas_conv}`.

**Qué es y qué NO es.** Pruebas de **mecanismo**, sin ataques de MITRE: tras revertir la VM a `lab-listo-vr`, se ejecuta una actividad inocua y reconocible
(`/bin/echo PROBEMARK_n`, crear → renombrar → `chmod` → borrar un fichero en `/home/angel/lab-legit/probe/`, un `curl` a `192.168.65.1:9`) y se mira qué llega al servidor.
Una iteración por opción. **No mide detección** ni cobertura de los 55 casos; sirve para saber qué opciones funcionan y cuáles descartar antes de gastar ataques.
Cuidado al leer los números: la actividad va en **una sola línea de comandos** de `bash -c`, así que cualquier opción que vea procesos «contiene» todas las palabras. Por eso lo que se mira es el **tipo de evento**, no la palabra.

## E0 — estado de partida (OK)
Servidor y cliente conectados; VM con **5 reglas** de auditd (md5 de `tfg.rules` ya verificado el 21-nov); reloj VM = reloj PC (a 1 s).
Incidencia resuelta: la VM mostraba 6 reglas porque la tabla del servidor se había quedado en la configuración O del piloto (`ProcessExecutions` instala `procmon`); con la tabla neutra vuelven a ser 5.

## Resultados por opción
| Opción | ¿Entrega? | 1ª marca | Qué se ve (tipo de evento) | Volumen | Notas |
|---|---|---|---|---|---|
| **B** EBPF afinado (`security_file_open`=N; `security_inode_rename`, `mkdir`=Y) | sí | 18 s | ejecuciones (`bash, mv, rm, chmod, curl, echo`), **renombrado** (`old_path/new_path`), **conexión** a `192.168.65.1:9`; **no** ve: crear fichero, **borrar con `rm`** (el evento `unlink` no recoge `unlinkat`), `chmod` (solo su ejecución) | 11,5 filas/s | el retraso del evento al servidor ≈ 25 s |
| **G** TrackProcesses `AlsoForwardUpdates=Y` | sí | **185 s** | solo procesos (línea de comandos, padre, hora de inicio/fin) | 2 filas/s | no aporta ficheros ni red; lo único propio es el árbol de procesos |
| **F2** seguir `audit.log` (artifact propio `watch_syslog`) | sí | 18 s | **líneas de auditd tal cual**: `execve`, renombrado, borrado (`nametype=DELETE`), escrituras en rutas vigiladas | 28,7 filas/s | incluye el ruido del propio cliente de Velociraptor (`comm="velociraptor"`) |
| **F1** `audit()` sin filtro (artifact propio) | sí | 92 s | los mismos eventos de auditd **ya parseados**, con la clave (`Tags=audit-wazuh-c/w`) | 6,5 filas/s | retraso medio ≈ 76 s. **Convive con auditd**: pid, reglas (5) y crecimiento del `audit.log` sin cambios |
| **E** subir `audit.log*` con `Generic.Collectors.File` (estándar) | sí (flujo FINISHED) | al final | el fichero **entero** (7,55 MB sin comprimir, con las 8 marcas) = los mismos bytes que lee Wazuh | puntual | el servidor lo guarda en **zlib**; hay que subir también `audit.log.1` (rotación, ver abajo) |

Opción **A** (EBPF por defecto) no se repitió: ya está medida en el piloto (≈43 filas/s, 93 % `security_file_open`).

## Coexistencia (la prueba que cambia el diseño)
| Prueba | Artifacts a la vez | Resultado |
|---|---|---|
| `TODOS` | EBPF afinado (B) + F1 + F2, y subida de `audit.log*` al final | **los tres entregan**; 1ª marca a los 19 s; EBPF 2000 filas, F1 907, F2 6000 |
| `SUPER` | EBPF con **todos** los eventos (los de fábrica + renombrado + `mkdir`) + F1 + F2, y subida al final | **los tres entregan**; EBPF 20 000 filas (113/s, 16 899 `security_file_open`), F1 935, F2 7000 |
En ambas, `auditctl -l` = 5 reglas antes y después, y el `audit.log` sigue creciendo (auditd no se ve afectado).
**Consecuencia:** una sola pasada con `SUPER` guarda todos los «ojos» de una vez, y las vistas A (de fábrica) y B (afinado) se obtienen **después, filtrando por `EventName`** (los ojos no se pueden «repetir» sobre datos ya guardados, pero un superconjunto sí se puede recortar).

## Hallazgos que afectan al diseño
1. **`audit()` no rompe auditd** (se temía por «registrarse como demonio de auditoría»): pid de auditd, reglas y `audit.log` intactos.
2. **Rotación del `audit.log`**: el snapshot arranca con ≈6,4 MB y rota cerca de 8,4 MB (`audit.log.1` = 8 388 770 bytes). Para la opción E hay que subir `audit.log*`, no solo `audit.log`.
3. **El propio cliente de Velociraptor mete ruido en auditd** (sus llamadas al sistema aparecen en el `audit.log`): lo ven todas las vistas basadas en auditd, y hay que declararlo.
4. **Entrega por lotes**: los recuentos salen redondos (2000, 5000, 6000, 7000, 20000), lo que sugiere lotes de 1000 filas; sigue siendo imprescindible la marca de FIN antes de cortar una ventana.
5. **Fallo mío corregido**: el primer informe de la opción E contó 0 porque el fichero subido está en zlib y no lo descomprimí; reprobado en `TODOS` y `SUPER` (8 marcas encontradas).
6. EBPF **no ve el borrado hecho con `rm`** (`unlinkat`) ni `chmod`; auditd con nuestras 5 reglas sí ve el borrado (y no ve `chmod` ni red). Es lo esperable por diseño, y es el motivo de guardar las dos fuentes.

## Límites
Una iteración por opción; actividad sintética (no es un ataque de MITRE); solo mecanismo. Cobertura real, determinismo y verificación independiente quedan para E2–E5.

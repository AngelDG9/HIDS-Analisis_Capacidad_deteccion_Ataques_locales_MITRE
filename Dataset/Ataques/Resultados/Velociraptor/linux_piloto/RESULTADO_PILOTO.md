# Piloto V0d de Velociraptor (Linux) — resultado (2026-11-21)

Plan: `_fases/velociraptor-piloto-procesos/plan.md` · Verificación independiente: `VERIFICACION_PILOTO.md` (0 fallos) · Datos crudos (fuera del repo): `D:\TFG-VMs\ataques-velociraptor-linux-piloto\{raw,crudo}`.

## Qué se hizo
6 casos (los 2 primeros de Impact, Exfiltration y Collection sin montaje especial: ATA001, 002, 008, 009, 011, 012), cada ventana desde `lab-listo-vr` (sin Wazuh, VM revertida), lanzados con `systemd-run` como en Wazuh v2.
- **Pasada E** (tabla del servidor = solo `Linux.Events.EBPF`): 6 casos × 2 iteraciones = **12 ventanas OK**.
- **Pasada O** (tabla = resto de `Linux.Events.*`): 6 casos × 1 iteración = **6 ventanas OK** (2 de ellas, ATA008 y ATA009, necesitaron un reintento porque la marca de inicio no llegó; los registros del primer intento se sobrescribieron con los del reintento; consta en `D:\TFG-VMs\lab-logs\velociraptor_piloto.txt`).
Se guarda todo: recorte por ventana (gz, sha256), salida del ataque, relojes, `auditctl -l` antes/después, y copia íntegra del datastore de eventos (`crudo`, 35 ficheros, 208 MB, con `MANIFEST.tsv`).

## Hallazgos (comprobados con datos)
1. **`Linux.Events.ProcessExecutions` no recoge nada en esta VM**: 0 filas en las 6 ventanas de la pasada O. Instala su regla (`procmon`; `auditctl -l` pasa de 5 a 6 reglas) pero ya existe una regla de `execve` (clave `audit-wazuh-c`) y el kernel anota solo esa clave: `ausearch -k procmon` = 0.
2. **`Linux.Events.TrackProcesses` por defecto no emite filas** (0 en las 6 ventanas): solo mantiene el árbol de procesos en memoria; reenviar exige el parámetro `AlsoForwardUpdates`.
3. **El `Linux.Events.EBPF` por defecto impide que entreguen los demás eventos.** Con EBPF en la tabla, `Journal` y `DNS` no dieron ninguna fila en 15 min; sin EBPF dieron filas en segundos. Además, en la pasada O la entrega de `Journal` es lenta (la marca de inicio tardó ≈115–132 s) y en 2 de 6 ventanas no llegó en 8 min.
4. **EBPF sí ve los procesos que importan**: `sched_process_exec` con `argv`, `pathname`, `cmdpath` y `pwd`. Los 6 casos tienen **todas** sus anclas (ejecutable y directorio de trabajo) vistas, y **la iteración 2 da exactamente los mismos números que la 1 en los 6 casos** (diferencias de «visto/no visto»: 0).
5. **Volumen:** ≈9 000–12 000 filas de EBPF por ventana de ≈210 s (≈43 filas/s con la VM trabajando; casi todo `security_file_open`). El servidor recibe los eventos de EBPF con ≈1 min de retraso (de ahí la marca de fin).
6. `Journal` solo contiene del caso el directorio de trabajo (3 menciones por ventana en los casos con ancla `audit_cwd`); no ve los ejecutables.

## Tabla de visibilidad (ancla vista = nº de eventos `sched_process_exec` que la cumplen; iter1 = iter2)
| Caso | Ancla | EBPF (estricto) | ProcessExecutions | TrackProcesses | Journal (cwd) |
|---|---|---|---|---|---|
| ATA001 T1486 | `openssl` / cwd | 2 / 10 | 0 | 0 | 0 / 3 |
| ATA002 T1485 | `dd` | 2 | 0 | 0 | 0 |
| ATA008 T1048 | `wget` | 1 | 0 | 0 | 0 |
| ATA009 T1567 | `curl` / cwd | 1 / 6 | 0 | 0 | 0 / 3 |
| ATA011 T1074 | `mkdir`, `cp` / cwd | 3, 3 / 12 | 0 | 0 | 0, 0 / 3 |
| ATA012 T1119 | `find`, `cp`, `tar` / cwd | 23, 1, 1 / 12 | 0 | 0 | 0, 0, 0 / 3 |

**Límites que hay que decir:** es **visibilidad**, no detección (ninguna fila «marca» nada como sospechoso; no se ha medido detección); son 6 casos y todos del tipo «se ejecuta un programa», que es lo mejor que ve EBPF (los casos de red, ficheros o reinicio podrían salir distinto); las anclas vienen del ground truth escrito antes de ver resultados y sirven aquí para comprobar el montaje, no como medida final.

## Decisión propuesta (la toma el humano)
- **Fuente de procesos para V1: `Linux.Events.EBPF` (`sched_process_exec`)**, sin tocar la VM. `ProcessExecutions` queda descartado con evidencia; `TrackProcesses` por defecto no aporta filas.
- **Declarar en la memoria** que la fuente de datos de Velociraptor (eBPF) no es la de Wazuh (auditd) y que EBPF por defecto «tapa» a los otros artifacts de eventos.
- **Pendiente de decidir:** qué hacer con `Journal`/`DNS` (que no conviven con EBPF por defecto): (a) V1 solo con la configuración E; (b) V1 con E y una segunda pasada O (duplica el tiempo); (c) ajustar EBPF para que no emita `security_file_open` (deja de ser «de fábrica»).

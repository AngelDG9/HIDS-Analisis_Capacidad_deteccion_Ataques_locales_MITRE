---
nombre: Velociraptor Linux - auditoria de los «ojos» (que sensor usar) antes de V1
fecha: 2026-11-23
estado: PROPUESTO - pendiente de aprobacion del humano (no se ha ejecutado nada)
depende_de: _fases/velociraptor-piloto-procesos/plan.md · Dataset/Ataques/Resultados/Velociraptor/linux_piloto/RESULTADO_PILOTO.md · Soporte/Laboratorio/velociraptor/MONTAJE_V0.md
---

# Auditoria de los «ojos» de Velociraptor en Linux

## 1. Para que
Decidir **con datos** que sensor (los «ojos») usa Velociraptor en V1 (55 casos × 2), antes de gastar 110 ataques.
Los **ojos** son lo que registra los eventos (auditd, eBPF...). El **cerebro** (reglas/artifacts que dicen «esto es malo») es otra capa y **no se toca aqui**: se aplicara despues sobre los datos crudos (C2/C3).
Wazuh usa auditd (5 reglas en la VM, claves `audit-wazuh-c/w`). La comparacion es mas justa si los dos ven lo mismo; pero tambien interesa «Velociraptor tal como viene».

## 2. Lo que sabemos (hallazgos de hoy, leyendo las definiciones; **aun no probados en la VM**)
1. `Linux.Events.ProcessExecutions` **no lee `audit.log`**: usa el plugin `audit()` (flujo del kernel), **instala una sola regla** (`execve`, solo `b64`, clave `procmon`) y **filtra** `"procmon" in Tags`. Por eso, con nuestra regla previa (`audit-wazuh-c`), no recibio filas en el piloto.
2. `Linux.Events.EBPF` tiene un **parametro `Events`** (tabla Y/N de eventos). Por defecto activa 14, entre ellos `sched_process_exec`, `security_socket_connect/bind/accept`, `unlink`, `setxattr`, `fchownat`, `security_file_open` (el ruidoso) y deja **desactivados** `security_inode_rename`, `mkdir`, `chdir`, `file_modification`, `openat`. Se puede afinar **sin escribir codigo**.
3. `Generic.Collectors.File` (artifact estandar) sube ficheros por patron: permitiria subir **`/var/log/audit/audit.log` entero** tras cada ventana = **exactamente lo que lee Wazuh**.
4. El plugin `audit()` sin el filtro de `Tags` podria entregar **todo el flujo de auditd** en continuo (incluidas las reglas de ficheros). **Hay que comprobarlo.** Seria un artifact propio (de ojos, no de reglas).
5. El ground truth de Linux esta escrito en **vocabulario auditd**: 104 senales `audit_exe`, 51 `audit_cwd`, 2 `rule_id` (los 157 `tipo=deteccion`). En EBPF se traducen a `pathname/argv` y `pwd` (piloto: funciona para ejecuciones).
6. Piloto: EBPF por defecto ve las ejecuciones de los 6 casos, pero **tapa** a Journal/DNS y mete ~43 filas/s (93 % `security_file_open`).

## 3. Opciones a comparar
| ID | Opcion | De fabrica | Codigo propio | Toca la VM | Mismos ojos que Wazuh | Cubre (esperado) |
|---|---|---|---|---|---|---|
| **A** | EBPF por defecto | si | no | no | no (otra tecnica) | procesos, red, borrados, atributos, ficheros abiertos |
| **B** | EBPF con `Events` afinado (sin `security_file_open`; con `security_inode_rename`, `mkdir`) | parametro oficial | no | no | no | igual, con menos ruido y mas renombrados |
| **C** | ProcessExecutions tal cual | si | no | si (regla extra) | parcial | **descartada** (0 filas en el piloto) |
| **D** | ProcessExecutions arreglado: VM variante con el `execve` de auditd con clave `procmon` | si | no | **si: snapshot nuevo** | parcial (solo ejecuciones b64) | solo procesos |
| **E** | `audit.log` entero subido con `Generic.Collectors.File` al final de cada ventana | si | no | no | **si, los mismos bytes** | procesos y ficheros (las 5 reglas) |
| **F** | Artifact propio: `audit()` sin filtro (continuo) | no | **si** (pequeno) | no | si (mismo flujo del kernel) | las 5 reglas, por confirmar |
| **G** | TrackProcesses con `AlsoForwardUpdates=Y` | parametro oficial | no | no | no | arbol de procesos (complemento, no ojos completos) |
| **H** | Combinaciones (p. ej. B + E) | — | — | — | — | se decide al final |

## 4. Criterios, **fijados antes de ver resultados**
**Filtro (imprescindibles):** (i) entrega las marcas de inicio y fin en todas las ventanas; (ii) trae las anclas de los 6 casos del piloto; (iii) iteracion 1 = iteracion 2 en «visto / no visto»; (iv) cualquier cambio en la VM esta declarado y es reversible.
**Entre las que pasan, por este orden:** 1º mismos ojos que Wazuh; 2º cobertura (procesos + ficheros + red en los casos de ampliacion); 3º de fabrica / sin codigo propio; 4º volumen y retraso.
**Salida posible:** un sensor principal + un control (p. ej. principal = EBPF «de fabrica»; control = auditd, para la comparacion justa). La decision final es **del humano**.

## 5. Casos de prueba
- Base: los **6 del piloto** (ATA001, 002, 008, 009, 011, 012): ya tenemos su resultado con A.
- Ampliacion, por **regla objetiva** (primer ATA que lo cumpla en cada categoria; los IDs concretos se **ensenan antes de ejecutar**): que borre/renombre ficheros · que cambie permisos/atributos · que haga conexion de red con `nc/socat/ssh`. Sirven para ver diferencias de cobertura que los 6 del piloto (todos «se ejecuta un programa») no muestran.
- Misma ventana y lanzador que Wazuh y que el piloto (`systemd-run`, t0, t1 = fin + 30 s, recorte [t0-60, t1+120]).

## 6. Pasos
| Paso | Que | Criterio de aceptacion |
|---|---|---|
| **E0** | Preparar: levantar el servidor de Velociraptor; revisar VM, snapshots y reloj; **comprobar `auditctl -l` = 5 reglas** | Servidor y cliente conectados; 5 reglas |
| **E1** | **Cribado (1 caso, 1 iteracion por opcion)** con ATA009: A, B, D, E, F, G. Cada opcion en su propia pasada (como cfg E/O del piloto) | Se sabe cuales producen filas y cuales no; las que no, se descartan con evidencia |
| **E2** | **Cobertura:** las opciones que pasan E1 sobre los 6 del piloto + 3 de ampliacion (1 iteracion) | Tabla opcion × caso × ancla (procesos / ficheros / red) |
| **E3** | **Determinismo:** 2ª iteracion de las 1-2 finalistas | 0 diferencias «visto / no visto» |
| **E4** | **Copia cruda integra** + manifest sha256 de todo lo recogido | Todo guardado fuera del repo; ningun fichero vacio |
| **E5** | **Verificacion independiente** (script que recalcula desde el crudo, como en el piloto) | 0 fallos, o cada fallo anotado |
| **E6** | Informe `RESULTADO_OJOS.md` (tabla, hallazgos, limites) + recomendacion; commit + push | Repo limpio y subido; el humano decide |

Tiempo: la etapa E1 es corta; E2/E3 dependen de cuantas opciones sobrevivan. Lo estimo y te lo digo **al acabar E1**, antes de seguir.

## 7. Cambios en la VM / servidor (todos declarados, ninguno sin avisar)
- **D** exige un snapshot nuevo (`lab-listo-vr-audit`) con el `execve` de auditd con clave `procmon`. **No se toca** `lab-listo-vr` ni `lab-listo`.
- **F** exige subir un artifact propio al servidor (`Custom.Linux.Events.AuditRaw`). Es codigo de **ojos**, no de reglas; se versiona en el repo.
- El resto no cambia nada en la VM.
- Contrasena de las VMs: solo por variable de entorno en memoria; nunca en ficheros ni en git.

## 8. Verificacion y pruebas (E5)
1. sha256 de los recortes y del crudo contra el manifest. 2. Marcas inicio/fin en todas las ventanas. 3. Recomputo de las anclas desde el crudo con codigo independiente. 4. Determinismo iter1 vs iter2. 5. Pruebas unitarias nuevas para lo que se anada al extractor (p. ej. lectura de `audit.log`). 6. `auditctl -l` antes y despues de cada pasada. 7. Revision a mano de 2 ventanas. 8. Sin secretos en lo subido a git.

## 9. Riesgos
| # | Riesgo | Mitigacion |
|---|---|---|
| R1 | `audit()` o `Generic.Collectors.File` no se comportan como dicen las definiciones | Por eso E1 es un cribado barato antes de gastar mas |
| R2 | `audit.log` crece y mezcla ventanas | La VM se revierte en cada ventana; se recorta por hora despues |
| R3 | Parsear auditd a mano introduce errores | En E se guardan las **lineas tal cual**; el parseo se hace offline y con pruebas |
| R4 | Cambiar `Events` de EBPF deja de ser «de fabrica» | Se declara: es un parametro oficial, y A sigue medida como referencia |
| R5 | Los casos de ampliacion se eligen «a gusto» | Regla objetiva escrita aqui, IDs ensenados antes de ejecutar |

## 10. Lo que NO es esta auditoria
Ni V1, ni la ventana legitima de 72 h, ni Windows, ni reglas/cerebro (C2/C3), ni cambiar Wazuh. Tampoco se repiten con otras reglas de auditd (trabajo futuro).

---
nombre: Velociraptor Linux - piloto V0d (6 casos x 2) y decision de la fuente de procesos
fecha: 2026-11-21
estado: EJECUTADO y VERIFICADO (2026-11-21) - ver Dataset/Ataques/Resultados/Velociraptor/linux_piloto/RESULTADO_PILOTO.md
depende_de: _fases/velociraptor-linux/plan.md (V0d) · Soporte/Laboratorio/velociraptor/MONTAJE_V0.md (§5, §5b)
---

# Piloto V0d de Velociraptor en Linux

## 1. Para qué
1. **Decidir con datos** de dónde sale la telemetría de procesos: `Linux.Events.ProcessExecutions` (lee auditd, pero **instala su propia regla**),
   `Linux.Events.EBPF` (kernel; no toca la VM) o `Linux.Events.TrackProcesses` (eBPF, rastrea procesos).
2. Comprobar el **mecanismo** (tabla de monitorización del servidor → cliente → filas en el servidor → extracción por ventana).
3. **Congelar el formato** de extracción y de salida antes de V1 (55 casos × 2).

No es todavía la medida final. Estos 6 casos pasan a ser «casos de desarrollo» (no cuentan para validar artifacts propios, V2).

## 2. Decisiones de diseño (y por qué)
| # | Decisión | Por qué |
|---|---|---|
| P1 | **Una sola pasada con los 3 artifacts de procesos activos a la vez** (+ el resto de `Linux.Events.*`) | Mismo ataque, tres observadores: la comparación es justa y no hay que repetir ataques. Coste: en el piloto la regla de auditd de `ProcessExecutions` existe en la VM (se declara; en V1 se decide la configuración y se congela) |
| P2 | **Casos: los 2 primeros de cada táctica del alcance que no necesitan montaje especial** (sin reinicio, rsync, paquetes ni rclone): Impact **ATA001, ATA002** · Exfiltration **ATA008, ATA009** · Collection **ATA011, ATA012** | Regla objetiva, escrita antes de ver resultados; sin elegir a mano los «favorables» |
| P3 | **Doble iteración** (iter1, iter2), cada una desde `lab-listo-vr` revertido | Misma unidad que Wazuh; permite medir si la extracción es determinista |
| P4 | **Mismo lanzador y misma ventana que Wazuh v2**: `systemd-run --uid=angel --pipe --wait`, t0 = marca `T0=` del ataque, t1 = fin del lanzamiento + 30 s, recorte crudo [t0-60 s, t1+120 s] | Comparabilidad con Wazuh (sin FIM forzado: no hay agente de Wazuh) |
| P5 | **Marcas de control** antes y después del ataque (`/bin/echo TFGMARK<n>`): se espera a verlas en los 3 artifacts de procesos | Equivale al `logger` que usamos con `logall`: demuestra que la tubería funciona **antes** de contar nada y que ya llegó todo **después**. Si no llegan, la ventana **falla** (no se cuenta vacía) |
| P6 | **Se guarda TODO**: copia íntegra del datastore de eventos del cliente (con sha256) + recorte por ventana (gz) + salida del ataque + relojes | Regla del usuario: no repetir nada |
| P7 | **Visibilidad = la «ancla» del caso aparece**: patrones de `*_esperado.csv` (señales `tipo=deteccion`), buscados con límites de palabra en las filas de la ventana, **por artifact** | Reutiliza el ground truth ya validado antes de ver resultados. Es **visibilidad**, no detección |
| P8 | Wazuh manager y VM Windows **apagados** (RAM); reloj del anfitrión como referencia (VM–PC ≈ 1 s, se registra en cada ventana) | El manager no hace falta y el PC va justo de RAM |

## 2b. Hallazgos de P0 (21-nov, en la VM viva; CAMBIAN el diseño P1)
Comprobados con datos, no con la documentación:
1. **`ProcessExecutions` instala su regla (`procmon`) pero NO recoge nada**: en la VM ya hay reglas de auditd para `execve` (clave `audit-wazuh-c`)
   y el kernel anota solo esa clave en cada registro; `ausearch -k procmon` = 0 eventos y 0 filas en el servidor tras ~20 `execve` y 9 min.
2. **`TrackProcesses` por defecto no emite filas** (solo mantiene en memoria el árbol de procesos para otros artifacts; reenviar exige el parámetro `AlsoForwardUpdates`).
3. **El `Linux.Events.EBPF` por defecto «tapa» a los demás eventos**: con EBPF activo, `Journal` y `DNS` no entregaron nada en 15 min;
   al quitar EBPF de la tabla entregaron filas en segundos (Journal 261, DNS 143). EBPF por defecto emite ~50 filas/s con la VM trabajando (casi todo `security_file_open`).
4. **EBPF sí trae lo que necesitamos para procesos**: `sched_process_exec` con `argv`, `pathname`, `cmdpath` y `pwd` (= las anclas `audit_exe` y `audit_cwd`).
5. El servidor tarda ≈1 min en recibir los eventos de EBPF (hora de recepción `_ts` − hora del evento ≈ 54 s) ⇒ la marca de FIN es imprescindible.

**Diseño P1 revisado:** dos configuraciones de la tabla de monitorización, cada una en su pasada:
**E** = solo `Linux.Events.EBPF` (las 12 ventanas) y **O** = el resto de `Linux.Events.*` (6 ventanas, iteración 1) para documentar `ProcessExecutions`/`Journal`/`DNS` y no dar por buena una cobertura que no existe.

## 3. Pasos
| Paso | Qué | Criterio de aceptación |
|---|---|---|
| **P0** | Probar el mecanismo **en la VM viva**: activar la tabla de monitorización (`add_client_monitoring`), ver que llegan filas de cada artifact, **dónde** y **con qué formato** se guardan, qué campo es la hora del evento, latencia | Filas de los 3 artifacts de procesos en el servidor; formato y ruta anotados |
| **P1** | Escribir `orquestar_velociraptor_linux.py` (reutiliza el orquestador de Wazuh) y `extraer_ventana_velociraptor.py` (recorte + anclas), con **pruebas unitarias** | Tests pasan; el extractor es determinista (misma entrada → mismos bytes) |
| **P2** | **Ensayo de 1 ventana** (ATA002_iter1) y revisión a mano de lo recogido | Marcas inicio/fin vistas; filas del caso presentes; formato correcto |
| **P3** | Las 12 ventanas (6 casos × 2) | 12/12 `OK`, ninguna con marcas ausentes |
| **P4** | Copia cruda íntegra + manifest sha256; análisis: tabla caso × artifact (ancla vista SÍ/NO, nº filas), determinismo iter1 vs iter2 | Tabla y conclusión en `RESULTADO_PILOTO.md` |
| **P5** | **Verificación/testing** (ver §4) | Todo OK o discrepancias anotadas |
| **P6** | Commit + push; actualizar `MONTAJE_V0.md` / plan con la decisión propuesta (la decisión final es del humano) | Repo limpio y subido |

## 4. Verificación y pruebas (ronda final)
1. **Integridad:** `sha256` de cada fichero crudo y de cada recorte contra el manifest; ningún fichero vacío.
2. **Completitud:** 12/12 ventanas con marca de inicio y de fin en los 3 artifacts; nº de filas por artifact y ventana > 0.
3. **Recomputación independiente:** repetir el análisis de anclas **desde la copia cruda** (no desde los recortes) y comparar con la tabla.
4. **Determinismo:** misma extracción dos veces → mismos bytes; iter1 vs iter2 → diferencias listadas.
5. **Pruebas unitarias** del extractor (límites de ventana, anclas con límite de palabra, ficheros zlib concatenados — fallo ya cometido el 21-nov).
6. **Estado de la VM:** nº de reglas de auditd antes/después (qué añade `ProcessExecutions`); sin cambios inesperados.
7. **Revisión a mano** de 2 ventanas (comparar filas con la salida del propio ataque).
8. **Sin secretos** en lo que se sube a git (contraseña de las VMs solo en memoria/entorno).

## 5. Riesgos
| # | Riesgo | Mitigación |
|---|---|---|
| R1 | La tabla de monitorización tarda en llegar tras revertir la VM | Marca de inicio obligatoria; espera con tope; si no llega, ventana `FALLO` y reintento |
| R2 | Eventos que llegan tarde al servidor | Marca de fin obligatoria antes de cortar |
| R3 | La regla de auditd de `ProcessExecutions` altera la VM | Se anota `auditctl -l` antes/después; la VM se revierte en cada ventana |
| R4 | Ficheros de resultados comprimidos en varios trozos (error del 21-nov) | El lector descomprime **todos** los flujos zlib; hay prueba unitaria |
| R5 | RAM del PC | Solo servidor + 1 VM |
| R6 | Ancla demasiado laxa (p. ej. `dd`) da falsos «visto» | Límite de palabra y revisión a mano de los casos dudosos |

## 6. Lo que NO es este piloto
Ni la medida final (V1), ni la ventana legítima de 72 h (V1-L), ni artifacts propios (V2), ni Windows.

## 7. Incidencias (21-nov, al cerrar)
- Pasada O: 2 de 6 ventanas (ATA008, ATA009) necesitaron un reintento porque la marca de inicio no llego (Journal poco fiable); ambas OK al reintentar.
- **Pruebas:** `pytest _artefactos/scripts/tests` = 568 OK y **3 FALLOS** en `test_ejecucion_windows.py::test_los_10_errores_y_10_reintentos_se_escriben[1-3]` (pruebas del controlador del legitimo de Windows, que ejecutan `cmd` reales en el PC). No se ha tocado ningun fichero versionado (solo ficheros nuevos de Velociraptor) y NO se ha diagnosticado la causa: es una incidencia abierta, no resuelta. Los 8 tests nuevos del extractor pasan.

# Ensayo E0 de V1-L (Velociraptor) - 2026-11-24

Plan: `_fases/velociraptor-v1l/plan.md` (L3). Evidencia: `ensayo_E0/` (en este repo, pequena) y el crudo completo fuera del repo: `D:\TFG-VMs\legitimo-vr-ensayo-E0\` (+ copia comprimida en `C:\TFG-copia\velociraptor-v1l\E0_cosecha.zip`).

## Que se hizo (con la maquina REAL de la ventana: snapshot `lab-listo-legit-vr`)
Ensayo **real** del dia 1 de la receta (no comprimido): `prep` (G-1..G-12) a las 12:31 UTC -> `arm` (timer del invitado, T0 de prueba 13:20, disparo a 13:15) -> tareas programadas del PC (vigilancia y servidor, cada 30 min) -> **7 h** de funcionamiento sin tocar la VM (bloque de la manana, pausa, tarde, campana B6 y reposo hasta las 19:30) -> cosecha con `cosecha_vr.py` -> verificadores -> limpieza y `revert`.

## Resultado frente a los criterios de L3
| Criterio | Resultado |
|---|---|
| (a) fondo + keepalive >= 60-120 min sin acciones | **PASS**: 17:50-19:30 (100 min) sin acciones de la receta: **~150 000 filas EBPF/h** y **~3 600 eventos auditd/h** (igual que con actividad: **el fondo domina**; la receta anade <5 %) |
| (b) coste por accion | **PASS**: 63 acciones/6 h; EBPF 140-150 k filas/h con o sin acciones |
| (c) arm + disparo real del timer | **PASS**: `keepalive.log` arranca a las **13:15:02Z** (T0-5 min); el cliente GHOSTS corre; **primera vez que se prueba en vivo el timer** (en Wazuh no se probo) |
| (d) subida grande por Velociraptor | **PASS**: 300 MB en **48 s**, sha256 coincide; borrado de la VM |
| (e) cosecha completa con script | **PASS**: 209 ficheros con sha256; la subida de `audit.log*` por VR y la copia directa (`tar`) contienen **los mismos 20 198 eventos**; marca FIN vista a los 30 s; borde de medianoche probado con datos sinteticos (3 + 1 filas, borde inclusivo, ficheros zlib concatenados) |
| (f) `USER_START/LOGIN` de cron frente a SSH | **PASS**: en la ventana solo hay sesiones de `cron` (43 en 6 h); V4 las excluye y detecta `sshd/login` |
| (g) `revert` | **PASS** (VM apagada, 8 snapshots, ninguno modificado) |
| **Puerta D2 (disco)** | **PASS**: espacio libre de la VM **4 420 -> 4 388 MB en 6 h** (~5 MB/h); extrapolado a 72 h ~385 MB (acabaria en ~4 035 MB libres, 9 % del libre inicial; limite 50 %; alarma a 2 GB; guardia del keepalive 1 GB). auditd ~**3,6-6,9 MB/h** (<= ~500 MB en 72 h; tope 120 x 8 MB = 960 MB). Cola del cliente VR: 0 (`Velociraptor_Buffer.bin` no existe) |

## Verificadores sobre el ensayo (`ensayo_E0/veredicto_validez.md`)
**8 de 9 PASS.** V2 (actividad) **FALLA por diseno del ensayo**: la ventana de prueba 13:20-19:30 cubre solo el 38,7 % del dia 1 (63 de 163 acciones), porque arme a las 12:35. No es un fallo del mecanismo (0 acciones fuera de bloque). V3 PASS (15 chequeos, 0 alarmas, hueco max 30,1 min), V7 PASS (huellas de VM, tabla cfg S y `sha256sums_vr` iguales), V8 PASS.

## Volumen medido (para estimar los 72 h)
EBPF: ~146 000 filas/h (~**87-98 MB/h** en el PC) -> **~10,5 M filas y ~7 GB** en 72 h. auditd: ~3 270 eventos/h (en E0: 20 198 eventos y 111 599 lineas en 6 h 10 min) -> ~236 000 eventos en 72 h (Wazuh: ~4 270 eventos/h en archives). Disco del PC: sobra (635 GB).

## Defectos encontrados y corregidos durante el ensayo (todos en MIS scripts)
1. Un proceso `tail -F` mio mantenia abierto el log de vigilancia y Windows impedia escribir en el (arreglado: `Add-LineaSegura` con reintentos y fichero de rescate; el verificador lee ademas el log de control).
2. Contadores de bytes en `[int]` (32 bits) se habrian desbordado con >2 GB de EBPF: ahora `[int64]`.
3. El estado del vigilante dependia de `$env:TEMP`, que **varia segun como el programador lance la tarea**: el chequeo automatico no encontraba su estado previo (`ebpf=-1B`). Ahora **ruta fija** (`D:\TFG-VMs\lab-logs\...`) y el log incluye `prev=...`.
4. El verificador V5 buscaba «default» en toda la salida (`ip addr` lleva «group default qlen»): ahora solo mira `ip route`.
5. La cosecha contaba lineas en vez de filas CSV y volcaba **toda** la tabla de GHOSTS (779 MB, con el historico de ventanas anteriores): ahora cuenta filas y vuelca desde t0-1 dia, comprimido.
6. Un volumen de ~25 MB de auditd en los 3 primeros minutos tras arrancar (`prep` hace muchas operaciones por SSH): es ruido de **antes de t0**, no de la ventana.

## Pendiente para L4 (armado real)
Regenerar `recetas_vr/` con el mapa 30/11 (**hecho**) y re-sellar (`sellar_vr.py sellar`, **hecho**, hay que repetirlo si se toca algo); pausar Windows Update antes de `prep` (G-10); registrar las tareas con T0/T1 reales; `prep` a t0-45 min y `arm` a t0-20 min en vivo; `legit_vr.py sellar-vm` antes de t0.
**Nota de host:** Windows Update ya tenia la politica `NoAutoUpdate=1` de las ventanas anteriores; en el ensayo solo se paro el servicio y despues se devolvio a `Manual` (sin usar `restaurar`, que habria borrado esa politica).

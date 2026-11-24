# RUNBOOK de la ventana V1-L (Velociraptor, Linux) - 25/11 -> 28/11/2026

**Ventana:** `t0 = 2026-11-25T00:00:00Z` -> `t1 = 2026-11-28T00:00:00Z` (72 h; miercoles-viernes; CET = UTC+1, sin cambio de hora).
Decision del humano el 2026-11-24 (cambio respecto al plan v2: empieza hoy en vez del lunes 30/11; se declara en la memoria: la receta son jornadas genericas, sin dependencia del dia de la semana).
Plan: `_fases/velociraptor-v1l/plan.md` · Auditoria: `_fases/auditoria-ventanas-wazuh/AUDITORIA.md` · Ensayo: `ensayo_E0_vr.md`.
**Reglas:** contrasena de la VM SOLO en el entorno del proceso (`TFG_MANAGER_PW=...` en la linea de comandos; nunca en ficheros ni git) · **NADA por SSH a la victima dentro de `[t0,t1]`** · el `watch` solo lee el host · sin parada automatica · si la ventana sale invalida se repite entera.
Rutas: `R=D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE` · `VR=$R\Soporte\Laboratorio\legitimo_72h_vr` · scripts en `$R\_artefactos\scripts`.
Cliente VR de la VM: `C.0421bea0cf56b59b` (en `legit_vr_config.json`). Salida de la cosecha: `D:\TFG-VMs\legitimo-vr-2026-11-25`.

## Antes (host, sin tocar la VM) - hecho el 24/11 por la tarde
1. `recetas_vr/` con mapa `2026-11-25:1,26:2,27:3` (d1/d2/d3 identicos byte a byte a Wazuh) · tabla cfg S fijada (`recetas_vr/tabla_cfgS.sha256`).
2. Windows Update pausado (`$VR\pausar_windows_update.ps1 pausar`): el `watch` lo repausa cada 30 min. La politica `NoAutoUpdate=1` ya existia; **no usar `restaurar`** (la borraria); al acabar solo `Set-Service wuauserv -StartupType Manual`.
3. Tareas del PC: `powershell -File $VR\registrar_tareas_vr.ps1 -T0 2026-11-25T00:00:00Z -T1 2026-11-28T00:00:00Z` (Watch cada 30 min desde t0; Servidor cada 30 min desde t0-60 min). **Sin contrasena.** Verificar con `-Verificar`.

## 23:05Z  servidor y tabla
`powershell -File $R\Soporte\Laboratorio\velociraptor\arrancar_servidor.ps1` -> proceso 1, puertos 8000 y 8889 · `python legit_vr.py tabla check` -> `RESULT=PASS`.

## 23:15Z (t0-45 min)  PREP  (operador en vivo)
`TFG_MANAGER_PW=... powershell -File $VR\legitimo_host_control_vr.ps1 -Phase prep -T0 2026-11-25T00:00:00Z -T1 2026-11-28T00:00:00Z` (SIN `-Test`; log `legitimo_host_control_vr.log`). Espera `=== END prep ===` y G-1..G-12 OK (G-10 exige WU Disabled; G-2 >= 4096 MB libres; G-5/G-6 `gate` PASS).
Si falla una puerta: **no se arma**; se diagnostica; la ventana puede moverse (el timer admite otro T0 futuro).

## Tras el prep (SSH permitido: aun es antes de t0)
1. `TFG_MANAGER_PW=... python legit_vr.py sellar-vm` (4 huellas: cliente, config, auditd.conf, reglas; deben coincidir con el ensayo: `c216b7be...`, `33776228...`, `4f1836c7...`, `8c033b05...`).
2. `python sellar_vr.py sellar` -> `sha256sums_vr.txt` (34 ficheros) -> `git add/commit/push` (**despues de sellar no se toca ningun script**; V7 lo comprueba).

## 23:40Z (t0-20 min)  ARM
`TFG_MANAGER_PW=... powershell -File $VR\legitimo_host_control_vr.ps1 -Phase arm -T0 2026-11-25T00:00:00Z -T1 2026-11-28T00:00:00Z` -> el timer debe quedar en **`OnCalendar=2026-11-24 23:55:00 UTC`** (t0 - 5 min), `tfg-ghosts-legit.timer enabled`, cliente GHOSTS vivo. A partir de aqui **no se entra en la VM**.

## Durante (25/11 00:00Z -> 28/11 00:00Z)
Solo el host: `vigilancia_legitimo_vr.log` (un chequeo cada 30 min; `estado=OK`), `ALARMA_*.txt` si hay alarma, `D:` >= 60 GB, PC sin reiniciar. Chequeo diario (00:30Z de cada dia): ultimas lineas del `watch`, `vmrun list` (1 VM), `Get-Service wuauserv` Disabled, servidor VR activo, uptime del PC. Aborto temprano solo en las primeras 24 h y solo por invalidez objetiva (V1-V9 del plan). **No usar `tail -F` sobre ficheros que escribe el host.**
Si el servidor VR cae: la tarea lo reinicia (archiva su log); el cliente guarda en su cola.

## 28/11 00:02Z (t1+2 min)  COSECHA  (operador en vivo; la VM sigue encendida)
`TFG_MANAGER_PW=... python cosecha_vr.py --t0 2026-11-25T00:00:00Z --t1 2026-11-28T00:00:00Z --out D:\TFG-VMs\legitimo-vr-2026-11-25` (fases: acciones -> guest -> marca-fin -> subida -> datastore -> manifest). Si `marca-fin` no se ve: NO se para nada.
Despues, **solo con la cosecha verificada** (en este orden):
1. `exportar_denominador_vr.py --cosecha D:\TFG-VMs\legitimo-vr-2026-11-25 --t0 ... --t1 ... --out <DIR>\productos` (usa SOLO el flujo de subida de esta cosecha).
2. Copia a `C:\TFG-copia\velociraptor-v1l\V1L_cosecha.zip` (zip del directorio de la cosecha; contiene `MANIFEST.tsv` en la raiz) y comprobacion (`testzip`).
3. `verificar_validez_ventana_vr.py --cosecha ... --copia2 C:\TFG-copia\velociraptor-v1l\V1L_cosecha.zip --t0 ... --t1 ... --informe <DIR>\productos\veredicto_validez.md` (V7 compara con `sha256sums_vr.txt`).
4. Parar la VM (soft) y **despues** `vmrun snapshot ... post-legit-vr-2026-11-28` (la VM apagada).
5. `legitimo_host_control_vr.ps1 -Phase cleanup`, `registrar_tareas_vr.ps1 -Eliminar`, `Set-Service wuauserv -StartupType Manual`.
6. `git commit/push` de los productos pequenos (`ventana_meta.md`, `incidencias.md`, `veredicto_validez.md`, csv) y segunda copia de TODO en `C:`; pedir al humano el disco externo.

## Notas
- Prep/arm ocurren de noche UTC (fuera de bloques): el cliente GHOSTS arranca pero no actua hasta las 08:00Z (igual que en Wazuh).
- El ensayo mostro: ~98 MB/h de EBPF (~7 GB), auditd ~3,6-6,9 MB/h, disco de la VM ~5 MB/h (4,4 GB libres). Alarmas del watch: `df<3G` AVISO, `df<2G` ALARMA.
- Defectos ya corregidos en el ensayo: ver `ensayo_E0_vr.md`.
- **Ensayo general del `prep` real (24/11 20:00Z):** el primer intento fallo en G-7 porque la huella de la tabla incluia `"version"` (sello interno que cambia al reiniciar el servidor). Corregido en `legit_vr.py` (se excluye `version`; hallazgo 7 del ensayo) y comprobado tras un reinicio del servidor; el segundo intento paso G-1..G-12. G-2 midio 4 422 MB libres (mismo valor que el ensayo E0: 4 423).
- No arrancar `arrancar_servidor.ps1` desde Git Bash en primer plano (el servidor hereda la salida y la llamada no vuelve): usar la herramienta PowerShell o `nohup`.
- Los logs `legitimo_host_control_vr.log` y `vigilancia_legitimo_vr.log` ya contienen lineas del ensayo (24/11): los verificadores filtran por `[t0,t1]`.
- **Revision independiente pre-vuelo (24/11):** `_fases/velociraptor-v1l/revision_independiente_prevuelo.md` (0 ALTA, 6 MEDIA, 10 BAJA). Aplicado y comprobado: V3 exige cobertura hasta t1; V6 acepta la copia en zip; V7 sella solo lo que actua dentro de la ventana; V8 en UTC; V2 no pasa sin dias evaluados; la cosecha copia ademas la evidencia del PC (fase `host`) y aborta si el ledger esta vacio; el recuento usa solo el flujo de la subida de esta cosecha (**habia un riesgo real de mezclar con los flujos del ensayo**); `prep` repausa Windows Update si hace falta, comprueba el rc de revert/start y quita la contrasena del entorno antes de lanzar procesos largos; el vigilante no cae por un timeout de la API; las tareas del PC van con ventana oculta; la puerta G-5 espera hasta ver crecimiento (las filas llegan por lotes). Probado: servidor levantado por la tarea programada **sobrevive** al fin de la tarea (130 s). **No aplicado, declarado:** no se emite marca INI (la cobertura de inicio la cubre V1); `Generic.Client.DiskSpace` cada 30 min es una interaccion del cliente con la VM dentro de la ventana (equivalente al `df -P` del agente de Wazuh; ruido `comm=velociraptor`/`df` que el analisis debe separar); las tareas son `Interactive`: no cerrar sesion de Windows en 3 dias.
- **Ensayo general (24/11 20:00-20:36Z):** el `prep` real fallo dos veces por defectos MIOS (huella de tabla con `version`; puerta G-5 de 60 s fijos) y se corrigio; el 4.o intento paso G-1..G-12 y el `arm` real dejo el timer en `2026-11-24 23:55:00 UTC`.

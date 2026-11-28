# Ventana V1-L (Velociraptor 0.77.3, Linux, actividad legitima) - metadatos

- **Ventana:** t0 = 2026-11-25T00:00:00Z -> t1 = 2026-11-28T00:00:00Z (72 h, miercoles a viernes; CET = UTC+1, sin cambio de hora). Wazuh uso lunes a miercoles; se declara en la memoria.
- **Maquina:** snapshot `lab-listo-legit-vr` (agente Wazuh purgado, cliente VR C.0421bea0cf56b59b, auditd.conf num_logs=120 max_log_file=8 MB). Snapshot posterior: `post-legit-vr-2026-11-28` (VM apagada).
- **Ojos:** EBPF (cfg S: todos los eventos + security_inode_rename + mkdir) y auditd (`audit.log*` subido por Velociraptor y copia `tar` directa: mismo contenido, 247 309 eventos en ambos).
- **Actividad:** GHOSTS v8.3.1, receta d1/d2/d3 identica byte a byte a Wazuh: 163 + 178 + 163 = **504 acciones**, 100 % de cumplimiento por dia, 0 acciones fuera de bloque.
- **Datos:** EBPF **10 657 709 filas**; auditd **247 309 eventos** (1 371 623 lineas). Primer evento t0+1 s, ultimo t1-3 s. Estabilidad por dia: EBPF 3,57/3,55/3,54 M; auditd 82,4/82,5/82,4 mil.
- **Cosecha:** 28/11 00:04-00:09Z, `D:\TFG-VMs\legitimo-vr-2026-11-25` (8,9 GB, 1323 ficheros con sha256 en `MANIFEST.tsv`, `cosecha.done`). Marca FIN vista en EBPF a los 30 s. Copia 2: `C:\TFG-copia\velociraptor-v1l\V1L_cosecha.zip` (testzip OK, MANIFEST igual).
- **Veredicto de validez (`veredicto_validez.md`, `verificar_validez_ventana_vr.py`): VALIDA - V1..V9 todos PASS** (144 chequeos, 0 alarmas; 0 sesiones del operador; sin ruta default; huellas de VM y 33 ficheros sellados iguales; PC sin reinicio).
- **Declaraciones para la memoria:** ventana mie-vie vs lun-mie en Wazuh; cambio de retencion de auditd (num_logs=120 x 8 MB); `Generic.Client.DiskSpace` (`df -h`) cada 30 min y ruido propio del cliente VR (`comm=velociraptor`/`df`) que el analisis debe separar; el keepalive es ~72 % de los eventos auditd y wazuh-agentd ~18 % en Wazuh; no hay capa de reglas todavia (FP se calcula despues con C2/C3 sobre estos datos).
- **No hecho aun:** disco externo, analisis con reglas C2/C3.

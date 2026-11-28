# Veredicto de validez de la ventana V1-L (Velociraptor)

Ventana: 2026-11-25T00:00:00Z -> 2026-11-28T00:00:00Z. Generado por `verificar_validez_ventana_vr.py`.

**Veredicto: VALIDA**

| Criterio | Estado | Detalle |
|---|---|---|
| V1 Cobertura | PASS | EBPF: 10657709 filas, primera t0+1s, ultima t1-3s, hueco max 1 min / auditd: 247309 eventos, hueco max 0.5 min |
| V2 Actividad | PASS | acciones=504 por dia={'2026-11-25': 163, '2026-11-26': 178, '2026-11-27': 163} cumplimiento%={'2026-11-25': 100.0, '2026-11-26': 100.0, '2026-11-27': 100.0} fuera_de_bloque=0 [] |
| V3 Servidor y cliente | PASS | chequeos=144 alarmas=0 servidor_caido=0 hueco_max=30.2 min; cubre t0..t1 (primero a 0 min de t0, ultimo a 30 min de t1): True |
| V4 0 contaminacion | PASS | sesiones del operador en [t0,t1]: 0 [] |
| V5 Aislamiento | PASS | `ip route` sin ruta `default`: si (1 rutas) |
| V6 Crudo completo | PASS | ficheros con sha256 OK=1323 mal=0 cosecha.done=True copia2 ZIP V1L_cosecha.zip (testzip=None; MANIFEST == igual) |
| V7 Sin cambios | PASS | sha256 de VM (cliente, config, auditd.conf, reglas) iguales: True [] / tabla cfg S igual / sha256sums_vr: RESULT=PASS |
| V8 Host estable | PASS | ultimo arranque del PC 2026-11-24T09:54:21Z (< t0: True); eventos Kernel-Power 41/42/107 desde t0: 0 |
| V9 Recuperaciones | PASS | recovery.log: 2 lineas {'rotacion': 2} |

# Veredicto de validez de la ventana V1-L (Velociraptor)

Ventana: 2026-11-24T13:20:00Z -> 2026-11-24T19:30:00Z. Generado por `verificar_validez_ventana_vr.py`.

**Veredicto: INVALIDA (revisar: V2 Actividad)**

| Criterio | Estado | Detalle |
|---|---|---|
| V1 Cobertura | PASS | EBPF: 902141 filas, primera t0+2s, ultima t1-1s, hueco max 1 min / auditd: 20198 eventos, hueco max 0.5 min |
| V2 Actividad | FAIL | acciones=63 por dia={'2026-11-24': 63} cumplimiento%={'2026-11-24': 38.7} fuera_de_bloque=0 [] |
| V3 Servidor y cliente | PASS | chequeos=15 alarmas=0 servidor_caido=0 hueco_max=30.1 min |
| V4 0 contaminacion | PASS | sesiones del operador en [t0,t1]: 0 [] |
| V5 Aislamiento | PASS | `ip route` sin ruta `default`: si (1 rutas) |
| V6 Crudo completo | PASS | ficheros con sha256 OK=209 mal=0 cosecha.done=True  |
| V7 Sin cambios | PASS | sha256 de VM (cliente, config, auditd.conf, reglas) iguales: True [] / tabla cfg S igual / sha256sums_vr: RESULT=PASS |
| V8 Host estable | PASS | ultimo arranque del PC 2026-11-24T09:54:21Z (< t0: True); eventos Kernel-Power 41/42/107 desde t0: 0 |
| V9 Recuperaciones | PASS | recovery.log: 0 lineas {} |

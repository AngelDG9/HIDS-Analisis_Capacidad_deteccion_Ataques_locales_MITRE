# Contrarrevisión independiente (2026-11-21)

Un agente que **no vio mis conclusiones** recalculó la cadena **crudo → Detalle → Audited → T2** con su propio código (solo lectura).

| Comprobación | Resultado |
|---|---|
| 12 ventanas al azar (semilla 7; 6 Linux + 6 Windows, incl. ATA038, ATA067 y una `_rev`): alertas crudas en `[t0,t1]` == filas del Detalle | **OK 12/12** (p. ej. ATA038_iter1 2430=2430; ATA067_iter1 318=318) |
| Líneas de `raw` == `lineas_alerts/archives` del índice; hay eventos crudos (`archives`) dentro de la ventana | **OK** |
| Suma de categorías de `M1b/Auditado` == filas del Detalle | **OK 12/12** |
| **Barrido completo 128 Linux + 108 Windows** (índice vs raw; Detalle vs alertas crudas; Audited vs Detalle; sha256 de la cabecera vs Detalle real) | **OK 236/236** en cada una |
| T2 `#Alertas` y `#rule.id_distintos` recalculados a mano (C1/N0) | **OK 55/55 Linux, 54/54 Windows**; las 10 filas por caso (C0/C1 × 5 umbrales): **0 discrepancias en 1 090** |
| Copia cruda del manager: conteos por ventana == raw (24/24) y sha256 de 4 ficheros vs manifiesto | **OK**; manifiesto Linux 34/34 y Windows 43/43 sin huérfanos |
| Sin `t1<=t0`, sin ventanas sin eventos, sin tags huérfanos | **OK** |

**Discrepancias menores encontradas** (y qué se hizo):
1. Columna `filas_detalle` del índice Windows obsoleta en las filas con `t0` corregido (el Detalle/Audited/T2 sí usan el `t0` correcto) → **corregida** el 2026-11-21.
2. Última línea truncada (no JSON) en el raw de alertas de ATA020_iter1, ATA033_iter2 y ATA037_rev2: caen **fuera** de la ventana, no afectan al Detalle ni a T2.
3. Convención de borde: `t1` inclusivo solo hasta `t1.000` (coherente con la definición declarada).
4. 24 tags de Linux tienen filas duplicadas en el índice (reintentos y repeticiones); manda la última, y Detalle/raw/T2 corresponden a la última corrida (verificado por conteo).

**No pudo comprobar** (límites): las corridas anteriores sustituidas (su raw se sobrescribió); que el manager guardara todo lo que el agente generó; la corrección de la clasificación `categoria` (solo coherencia numérica); sha256 de ~70 ficheros de la copia cruda (el verificador del repo sí los recalcula todos); que `t0/t1` reflejen exactamente el instante del ataque (reloj de la VM).

# Resultado F2 — ventana legítima Windows de 72 h (T3-W) y comparación con Linux

> Ventana `2026-11-17T00:00:00Z .. 2026-11-20T00:00:00Z` · agente `002/victima-windows` · Wazuh 4.14.7 · Windows «virgen» (ruleset por defecto) ·
> `metrica_version=1`, `boveda_version=3` · **VÁLIDA** (A1–A11 PASS, ver `informe_validez_A1_A11.md`; sin incidencias en el plano de datos).
> Productos: `analisis/` (regenerables con `_artefactos/scripts/analizar_legitimo_windows.py`) y `Hojas/T3_legitimo_windows.csv`.
> Datos crudos: `D:\TFG-VMs\legitimo-windows-2026-11-17\` (fuera del repo; sumas en `SHA256_TODO.txt`).

## Cifras de la ventana

| Magnitud | Valor |
|---|---|
| `M` (líneas de `archives` del endpoint, unidad canónica) | **21 589** (total del manager 73 667) |
| Alertas (= unidades con alerta; 1 línea → 1 alerta) | **6 344** (coincide con las 6 344 del fichero `alerts` del manager) |
| Reglas distintas | 24 |
| Acciones GHOSTS | 504 (d1 163, d2 178, d3 163; jornada 147/153/141 + campaña 16/25/22) |
| Alertas por día (17/18/19) | 2 109 / 2 159 / 2 076 (estable) |
| Alertas del operador (SSH, tareas del laboratorio) | 6 (0,09 %) → FPR sin operador 0,293575 frente a 0,293853 |
| Alertas del propio HIDS (agente Wazuh / Sysmon) | 60 (sensibilidad «auto-ruido», no entra en el canónico) |

## FPR de Windows por umbral de nivel (N)

| N | FP | FPR (FP/M) | FP/hora | FP/acción | reglas |
|---:|---:|---:|---:|---:|---:|
| ≥0 y ≥3 | 6 344 | 29,39 % | 88,1 | 12,59 | 24 |
| ≥7 | 143 | 0,66 % | 1,99 | 0,28 | 6 |
| ≥10 | 88 | 0,41 % | 1,22 | 0,17 | 2 |
| ≥12 | 88 | 0,41 % | 1,22 | 0,17 | 2 |

Qué las produce: `67027` (A process was created, nivel 3) 5 023 · `92052` 504 · `92032` 256 · `61104` 158 · **`92213` (nivel 15, «ejecutable
soltado en carpeta típica de malware») 86** · `92201` (nivel 9) 51 · `91823` (nivel 14) 2 · resto < 60 cada una. Los 88 de N≥10 son
`92213` + `91823`: **actividad legítima de GHOSTS que Wazuh trata como crítica** (falsos positivos de nivel alto).

## Comparación con Linux (misma métrica, misma unidad; ventana Linux 2–4 nov, `M = 342 966`)

| | Linux **C0** (Wazuh virgen) | Linux **C1** (+ reglas auditd) | **Windows** (virgen) |
|---|---:|---:|---:|
| FP en N≥3 | 50 | 294 252 | 6 344 |
| FPR en N≥3 | 0,015 % | 85,80 % | 29,39 % |
| FP/hora en N≥3 | 0,69 | 4 086,8 | 88,1 |
| FP en N≥7 | 0 | 2 | **143** |
| FP/hora en N≥7 | 0 | 0,028 | **1,99** |

Lectura (declarada con cautela):
1. **No son comparables en bruto por `M`**: en Linux `M` incluye cada `execve` que registra auditd (342 966 eventos), en Windows solo lo que envía el agente
   (21 589). Por eso se comparan **FP/hora, FP/acción y los umbrales de nivel**, no solo el %.
2. **Windows virgen ya trae reglas que alertan** (Sysmon + eventos de seguridad), así que no hay «C0 sin ruido»: C0 = C1. En Linux virgen casi no alerta (50 en 72 h) y
   el ruido llega al añadir reglas de auditoría.
3. **En niveles altos (≥7) Windows genera ~70 veces más FP/hora que Linux C1** (1,99 frente a 0,028): el coste de usar Windows «virgen» en un entorno con
   actividad de usuario es que aparecen alertas críticas falsas (`92213`, `91823`).
4. La campaña de GHOSTS **está dentro de `M`** (se declara; no se fabrica un FPR sin campaña).

## Cautelas y límites (declarados)

- Operador identificado por `etiquetar_operador_legit.py` (no por `win_user=angel`, que es el usuario legítimo). 92052/92032 con padre `sshd.exe` son
  *artefacto de entrega* (SSH) y se tratan **por alerta** en M1b-W; en la ventana legítima no hubo SSH de operador (`SSH_INVITADO=0` en los 144 chequeos).
- `doble_uso` de Windows **no está calculado** (no se cruza aún con los ataques; se hará tras repetir los ataques en F3, para que sea homogéneo).
- T5 de Windows y el TPR comparado se recalcularán con los ataques **repetidos** (versión 2); los de la ronda SSH quedan como «versión 1».
- Datos de comparabilidad de Linux: `Hojas/T3_legitimo.csv` (versión de métrica 1, bóveda 2); Windows usa bóveda 3 (receta nueva con corrección `curl`).

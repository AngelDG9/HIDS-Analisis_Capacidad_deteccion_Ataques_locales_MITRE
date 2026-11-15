---
bloque: analisis-windows-legit
nombre: Analisis de la ventana legitima Windows (T3-W) y TPR comparado Linux<->Windows
version: 1
status: cerrado_en_rama   # NO fusionado en main (el ensayo WE0 del 15-16 nov usa main)
fecha: 2026-11-15
rama: bloque/analisis-windows-legit
commits: 1aca2b6 (bloque) · 00ff1da (revision)
---

# change-doc — bloque `analisis-windows-legit`

## Qué se hizo

| Pieza | Para qué |
|---|---|
| `_artefactos/scripts/analizar_legitimo_windows.py` | Espejo de `analizar_legitimo_72h.py` (Linux): indice evento↔alerta (`unidad = fichero:linea`), FPR **canonico y `sin_operador`**, `FP/accion`, `FP/hora`, catalogos de ruido y M1b, estabilidad por hora/dia. Alimenta **`tabla3_legitimo.py --so windows`** (la misma herramienta que Linux). |
| `_artefactos/scripts/sensibilidades_tpr.py` + `Hojas/T2_sensibilidades_comparadas.csv` | TPR de Linux y Windows con **las mismas 4 variantes**: canonico · sin entrega · sin doble uso · ambas. Ventana canonica = `rev1` si el caso esta en `repeticiones.csv`, si no `iter1` (igual que `tabla2_ataques.py`). |
| Tests | `test_analizar_legitimo_windows.py` (13) y `test_sensibilidades_tpr.py` (9). |

## Comprobado (con datos reales)

- Sobre el crudo de la prueba de 2 h (`legitimo-windows-2026-11-12`): **M = 881, FP_uni = 352, operador = 82** (coincide con las medidas previas); `tabla3_legitimo.py` acepta la salida.
- El `canonico` de `sensibilidades_tpr.py` **reproduce `T4` exactamente**: Linux 53/55 (N≥3) y 2/55 (N≥7); Windows 54/54 y 2/54. Hay un test que lo exige.
- Resultado: a N≥3, **Linux 53/55 → 2/55** sin doble uso; **Windows 54/54 → 16/54** sin entrega ni doble uso. Reclasificar solo el envoltorio SSH **no** cambia el 54/54.

## Hallazgo que motiva el bloque (plan.md M-22 / M-23)

El "envoltorio" SSH (`92052` con padre `sshd.exe`, `92032` con padre `cmd.exe`: `cmd /c echo SSH-OK`, `if exist …efecto_local.txt echo OK`, `sftp-server.exe`) salta por **como se lanzo el ataque**, no por la tecnica. En Linux el envoltorio (`dash`) cae como `ruido_conocido` porque tambien aparece en lo legitimo; en Windows no (lo legitimo lo lanza `ghosts.exe`).

## Limites declarados

1. `T5` de Windows es **provisional** (el legitimo era un baseline de 8 h): recalcular con la ventana de 72 h.
2. `sin_entrega` de Windows necesita las alertas **crudas** (`D:\TFG-VMs\crudo-ataques\alerts_ataques`); sin ellas sale `ND`, nunca un numero inventado.
3. **M1b-W (re-corte de los 54 ataques) NO esta hecho**: espera a la ventana de 72 h (necesita su catalogo).
4. En un **clon limpio** fallan 14 tests + 27 errores **ajenos** a este bloque (deuda CRLF conocida en `roadmap.md`); en `main` pasan los 527.

## Como se usa (tras la ventana)

    python _artefactos/scripts/analizar_legitimo_windows.py --archives <crudo>\archives --t0 <t0> --t1 <t1> --out-dir <salida>
    python _artefactos/scripts/tabla3_legitimo.py --so windows --detalle <salida>\T3_detalle_windows.csv --unidades-count <M> ...
    python _artefactos/scripts/sensibilidades_tpr.py

## Para fusionar (cuando no haya ventana en curso)

Son ficheros **nuevos** (no tocan nada sellado): `git merge bloque/analisis-windows-legit` en `main`, luego `pytest` completo.

# Plan — cierre del análisis de Wazuh (Linux + Windows) · 2026-11-21

> **Principio:** manda el dato, no la documentación. Todo lo que aquí se afirma sale de ficheros comprobados el 2026-11-20/21
> (inventario con recálculo de sha256, filas y conteos). Lo que no se ha comprobado se marca **[NC]**.
> Contexto: la campaña de ataques v2 (lanzador local, `logall_json=yes`) está completa en Linux (128/128) y en Windows
> (en curso; ATA067 aparte). Las ventanas legítimas de 72 h de Linux (2–4 nov) y Windows (17–20 nov) están cerradas.

## 0. Nombres (para no confundirnos)
- **`boveda_version`** (2 en Linux, 3 en Windows): versión de la métrica congelada. **No** es la versión de los datos.
- **datos v1 / v2**: v1 = ataques lanzados por SSH, sin `archives`; **v2 = lanzador local + `logall_json=yes`**.
- **M1b**: re-corte de los ataques con el catálogo de ruido de la ventana legítima (el titular de las tablas Linux es M1b).
- **C0 = {RS1}**, **C1 = {RS1,RS2} = «virgen»** (titular), C2/C3 = reglas añadidas (RS3/RS4, hoy vacías). En Windows C0 = C1.

## 1. Hechos comprobados que condicionan el plan
1. `Bitacora/ATA*.json` (109) solo existen para v1: `tabla2_ataques.py` saca de ahí `t0/t1/k/m/herramienta/doble_iteración`
   casando por nombre. **Apuntar T2 a `linux_v2` sin Bitácora v2 da `t_hasta_1a_deteccion_s` basura.** → hay que generar la Bitácora v2
   desde `windows_index.csv` (t0/t1 reales).
2. `filtrar_ataques_*_v2.py` llamó a `filtrar_ruido*.py` **sin `--catalogo`**: usó el catálogo viejo (Linux 12 reglas; Windows baseline de 8 h).
   El titular de Linux v1 usa `catalogo_M1b.csv` (15 reglas). → refiltrar v2 con el catálogo correcto (Linux M1b; Windows `catalogo_M1b_windows.csv`, 34 reglas).
3. **TPR Linux v2 = TPR Linux v1 (M1b)**: 53/53/2/0/0 (C1) y 2/2/2/0/0 (C0) en N=0/3/7/10/12; cambian los conteos de alertas, no el TPR.
4. **Dudosas** (`categoria=dudosa`): Linux v1 resueltas (1865 → `veredicto_humano`); **Linux v2: 3826 sin resolver**; Windows v1 resueltas; Windows v2 sin filtrar.
   La métrica **no mira `dudosa`**: solo cuenta `categoria=="deteccion"` → una dudosa que fuese detección real se perdería sin aviso.
5. T4/T5/sensibilidades de Windows siguen con el baseline de 8 h (`t3=_no_existe_t3_windows.csv`; «FP/hora 19,9»); el dato real de 72 h es **88,1 FP/h**.
6. No existe script que genere `T5_doble_uso_windows*.csv` ni la comparación Linux↔Windows; no hay `recortar_ataques_m1b_windows.py`.
7. Rutas absolutas `D:\TFG\...` en las cabeceras de los `Audited` v2 (los v1 usan relativas) → parametrizar/normalizar.
8. `T3_detalle.csv` de Linux solo está bajo `Soporte/` (no promovido a `Dataset/`).

## 2. Fases (cada una termina con una puerta de verificación)

### F-A · Cerrar la recogida de datos (hecho/por terminar)
- A1. Terminar la campaña Windows v2 (+ ATA067: manejo de reinicio ya escrito, `--only ATA067 --force`).
- A2. `verificar_completitud_ataques_v2.py --so linux|windows` (recalcula sha256 de la copia cruda, cruza alertas crudas vs Detalle, comprueba `archives`).
- **Puerta A:** Linux 128/128 y Windows 108/108 sin fallos de completitud; commit + push.

### F-B · Refiltrado correcto de v2
- B1. Añadir `--catalogo` a `filtrar_ataques_*_v2.py`; refiltrar Linux v2 con `catalogo_M1b.csv` y Windows v2 con `catalogo_M1b_windows.csv`.
- B2. Normalizar rutas relativas en las cabeceras.
- **Puerta B:** conteos por categoría coherentes; comparar con el filtrado antiguo (cuántas filas cambian y por qué).

### F-C · Dudosas (v2)
- C1. Medir **qué decidió v1** para cada par `(rule_id, motivo)`: tabla de veredictos humanos de v1 (Linux 1865, Windows 1970).
- C2. Aplicar a v2 **solo los pares con veredicto unánime y apoyo suficiente en v1**; el resto queda `dudosa` y **se declara** (nada se inventa).
- C3. Informe: cuántas se resuelven por regla, cuántas quedan, y si alguna `dudosa` residual pudiera ser detección (revisión dirigida).
- **Puerta C:** 0 dudosas con riesgo de ser detección sin revisar; informe `dudosas_v2.md`.

### F-D · Tablas
- D1. Bitácora v2 (JSON) desde el índice → `tabla2_ataques.py --bitacora`.
- D2. T2/T4/T5 **Linux v2** (con M1b/refiltrado) y **Windows v2**; mantener T2/T4/T5 v1 (versión 1 por SSH).
- D3. Windows con ventana de 72 h: T5 doble uso (catálogo 72 h), T3-W con `es_TP_en_algun_ataque`, T4-W con M, T5 pruning/steps, M1b-W (`recortar_ataques_m1b_windows.py`).
- D4. Comparación Linux↔Windows (v1 y v2) con FP/h, FP/acción y umbrales (no por `M` en bruto).
- D5. `sensibilidades_tpr.py` actualizado (T5 Windows 72 h).
- **Puerta D:** cada tabla lleva su cabecera con sha256 de entradas; regenerar dos veces da bytes idénticos.

### F-E · Verificación y testeo (ronda final)
- E1. Tests nuevos para: `filtrar_ataques_*_v2`, `verificar_completitud_ataques_v2`, bitácora v2, script de dudosas, M1b-W, T5 Windows.
- E2. `pytest _artefactos/scripts/tests` completo (Git Bash: `/c/Windows/System32` primero en el PATH, TMP escribible).
- E3. Reproducibilidad: regenerar T2/T4/T5 **v1** con los scripts parametrizados y comprobar que coinciden con las cabeceras actuales (prueba de que no rompí nada).
- E4. Contrarrevisión independiente (un agente que no ve mis conclusiones) de 10 ventanas al azar: de crudo → Detalle → Audited → tabla.
- **Puerta E:** todo verde; limitaciones declaradas en `RESULTADO_CIERRE_WAZUH.md`.

## 3. Lo que NO se hace en este cierre (declarado)
- Revisión humana de dudosas por una persona (solo la parte determinista por reglas + informe de lo que queda).
- C2/C3 con reglas externas (se hará con los datos crudos guardados; fuera de este plan).
- Evasión.

## 4. Riesgos
- Cambiar defaults rompe `test_sensibilidades_tpr.py::test_el_canonico_reproduce_la_tabla_T4_oficial` → parametrizar sin tocar defaults.
- Las unidades de Linux y Windows no son comparables en bruto (M 342 966 vs 21 589): comparar por hora/acción/umbral.

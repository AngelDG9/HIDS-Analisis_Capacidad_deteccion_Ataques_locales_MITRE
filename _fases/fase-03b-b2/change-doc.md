# change-doc — Bloque `B2` (ampliación de ataques Windows, segunda oleada)

> **Estado: CERRADO (2026-11-10).** Plan v1 aprobado (`84c5746`). **22 casos nuevos**
> (ATA088–ATA109); corpus Windows total **N=54** (32 de B1 + 22 de B2). **0 VMs al cierre.**
> **399 tests.** Linux intacto (875/875 semántico). **0 secretos.** `git push` no ejecutado.

---

## 1. Alcance y corpus

- **22 casos nuevos** (ATA088–ATA109):
  - **5 deudas de B1**: T1496.002, T1499.003, T1498.002, T1557.001, T1557.003.
  - **Archivo/manipulación**: T1560.002, T1560.003, T1565.001, T1565.002, T1565.003.
  - **Disco/medios**: T1561, T1561.001, T1561.002, T1025, T1052.001 (VHD 100 MB).
  - **Capas nuevas**: T1039, T1056.002, T1056.003, T1056.004, T1074.002, T1119, T1114.003.
- **20/22 con pareja Linux**; **6 ART adaptado, 16 manual**.
- **Tandas**: B2.0 prep · B2.1 (5) · B2.2 (5) · B2.3 (5) · B2.4 (7) · B2.5 cierre.
- **Método**: `esperado` sellado antes de `t0`; 2 iteraciones; C0; prueba de efecto;
  **0 dudosas**; **0 filas del ataque en ruido**.

## 2. Resultados (N=54)

- **T2**: `Hojas/T2_ataques_windows_b2.csv`, **540 filas**, `N_casos=54`, `corpus=54`,
  `CA-B1-02 PASA`, `sha256 = 446490126276a65d52c2df5303a3cb6ebfdb8ff1dc50f0dd7819f435307d0495`.
- **TPR**: **54/54 (1,000)** a `N=0/3`; **2/54 (0,037)** a `N≥7`.
  Los 2 TP a `N≥7` son **ATA073 y ATA097** (`92213`, nivel 15), **artefactos de compilación**
  (`Add-Type`/script block), **no** detección de la técnica. La detección real de las técnicas
  a `N≥7` es **0/54**.
- **`#Alertas`** (N=0) = **669**; `#rule.id` por caso: 3 (salvo ATA064=4, ATA067=7, ATA072=4,
  ATA073=5, ATA087=4, ATA089=4, ATA090=4, ATA091=5, ATA092=4, ATA096=4, ATA097=4, ATA105=4,
  ATA106=4).
- **T4**: `Hojas/T4_rendimiento_windows_b2.csv`, `N=54`, `sha256 = 52e2e01bc09099349a0d98bf2a3d2305544a5acafe9030438a4594a909f1c9ef`;
  `FPR/TNR/GM/Precisión/F1/Usabilidad = n/a` (sin `M`); `FP/hora = 19,875` descriptivo.
- **T5 doble uso**: `Hojas/T5_doble_uso_windows_b2.csv`, **36 reglas**, **1 doble uso**:
  **`67027`** (132 alertas baseline, **348 detecciones en 54/54**);
  `sha256 = 7e1c7d6a59e8069bdcc8d38f25dbb2a89696e621429338d1a44f36fd1cd61fa2`.
- **Sensibilidades (NO canónicas)**:
  - **FIM como detección**: 54/54 a `N=0/3`; **35/54 a `N≥7`** (solo `553`, nivel 7);
    `#Alertas=1371`; `sha256=982730d9…`. Responde a H-B2-1: **sí hay señal de nivel alto
    para el efecto de borrado**; no para creación/modificación (`550/554`, nivel 5).
  - **`sin_67027`**: TPR **intacto** (54/54/2/54); `#Alertas=1075`; `sha256=771f2104…`.
  - **`sin_operador`**: TPR idéntico; `#Alertas=666`; `sha256=e4084dba…`.
  - **`catalogo_v2`**: TPR idéntico; `#Alertas=666`; `sha256=be98879b…`.
- **Cadena**: `B2_sha256sums.txt` (452 líneas, 0 mal); `auditar_cadena_huellas.py`
  **2368 citas, 0 desincronías**, 100 omitidas (`.ps1` de Windows; el sums las verifica).

## 3. Comparación Linux ↔ Windows (20/22)

- Linux (`Hojas/T2_ataques.csv`, C1, N=55): **53/55**, regla principal **`80792`**.
- Windows (C0=C1, N=54): **54/54**, regla principal **`67027`**.
- **20/22** parejas B2 (ATA091 y ATA102 sin pareja Linux).
- **Hallazgos**:
  - **2 FN Linux**: ATA013 (T1560.002) y ATA034 (T1560.003); sus parejas Windows
    **ATA093/ATA094** son **TP** (5/5). Diferencia de implementación/telemetría.
  - **`80792` vs `67027`**: ambos genéricos de proceso/comando; la detección es por
    **ancla de carpeta**, no por regla específica de técnica.
  - **ATA106** (T1056.004) `efecto_parcial` en Windows (DLL cargada, sin captura TLS);
    **ATA091** sin pareja y `efecto_parcial`.
  - **ATA073/ATA097 `92213`**: artefactos de compilación/script block; únicos TP a `N≥7`.
  - **`review`**: ATA071 y ATA078 (B1); no afectan al TPR.
- La comparación es **por técnica y efecto**, nunca por comando ni `#Alertas`.

## 4. Lectura honesta

- **Windows 54/54 a `N=0/3`** porque **`67027`** (proceso genérico) ve todos los comandos;
  a `N≥7`, **2/54** (solo los artefactos `92213`). La detección real de las técnicas a `N≥7`
  es **0/54**.
- **`67027` es el doble uso principal**: detecta **54/54** y genera **132** alertas de baseline.
  La regla que detecta es la que ensucia.
- **FIM como detección** da **35/54** a `N≥7` (solo `553` de borrado); es una **sensibilidad**,
  no la canónica: cuenta la huella del propio ataque.
- **`sin_67027`** demuestra que el TPR **no depende** de que `67027` esté en el catálogo,
  pero sí del ancla de proceso; el `#Alertas` sube a 1075.
- **FPR/TNR/GM/Precisión/F1/Usabilidad = n/a** hasta la ventana legítima **W3**.

## 5. Desviaciones y deudas declaradas

- **ATA104 poll**: el sondeo del runner S1 (`cmd /c if exist …`) se reclasificó a
  `artefacto_ataque` (`poll_runner_s1`); el bruto queda en `-Audited_raw.csv`; el TPR de caso
  no cambia.
- **ATA096 proxy**: no reenvía el body original (un solo `Read`); el efecto de manipulación es
  válido; mejora pendiente (`Content-Length` en bucle).
- **ATA101**: fix de montaje **posterior** al `t0`; las ventanas válidas usan el script
  intermedio `97a5c709…`; trazabilidad corregida.
- **ATA106**: DLL inyectada, hook TLS sin captura → **`efecto_parcial`**.
- **ATA091**: Inveigh sin hash (co-locado, sin tercer host/relay) → **`efecto_parcial`**.
- **ATA073/ATA097 `92213`**: artefactos de compilación; **no** keylogging/manipulación.
- **ATA105**: `creds.txt` con credencial **dummy** (`TFG-DUMMY-PASS`), no secreto real.
- **`boveda_version`** 2 (métrica) + 3 (Windows v3.1/v3); **Linux** 875/875 **semántico**;
  **`pytest`** 399 en `_artefactos/scripts/tests` (raíz falla por `atomic-red-team`/`pydantic`).
- **`M` pendiente (W3)**: sin FPR no se puede decir “detecta mucho y molesta poco”.

## 6. Siguiente

1. **W3** (ventana legítima Windows) + **M1b-W** (re-juicio del corpus N=54 con el catálogo de 72 h).
2. **Velociraptor** (`V0/V1`).
3. **A1/A2** (comparativa, gráficas y memoria).

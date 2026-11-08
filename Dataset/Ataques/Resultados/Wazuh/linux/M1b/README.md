# M1b — re-corte de las 128 ventanas de ataque (2026-11-08)

Tanda **M1b** del bloque `legitimo-analisis` (`plan.md` §6). **No se re-ejecutó ningún
ataque**: se re-clasificaron las alertas ya extraídas (`-Detalle.csv`) con el catálogo de
ruido **M1b** (15 reglas) y se comparó con los `-Audited.csv` originales (M1a).

## 1. Entradas (solo lectura)

| Entrada | Ruta | `sha256` |
|---|---|---|
| Catálogo M1b (15 reglas) | `Dataset/Legitimo/legitimo_72h/analisis/catalogo_M1b.csv` | `72afc1044231d6488caff7664bf157fa63678b906f8ea1e01e63e808a9cdacfc` |
| Catálogo 72 h puro (11 reglas, sensibilidad) | `Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv` | `8a72d849512c22808827313b601e62cc34ad92f0ac71a839b7245684918e2dba` |
| Ventanas originales | `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*-Audited.csv` (128) | sin cambios |
| Detalles de alerta | `Dataset/Ataques/Resultados/Wazuh/linux/CSV/*-Detalle.csv` (128) | según cabecera original |
| Señales esperadas / revisiones | `Dataset/Ataques/Comandos/...` y `.../Auditado/*-Revision.csv` | según cabecera original |

La procedencia de cada ventana (`alerta`, `esperado`, `revision`) se tomó de la **cabecera
del `-Audited.csv` original** y se verificó su `sha256` antes de re-ejecutar. **0 errores**
de integridad.

## 2. Comando

```powershell
python _artefactos/scripts/recortar_ataques_m1b.py `
  --auditado-origen Dataset/Ataques/Resultados/Wazuh/linux/Auditado `
  --catalogo Dataset/Legitimo/legitimo_72h/analisis/catalogo_M1b.csv `
  --catalogo-sensibilidad Dataset/Legitimo/legitimo_72h/analisis/catalogo_ruido_72h.csv `
  --out-dir Dataset/Ataques/Resultados/Wazuh/linux/M1b
```

El script invoca `filtrar_ruido.py` una vez por ventana con `--catalogo` M1b y las mismas
entradas (incluida `--revision` cuando existe). Los originales son **solo lectura**.

## 3. Resultado canónico M1b

| Métrica | Valor |
|---|---:|
| Ventanas re-ejecutadas | **128/128** |
| Filas de datos comparadas | **130.017** |
| Líneas de datos distintas vs original | **0** |
| Errores de integridad / ejecución | **0** |
| `-Revision.csv` generados (dudosas pendientes) | **0** |

- `diff.csv`: **0 filas** (cabecera `diferencias=0`).
- `resumen_recorte.csv`: 128 filas, `lineas_distintas=0` en todas.
- `MANIFEST_sha256.tsv`: `sha256` de los 128 `-Audited.csv` nuevos.
- Cadena agregada de los 128 `-Audited.csv` M1b: `8e7a962516dbf5dbf4621b18341896289f8eb3e6e4c71c5e16345b7bf7736c1a`.
- Cadena agregada de los 128 originales: `37090dfb34be476a026026688ab2ab3030ee34fd088950be32f8c6d57778f55a` (no modificada).

La única diferencia con el original es la **cabecera** (`catalogo=...` con el `sha256`
nuevo); el contenido de datos es idéntico. `filtrar_ruido.py` no añade
`boveda_version` a la cabecera del `-Audited.csv` (la versión de bóveda se declara en
las tablas T4/T5, que sí la llevan).

## 4. T2 canónica y comparación con M1a

```powershell
python _artefactos/scripts/tabla2_ataques.py `
  --auditado Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado `
  --out Hojas/T2_ataques.csv
python _artefactos/scripts/comparar_t2_m1b.py
```

| Comprobación | Valor |
|---|---:|
| Filas T2 | **550** (55 × 2 configs × 5 umbrales) |
| Filas idénticas a M1a (todas las columnas de datos) | **550/550** |
| Filas cambiadas | **0** |
| `C1×N0` / `C1×N3` | **TP=53 / FN=2** |
| `FN` | **ATA013, ATA034** |
| `C0×N0` / `C0×N3` | **TP=2 / FN=53** |
| Repeticiones canónicas | **9** (`_rev1`) |

Producto: `Hojas/T2_M1b_vs_M1a.csv` (550 filas, `cambiada=NO` en todas; columna
`columnas_distintas` vacía). El histórico M1a se conserva en
`Hojas/historico/T2_ataques_M1a.csv`.

## 5. Sensibilidad con el catálogo 72 h puro (NO canónica)

```powershell
python _artefactos/scripts/recortar_ataques_m1b.py --solo sensibilidad
python _artefactos/scripts/tabla2_ataques.py `
  --auditado Dataset/Ataques/Resultados/Wazuh/linux/M1b/sensibilidad_72h/Auditado `
  --out Hojas/T2_sensibilidad_catalogo72h.csv `
  --nota "NO CANONICA: catalogo 72 h puro (11 reglas); ...; no se usa en T4"
```

La cabecera del CSV incluye `nota=NO CANONICA: ...` para que el artefacto sea
autodescriptivo.

**Resultado real: `C1×N0 = 54/55` (FN = `ATA013`), no 55/55.** El plan esperaba 55/55;
la diferencia se debe al orden congelado de decisión de `filtrar_ruido.py`:

- **`ATA034` sí pasa a TP**: sus filas `5501/5502` de la ventana canónica (`iter1`) son
  `ruido_conocido/baseline`; al no estar en el catálogo 72 h pasan a `novel → deteccion`.
- **`ATA013` sigue FN**: sus filas `5501/5502` (y `5715`) son `dudosa/sin_campos` porque
  el `esperado` no declara ningún campo evaluable para ellas. El paso 3 (`dudosa`) se
  evalúa **antes** del paso 4 (`novel`), y la `-Revision.csv` firmada las pliega a
  `ruido`. Por tanto **no** se convierten en `deteccion`; no se ha re-etiquetado nada a mano.
- **Filas flipadas totales** (todas las ventanas, ambas iteraciones): **462** líneas de
  datos en 42 ficheros — `5502` 215, `5501` 204, `5402` 38, `5715` 5. No son solo 16: el
  catálogo 72 h puro no contiene `5402/5501/5502/5715`, así que muchas filas de otras
  ventanas también pasan a `deteccion`. En las **55 ventanas canónicas** el diff es de
  **109** líneas (`5502` 55, `5501` 46, `5715` 4, `5402` 4) en 13 casos; por eso
  `C1×N0` sube de 53/55 a **54/55** (solo recupera `ATA034`).
- **En ATA013/ATA034 (ambas iteraciones)** hay **16** filas `5501/5502`; de ellas solo
  **8** (las de `ATA034`) flipan. Las **8** de `ATA013` quedan en `dudosa → ruido` por la
  revisión firmada. Las **6** filas `5715` de esas dos ventanas siguen en ruido
  (`operador:5715` o `sin_campos`); las **5** filas `5715` que sí flipan están en
  `ATA002`, porque su `srcip` no es la del operador.

**Por qué se rechaza como medida:** el catálogo 72 h puro **no observó** sesiones del
operador (PAM/sudo/SSH) porque la ventana legítima no las tuvo (`V4`). Al no estar en el
catálogo, el método las trataría como `novel` y las contaría como detección; es un **falso
positivo de método**, no una detección del ataque. Además, el resultado real (54/55) sigue
sin recuperar `ATA013`, cuyo punto ciego es `python3`/`92600`, no PAM. Por eso la medida
canónica es M1b (72 h ∪ 4 reglas históricas del operador) y esta tanda se publica solo
como **sensibilidad declarada, no canónica**.

## 6. T4/T5 regenerados con M1b

```powershell
python _artefactos/scripts/tabla4_rendimiento.py `
  --t2 Hojas/T2_ataques.csv --t3 Hojas/T3_legitimo.csv `
  --auditado Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado `
  --out Hojas/T4_rendimiento.csv
python _artefactos/scripts/tabla5_pruning.py `
  --t2 Hojas/T2_ataques.csv --t3 Hojas/T3_legitimo.csv `
  --auditado Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado `
  --out Hojas/T5_pruning.csv --steps Hojas/T5_steps.csv
python _artefactos/scripts/cruzar_doble_uso.py `
  --auditado Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado `
  --out Hojas/T5_doble_uso.csv
```

| Tabla | ¿Cambia vs M1a? |
|---|---|
| `Hojas/T4_rendimiento.csv` | **No** (20 líneas de datos idénticas; solo cabecera con procedencia) |
| `Hojas/T5_pruning.csv` | **No** (61 líneas idénticas) |
| `Hojas/T5_steps.csv` | **No** (25 líneas idénticas) |
| `Hojas/T5_doble_uso.csv` | **No** (12 líneas idénticas) |

Valores GM (C1×N0): `No Pruning 0.369963`; `Pruning 500/1000 0.233395`;
`Conservative 0.378306`; `Generalized Conservative 0.190693`;
`Aggressive (G-Mean) 0.547509` (quita `554,591,80711,80730,80780,80781,80782,80790,80791`
y **conserva `80792`**).

T4 (C1×N0): TPR `0.963636`, FPR `0.857963`, TNR `0.142037`, Precisión `0.006764`,
F1 `0.013435`, GM `0.369963`, Usab `146.8323`, Usab`^c` `4746.0000`.

## 7. Trazabilidad de cabeceras

- `Hojas/T2_ataques.csv`: `auditado=Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado`.
- `Hojas/T4_rendimiento.csv`: `auditado=.../M1b/Auditado`, `t2=Hojas/T2_ataques.csv`,
  `t3=Hojas/T3_legitimo.csv`, `sha256_entradas=...`.
- `Hojas/T5_pruning.csv` y `Hojas/T5_steps.csv`: `auditado=.../M1b/Auditado`,
  `t2=Hojas/T2_ataques.csv`, `t3=Hojas/T3_legitimo.csv`, `sha256_entradas=...`.
- `Hojas/T5_doble_uso.csv`: `catalogo=...`, `indice=...`,
  `auditado=.../M1b/Auditado`, `t2=n/a` (se recalcula del `Auditado`).

## 8. Ficheros generados

```
M1b/
├── Auditado/*-Audited.csv              (128)
├── diff.csv                            (0 diferencias)
├── resumen_recorte.csv                 (128 filas, 0 distintas)
├── MANIFEST_sha256.tsv                 (128 huellas)
├── sensibilidad_72h/
│   ├── Auditado/*-Audited.csv          (128)
│   ├── diff.csv                        (462 diferencias declaradas)
│   ├── resumen_recorte.csv
│   └── MANIFEST_sha256.tsv
└── README.md
```

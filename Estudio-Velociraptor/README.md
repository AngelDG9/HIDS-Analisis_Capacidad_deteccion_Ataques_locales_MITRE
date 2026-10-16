# Estudio-Velociraptor/ — placeholder (se puebla en `V0`/`V1`)

> **Estado: PLACEHOLDER declarado.** R2 (`reencuadre-metrica`) deja la **estructura** y la
> **unidad común** de comparación, pero **no** los números de Velociraptor: la unidad de VR
> ("fila de artifact") y el mapeo de perfiles `P1..P4` **se fijan al desplegar VR**
> (`V0`/`V1`). Hasta entonces, este directorio queda **vacío** (nada de humo).

- **HIDS:** Velociraptor (artifacts públicos/nativos; "virgen" = sin artifacts propios).
- **Export previsto:** `TFG_HIDS_Velociraptor_linux.xlsx` (misma estructura que
  `Estudio-Wazuh/TFG_HIDS_Wazuh_linux.xlsx`, generado por `_artefactos/scripts/exportar_excel.py`).
- **Comparación VR↔Wazuh:** **unidad común** = acción de GHOSTS / hora (`FP/acción`, `FP/hora`)
  + comparación **por técnica** (`ATA<NNN>`); **nunca** por "evento" en crudo (los eventos de
  Wazuh ≠ las filas de artifact de VR). Ver `Soporte/Metrica/metrica_hids.md` §10.
- **Windows Wazuh** (`TFG_HIDS_Wazuh_windows.xlsx`): pendiente del bloque `B1`.

Referencia: `Soporte/Metrica/metrica_hids.md` (§10) y `Soporte/Metrica/boveda_congelacion.md` (B1, B4, B5).

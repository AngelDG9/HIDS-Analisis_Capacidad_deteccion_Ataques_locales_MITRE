# change-doc — Fase 1: Corpus MITRE (F-01)

> Cierre de fase. Fecha: **2026-09-19**. Estado: **CERRADA** (verificación PASA).
> Plan de referencia: `plan-fase1.md` (v3, `status: approved_by_human`).

---

## 1. Qué se ha hecho

Obtener, de forma **reproducible**, la lista de técnicas/subtécnicas de **MITRE ATT&CK
Enterprise v19.1** con telemetría endpoint (filtro inverso host) y **elegir el corpus**.

| Tarea | Resultado |
|---|---|
| **1.1 — T-01** Descarga STIX v19.1 | `enterprise-attack-19.1.json`, 53 277 393 B, `x_mitre_version=19.1` verificada |
| **1.2 — T-02** Script filtro inverso | `extraer_tecnicas_host.py` (cadena v19 DS→AN→DC + fallback) |
| **1.3 — T-02/tests** Tests | 15 tests en verde (unitarios con fixture + integración sobre STIX real) |
| **1.4 — T-03** CSV + lista + ajuste de esquema | `corpus_host.csv` (697 filas) + `lista_tecnicas_validas.md` |
| **1.5 — [HUMANO]** Selección del corpus | **13 técnicas** elegidas (7 Impact / 3 Exfiltration / 3 Collection) |
| **1.6** Materializar corpus | `Hojas/ATA_index.csv` (ATA001..ATA013, `pendiente`) |
| **1.7** Verificación | `tfg-tester` → **PASA** |

---

## 2. Entregables (ficheros)

| Fichero | Estado |
|---|---|
| `_artefactos/mitre/enterprise-attack-v19.1.json` | creado (**gitignored**) |
| `_artefactos/mitre/enterprise-attack-v19.1.sha256` | creado (URL + versión + fecha + hash) |
| `_artefactos/scripts/extraer_tecnicas_host.py` | creado |
| `_artefactos/scripts/tests/` (2 test + 1 fixture) | creado |
| `Hojas/corpus_host.csv` | creado (697 técnicas) |
| `Hojas/lista_tecnicas_validas.md` | creado (lista priorizada) |
| `Hojas/ATA_index.csv` | creado (13 técnicas) |
| `.gitignore` | modificado (`_artefactos/mitre/*.json` ignorado; `.sha256` no) |
| `plan-fase1.md` / `requirements.md` | actualizados (v3 / R-03) |

**sha256 STIX:** `bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3`
**URL:** `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json`

---

## 3. Resultados del corpus

- Técnicas/subtécnicas activas analizadas: **697** (161 deprecated/revoked excluidas).
- `host_eligible=YES`: **625** · `NO`: **72** (41 `solo_red`, 31 `sin_datacomponents`).
- Prioridad entre elegibles: **P1=89 · P2=459 · P3=77**.
- Reproducibilidad (R-02): CSV y MD **idénticos** al regenerar (hash byte a byte).

**Corpus elegido (13):** T1486, T1485, T1490, T1489, T1561, T1565, T1491, T1048, T1567,
T1041, T1074, T1119, T1560.

---

## 4. Decisiones humanas (2026-09-19)

1. **Interpretación amplia** del filtro inverso: un DC de red (pura o descartada) no otorga
   elegibilidad pero **no anula** una técnica con telemetría host. Fundamento: T1039 (DET0410).
2. **T1046 se ratifica como híbrida** (`host_eligible=YES`): su detección incluye
   `DC0032 Process Creation` además de DC de red. Caso "red pura" cubierto por T1595.
3. **STIX gitignored** (repo ligero) + `sha256` versionado.
4. **`Hojas/Mapeos.xlsx` diferido** a Fase 3/5.
5. **Corpus = 13 técnicas** con dos ajustes sobre la recomendación automática:
   **T1041** entra por T1052 (USB: difícil en VM) y **T1560** por T1114 (correo: difícil).

---

## 5. Verificación (tfg-tester)

Veredicto **PASA**. Comprobado: coherencia `ATA_index.csv` ↔ `corpus_host.csv`, IDs
correlativos, táctica correcta, `pytest` en verde (15/15), reproducibilidad, integridad del
STIX (sha256), `.gitignore` correcto, `_recursos/` intacto, sin commits.

---

## 6. Deudas y siguientes pasos

- **Deuda de diseño (menor):** el corpus se concentra en 3 tácticas (foco R/E/S); el profesor
  pidió "1 técnica por táctica" en ciclos. **Se le plantea en el hito H1** como ciclo siguiente.
- **Hito H1** para el tutor: lista de técnicas + criterio del filtro inverso + esta selección.
- **Commit local** de la Fase 1 (el `push` lo hace el humano).
- **Fase 2 — Laboratorio Wazuh** (arranca con el humano: topología + importar VMs).

---

## 7. Riesgos abiertos

| Riesgo | Nota |
|---|---|
| Comentario `#` antes de la cabecera de los CSV | Aceptable; parsers deben saltar líneas `#`. |
| Algunas técnicas del corpus son farragosas de montar | T1052/T1114 ya sustituidas; el resto es Linux-friendly. |
| Modelo de datos ATT&CK v19 | Parser adaptado y documentado; tests de integración contra el STIX real. |

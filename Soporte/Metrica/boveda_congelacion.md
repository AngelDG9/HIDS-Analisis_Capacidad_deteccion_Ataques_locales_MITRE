---
bloque: reencuadre-metrica
nombre: Bóveda de congelación (lo que se sella antes de medir)
version: 2
status: congelada
fecha: 2026-10-16
fecha_actualizacion: 2026-11-05
actualizado_por: cierre legitimo-v3 (B10 medido)
autor: tfg-executor
sha256: boveda_congelacion.sha256
depende_de: Soporte/Metrica/metrica_hids.md (v1)
---

# Bóveda de congelación — versión 2

> **Qué es esta bóveda.** El conjunto de elementos que se **sellan antes de la primera medida**.
> Si **cualquiera** de B1–B10 cambia ⇒ la **métrica/medida queda invalidada**
> (`metrica_hids.md` §9) y hay que **recalcular y declarar**. Las huellas están en
> `boveda_congelacion.sha256`. Los `sha256` citados abajo son de la fecha de congelación
> (B1–B9: 2026-10-16; **B10: 2026-11-05**, al cerrar `legitimo-v3`).

## B1 — Versión del HIDS

- **Wazuh `4.14.7-1`** (manager/indexer/dashboard + agente 001 `victima-linux`).
  Fuente: `Soporte/Wazuh/Configuracion/version_wazuh.txt`
  `sha256 = 0b8b0c063a1769cdb4973c48191eafed4a65bbe2b689b394a2f90bc5d82c4994`.
- **Velociraptor:** se fija al desplegar (`V0`) — **placeholder declarado** (aún no instalado).

## B2 — Ruleset por defecto

- Fuente: `Soporte/Wazuh/Configuracion/active_ruleset.txt`
  `sha256 = 64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b`.
- Conteo por fichero de origen: **RS1 4.471 · RS2 44 · RS3 0 · RS4 0**.
- `RS3 = RS4 = 0` en virgen ⇒ los bloques `C2`/`C3` nacen **vacíos** (caso L8).

## B3 — Telemetría

- **auditd** (separadores, clave `audit-wazuh-c`): `Soporte/Wazuh/Reglas/auditd_tfg.rules`
  `sha256 = 8c033b0508b0668ac4b74a9d2e3ababd6a47d0f8fe41196b259dc0606064cbb5` +
  despliegue `Soporte/Wazuh/Scripts/deploy_rs2_auditd.sh`
  `sha256 = f53cf1ebb6be229bc09d0c9dbcd997db418daa51b28d5240d50d933008fc6005` +
  parche `Soporte/Wazuh/Scripts/patch_agent_audit.py`
  `sha256 = 2e9ded4e3313c92586e3f32d54220b5c64c761eae58e6f2e4a83e61e0f46ea32`.
- **Sysmon v15.22** (config SwiftOnSecurity): **material externo** (no versionado en el repo);
  declarado en `Soporte/Laboratorio/*`; se cita en la memoria.
- **Canales Windows** (Security + Sysmon + PowerShell 4104), FIM: declarados en
  `Soporte/Laboratorio/telemetria_windows.md`.

## B4 — Imágenes / snapshots

- Nombres e identidad (VMware): **`lab-listo`** (víctima-linux), **`base-limpia`**,
  **`lab-listo-windows`**, **`lab-listo-windows-baseline`**. Sin fichero (config del hipervisor);
  se citan por nombre. Decisión: la medida se hace **siempre** revirtiendo a `lab-listo`.

## B5 — Umbrales

- **Wazuh:** `N ∈ {0, 3, 7, 10, 12}` (`metrica_hids.UMBRALES`).
- **Velociraptor:** perfiles `P1..P4` (se fijan en `V0`; **placeholder**).

## B6 — Definición de "virgen"

> **"Virgen" = ruleset de detección de fábrica, sin reglas propias ni de terceros; la telemetría
> estándar SÍ se activa.** Para **Wazuh** = `RS1 + RS2` (`C1`), con **RS3 = RS4 = 0**. Para
> **Velociraptor** = **artifacts públicos/nativos**, sin artifacts propios. **auditd/Sysmon son
> FUENTE de telemetría, no "reglas"** ⇒ **sí** se activan en virgen.

## B7 — Constantes de la métrica congelada de Fase 3

- `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` (v7)
  `sha256 = c2abdcdc358ae87dda7c1daec205d38ab0e76f962127df445b58208c5851d33a`.
- `_artefactos/scripts/filtrar_ruido.py`
  `sha256 = 9cbaf51a7b289f8f2ae3a60a3de5aae964df0c44094ca76764f40478fa5cead6`.
- Constantes reutilizadas sin alterar: `ATTACK_ROOT`, `OPERADOR_SRCIPS`, `CATEGORIAS`, `OUT_HEADER`.

## B8 — Versión de la métrica

- `Soporte/Metrica/metrica_hids.md` **v1**
  `sha256 = 80216fc7c681c6ca4f0181116f12168d439455a9206cb2d2d9f544bc88a38bfd`.
- Módulo: `_artefactos/scripts/metrica_hids.py` (`VERSION_METRICA = 1`).

## B9 — Corpus congelado

- `Hojas/ATA_index.csv`
  `sha256 = 89993656845aacaf995b231c6fe19a948c74d4680aad9d24f19eff21459cc445`.
- `Hojas/repeticiones.csv`
  `sha256 = 9e4c17b1c47c3089cc81427bff69d8684659dcb32561de2fe741283d362d4ea7`.
- Extractores (solo lectura): `_artefactos/scripts/extraer_alertas.py`
  `sha256 = 4019fda84a59f4079529f7f95cc6fe9d250b46fb447b235b3c9a90ba64569c44`,
  `Soporte/Ataques/criterio_doble_iteracion.md`
  `sha256 = 292aa5ea2a17415ae271c86120093e5e72889cd086cb852113b057adf4f28dbc`.
- **Cadena de huellas de los 55 `-Audited.csv` canónicos (ventana canónica §8):**
  `cadena_auditado_sha256 = 43ebba30cbfdca0a64130d857791289766939adf425b7ef63dfe7813bbc5ac01`
  (55 ficheros; re-derivable con `tabla2_ataques.py`).

## B10 — Config del legítimo

> **Sellado el 2026-11-05** (cierre de `legitimo-v3`) con los valores **medidos** de la ventana
> `2026-11-02T00:00:00Z .. 2026-11-05T00:00:00Z`. Detalle completo y huellas:
> `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` (**v3**) y
> `Soporte/Laboratorio/legitimo_72h/sha256sums.txt`.

- **Ventana:** **2026-11-02T00:00:00Z → 2026-11-05T00:00:00Z** (72 h, 3 días, medianoche UTC).
  `t0`/`t1` firmados; `logall_json` **ON solo** en `[t0,t1]`; `off` + `CONFIG_IDENTICA` al cerrar.
- **GHOSTS:** `cmu-sei/GHOSTS` **v8.3.1** (commit `4d2e160860f508f699f935472b5515358f534844`),
  .NET 8, PostgreSQL 16.15. Cliente Linux en `/home/angel/ghosts-client` con **`cwd=/home/angel`**;
  binario `ghosts.client.linux`
  `sha256 = 3e1a73a49f7e95fc52864a4c52e89e5af38a0644791bee2115a7ac96b742c659`.
- **Wazuh:** **`4.14.7-1`**, config **virgen `C1 = {RS1, RS2}`** (`RS3 = RS4 = 0`); ruleset
  `sha256 = 64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b`.
- **Receta v2 ejecutada:** `d1` **163** / `d2` **178** / `d3` **163** acciones
  (`sha256 0b2fa91c…c7df` / `0e0329cc…c58a` / `885a80b2…1345`) + `calendario.json`
  (`14463efd…26a7`) + `bloques.env` (`ee43ff46…64fd`, **B6 17:05–17:50**).
- **Campaña de FP:** **11 casos no mutantes**, pre-registrados (`casos.md`
  `sha256 = 2003c9cc71624c40ca8a70931027b552bed15a17b9cc0044720c5801c99f2a49`), **dentro** de la
  ventana; **11/11 `SI`**, **0 alertas `N ≥ 7`**.
- **Instrumentación `M`:** `<logall_json>yes</logall_json>` ⇒ `archives.json`; rotación diaria
  `ossec-archive-<DD>.json.gz`; copia con `MANIFEST` + dedupe `sha256`; contador `--estricto`
  (**`exit 0`**, sin solapes). **Un solo `M` sobre `[t0,t1]`**.
- **Medida:** **`M` endpoint (001) = 342 966** eventos (total con manager: 394 739; **el manager
  se excluye** del denominador). Cobertura `2026-11-02T00:00:04Z .. 2026-11-04T23:59:56Z`.
  **43 567 376 B** (41,55 MiB) en 3 `.gz` → **0,61 MB/h**; **4 763,4 eventos/h**;
  **acciones/día 163 / 178 / 163**; **294 253 alertas** y **11 `rule_id`**.
- **Lo que actuó dentro:** **0 recuperaciones**, **2 rotaciones** (`2026-11-03T07:45:27Z` y
  `2026-11-04T07:45:08Z`, `resultado=ok`), **3 arranques** del cliente; **144** chequeos de
  vigilancia (**140 OK + 4 AVISO** de `sin_df` en la rotación de medianoche, **0 `ALARMA`**).
- **Snapshot:** **`lab-listo-legit-v3`** (6 en total; `lab-listo-legit-v2` intacto).
- **Navegador:** **`receptor_navegador = none`**.
- **Versiones de medida:** **`metrica_version = 1`**, **`boveda_version = 2`**.
- **Incidencia declarada (V6):** orden de extracción invertido (`off` antes de cerrar la copia);
  **fuente diaria íntegra** y `M` **re-extraído idéntico** (`exit 0`) ⇒ ventana **VÁLIDA CON
  INCIDENCIA**.
- **Límites declarados:** 4 `AVISO` de rotación; `rule 11` = **UNKNOWN** (1 alerta `stats`);
  `ghosts_acciones.csv` con granularidad **horaria**; `n_acciones` vacío en `campana_fp.csv`;
  swap ~1,9 GB en la víctima; sin navegador. La campaña está **dentro** de `M` (tabla aparte, sin
  FPR alternativo).

---

## Regla

> Si **cualquiera** de B1–B10 cambia ⇒ **métrica/medida invalidada** (`metrica_hids.md` §9) y
> hay que **recalcular** con `metrica_version`/`boveda_version` nuevos y **declararlo**.

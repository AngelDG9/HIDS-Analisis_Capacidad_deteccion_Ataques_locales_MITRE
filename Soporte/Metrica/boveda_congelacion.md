---
bloque: reencuadre-metrica
nombre: Bóveda de congelación (lo que se sella antes de medir)
version: 1
status: congelada
fecha: 2026-10-16
autor: tfg-executor
sha256: boveda_congelacion.sha256
depende_de: Soporte/Metrica/metrica_hids.md (v1)
---

# Bóveda de congelación — versión 1

> **Qué es esta bóveda.** El conjunto de elementos que se **sellan antes de la primera medida**.
> Si **cualquiera** de B1–B10 cambia ⇒ la **métrica/medida queda invalidada**
> (`metrica_hids.md` §9) y hay que **recalcular y declarar**. Las huellas están en
> `boveda_congelacion.sha256`. Los `sha256` citados abajo son de la fecha de congelación.

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

- **GHOSTS** (versión) + **"internet local"** + **fichero de instrumentación del denominador**
  (`<logall_json>` ⇒ `archives.json`). **Estado: pendiente** — se sella al construir el legítimo
  (`L0`/`L1`). Hoy **no existe**; declarado (caso L11 y `metrica_hids.md` §13).

---

## Regla

> Si **cualquiera** de B1–B10 cambia ⇒ **métrica/medida invalidada** (`metrica_hids.md` §9) y
> hay que **recalcular** con `metrica_version`/`boveda_version` nuevos y **declararlo**.

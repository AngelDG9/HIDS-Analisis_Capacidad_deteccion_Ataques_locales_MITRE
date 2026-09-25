# Atomic Red Team — el «cajón de los ataques» (Fase 3, bloque `fase-03-atomic`)

> Documento del bloque **`fase-03-atomic` (A2.3 · R-12 / R-13)**. Redactado el **2026-09-25**.
> **Este bloque NO ejecuta ataques**: deja Atomic Red Team **descargado, fijado, documentado y
> consultable**. La primera ejecución real será el **piloto (T-09/T-10)**.

## 1. Qué es Atomic Red Team (ART)

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) es la biblioteca de **pruebas
atómicas** de Red Canary: cada *atomic test* es un procedimiento **pequeño, reproducible y de
código abierto** que ejecuta **una técnica/subtécnica concreta de MITRE ATT&CK**. Se usa en el TFG
como **catálogo de ataques** para las 13 técnicas del corpus (`Hojas/ATA_index.csv`).

- **Licencia: MIT.** El clon **no se redistribuye** (no se versiona), solo se fija su commit.
- Estructura relevante: `atomics/T<ID>/T<ID>.yaml` (definición de la prueba) y
  `atomics/Indexes/Indexes-CSV/*.csv` (índices planos por plataforma).

## 2. Dónde vive y por qué (⚠️ el revert borra la víctima)

**El cajón vive en el SOBREMESA / repo:** `Soporte/Ataques/atomic-red-team/` (ruta que exige R-12).

- **La víctima revierte a `lab-listo` antes de cada ataque** (`Soporte/Laboratorio/vmrun_config.md`
  §4): todo lo que se copie dentro de la víctima **desaparece** en el revert. Por eso el material
  **no** vive en la víctima.
- **No se «hornea» en un snapshot nuevo:** mantener `lab-listo` **prístino** (es la imagen limpia
  sobre la que se grabó el baseline de Fase 2).
- **No vive en el manager:** `wazuh-server` es el **detector**, no el sitio de los payloads.
- **Consecuencia:** el cajón **sobrevive a todos los reverts** y en ataque **no se necesita
  internet** (ver §5).

## 3. Reproducción (receta + commit)

El clon **NO se versiona** (miles de ficheros, ~0,6 GB en GitHub); se versiona el **sidecar**
`Soporte/Ataques/atomic-red-team.version` (url + commit + fecha + licencia). En `.gitignore`:

```text
Soporte/Ataques/atomic-red-team/
```

Para **reproducir exactamente** la versión usada:

```bash
git clone https://github.com/redcanaryco/atomic-red-team.git Soporte/Ataques/atomic-red-team
cd Soporte/Ataques/atomic-red-team
git checkout 388942adbd9641f4dfdcf079d7efe9a75ec0ac43
```

| Dato | Valor |
|---|---|
| URL | `https://github.com/redcanaryco/atomic-red-team.git` |
| **Commit fijado** | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Fecha del commit | `2026-09-05 12:26:57 -0400` |
| Rama / estado al clonar | `master`, árbol limpio |
| Clonado el | `2026-09-25` |
| Nº de directorios `atomics/T*` | **344** |
| Licencia | **MIT** |

> **Regla:** el sidecar registra **exactamente** lo que se clona. Si master avanza y se re-clona,
> se actualiza el commit (y **se regenera el mapa de cobertura**, §6).

## 4. Cómo se usa en ataque: copia **al vuelo** por técnica

En el ataque **solo se copian los ficheros de la técnica necesaria** del sobremesa a la víctima por
`scp` sobre `VMnet1` (`192.168.65.0/24`), a un directorio de trabajo efímero
(`/home/angel/lab-attack/`):

```powershell
# En el SOBREMESA (host). La víctima se revierte a `lab-listo` ANTES de copiar/atacar.
scp -i "C:\Users\angel\.ssh\id_ed25519_tfg_lab" -r `
  "Soporte\Ataques\atomic-red-team\atomics\T1486" `
  angel@192.168.65.129:/home/angel/lab-attack/
```

- La **copia es efímera**: el revert de la víctima la elimina y no contamina el baseline.
- **Aislamiento por técnica:** se copia `atomics/T<ID>/` (y sus subtecnicas si el ataque las usa),
  nunca el clon completo.
- **Sin internet en la víctima:** todo el material ya está en el host.

## 5. NAT: **OFF** (y contingencia de dependencias para T-09)

**El NAT (`ethernet1` = VMnet8) permanece DESCONECTADO** en ambas VMs
(`ethernet1.startConnected = "FALSE"`). La descarga de ART se hace **en el host** (que sí tiene
internet), así que el NAT de las VMs **no interviene**. Verificado el 2026-09-25 (solo lectura de
los `.vmx`): `FALSE` en `victima-linux` y en `wazuh-server`.

**Contingencia (solo si una atómica necesita dependencias en la víctima).** Se resolverá en **T-09**,
nunca durante una captura. Receta (`vmrun_config.md` §5):

1. Con la **VM apagada**, editar el `.vmx`: `ethernet1.startConnected = "TRUE"`.
2. Arrancar, instalar la dependencia (`apt-get install -y …`), verificar.
3. Apagar la VM y **volver a poner `"FALSE"`** (regla de oro: **NAT OFF** en todo ataque).
4. **Punto abierto para T-09:** como la víctima revierte a `lab-listo` antes de cada ataque, hay que
   decidir si las dependencias se instalan **después de cada revert** (por ataque) o si se admite
   una actualización controlada del snapshot. **No se decide aquí.**

> Ejemplo (T1486): la prueba #1 usa `gpg` (normalmente **ya presente** en Ubuntu 24.04). Las de
> `ccrypt`/`7z` podrían necesitar `apt`; se tratarían por esta vía en T-09.

## 6. Mapa de cobertura (`Hojas/cobertura_atomic.csv`)

Generado **desde el clon real** (no del borrador) por
`_artefactos/scripts/cobertura_atomic.py` (solo stdlib, determinista, offline). Cruza el corpus con
`atomics/Indexes/Indexes-CSV/{index,linux-index,windows-index}.csv`; los recuentos **incluyen
subtecnicas** (`T<ID>.<n>`).

| ATA | Técnica | Nombre | ART | Linux | Win | Ruta | Nota (Linux) |
|---|---|---|---:|---:|---:|---|---|
| ATA001 | T1486 | Data Encrypted for Impact | sí | 4 | 4 | `atomics/T1486` | cubierta |
| ATA002 | T1485 | Data Destruction | sí | 1 | 3 | `atomics/T1485` | cubierta |
| ATA003 | T1490 | Inhibit System Recovery | sí | 0 | 12 | `atomics/T1490` | solo_windows |
| ATA004 | T1489 | Service Stop | sí | 5 | 4 | `atomics/T1489` | cubierta |
| ATA005 | T1561 | Disk Wipe | no | 0 | 0 | — | sin_pruebas |
| ATA006 | T1565 | Data Manipulation | no | 0 | 0 | — | sin_pruebas |
| ATA007 | T1491 | Defacement | sí | 0 | 4 | `atomics/T1491.001` | solo_windows |
| ATA008 | T1048 | Exfiltration Over Alternative Protocol | sí | 9 | 7 | `atomics/T1048;…002;…003` | cubierta |
| ATA009 | T1567 | Exfiltration Over Web Service | sí | 3 | 4 | `atomics/T1567.002;…003;…004` | cubierta |
| ATA010 | T1041 | Exfiltration Over C2 Channel | sí | 0 | 2 | `atomics/T1041` | solo_windows |
| ATA011 | T1074 | Data Staged | sí | 1 | 2 | `atomics/T1074.001` | cubierta |
| ATA012 | T1119 | Automated Collection | sí | 0 | 4 | `atomics/T1119` | solo_windows |
| ATA013 | T1560 | Archive Collected Data | sí | 9 | 8 | `atomics/T1560;…001;…002` | cubierta |

**Resumen (insumo directo para T-09):** **cubiertas en Linux 7/13** · **solo Windows 4/13**
(T1490, T1491, T1041, T1119 → en Linux requieren **script custom**) · **sin pruebas en ART 2/13**
(T1561, T1565 → **custom obligatorio**). **6/13 requieren custom** en Linux (o replantear víctima
Windows, decisión **pendiente de tutoría**).

> **El mapa real coincide con el borrador del plan §4** (mismos recuentos y veredictos): 7/13 en
> Linux. Única matiz: el `path` de T1567 incluye además `T1567.003` (subtecnica que solo tiene
> pruebas de Windows); no altera los recuentos ni el veredicto.

Regenerar:

```bash
python _artefactos/scripts/cobertura_atomic.py
```

## 7. Preparación EN SECO de una técnica (T1486) — **sin ejecutarla**

**Ubicación del artefacto:** `Soporte/Ataques/atomic-red-team/atomics/T1486/` → contiene **solo**
`T1486.yaml` (definición) y `T1486.md` (documentación). **No hay payloads externos** (no existe
`src/` ni `files/` en el directorio).

**Qué se copiaría a la víctima:** el directorio completo `atomics/T1486/` (2 ficheros), por `scp`
sobre `VMnet1` (§4). No se copia nada más.

**Qué se ejecutaría** (prueba Linux #1 «Encrypt files using gpg», GUID
`7b8ce084-3922-4618-8d22-95f996173765`, `elevation_required: false`):

```bash
# 0) Dependencia (prereq): comprobar gpg
which gpg
#    -> si falla: apt-get install -y gpg   (ver §5, NAT OFF: NO se hace aquí)

# 1) Executor (sh) con los argumentos por defecto del YAML:
echo "passwd" | $(which gpg) --batch --yes --passphrase-fd 0 \
  --cipher-algo AES-256 -o /tmp/passwd.gpg -c /etc/passwd

# 2) Cleanup:
rm /tmp/passwd.gpg
```

Los otros 3 tests Linux del YAML son `7z`, `ccrypt` y `openssl` (mismo patrón: dependencia +
comando + cleanup). **Ninguno se ha ejecutado en este bloque** (ver §8).

## 8. Cómo se prueba que funciona (sin ejecutar ataques)

El DoD del bloque es «descargado + documentado + usable». Se demuestra con **integridad + consulta +
preparación en seco, offline**:

1. **Integridad/fijado:** el clon existe y `git rev-parse HEAD` == commit del sidecar (CA1).
2. **Consulta:** `cobertura_atomic.py` genera el mapa (CA3) de forma determinista (CA4).
3. **Preparación en seco:** T1486 localizada y comando listado (§7), **sin lanzarlo**.
4. **Offline:** todo funciona con **NAT desconectado** (CA5).
5. **CA6:** **no** se ejecutó ninguna atómica (no hay payloads ni procesos fuera del cajón).

## 9. Referencias

- Plan del bloque: `plan.md` (raíz), `status: approved_by_human`.
- Snapshot y `vmrun`: `Soporte/Laboratorio/vmrun_config.md`.
- Corpus de técnicas: `Hojas/ATA_index.csv` · mapa: `Hojas/cobertura_atomic.csv`.
- Herramienta: `_artefactos/scripts/cobertura_atomic.py` (+ tests offline).

---
fase: 3
bloque: fase-03-ampliacion-2
tanda: C
ata_id: ATA039
tecnica: T1039
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA039 · T1039 Data from Network Shared Drive (recurso compartido local) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda C**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA039** |
| Técnica | **T1039 — Data from Network Shared Drive** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** del cliente (`rsync`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`rsync`** 3.2.7 en modo daemon (`rsync://192.168.65.128:9873/share/`) |
| Efecto | **recolección** del recurso compartido remoto a `lab-attack/ATA039/share_copy/` |
| Elevación | **no** |
| Guardarraíl | el recurso **DEBE** ser `192.168.65.128:9873`; destino bajo `lab-attack/ATA039` |

Artefacto: `.../T1039-Data_from_Network_Shared_Drive/ATA039_ataque.sh`
(`sha256=4b8724645a38d5b6e51c58ec7ec824dbf2971115bd5596033b52fd9185e6c8c5`).
Señales: `.../ATA039_esperado.csv` (`sha256=9a0421f602585efab2f56470233de217e3db31f794e3d1c75ba01253ad8a8261`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA039_logtest.txt` (`sha256=52fc71ff52517822a3c40eb95ca3a41076a71d287e3361bd1738368048ed86d6`)
→ `ATA039_preflight.md` (`sha256=7ccfc01deac6bb98ce13322bbc16b5986f4e5f19b90b4d7e65a5d9a6383bc9b9`) **PASA**
(1 evento `rsync` → `80792` level 3; sin silenciador).

## 3. ⚠️ Qué se montó para el «recurso compartido» (paso 0)

**No hay cliente NFS/SMB offline** (`mount.nfs`/`mount.cifs`/`sshfs` **no existen** en la víctima y no
se instalan sin NAT) ⇒ **no se montó ningún sistema de ficheros**. La opción local más simple es el
**daemon `rsync` del manager**: directorio **`/home/angel/lab-share/export/`** exportado como módulo
**`share`** (solo lectura) en `rsync://192.168.65.128:9873/share/` (VMnet1, sin autenticación).
«Montar» = arrancar el daemon antes de `t0`; «desmontar» = pararlo y borrar `~/lab-share` al cerrar
la tanda (ver §10). **Nada de NAT/internet.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | snapshot |
|---|---|---|---|---|
| 1 | `2026-09-29T11:42:42Z` | `2026-09-29T11:43:15Z` | 33 s | `lab-listo` |
| 2 | `2026-09-29T11:46:41Z` | `2026-09-29T11:47:13Z` | 32 s | `lab-listo` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA039
bash ATA039_ataque.sh    # rsync --list-only + rsync -a rsync://192.168.65.128:9873/share/ share_copy/
```

## 6. Evidencia

`Logs/ATA039_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `recurso_remoto.txt`.

**Prueba de éxito — los datos se leyeron del recurso compartido** (sha256 local == sha256 remoto del
manager, `recurso_remoto.txt`):

| Fichero | sha256 (coincide) |
|---|---|
| `finanzas/ventas_2026.csv` | `2ad637b8797a4c6e22a5da27f698f31c9da4088367df78a795414d1a6721d9e6` |
| `rrhh/nominas_2026.csv` | `b5c25b1a11f3e25998ed228122476a0352b894f14221cc9a94257705601a810d` |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 949 | 942 | 943 |
| 2 | 1113 | 1106 | 1107 |

> (`_raw` incluye los 7 agentes ajenos/iter, descartados por el filtro a `agent_name == victima-linux`.)

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 943 | **3** | 613 | 306 | **0** | 21 | 10 | 933 | 0 | 0 |
| 2 | 1107 | **3** | 623 | 460 | **0** | 21 | 1 | 1106 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas | primera evidencia |
|---|---|---|---|---|---|
| 1 | 3 | 1 · `{80792}` | **S1** | 0 | `11:42:44.137Z` `Audit: Command: /usr/bin/rsync` |
| 2 | 3 | 1 · `{80792}` | **S1** | 0 | `11:46:43.541Z` `Audit: Command: /usr/bin/rsync` |

- **`80792`** `Audit: Command: /usr/bin/rsync` (señal `S1`, anclado al `cwd`) — el cliente `rsync`
  (listado + recolección). 3 execve/iter.
- **`dudosa` resueltas:** iter1 **9** (2 `80791` *Deleted* `audit_exe=rsync` → **`artefacto`**;
  7 PAM `5501`/`5502` del login del operador → **`ruido`**); iter2 **3** (2 `80791` → `artefacto` +
  1 `5502` → `ruido`). **Ninguna** fila del ataque en `ruido`.
- **`artefacto_ataque`** (21/21): procesos internos del guion (`bash`, `hostname`, `date`, `rm`,
  `mkdir`, `find`, `sha256sum`, `xargs`, `sort`…) anclados a la carpeta del ataque. **`AVISO`** de
  execve no declarado (transparencia) — son helpers, no la señal de la técnica.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `11:42:44.137Z` `Audit: Command: /usr/bin/rsync` | **1/1** (`S1`) | 3 / 21 / 306 | 3 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `11:46:43.541Z` `Audit: Command: /usr/bin/rsync` | **1/1** (`S1`) | 3 / 21 / 460 | 3 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|3−3|=0 ≤ 2`. **C3′:** ✅ sin dudosas (9 + 3 resueltas).
  Ver `Bitacora/ATA039.json`.

## 10. Limitaciones y hallazgos

1. **⚠️ Sin cliente NFS/SMB offline:** el «recurso compartido» es un **daemon `rsync`** del manager
   (declarado en §3); no se monta FS. El HIDS de host **no ve la red** → la detección es el **proceso
   cliente** (`rsync`), y la prueba real es el **sha256 coincidente**.
2. **`rsync` en modo daemon** ejecuta **sin `ssh`** (un único binario cliente) → detectado limpio por
   `80792` anclado.
3. **Recolección = lectura** (leer no deja rastro en `-p wa`): la señal es el `execve` del lector.
4. **Cierre:** daemon `rsync` parado y `~/lab-share` **borrado** (verificado) al cerrar la tanda.

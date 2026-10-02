---
fase: 3
bloque: fase-03-p1-cierre
tanda: B
ata_id: ATA049
tecnica: T1567.002
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA049 · T1567.002 Exfiltration to Cloud Storage (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda B**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA049** |
| Técnica | **T1567.002 — Exfiltration to Cloud Storage** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **ART adaptado** |
| Capa del HIDS | **`execve` (`rclone`, `80792`)** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `fuente_norm` / `motivo_codigo` | `ART_adaptado` / `na_art_usado` |
| Motivo | se usó ART adaptado |
| ART (guid, plataforma) | `a4b74723-5cee-4300-91c3-5e34166909b4` (Linux) |
| Material externo | **sí** (rclone v1.75.1 linux-amd64 (URL+sha256, pre-steado); receptor sink_webdav.py del repo) |
| Ataque | `T1567.002-Exfiltration_To_Cloud_Storage/ATA049_ataque.sh` (`sha256=0b0096d884f2ecc93aa2601a0789f5fb5ddc2b35c1baf073f9cedf697e1ae038`) |
| Señales | `T1567.002-Exfiltration_To_Cloud_Storage/ATA049_esperado.csv` (`sha256=b27406fd5278343eed708e60e94b9cd05dc99a46db2d1894d2e19a3173680d86`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA049_logtest.txt` (`694b6aff1b600fa446cd9432046f59187d5c20b32389ea33094fefa3174f2491`) → `ATA049_preflight.md` **PASA (sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | artefacto | ruido | auto_ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T01:37:35Z` | `2026-10-02T01:38:07Z` | 763 | 1 | 11 | 117 | 634 | `0b0096d8…` |
| 2 | `2026-10-02T01:46:43Z` | `2026-10-02T01:47:15Z` | 768 | 1 | 12 | 116 | 639 | `0b0096d8…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA049
bash ATA049_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** rclone subio 3/3 ficheros (199 B); sink.log PUT con sha256 identico: clientes bc8bf1dc…, nominas 3a2ec5e2…, notas 04c33e33…; 0 rclone residuales
- **Iter 2:** idem iter1 (3/3 ficheros, sha256 identicos); bucket limpiado por iteracion para forzar la subida
- Evidencia en `Logs/ATA049_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `sink.log`).

## 7. Ventana extraída

| Iter | detalle | deteccion |
|---|---|---|
| 1 | 763 | 1 |
| 2 | 768 | 1 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 763 | **1** | 634 | 117 | **0** | 11 |
| 2 | 768 | **1** | 639 | 116 | **0** | 12 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 | 0 |
| 2 | 1 | 1 · `{80792}` | 1 | 0 |

- Iter 1: 1x audit_exe=/home/angel/lab-attack/ATA049/rclone (execve 80792, cwd del ataque).
- Iter 2: 1x audit_exe=/home/angel/lab-attack/ATA049/rclone (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T01:37:36.782Z` (execve anclado) | **1/1 (S1)** |
| 2 | **sí** | `{80792}` | `2026-10-02T01:46:44.976Z` (execve anclado) | **1/1 (S1)** |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; conjuntos de `rule_id` idénticos; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS de host NO ve la red; la deteccion es el execve de rclone anclado al cwd; la prueba es el sha256 del sink WebDAV.
2. El binario rclone se ejecuta desde la carpeta del ataque (cwd=/home/angel/lab-attack/ATA049), por lo que la senal ancla; el binario es externo (pre-steado) y no se versiona.
3. C0 sin silenciador. Endpoint WebDAV local, sin claves reales.
4. La atómica Linux a4b74723 usa rclone+terraform->AWS S3 real con claves; se conserva rclone y se sustituye el destino por un WebDAV LOCAL del HOST; se retira terraform.
5. Sustituto declarado: AWS S3/Mega reales -> WebDAV local del laboratorio (192.168.65.1:9090, sink_webdav.py).
6. Realismo acotado declarado (README).


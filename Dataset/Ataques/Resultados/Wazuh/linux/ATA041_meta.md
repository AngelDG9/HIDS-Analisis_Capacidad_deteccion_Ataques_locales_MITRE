---
fase: 3
bloque: fase-03-ampliacion-2
tanda: C
ata_id: ATA041
tecnica: T1048.002
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA041 · T1048.002 Asymmetric Encrypted Non-C2 (`openssl` RSA + HTTP) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda C**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos**
> (claves **efímeras de juguete**). Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica O1+O2.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA041** |
| Técnica | **T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`openssl`, `curl`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`openssl`** 3.0.13 (`genpkey` RSA + `pkeyutl`), **`curl`** 8.5.0 |
| Efecto | **cifrado asimétrico** del dato + envío del blob cifrado por HTTP al receptor |
| Elevación | **no** |
| Guardarraíl | endpoint **DEBE** ser `http://192.168.65.1:9090/…`; claves **efímeras** |

Artefacto: `.../T1048.002-Asymmetric_Encrypted_Non-C2/ATA041_ataque.sh`
(`sha256=bedfd720bcd65168338bd416191a7cc65d3a9b5811f38f7df1616ac91584a990`).
Señales: `.../ATA041_esperado.csv` (`sha256=8fe608a68195898455f5ca11d1d8114a57ddb3bf7b02018a725875d7a4024fbe`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA041_logtest.txt` (`sha256=6366418df437668bc410822560c779ad0a94627554ac5cda59aef461f82b1667`)
→ `ATA041_preflight.md` (`sha256=72922dbbbc9bcabece8310dd00d1a3259bf7fe110add7a985d41fe0d4248df69`) **PASA**
(2 eventos `openssl`/`curl` → `80792` level 3; sin silenciador).

## 3. Snapshot, red y seguridad

Víctima revertida a **`lab-listo`** antes de cada iteración. **NAT off**. Receptor (`sink_http.py`) en
el HOST (`192.168.65.1:9090`), levantado **antes de `t0`** y parado **tras `t1`**. Claves RSA
**efímeras** generadas en `lab-attack` (se pierden al revertir). **Sin claves/credenciales reales.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | snapshot |
|---|---|---|---|---|
| 1 | `2026-09-29T11:55:23Z` | `2026-09-29T11:55:55Z` | 32 s | `lab-listo` |
| 2 | `2026-09-29T11:58:02Z` | `2026-09-29T11:58:35Z` | 33 s | `lab-listo` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA041
bash ATA041_ataque.sh   # genpkey RSA efimera + pkeyutl -encrypt + curl POST + pkeyutl -decrypt
```

## 6. Evidencia

`Logs/ATA041_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sink.log`.

**Prueba de exfiltración — `sink.log` con sha256 idéntico al blob CIFRADO enviado:**

| Iter | `sink.log` (sha256) | sha256 cifrado (`ejecucion.out`) | round-trip |
|---|---|---|---|
| 1 | `a3f7d8b41b51dc39a98a760636a8c47145f02744e1b181b724a4f2610028ab98` | **idéntico** | == original ✅ |
| 2 | `1c8a32227da6096fd2c89a2563da25b82c133af11e979ec578a0e0c427984268` | **idéntico** | == original ✅ |

`sha256` original (dato de juguete): `69ae035970a4663b3a45bbe0c24adc33affa9b0feac41d7273260cf94520b854`
(`sink.log` iter1: `sha256=6d222519…` archivo; iter2: `4a150a3b…`).

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1114 | 1107 | 1108 |
| 2 | 1105 | 1098 | 1099 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1108 | **5** | 625 | 464 | **0** | 14 | 4 | 1104 | 0 | 0 |
| 2 | 1099 | **5** | 612 | 467 | **0** | 15 | 7 | 1092 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas | primera evidencia |
|---|---|---|---|---|---|
| 1 | 5 | 1 · `{80792}` | **S1+S2** | 0 | `11:55:25.606Z` `Audit: Command: /usr/bin/openssl` |
| 2 | 5 | 1 · `{80792}` | **S1+S2** | 0 | `11:58:05.007Z` `Audit: Command: /usr/bin/openssl` |

- **`80792`** `openssl` ×4 (`genpkey`, `rsa -pubout`, `pkeyutl -encrypt`, `pkeyutl -decrypt`) +
  **`80792`** `curl` ×1 (`POST /exfil/ATA041`). Señales `S1`/`S2` ancladas al `cwd` (`S3`).
- **`dudosa` resueltas:** iter1 **3** PAM → `ruido`; iter2 **5** PAM → `ruido`. **0** filas del ataque
  en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `11:55:25.606Z` `Audit: Command: /usr/bin/openssl` | **2/2** (`S1`,`S2`) | 5 / 14 / 464 | 5 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `11:58:05.007Z` `Audit: Command: /usr/bin/openssl` | **2/2** (`S1`,`S2`) | 5 / 15 / 467 | 5 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|5−5|=0 ≤ 2`. **C3′:** ✅ sin dudosas (3 + 5). Ver
  `Bitacora/ATA041.json`.

## 10. Limitaciones y hallazgos

1. **Distinción de ATA008/ATA019:** aquí el cifrado es **asimétrico real** (`openssl` RSA
   efímero + `pkeyutl`), y el canal es **HTTP** (`curl`). ATA008 fue un POST `wget` **sin cifrado**;
   ATA019, cifrado **simétrico** por TCP.
2. **El HIDS ve el proceso, no el contenido** (ni la red): la detección es el `execve`
   (`openssl`/`curl`); la **prueba** de la exfiltración es el `sink.log` (sha256 del cifrado) + el
   round-trip.

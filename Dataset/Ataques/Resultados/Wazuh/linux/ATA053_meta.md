---
fase: 3
bloque: fase-03-p1-cierre
tanda: B
ata_id: ATA053
tecnica: T1056.002
tactica: Collection;Credential Access
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA053 · T1056.002 GUI Input Capture (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda B**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA053** |
| Técnica | **T1056.002 — GUI Input Capture** |
| Táctica | Collection;Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **custom** |
| Capa del HIDS | **`execve` (`xinput`/`xdotool`, `80792`)** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART no trae prueba Linux de T1056.002 (solo AppleScript bash para macOS y PowerShell); sin prueba Linux. |
| Material externo | **sí** (Xvfb + xinput + xdotool empaquetados Debian URL+sha256; display :99) |
| Ataque | `T1056.002-GUI_Input_Capture/ATA053_ataque.sh` (`sha256=687c367a8d7555753de36b6b42adfabd286797e9bf3be422631b73f578fb1bdf`) |
| Señales | `T1056.002-GUI_Input_Capture/ATA053_esperado.csv` (`sha256=c858ca0b3b8c7b48f7789f87f52dabb491280c1c8aa8ec128caa342deba1dfb7`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA053_logtest.txt` (`f2950ee4cc25b0d67b13d8df0665b6bb0c47c9acd7ac6c8614816dd49257e2eb`) → `ATA053_preflight.md` **PASA (sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | artefacto | ruido | auto_ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T02:47:43Z` | `2026-10-02T02:48:22Z` | 761 | 3 | 17 | 80 | 661 | `687c367a…` |
| 2 | `2026-10-02T02:54:07Z` | `2026-10-02T02:54:45Z` | 728 | 3 | 17 | 80 | 628 | `687c367a…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA053
bash ATA053_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** keylog.txt 2.234 lineas, 111 eventos KeyPress capturados; sha256 registrado
- **Iter 2:** idem iter1: 2.234 lineas, 111 KeyPress
- Evidencia en `Logs/ATA053_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `sink.log`).

## 7. Ventana extraída

| Iter | detalle | deteccion |
|---|---|---|
| 1 | 761 | 3 |
| 2 | 728 | 3 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 761 | **3** | 661 | 80 | **0** | 17 |
| 2 | 728 | **3** | 628 | 80 | **0** | 17 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 3 | 1 · `{80792}` | 3 | 0 |
| 2 | 3 | 1 · `{80792}` | 3 | 0 |

- Iter 1: 1x audit_exe=/usr/bin/xinput + 2x audit_exe=/usr/bin/xdotool (execve 80792, cwd del ataque).
- Iter 2: 1x audit_exe=/usr/bin/xinput + 2x audit_exe=/usr/bin/xdotool (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T02:47:45.356Z` (execve anclado) | **2/2 (S1,S2)** |
| 2 | **sí** | `{80792}` | `2026-10-02T02:54:07.799Z` (execve anclado) | **2/2 (S1,S2)** |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; conjuntos de `rule_id` idénticos; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. FACTIBLE: el mecanismo fiel de captura de eventos X11 se logra sin usuario real (entrada sintetica xdotool + Xvfb).
2. El HIDS ve xinput y los 2 xdotool anclados al cwd (3 ejecuciones).
3. C0 sin silenciador.
4. Ataque propio: captura de eventos X11 con `xinput test-xi2 --root` mientras `xdotool` inyecta entrada sintetica (tecleo de credenciales de juguete). Keylog en keylog.txt.
5. Sustituto declarado: captura de entrada de un usuario real -> captura de eventos X11 con entrada SINTETICA (xdotool) sobre Xvfb.
6. Realismo acotado declarado (README).


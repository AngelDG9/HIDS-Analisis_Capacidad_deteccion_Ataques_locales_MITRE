---
fase: 3
bloque: fase-03-p1-cierre
tanda: B
ata_id: ATA052
tecnica: T1115
tactica: Collection
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA052 · T1115 Clipboard Data (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda B**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA052** |
| Técnica | **T1115 — Clipboard Data** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **ART adaptado** |
| Capa del HIDS | **`execve` (`xclip`, `80792`)** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `fuente_norm` / `motivo_codigo` | `ART_adaptado` / `na_art_usado` |
| Motivo | se usó ART adaptado |
| ART (guid, plataforma) | `ee363e53-b083-4230-aff3-f8d955f2d5bb` (Linux) |
| Material externo | **sí** (Xvfb + xclip empaquetados Debian URL+sha256; display :99) |
| Ataque | `T1115-Clipboard_Data/ATA052_ataque.sh` (`sha256=d784f51e4bcfe7290709da15d47b9073c15db7b775857f6a1c60e2619c69dae6`) |
| Señales | `T1115-Clipboard_Data/ATA052_esperado.csv` (`sha256=00f0b695deba40dbe5c69473477f93fab9d1248b94edaec6e80963c77962dcb1`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA052_logtest.txt` (`31d9e52ab40aea60f244c5664a8bb6b7e345f6249bdd1d7708af10a3fbb26daa`) → `ATA052_preflight.md` **PASA (sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | artefacto | ruido | auto_ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T02:35:10Z` | `2026-10-02T02:35:43Z` | 714 | 2 | 10 | 77 | 625 | `d784f51e…` |
| 2 | `2026-10-02T02:41:25Z` | `2026-10-02T02:41:58Z` | 766 | 2 | 10 | 77 | 677 | `d784f51e…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA052
bash ATA052_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** round-trip portapapeles OK (capturado == sembrado); sha256 fuente==capturado 7b9b90b1…
- **Iter 2:** idem iter1: round-trip OK; sha256 7b9b90b1… identico
- Evidencia en `Logs/ATA052_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `sink.log`).

## 7. Ventana extraída

| Iter | detalle | deteccion |
|---|---|---|
| 1 | 714 | 2 |
| 2 | 766 | 2 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 714 | **2** | 625 | 77 | **0** | 10 |
| 2 | 766 | **2** | 677 | 77 | **0** | 10 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 2 | 1 · `{80792}` | 2 | 0 |
| 2 | 2 | 1 · `{80792}` | 2 | 0 |

- Iter 1: 2x audit_exe=/usr/bin/xclip (execve 80792, cwd del ataque).
- Iter 2: 2x audit_exe=/usr/bin/xclip (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T02:35:12.436Z` (execve anclado) | **1/1 (S1)** |
| 2 | **sí** | `{80792}` | `2026-10-02T02:41:27.295Z` (execve anclado) | **1/1 (S1)** |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; conjuntos de `rule_id` idénticos; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS ve los 2 execve de xclip (poner y leer) anclados al cwd.
2. xclip deja un proceso dueno de la seleccion X; el revert de la victima lo elimina entre ventanas.
3. C0 sin silenciador.
4. Atomica Linux 'Add or copy content to clipboard with xClip': xclip -sel clip (poner) + xclip -o (leer). La fuente `history` (sin sesion interactiva) se sustituye por un historial simulado.
5. Sustituto declarado: portapapeles de sesion interactiva -> portapapeles del display Xvfb :99, con historial simulado.
6. Realismo acotado declarado (README).


---
fase: 3
bloque: fase-03-p1-cierre
tanda: B
ata_id: ATA051
tecnica: T1113
tactica: Collection
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA051 · T1113 Screen Capture (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda B**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA051** |
| Técnica | **T1113 — Screen Capture** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **ART adaptado** |
| Capa del HIDS | **`execve` (`xwd`/`xwud`, `80792`)** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `fuente_norm` / `motivo_codigo` | `ART_adaptado` / `na_art_usado` |
| Motivo | se usó ART adaptado |
| ART (guid, plataforma) | `8206dd0c-faf6-4d74-ba13-7fbe13dce6ac`, `9cd1cccb-91e4-4550-9139-e20a586fcea1` (Linux) |
| Material externo | **sí** (Xvfb + x11-apps (xwd/xwud) empaquetados Debian URL+sha256; display :99) |
| Ataque | `T1113-Screen_Capture/ATA051_ataque.sh` (`sha256=c4df2149098f828a8df0c9e1f42ad86fcc17c0053f3c4b4d192e6cd175ac5e2f`) |
| Señales | `T1113-Screen_Capture/ATA051_esperado.csv` (`sha256=541ede2e063fdd0c3a7876d29055a5b4e98e492e997952878778fcd2758441f7`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA051_logtest.txt` (`3cab19237eae4701637b8276cba237b11f1c7e6ae8820570b65802d48c3bb2c6`) → `ATA051_preflight.md` **PASA (sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | artefacto | ruido | auto_ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T02:22:26Z` | `2026-10-02T02:23:01Z` | 725 | 2 | 16 | 79 | 628 | `c4df2149…` |
| 2 | `2026-10-02T02:28:51Z` | `2026-10-02T02:29:26Z` | 724 | 2 | 16 | 79 | 627 | `c4df2149…` |

> `iter1`/`iter2` corresponden al **orden cronológico**; los ficheros `ATA051_iterN-*` conservan su nombre original (ver §4).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA051
bash ATA051_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** captura .xwd 4.099.179 B, cabecera XWD 0000006b…; xwud revisa; sha256 de la captura registrado
- **Iter 2:** idem iter1: captura .xwd 4.099.179 B, cabecera XWD valida
- Evidencia en `Logs/ATA051_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `sink.log`).

## 7. Ventana extraída

| Iter | detalle | deteccion |
|---|---|---|
| 1 | 725 | 2 |
| 2 | 724 | 2 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 725 | **2** | 628 | 79 | **0** | 16 |
| 2 | 724 | **2** | 627 | 79 | **0** | 16 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 2 | 1 · `{80792}` | 2 | 0 |
| 2 | 2 | 1 · `{80792}` | 2 | 0 |

- Iter 1: 1x audit_exe=/usr/bin/xwd + 1x audit_exe=/usr/bin/xwud (execve 80792, cwd del ataque).
- Iter 2: 1x audit_exe=/usr/bin/xwd + 1x audit_exe=/usr/bin/xwud (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T02:22:28.728Z` (execve anclado) | **2/2 (S1,S2)** |
| 2 | **sí** | `{80792}` | `2026-10-02T02:28:52.346Z` (execve anclado) | **2/2 (S1,S2)** |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; conjuntos de `rule_id` idénticos; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. La pantalla es SIN usuario real (Xvfb :99); xeyes pre-steado para dar contenido.
2. Incidente resuelto: el dpkg -i del pre-staging necesito completar la configuracion de dependencias (dpkg --configure -a) porque falta un .deb en el set; se corrigio el prestaging y se repitio la ventana (prestaging genuino, fuera de [t0,t1]).
3. Backlog de analysisd tras el FIM scan del pre-staging: los execve podian llegar >t1; se espera a que drene (120 s) antes de t0.
4. C0 sin silenciador.
5. Atomica Linux 'X Windows Capture': xwd -root -out (captura) + xwud -in (revision). Se envuelve xwud en timeout (visor interactivo). Pantalla Xvfb :99 SIN usuario real.
6. Sustituto declarado: pantalla X real -> framebuffer sintetico Xvfb :99 (declarado).
7. Realismo acotado declarado (README).


# change-doc — Bloque `B1` (ataques Windows, `fase-03b`)

> **Estado: CERRADO (2026-11-09).** Plan v3 aprobado (`c68030b`, ratificación `G-SSH.1`).
> **32 casos** (ATA056–ATA087), **5 tandas de ataque** + infra + cierre. **0 VMs al cierre.**
> **389 tests.** Linux intacto (875/875 semántico). **0 secretos.** `git push` no ejecutado.

---

## 1. Alcance y corpus

- **32 casos** Windows: **2 ART tal cual** (ATA056, ATA057), **16 ART adaptado**
  (ATA058, ATA059, ATA062–067, ATA068–073, ATA074, ATA081) y **14 manual**
  (ATA060, ATA061, ATA075–080, ATA082–087).
- **Tandas**: B1.0 infra · **B1.1** piloto mixto (ATA056–061) · **B1.2** Impact
  (ATA062–067) · **B1.3** Collection (ATA068–073, 3 interactivos S1) · **B1.4** Exfil
  (ATA074–080) · **B1.5** Windows-only + datos + recursos (ATA081–087) · **B1.6** cierre.
- **Método**: 2 iteraciones/caso; `esperado` **sellado antes de `t0`**
  (`pre_registro.sha256` + `sello_verificacion.txt`); C0; prueba de efecto independiente;
  **0 dudosas**; **0 filas del ataque en ruido**.

## 2. Resultados (T2/T4/T5-W)

- **T2-W**: `Hojas/T2_ataques_windows.csv`, **320 filas**, `N_casos=32`, `corpus=32`,
  `CA-B1-02 PASA`, `sha256 = fb83d19d5eec915d00699ae6a2ecfe50e5ffa5e5c06e67a2b5435d1206167ec5`.
- **TPR**: **32/32 (1,000)** a `N=0/3`; **1/32 (0,03125)** a `N≥7`.
  El único TP a `N≥7` es **ATA073 `92213`** (nivel 15), **artefacto de compilación**
  (`Add-Type`), **no keylogging**: la detección real de los ataques a `N≥7` es **0/32**;
  el `1/32` es "detección por tooling".
- `#Alertas` (N=0) = **539**; `#rule.id` por caso = **3** (`67027`, `92032`, `92052`),
  salvo ATA064=4, ATA067=7, ATA072=4, ATA073=5, ATA087=4.
- **T4-W**: `Hojas/T4_rendimiento_windows.csv`, `N=32`, TPR + `FP/hora` (19,875);
  `FPR/TNR/GM/Precisión/F1/Usabilidad = n/a` (sin `M`); `sha256 = d7557837ef8623d9a92c165949e5706639bc376551dd2c01b74bc4cb50aa7177`.
- **T5-W provisional**: `Hojas/T5_doble_uso_windows.csv`, **17 reglas**, **1 doble uso**:
  **`67027`** (132 alertas baseline, **281 detecciones en 32/32 casos**);
  `sha256 = be0015944290a24dbb4c41ec3efbe8181c561438e0318dc7c5965c0499d1c2b9`.
- **Sensibilidades (NO canónicas)**: `sin_operador` (`7927564f…`), `catalogo_v2`
  (`a4d44294…`), `sin_67027` (`25f4668e…`, `#Alertas=847`, TPR igual).
- **Cadena**: 2214 citas verificadas, **0 desincronías** (`B1.6_sha256sums.txt`, 137 líneas).

## 3. Canal y laboratorio

- **SSH** como canal del operador (OpenSSH Server 7.7p1 ya presente; configurado con clave,
  firewall 22 solo `192.168.65.0/24`). **`OPERADOR_WIN`**: `60106/60137` por `angel`+tipo 3;
  `67028` por `angel`; `sshd.exe` como `auto_ruido`. **Candado**: una fila con evidencia de
  `C:\lab-attack\ATA<NNN>` **nunca** cae en operador/auto_ruido.
- **`C0 ≡ C1`** (RS2 vacía en Windows); la rejilla pierde ese eje; el eje útil es el **umbral**
  y la **capa** (proceso / FIM / PowerShell / Sysmon).
- **Bóveda v3** (`boveda_version=2` de la métrica congelada + `3` de Windows); extractor
  Windows de **27 columnas** (23 previas + `win_target`, `logon_type`, `win_parent_image`,
  `win_target_user`); snapshots `lab-listo-windows-ataques-ssh` y `-gui`.
- **Laboratorio cerrado**: 0 VMs, 0 tareas `TFG-*`, servicios del host parados,
  `TFG_GUEST_PW` ausente.

## 4. Desviaciones y deudas declaradas

- **ATA074 y ATA081** son **`ART_adaptado`** (`curl.exe` en vez de `Invoke-WebRequest`;
  Outlook → perfil sintético); **ATA082–087 manual**.
- **ATA071** = TP + **`review`** (75 vs 59, C2′); **ATA078** = TP + **`review`**
  (10 vs 13 procesos `git`). **El TPR no cambia.** **`efecto_parcial`: ninguno.**
- **ATA073 `92213`**: artefacto de compilación, no keylogging; el `1/32` a `N≥7` no debe
  presentarse como "el keylogging se detecta a nivel alto".
- **ATA086**: efecto real (~527 MB), pero **sin capa de recursos**; detección solo de proceso.
  **ATA085/087**: efectos reales (64 MiB / servicio agotado), **sin capa de red/recursos**;
  detección de proceso.
- **ATA079/ATA086**: intentos fallidos (fecha/centinela; memoria sin compromiso de páginas)
  **fuera** de las ventanas válidas; el `esperado` no se tocó. **ATA071 iter1** sin
  `s1_task_principal.txt` (efecto real; principal verificado en iter2).
- **`boveda_version`** 2+3; **Linux** 875/875 **semántico** (no byte a byte por CRLF/`#`
  preexistente); **`pytest`** 389 en `_artefactos/scripts/tests` (la raíz falla por
  `atomic-red-team`/`pydantic`, preexistente).
- **FPR/TNR/GM/Precisión/F1/Usabilidad = n/a**: falta `M` (ventana legítima Windows, W3).

## 5. Consecuencia para el TFG

- **Windows**: **32/32** a `N=0/3`, pero la detección es **de proceso** (nivel 3–4); a `N≥7`
  se pierde (salvo el artefacto de compilación). **Mismo patrón que Linux** (`80792` nivel 3).
- **`67027`** es el **doble uso principal**: detecta **32/32** y genera **132** alertas de
  baseline; la regla que detecta es la que más ruido genera.
- La comparación Linux↔Windows es **por técnica y efecto**, no por comando; los **manuales**
  son los más dispares (se declara).
- **FPR de Windows y re-juicio M1b-W** quedan pendientes de la ventana legítima W3.

## 6. Siguiente

1. **Ampliación de ataques (segunda oleada)** antes de la ventana legítima Windows.
2. **W3** (ventana legítima Windows) + **M1b-W** (re-juicio con el catálogo de 72 h).
3. **Velociraptor** (`V0/V1`).
4. **A1/A2** (comparativa, gráficas y memoria).

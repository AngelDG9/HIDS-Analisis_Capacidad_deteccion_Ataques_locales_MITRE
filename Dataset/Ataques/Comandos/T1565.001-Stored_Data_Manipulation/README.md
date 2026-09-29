# ATA032 · T1565.001 — Stored Data Manipulation (ledger en reposo, custom)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda A**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA032** |
| Técnica | **T1565.001 — Stored Data Manipulation** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **manipula datos EN REPOSO**: altera un registro de un **libro mayor (ledger)
  simulado** (replace + append) sin destruirlo. Distinto de **ATA026/T1565.002**
  (manipulación **en tránsito**): aquí el objeto es un **activo concreto en reposo**.
- **Destino:** `/home/angel/lab-legit/finanzas/ledger_2026.csv` (ruta **VIGILADA**).
- **Capa del HIDS que ejercita:** **`execve`** (`sed`) + **`watch`** de contenido en reposo.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `sed`, `mkdir`, `grep`, `sha256sum`, `awk` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA032` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA032 && bash ATA032_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA032_esperado.csv`:

- `T1565.001-S1` (**deteccion**) `audit_exe=/usr/bin/sed` — la manipulación del ledger (`80792`).
- `T1565.001-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA032/*` — ancla H4.
- `T1565.001-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — escrituras bajo el **watch** de
  `lab-legit` → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **Nota de solapamiento con ATA006/T1565 (declarado):** la **herramienta** es la misma (`sed -i`);
> el **objeto** es distinto (ledger de finanzas como activo con integridad, no un fichero de datos
> genérico). Es el patrón ya aplicado de cubrir **padre + sub-técnica**.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `sed` (`80792`) anclado al `cwd` del ataque.
- La alteración del ledger en reposo es visible por el **`watch`** (`80790/80781`), declarado
  **`ambigua`** (efecto, no detección declarada).

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: el `sha256` del ledger **antes ≠ después** y los marcadores (`999999.99`,
`Ajuste manual no autorizado`) están presentes. Evidencia en `Logs/ATA032_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`, ni secretos, ni datos reales (ledger de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se manipula un ledger
> simulado, nunca datos financieros reales); **el entorno no tiene usuarios/servicios reales** y
> **las rutas del ataque son conocidas por el analista**.

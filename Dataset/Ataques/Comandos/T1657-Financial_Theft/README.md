# ATA017 · T1657 — Financial Theft (fraude sobre libro de cuentas local, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda A**. Redactado el **2026-09-29** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Validación humana:
> **APROBADO 2026-09-29**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA017** |
| Técnica | **T1657 — Financial Theft** |
| Táctica | Impact (sabotaje/fraude) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (la prueba ART depende de servicios/red → sin NAT se escribe a mano) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **sabotaje/fraude**: añade una **transferencia fraudulenta** al **libro de cuentas
  local** y altera el saldo; además **sustrae** una **cartera simulada**. Todo son **datos de
  juguete** (escena de empresa) en la ruta **VIGILADA** `/home/angel/lab-legit`.
- **Destino:**
  - **Modificación** de `/home/angel/lab-legit/libro_cuentas_2026.csv` (vigilado → `watch`).
  - **Sustracción** (copia) a `/home/angel/lab-attack/ATA017/collected/`.
- **Capa del HIDS que ejercita:** **`watch`** (modificación en ruta vigilada) + `execve`.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`cat`, `sed`, `cp`, `grep`, `mkdir`, `sha256sum`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA017/`.
2. `cd /home/angel/lab-attack/ATA017/ && bash ATA017_ataque.sh 2>&1 | tee ejecucion.out`.

## 5. Señales esperadas (convención H4)

`ATA017_esperado.csv`:

- `T1657-S1` (**deteccion**) `audit_exe=sed` — manipulación del libro (transferencia fraudulenta).
- `T1657-S2` (**deteccion**) `audit_exe=cp` — sustracción del libro y la cartera.
- `T1657-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA017/*` — ancla H4.
- `T1657-A1/A2/A3` (**ambigua**) `rule_id ∈ {80790, 80781, 80782}` — modificación bajo **watch** en
  `lab-legit` (efecto) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de **`sed`/`cp`** (`80792`, nivel 3) anclado al `cwd` del ataque.
- La **manipulación** bajo `watch` dispara `80790/80781/80791` (declarada `ambigua`, **efecto**).

## 7. Prueba de éxito (independiente de la alerta)

El `sha256` del libro **cambia**, aparece la transferencia fraudulenta (**`TRF-9999`**) y la copia
en `lab-attack` es **idéntica** ⇒ el fraude y la sustracción **ocurrieron de verdad**. Evidencia en
`Logs/ATA017_iter*/ejecucion.out` + `sha256_artefacto.txt`.

## 8. Reversión e higiene

- **Reversión:** víctima a **`lab-listo`**; el manager **no** se revierte.
- **Higiene:** sin credenciales reales; **ninguna** cuenta/servicio financiero real se toca.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**; **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. El libro y
> la cartera son **datos de juguete** con **nombres creíbles**, pero **no son datos reales**.

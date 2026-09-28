# ATA011 · T1074 — Data Staged (`mkdir` + `cp` sobre datos simulados)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda B**. Redactado el **2026-09-29** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA011** |
| Técnica | **T1074 — Data Staged** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1074` aparece en `Hojas/cobertura_atomic.csv` con **1 prueba Linux** (test que descarga datos de
**GitHub**) → **NO es ejecutable en el laboratorio sin NAT**. La técnica **sí aplica a Linux**, así
que el ataque **se escribe a mano**: se **reúnen** unos datos simulados en una carpeta de *staging*
(acción característica de T1074), dejándolos listos para una exfiltración posterior.

## 3. Qué hace y dónde escribe

- **Qué hace:** crea un directorio de **puesta en escena** (`mkdir -p`) y **copia** (`cp`) unos
  datos simulados ("recolectados") a esa carpeta, generando además un **manifiesto con `sha256`**
  (el inventario de lo reunido). Deja el paquete listo para exfiltrar.
- **Origen/ejecución:** todo en **`/home/angel/lab-attack/ATA011/`** (`recoleccion/` → `staging/`),
  **NO vigilado** → la detección es por **`execve`** (`mkdir`, `cp`).
- **Efecto (D3):** **no** toca `lab-legit`: T1074 es *reunir*, no exfiltrar; los datos de juguete se
  siembran dentro de la propia carpeta del ataque. ⇒ **sin** señales `ambigua` (y, por tanto, sin el
  riesgo de capturar *churn* ajeno que tuvo la `ambigua` amplia de ATA003).
- **Semilla:** si no existen, los datos se crean con `printf` (builtin, contenido fijo) ⇒
  **determinista** e idempotente.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **NO** `find` masivo por el sistema (eso es **T1119 / ATA012**).
- **NO** compresión ni empaquetado en archivo (`tar`/`gzip`) (eso es **T1560 / ATA013**).
  El "empaquetado" aquí es **reunir en el directorio de staging + manifiesto**, no crear un archivo.
- **NO** se toca el sistema real, ni `lab-legit`, ni ningún servicio/disco.
- Guardarraíl en el guion: el destino **DEBE** quedar bajo `lab-attack/ATA011` (aborta si no).

## 5. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramientas | **`mkdir`, `cp`, `sha256sum`** (coreutils de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** |
| C0 | `mkdir`/`cp` no deben caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA011_c0_plan.md`) |

## 6. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA011/`.
2. `cd /home/angel/lab-attack/ATA011/ && bash ATA011_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El guion hace `cd` a su carpeta (cwd = ancla H4) e imprime `T0=…`/`T1_LOCAL=…`.

## 7. Señales esperadas (convención H4)

`ATA011_esperado.csv`:

- `T1074-S1` (**deteccion**) `audit_exe=mkdir` — creación del directorio de puesta en escena (`80792`).
- `T1074-S2` (**deteccion**) `audit_exe=cp` — reunión de los datos en el staging (`80792`).
- `T1074-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA011/*` — ancla H4 del proceso.

> **Sin** señales `ambigua`: el ataque **no** escribe bajo *watch* (ni `lab-legit` ni `/etc`).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El guion comprueba que el `staging/` contiene **≥ 3 ficheros** y que el **manifiesto** con `sha256`
existe ⇒ los datos quedaron **reunidos y listos**. Evidencia en `Logs/ATA011_iter*/ejecucion.out`.

## 9. Solapamiento declarado (vecinas de Collection)

- **vs ATA012 (T1119 Automated Collection):** ATA012 **recolecta automáticamente** (`find`+`cp`);
  ATA011 **reúne** un conjunto ya conocido en una carpeta de staging (`mkdir`+`cp`).
- **vs ATA013 (T1560 Archive Collected Data):** ATA013 **archiva/comprime** (`gzip`); ATA011 **no**
  comprime: agrupa y deja listo. Aquí el "paquete" es el directorio + manifiesto, no un archivo.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa: informes de
> ventas, clientes, proveedores) para que la ventana parezca un caso realista, pero **no son datos
> reales**.

# ATA012 · T1119 — Automated Collection (`find` + `cp` + `tar`)

> Artefacto **R-13** del bloque `fase-03-piloto-custom`. Redactado el **2026-09-26** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (2º gate, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA012** |
| Técnica | **T1119 — Automated Collection** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1119` aparece en `Hojas/cobertura_atomic.csv` como **`solo_windows`** (`tests_linux=0`, path
`atomics/T1119`): **Atomic Red Team NO trae ninguna prueba de Linux** para esta técnica. La
técnica **sí aplica a Linux**, así que el ataque **se escribe a mano**. Es el segundo de los dos
ataques manuales de este bloque.

## 3. Qué hace y dónde escribe

- **Qué hace:** **recolecta automáticamente** ficheros de configuración legibles del sistema y los
  **almacena (stage)** en un directorio, empaquetándolos después para una exfiltración posterior.
- **Destino:** **`/home/angel/lab-attack/ATA012/`** (`collected/` + `collected.tar.gz`).
- **Ruta NO vigilada:** `/home/angel/lab-attack/` **no** está en el `-w` de auditd **ni** en las
  rutas FIM del agente (verificado en el paso 0) → **no habrá eventos watch**; la detección es
  **por `execve`** (igual que ATA008/ATA013).

## 4. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0) |
|---|---|
| Herramientas | **`find`, `cp`, `tar`** (`/usr/bin/find`, `/usr/bin/cp`, `/usr/bin/tar`) |
| Dependencias | ninguna nueva (de serie) |
| Instalación | **no se instala nada** (`lab-listo` prístino) |
| Elevación | **no** (lee rutas *world-readable*) |

## 5. Cómo se ejecuta

1. (Fase B, tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA012/`.
2. `cd /home/angel/lab-attack/ATA012/ && bash ATA012_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El script imprime `T0=…` al inicio y `T1_LOCAL=…` al final (marcadores UTC;
   el `t1` oficial se sella tras el scan FIM forzado, runbook §2 paso 7).

## 6. Señales esperadas (convención H4)

`ATA012_esperado.csv`:

- `T1119-S1` (**deteccion**) `audit_exe=find` — recolección de ficheros.
- `T1119-S2` (**deteccion**) `audit_exe=cp` — copia de lo recolectado al staging.
- `T1119-S3` (**deteccion**) `audit_exe=tar` — empaquetado/staging.
- `T1119-S4` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA012/*` — ancla H4.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md`). Las señales se redactan **antes** de atacar y las
> **valida el humano** (2º gate).

## 7. Hipótesis de detección

- **DETECTADO** (≥3 eventos): `execve` de **`find`**, **`cp`** y **`tar`** → `80792` (nivel 3),
  ninguno silenciado por reglas de fábrica (**capturas C0**,
  `Soporte/Ataques/c0/ATA012_logtest.txt`: las 3 ganadoras son `80792` level 3 → **no avisa**).
- **No** se espera evento de fichero (`watch`/FIM): la ruta del ataque **no está vigilada**.

## 8. Reversión

Revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El manager **no** se
revierte.

## 9. Higiene

- **Sin contraseñas, claves ni tokens.** Se ejecuta como `angel` **sin `sudo`**. Solo lee ficheros
  *world-readable* (`/etc/*.conf`, `hosts`, `passwd`, `os-release`).

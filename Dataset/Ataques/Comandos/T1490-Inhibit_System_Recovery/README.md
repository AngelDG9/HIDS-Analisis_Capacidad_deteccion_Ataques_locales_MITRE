# ATA003 · T1490 — Inhibit System Recovery (`rm -rf` de "puntos de recuperación" *mock*)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda A**. Redactado el **2026-09-28** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-28**. **No
> contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA003** |
| Técnica | **T1490 — Inhibit System Recovery** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1490` aparece en `Hojas/cobertura_atomic.csv` como **`solo_windows`** (`tests_linux=0`, 12 tests
Windows): Atomic Red Team **no trae ninguna prueba de Linux**. La técnica **sí aplica a Linux** (un
ransomware destruye las copias de seguridad / puntos de recuperación antes de cifrar) → el ataque
**se escribe a mano**.

## 3. Qué hace y dónde escribe — **SIMULACIÓN SEGURA**

- **Qué hace:** **borra** (`rm -rf`) unas **copias de seguridad mock** (`backup_full_2026-08.tar`,
  `backup_incremental_2026-09-15.tar`, `export_clientes_2026-08.csv`, `dump_postgres_2026-09.dump`)
  de un directorio `copias_seguridad/` para simular la inhibición de la recuperación (el ransomware
  destruye las copias antes de cifrar). Son datos de juguete; la escena imita copias reales.
- **Ejecución:** `/home/angel/lab-attack/ATA003/` (**NO** vigilado → detección del proceso por
  **`execve`**).
- **Efecto (D3):** **`/home/angel/lab-legit/copias_seguridad/`** — la carpeta **vigilada** por
  `auditd` → el borrado genera eventos **watch** (`80780`/`80781`).
- **Semilla:** si el directorio no existe, el guion lo **crea** (`mkdir -p`) con 4 ficheros fijos ⇒
  determinista e idempotente. Ese `mkdir` de *setup* es un **artefacto** del ataque (se atribuye por
  **veredicto humano `artefacto`**, nunca `ruido`; plantilla v4 §5).

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **NO** se toca: `wazuh-agent`, `cron`, `chrony`, `systemd` real, `/etc` real, `/var/backups` real,
  ni **ningún** servicio/timer del sistema.
- **DECISIÓN DE ALCANCE:** la variante "deshabilitar un temporizador *lab-owned*" (`systemctl`) se
  **omite a propósito**: exigiría `root`/sesión systemd de usuario y **arriesga** la VM (prohibido
  por el encargo); además `systemctl` ya queda cubierto por **ATA004** (T1489). El vector de T1490
  aquí es el **borrado de copias**. **Si el humano quiere la variante `systemctl`**, se añade un
  temporizador *lab-owned* y su C0 (con línea **journald real**, lección del `40700 = level 0` de
  ATA004); por defecto **no** se hace.

## 5. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramientas | **`rm`, `mkdir`** (coreutils de serie) |
| Dependencias | ninguna nueva (se instala **nada**) |
| Elevación | **no** |
| Guardarraíl | el objetivo **DEBE** ser exactamente `$HOME/lab-legit/copias_seguridad` (aborta si no) |

## 6. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA003/`.
2. `cd /home/angel/lab-attack/ATA003/ && bash ATA003_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 7. Señales esperadas (convención H4)

`ATA003_esperado.csv`:

- `T1490-S1` (**deteccion**) `audit_exe=rm` — borrado de las copias de seguridad mock (`80792`).
- `T1490-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA003/*` — ancla H4 del proceso.
- `T1490-A1` (**ambigua**) `rule_id=80781` — borrado/escritura en la ruta vigilada `lab-legit`.
- `T1490-A2` (**ambigua**) `rule_group=audit_watch_write` — evento watch en `lab-legit` (lo "tapa"
  el baseline) → va a **`dudosa`**/revisión humana.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md` v4).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El guion hace `test -e` del directorio de copias de seguridad **antes** (EXISTE) y **después**
(NO EXISTE) ⇒ la inhibición de la recuperación ocurrió. Evidencia en
`Logs/ATA003_iter*/ejecucion.out`.

## 9. C0 (pre-flight base-contra-base) — **EJECUTADO** (2026-09-28)

Captura `Soporte/Ataques/c0/ATA003_logtest.txt`
(`sha256=ffabd7073909c04cf1cb00754993e123cefa5f8a5053a5169f68b1c18dfe01b8`) → informe
`Soporte/Ataques/c0/ATA003_preflight.md`. **Resultado: PASA**.

- **Ganadora de fábrica:** `80792` *Audit: Command: /usr/bin/rm*, **`level 3` ⇒ SÍ avisa**.
  **Sin** silenciador de fábrica. Plan original en `Soporte/Ataques/c0/ATA003_c0_plan.md`.
- **NO se usa `journald`** (no hay `systemctl`): la detección se declara por el **`rule_id` del
  `execve`** (`80792`). El punto ciego de journald (`40700 = level 0`) queda **documentado** en la
  ficha de ATA004.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/` y
  `/home/angel/lab-legit/copias_seguridad/`). El manager **no** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa) para que la
> ventana se parezca a un caso realista, pero **no son datos reales**.

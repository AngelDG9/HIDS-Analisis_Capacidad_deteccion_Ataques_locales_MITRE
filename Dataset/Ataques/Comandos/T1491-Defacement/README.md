# ATA007 · T1491 — Defacement (`cp` sobre una página "pública" simulada)

> Artefacto **R-13** del bloque `fase-03-piloto-custom`. Redactado el **2026-09-26** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (2º gate, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA007** |
| Técnica | **T1491 — Defacement** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1491` aparece en `Hojas/cobertura_atomic.csv` como **`solo_windows`** (`tests_linux=0`, path
`atomics/T1491.001`): **Atomic Red Team NO trae ninguna prueba de Linux** para esta técnica. La
técnica **sí aplica a Linux**, así que el ataque **se escribe a mano** (no se copia de ART). Es
uno de los dos ataques manuales de este bloque que validan el camino "ataque escrito por nosotros".

## 3. Qué hace y dónde escribe

- **Qué hace:** **modifica el contenido de una página "pública" simulada** (mock web) copiando
  (`cp`) un HTML de defacement sobre el fichero objetivo.
- **Origen:** `~/lab-attack/ATA007/defacement.html` (lo trae el artefacto; efímero).
- **Destino:** **`/home/angel/lab-legit/public_site/index.html`** — la **única ruta escribible por
  `angel` que está en el `-w` de auditd** (`-w /home/angel/lab-legit -p wa -k audit-wazuh-w`;
  verificado en el paso 0). **`/etc` no es escribible por `angel` sin `sudo`**.
- **Mock declarado:** **no hay servidor web** real; el "defacement" es la **sobrescritura del
  fichero**. Se declara aquí para no confundir el alcance.

## 4. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0) |
|---|---|
| Herramienta | **`cp` (coreutils)** — `/usr/bin/cp` |
| Dependencias | ninguna nueva (coreutils de serie) |
| Instalación | **no se instala nada** (`lab-listo` prístino) |
| Elevación | **no** (usuario `angel`; la ruta es suya) |

## 5. Cómo se ejecuta

1. (Fase B, tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA007/` (incluye `ATA007_ataque.sh` y `defacement.html`).
2. `cd /home/angel/lab-attack/ATA007/ && bash ATA007_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El script imprime `T0=…` al inicio y `T1_LOCAL=…` al final (marcadores UTC;
   el `t1` oficial se sella tras el scan FIM forzado, runbook §2 paso 7).

## 6. Señales esperadas (convención H4)

`ATA007_esperado.csv`:

- `T1491-S1` (**deteccion**) `audit_exe=cp` — `execve` de `cp` (`80792`, *Audit: Command*).
- `T1491-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA007/*` — ancla H4 del proceso.
- `T1491-A1` (**ambigua**) `rule_id=80790` — creación genérica bajo watch.
- `T1491-A2` (**ambigua**) `rule_id=80781` — escritura en la ruta vigilada compartida.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md`). Las señales se redactan **antes** de atacar y las
> **valida el humano** (2º gate).

## 7. Hipótesis de detección

- **DETECTADO por el proceso:** `execve cp` → `80792` (nivel 3), que **no** está silenciado por
  ninguna regla de fábrica (confirmado con la **captura C0**, `Soporte/Ataques/c0/ATA007_logtest.txt`:
  ganadora `80792` level 3 → **no avisa**).
- La **escritura** en `lab-legit` (`80781`/`80790`) se declara **`ambigua`** → `dudosa`/revisión
  humana (ver §9).

## 8. Reversión

Basta revertir la víctima a **`lab-listo`**: borra `/home/angel/lab-attack/` y
`/home/angel/lab-legit/public_site/`. El manager **no** se revierte.

## 9. ⚠️ Limitación declarada — el baseline puede "tapar" la escritura (§3.1 del plan)

`ATA007` escribe en **`/home/angel/lab-legit`**, la **misma carpeta** donde corrió el script de
baseline. Las reglas de escritura de esa ruta (`80781`, `80790`) **están en el catálogo de ruido**
→ la **escritura** del defacement se **descartaría como `ruido_conocido`** si se declarara
`deteccion`. Por eso:

- esas escrituras se declaran **`ambigua`** (`T1491-A1`/`T1491-A2`) → van a **`dudosa`** y las
  decide un **humano**; **no** se descartan en silencio;
- la **detección "dura"** sigue siendo el **proceso** (`execve cp` → `80792`).

> **Limitación del método (a declarar en la memoria):** *cuando el ataque comparte ruta con la
> actividad legítima, el filtro por catálogo desclasifica la escritura; por eso las señales de
> ruta se marcan ambiguas y se resuelven por revisión humana.*

## 10. Higiene

- **Sin contraseñas, claves ni tokens.** Se ejecuta como `angel` **sin `sudo`**.

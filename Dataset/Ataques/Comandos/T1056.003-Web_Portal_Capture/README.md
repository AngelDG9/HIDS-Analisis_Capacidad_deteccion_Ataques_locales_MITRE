# ATA028 · T1056.003 — Web Portal Capture (portal falso local, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda C**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA028** |
| Técnica | **T1056.003 — Input Capture: Web Portal Capture** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **captura credenciales** por un **portal web falso** servido **localmente**:
  1. levanta un **portal simulado** (listener HTTP en `127.0.0.1`) cuyo **código del atacante
     registra el POST** (`nc -l` → `request.http`), y
  2. un cliente (`curl`) envía **credenciales de juguete** al portal; el POST **queda capturado**.
- **Destino:** `127.0.0.1:8081` (**loopback**) + captura en `lab-attack/ATA028/request.http`.
- **Capa del HIDS que ejercita:** **`execve`** de `nc` y `curl`. Mezcla **red (loopback) +
  fichero (la captura)**. El listener usa **`nc`** (no `python3`) → **no** se activa el punto
  ciego de fábrica `92600`.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`nc`** (OpenBSD netcat 1.226), `curl`, `timeout`, `sleep`, `grep` (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA028/`.
2. `cd /home/angel/lab-attack/ATA028 && bash ATA028_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA028_esperado.csv`:

- `T1056.003-S1` (**deteccion**) `audit_exe=nc` — portal falso (listener) (`80792`).
- `T1056.003-S2` (**deteccion**) `audit_exe=curl` — cliente que envía las credenciales (`80792`).
- `T1056.003-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA028/*` — ancla H4.

> **No hay señales `ambigua`:** la captura queda **dentro** de `lab-attack` (NO vigilado).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `nc`/`curl` (`80792`, nivel 3) anclado al `cwd` del ataque.
- **Punto ciego evitado:** si el portal se hubiera servido con **`python3`**, el `execve` habría
  caído en el silenciador de fábrica **`92600`** (como ATA013); se usa **`nc`** a propósito.

## 7. Prueba de éxito (independiente de la alerta)

El fichero `request.http` **contiene** el POST con `usuario=demo` y `clave=demo-solo-juguete`
(credenciales **de juguete**); `PORTAL_CAPTURE=OK`. Evidencia en
`Logs/ATA028_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte. El guion
  lleva un **`trap`** que mata el listener si quedara vivo.
- **Higiene:** **cero** credenciales reales; las de juguete no valen para nada. Todo es **local**
  (loopback); sin NAT, sin servicios externos.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no hay portal real ni
> credenciales reales); **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque
> son conocidas por el analista**.

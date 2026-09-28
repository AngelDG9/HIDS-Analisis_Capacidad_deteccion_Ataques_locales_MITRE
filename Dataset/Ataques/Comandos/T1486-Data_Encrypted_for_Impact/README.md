# ATA001 · T1486 — Data Encrypted for Impact (`openssl enc`, control ART)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda A**. Redactado el **2026-09-28** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-28**. **No
> contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA001** |
| Técnica | **T1486 — Data Encrypted for Impact** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **Atomic Red Team** (control) — prueba *Encrypt files using openssl* |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Fuente de la atómica (Atomic Red Team)

| Campo | Valor |
|---|---|
| Prueba | *Encrypt files using openssl (FreeBSD/Linux)* |
| **GUID** | `142752dc-ca71-443b-9359-cf6f497315f1` |
| Path en el clon | `atomics/T1486/T1486.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Repo | `https://github.com/redcanaryco/atomic-red-team.git` (MIT) |

Comando original de la atómica (`input_arguments` por defecto: claves RSA en `/tmp`, entrada
`/etc/passwd`, salida `/tmp/passwd.zip`):

```bash
which_openssl=`which openssl`
$which_openssl genrsa -out /tmp/key.pem 2048
$which_openssl rsa -in /tmp/key.pem -pubout -out /tmp/pub.pem
$which_openssl rsautl -encrypt -inkey /tmp/pub.pem -pubin -in /etc/passwd -out /tmp/passwd.zip
```

Es **1 de los 4 tests Linux** de T1486 (gpg / 7z / ccrypt / **openssl**). Es el **único** de los 7
ataques del escalado que usa ART **tal cual** (los otros 6 son custom; ver plan §1).

## 3. Qué hace y dónde escribe

- **Qué hace:** **cifra** un fichero de datos **falso** del laboratorio (escena de empresa: un
  *export* de clientes) para simular el impacto de un ransomware (los datos quedan ilegibles sin
  la clave).
- **Destino:** **`/home/angel/lab-attack/ATA001/`**
  (`datos_clientes_2026.csv` → `datos_clientes_2026.csv.enc`; el descifrado de prueba reconstruye
  `datos_clientes_2026.recovered.csv`). Son **datos de juguete** (clientes inventados; **sin**
  datos personales reales).
- **Ruta NO vigilada:** `/home/angel/lab-attack/` **no** está ni en el `-w` de `auditd` ni en las
  rutas FIM del agente → **no hay eventos watch/FIM**; la detección es **por `execve`** (como
  ATA008/ATA012/ATA013).
- **Nada fuera de `$HOME`.** No se toca `/etc`, ni ficheros reales, ni ningún dispositivo.

## 4. ⚠️ Desviación declarada — `openssl enc` (AES) en vez de `genrsa`+`rsautl`

El plan §4 fija el cifrado con `openssl enc -aes-256-cbc -pbkdf2 -salt -in … -out …`. La atómica
original de ART usa **RSA** (`genrsa` + `rsautl -encrypt`), que:

1. **solo admite entradas cortas** (≈245 B con RSA-2048), insuficiente para un fichero normal; y
2. usa `rsautl`, **deprecado** en OpenSSL 3.x.

Por eso se sigue la forma **simétrica** del plan (AES-256-CBC + PBKDF2 + salt), **equivalente en
impacto** y reproducible. La passphrase (`tfg-lab-ata001`) es **simbólica del laboratorio**: **no
es un secreto real**, se declara aquí y en el guion, y **no se versiona** ninguna credencial.

## 5. Herramienta, dependencias y elevación

| Elemento | Valor (a verificar en el paso 0 del escalado) |
|---|---|
| Herramienta | **`openssl`** (OpenSSL 3.x de serie en Ubuntu 24.04) |
| Dependencias | ninguna nueva (se instala **nada**) |
| Elevación | **no** (usuario `angel`; escribe en su `$HOME`) |
| Fallback | el plan preveía `gpg` si faltara `openssl`; el **preflight confirma `openssl`**, así que el guion **falla ruidosamente** si no está (sin ruta de fallback no probada) |

## 6. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA001/`.
2. `cd /home/angel/lab-attack/ATA001/ && bash ATA001_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El guion hace `cd` a su carpeta (cwd determinista = ancla H4) e imprime
   `T0=…`/`T1_LOCAL=…` (UTC).

## 7. Señales esperadas (convención H4)

`ATA001_esperado.csv` (**rehace el EJEMPLO** que había en el repo, que declaraba watch/FIM en
`lab-attack` — imposible: esa ruta no está vigilada):

- `T1486-S1` (**deteccion**) `audit_exe=openssl` — `execve` de `openssl` (`80792`).
- `T1486-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA001/*` — ancla H4 del proceso.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md` v4). Las señales se redactan **antes** de atacar y las
> **valida el humano**.

## 8. Prueba de éxito del ataque (independiente de la alerta)

El guion **descifra** `datos_clientes_2026.csv.enc` con la misma clave y compara el **`sha256`** con
el original: si coinciden, **el ciphertext es válido** ⇒ el ataque "funcionó" más allá de que el
HIDS alerte. Evidencia en `Logs/ATA001_iter*/ejecucion.out` + `sha256_artefacto.txt`.

## 9. C0 (pre-flight base-contra-base) — **EJECUTADO** (2026-09-28)

Captura `Soporte/Ataques/c0/ATA001_logtest.txt`
(`sha256=b73d6f291b0d4ee3a23ceb239528f44a6628f089ea338ab247c3190474151923`) → informe
`Soporte/Ataques/c0/ATA001_preflight.md`. **Resultado: PASA**.

- **Ganadora de fábrica:** `80792` *Audit: Command: /usr/bin/openssl*, **`level 3` ⇒ SÍ avisa**.
  **Sin** silenciador de fábrica. Plan original en `Soporte/Ataques/c0/ATA001_c0_plan.md`.
- Si el C0 hubiera descubierto un **silenciador de fábrica**, se documenta y la detección se declara
  por el `execve` (D5: **no** se escriben reglas RS3).

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El manager
  **no** se revierte.
- **Higiene:** sin contraseñas reales, claves ni tokens. Passphrase **simbólica** declarada. Se
  ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa) para que la
> ventana se parezca a un caso realista, pero **no son datos reales**.

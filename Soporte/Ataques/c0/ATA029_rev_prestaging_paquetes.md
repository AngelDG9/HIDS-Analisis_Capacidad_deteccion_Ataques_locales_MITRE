# ATA029_rev — pre-staging de paquetes (dependencias offline de la atómica T1005)

> Constancia **reproducible** del material pre-steado (§C.2 de `Soporte/Ataques/criterio_ataques.md`):
> **URL + `sha256`**. Entra **ANTES de `t0`** (fuera de `[t0,t1]`) y el revert lo elimina.
> **No contiene secretos.** Creado el **2026-10-01** (bloque `fase-03-repeticiones`, tanda R1).

La atómica de ART «Find and dump sqlite databases (Linux)» (guid `00cbb875-7ae4-4cf1-b638-e543fd825300`)
necesita `sqlite3`, `strings` y `curl`. En la víctima **no estaban** `sqlite3` ni `strings` (§7-R3 del plan).
La decisión humana (gate 2026-10-01) fue **pre-stejar los paquetes e instalarlos OFFLINE**. `curl` **no** hizo
falta: el `curl -O` remoto se sustituyó por los 3 `src/` pre-steados (sin NAT).

## Paquetes de `sqlite3` (descargados en el host desde archive.ubuntu.com)

| Paquete | URL | `sha256` |
|---|---|---|
| `sqlite3_3.45.1-1ubuntu2.8_amd64.deb` | `http://archive.ubuntu.com/ubuntu/pool/main/s/sqlite3/sqlite3_3.45.1-1ubuntu2.8_amd64.deb` | `78493e56909614ec1d588c9fae1739a704d9e1a6ff65509b1f06c3e4d53ed0c3` |
| `libsqlite3-0_3.45.1-1ubuntu2.8_amd64.deb` | `http://archive.ubuntu.com/ubuntu/pool/main/s/sqlite3/libsqlite3-0_3.45.1-1ubuntu2.8_amd64.deb` | `b1190bb72359f5fcc47406aa46065eaf4f1ca208085c51224a52b04bedc0b4bb` |

## Paquetes de `binutils` (que provee `/usr/bin/strings`)

Procedencia: caché `apt` del manager (`/var/cache/apt/archives/`, Ubuntu noble `2.42-4ubuntu2.10`);
copiados al host y luego a la víctima por `scp` sobre `VMnet1`. Instalados con `dpkg -i` **offline**.

| Paquete | `sha256` |
|---|---|
| `binutils_2.42-4ubuntu2.10_amd64.deb` | `b3b5a84181a38fd191820b2cdcc1a3eeb1cd6333ad472f2092f96e81047e9c74` |
| `binutils-common_2.42-4ubuntu2.10_amd64.deb` | `d136073f5e2153f3df11c1d08d66727b9466b28ff483f50085f14bbe3464b5ee` |
| `binutils-x86-64-linux-gnu_2.42-4ubuntu2.10_amd64.deb` | `1e510a15f30208d39edcd840e48f26a77bbca7c417805eeccb1e3f7de198ef29` |
| `libbinutils_2.42-4ubuntu2.10_amd64.deb` | `064dce00ce94e1fc2d33779cb0071088f4c8aac79e85345f2e78a020f7d14699` |
| `libctf0_2.42-4ubuntu2.10_amd64.deb` | `7ec86d697c3668503c85f308a6832f092075b5880ad002f22185264da0bd4645` |
| `libctf-nobfd0_2.42-4ubuntu2.10_amd64.deb` | `da352eb7fa6c4369d2a6c1e5e680f574eda2e38576563326b18d9e47e61c4078` |
| `libgprofng0_2.42-4ubuntu2.10_amd64.deb` | `1b7e3c2fc162e8358ca6e5a3fffdb4d0d632f790630323215841bb36a63c0ab8` |
| `libsframe1_2.42-4ubuntu2.10_amd64.deb` | `72093fb456864db55f1352bfa5e952a94f7abaff64e71dff1fbf001db1984564` |

## Resultado de la instalación (verificado en la víctima)

```text
sqlite3=3.45.1
strings=GNU strings (GNU Binutils for Ubuntu) 2.42
```

## `src/` de la atómica (pre-steados antes de t0, en lugar del `curl` remoto)

`art`, `gta.db`, `sqlite_dump.sh` — del clon de ART fijado
`atomics/T1005/src/` (`commit=388942adbd9641f4dfdcf079d7efe9a75ec0ac43`). El `sqlite_dump.sh` del clon
tiene finales de línea CRLF (checkout Windows) → se normaliza a LF (`sed -i 's/\r$//'`) antes de ejecutarlo
(no cambia el mecanismo; si no, el ejecutor falla con *"required file not found"*).

## Alcance declarado

Instalación **offline** de paquetes fijados (URL+`sha256`); **sin NAT**. Es pre-staging §C, permitido:
el material entra **antes de `t0`** y el revert de la víctima lo elimina. La atómica queda **factible offline**.

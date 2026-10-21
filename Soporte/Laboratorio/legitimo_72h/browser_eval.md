# `browser_eval.md` — evaluación del navegador headless (DT-B0…DT-B5)

> **Bloque:** `legitimo-fix` (v3). **Encargo del humano (2026-10-21):** evaluar meter un
> navegador headless en el bloque "navegar".
> **Regla pre-registrada (§4.7):** *el navegador se usa en **un solo bloque (B3)** **solo si
> DT-B0…DT-B5 pasan TODOS**. Cualquier fallo ⇒ **se descarta** y B3 sigue con `curl`. No hay
> repetición "por si acaso".*
> **Tope duro:** 90 min. **Corte en DT-B0** si falla (30 min).
> **Decisión pre-registrada (§4.8):** descartarlo. **Este documento es su test de falsación.**

- **Candidato:** **Chrome for Testing** `155.0.8059.84` (linux64) + `chromedriver` `155.0.8059.84`
  (versiones **emparejadas**; Firefox descartado de entrada por el bucle caliente de
  `BrowserFirefox.cs:28-30` y por arrancar al inicio del cliente).
- **Dónde:** revert de `lab-listo-legit` (desechable) en `victima-linux`, con el cliente
  arreglado desplegado y manager + GHOSTS + internet local arriba.
- **Fecha/hora (UTC):** 2026-10-20T23:00Z – 2026-10-20T23:15Z.

## Artefactos descargados (pre-staging en el HOST)

| Fichero | URL | Bytes | `sha256` |
|---|---|---|---|
| `chrome-linux64.zip` | `https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.84/linux64/chrome-linux64.zip` | 199 014 491 | `cf0f049892dea22e6a6db26d47ed0d7776b7158edcbec4634086633df8bafcbc` |
| `chromedriver-linux64.zip` | `https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.84/linux64/chromedriver-linux64.zip` | 11 896 800 | `4fe2433044363e5233d642e70fa50278b471bda08032d922402c8bd7c6d743fd` |

Origen de las versiones: `https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json`
(canal `Stable` = `155.0.8059.84`). Los `.zip` quedan **fuera del repo** (`D:\TFG-VMs\material-ghosts\browser-eval\`).

## DT-B0 — Pre-staging (PASS/FAIL)

| Comprobación | Resultado | Veredicto |
|---|---|---|
| Descarga + `sha256` + tamaño | los dos `.zip` descargados y huellados (tabla) | **PASS** |
| Descompresión en `~/browser/` | `unzip` **no existe** en la víctima ⇒ se usa `python3 -m zipfile -e` (workaround declarado) | **PASS (con workaround)** |
| `chrome --version` | **no arranca**: `error while loading shared libraries: libatk-1.0.so.0` | **FAIL** |
| `chromedriver --version` | `ChromeDriver 155.0.8059.84` | PASS |
| `ldd chrome \| grep 'not found'` | **12 librerías ausentes** | **FAIL** |
| Disco libre tras el staging | **3,4 GB** (antes 4,0 GB; el navegador ocupa **424 MB**) | **FAIL** (< 3,5 GB) |

Salida literal (recortada):

```text
$ python3 -m zipfile -e /tmp/chrome-linux64.zip .
$ python3 -m zipfile -e /tmp/chromedriver-linux64.zip .
$ du -sh ~/browser
424M    /home/angel/browser
$ df -h /
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  5.9G  3.4G  64% /

$ ~/browser/chrome-linux64/chrome --version
/home/angel/browser/chrome-linux64/chrome: error while loading shared libraries:
  libatk-1.0.so.0: cannot open shared object file: No such file or directory

$ ~/browser/chromedriver-linux64/chromedriver --version
ChromeDriver 155.0.8059.84 (5869fe313571d75152b77813cf0a4ee26a4e6df0-refs/branch-heads/8059@{#1303})

$ ldd ~/browser/chrome-linux64/chrome | grep -c 'not found'
12
    libatk-1.0.so.0 => not found
    libatk-bridge-2.0.so.0 => not found
    libcups.so.2 => not found
    libasound.so.2 => not found
    libgbm.so.1 => not found
    libcairo.so.2 => not found
    libpango-1.0.so.0 => not found
    libXcomposite.so.1 => not found
    libXdamage.so.1 => not found
    libXfixes.so.3 => not found
    (…)
```

**Por qué el disco es un fallo duro (no un matiz):** el staging deja **3,4 GB** libres. El
guardarraíl **G-2** de `prep` exige **≥ 4 GB** (y DT-B0 pedía ≥ 3,5 GB). Es decir: **con el
navegador instalado, `prep` abortaría y la ventana no podría ni armarse**. No es un umbral
inventado para esta prueba: es el margen que el plan fijó para no repetir el fallo del disco.

**Por qué no se resuelven las 12 librerías:** exigiría descargar y `dpkg -x` **12+ paquetes
`.deb`** a mano (la víctima **no tiene NAT** y no se instala software durante la ventana), lo
que además **reduce aún más** el disco libre — agravando el fallo de G-2. Es exactamente la
**fragilidad offline** que el plan anticipó (§4.5, §4.8: «driver offline + librerías»).

## DT-B1…DT-B5 — **NO EJECUTADAS**

| # | Prueba | Estado | Motivo |
|---|---|---|---|
| **DT-B1** | ¿Misma secuencia? (2 ejecuciones de 6 `browse`) | **NO EJECUTADA** | Corte pre-registrado en DT-B0 |
| **DT-B2** | Ciclo de vida y orfandades (`stop`, `kill -9`) | **NO EJECUTADA** | ídem |
| **DT-B3** | Recursos (RAM libre, swap, load, perfil) | **NO EJECUTADA** | ídem (el disco ya falló) |
| **DT-B4** | Impacto en `M` (navegador vs `curl`) | **NO EJECUTADA** | ídem |
| **DT-B5** | Modo de fallo (driver oculto, 5 min) | **NO EJECUTADA** | ídem |

La regla pre-registrada dice: *«Si DT-B0 falla (libs, versiones, offline): **se para ahí**
(30 min perdidos, no 90)»*. Se ha parado ahí.

## Veredicto

> **DT-B0 = FAIL** (Chrome no arranca: 12 librerías ausentes; y el staging deja el disco en
> **3,4 GB** < 3,5 GB ⇒ G-2 rechazaría `prep`).
> **Decisión: se MANTIENE el descarte del navegador (§4.8)** y **B3 sigue con la sesión web
> *browser-like* con `curl`** (§5.7). La receta **no cambia**: `d1/d2/d3` se quedan como están
> (**0** handlers `Browser*`; `receptor_navegador=none`).

**Higiene (regla del plan):** se **revierte** la víctima a `lab-listo-legit` y se **borra** todo
el material del navegador (`.zip` en `/tmp`, `~/browser/`); se verifica
`receptor_navegador=none` y el disco recuperado. **No queda software ni configuración** de la
prueba; lo que se conserva son **textos y cifras** (este documento).

## Lo que NO se puede afirmar (declarado, §18.3-11)

- DT-B **no** ha medido si el navegador sería "más realista" en la ventana: se ha cortado en el
  pre-staging por criterios **objetivos** (librerías y disco). La decisión es **proporcionada**,
  no exhaustiva. Si en el futuro la víctima tuviera más disco, más RAM y una vía offline de
  librerías, DT-B podría repetirse **antes** de otra ventana.
- El **workaround** de descompresión (`python3 -m zipfile` en vez de `unzip`) **no** afecta al
  veredicto: el bloqueo está en las **librerías del sistema** y en el **disco**, no en el
  desempaquetado.

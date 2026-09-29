# ATA041 · T1048.002 — Asymmetric Encrypted Non-C2 (`openssl pkeyutl` RSA + HTTP)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda C** (3.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos** (claves **efímeras de juguete**).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA041** |
| Técnica | **T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica exige **cifrado asimétrico** (clave pública/privada) del dato antes de exfiltrarlo. Es el
nodo ATT&CK **T1048.002** (el padre `T1048` lo cubrió `ATA008`, que fue un POST `wget` **sin**
cifrado real). Se distingue de `ATA019/T1048.001` (cifrado **simétrico**, `openssl enc`). ART trae
pruebas de T1048.002 basadas en servicios **cloud** (file.io) no viables sin NAT → guion propio.

## 3. Qué hace y dónde escribe

- **Qué hace:** genera un **par RSA efímero**, **cifra** un extracto de clientes simulado con la
  **clave pública** (`openssl pkeyutl -encrypt`), **envía el blob cifrado** por HTTP al receptor del
  HOST (`curl`) y **descifra** el blob (round-trip) para demostrar el cifrado asimétrico.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA041/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino (efecto):** el **receptor del HOST** en VMnet1, **`http://192.168.65.1:9090/exfil/ATA041`**.
- **Claves:** **efímeras** (generadas en `lab-attack`; se pierden al revertir la VM). **Cero** claves
  o credenciales reales.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Sin NAT**: **no** se sale a internet; el receptor es **infraestructura local** (VMnet1).
- **NO** se toca el sistema real ni ninguna ruta vigilada → **sin** señales `ambigua`.
- Guardarraíl en el guion: el endpoint **DEBE** ser `http://192.168.65.1:9090/…` (aborta si no).

## 5. Señales esperadas (convención H4)

`ATA041_esperado.csv`:

- `T1048.002-S1` (**deteccion**) `audit_exe=openssl` — par RSA + cifrado/descifrado (`80792`).
- `T1048.002-S2` (**deteccion**) `audit_exe=curl` — envío del blob cifrado (`80792`).
- `T1048.002-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA041/*` — ancla H4.

> La **red no es visible** para el HIDS de host: la detección es el **proceso** (`openssl`/`curl`);
> la **prueba** de la exfiltración es el `sink.log` del HOST. **Sin** señales `ambigua`.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`openssl`** 3.0.13, **`curl`** 8.5.0, **`sha256sum`**, **`stat`**, **`awk`** |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `openssl`/`curl` no deben caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA041_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA041/`.
3. `cd /home/angel/lab-attack/ATA041/ && bash ATA041_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el receptor tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sink.log` del HOST registra `POST /exfil/ATA041 … sha256=<H>`; ese `<H>` **coincide** con el
`sha256` del blob **cifrado** (`…txt.enc`) que el guion imprime ⇒ el dato cifrado **salió** de la
víctima. Además, el **round-trip** descifrado **coincide** con el original ⇒ el cifrado es
**asimétrico** (clave pública/privada). Evidencia en `Logs/ATA041_iter*/` (`sink.log` + `ejecucion.out`).

## 9. Receptor — cómo se levanta y se retira

```powershell
# Levantar (HOST), ANTES de t0:
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA041_iter1\sink.log"
# Parar tras t1: Ctrl+C / matar el proceso python de sink_http.py
```

> El receptor se **recrea por ventana** y se **retira al cerrar la tanda** (CA-B9). `/exfil/ATA041` lo
> sirve el handler `do_POST` genérico del receptor (no requiere código nuevo).

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`, incluidas las claves
  efímeras). El **manager NO** se revierte.
- **Higiene:** claves **efímeras** de juguete; **cero** credenciales reales. Se ejecuta como `angel`.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «servidor de exfiltración»
> es un **receptor local simulado** (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa) pero **no son datos reales**.

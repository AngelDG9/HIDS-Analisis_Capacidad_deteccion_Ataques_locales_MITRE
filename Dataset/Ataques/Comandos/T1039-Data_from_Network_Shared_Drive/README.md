# ATA039 · T1039 — Data from Network Shared Drive (recurso compartido local → recolección)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda C** (1.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA039** |
| Técnica | **T1039 — Data from Network Shared Drive** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica consiste en **recolectar datos de un recurso compartido de red** (SMB/NFS/WebDAV), no del
sistema de ficheros local. La biblioteca ART no trae una prueba Linux ejecutable **sin NAT**, así que
se escribe a mano. Es distinta de `ATA011/T1074` (staging **local**) y de `ATA020/T1020` (exfiltración
**hacia fuera**): aquí el movimiento es **desde** un recurso remoto **hacia** el atacante.

## 3. ⚠️ Qué se montó exactamente (paso 0) y por qué

**No se montó ningún sistema de ficheros.** En este laboratorio **no hay cliente NFS/SMB disponible
sin NAT**: en la víctima **no existen** `mount.nfs`, `mount.cifs` ni `sshfs`, y no se pueden instalar
(sin acceso a internet). La **opción local más simple** que sí funciona es un **recurso compartido
servido por el manager** (el «servidor de ficheros» del laboratorio) con el **daemon de `rsync`**
(`rsync://`, puerto **9873**, **sin autenticación**, solo alcanzable por **VMnet1**).

| Elemento | Valor |
|---|---|
| Qué es | directorio **`/home/angel/lab-share/`** del manager, exportado como módulo rsync **`share`** (solo lectura) |
| «Montaje» | **arrancar** el daemon `rsync --daemon --config=/tmp/rsyncd_tfg.conf --detach` **antes de `t0`** |
| «Desmontaje» | **parar** el daemon (`pkill -f rsyncd_tfg.conf`) y eliminar `~/lab-share` **al cerrar la tanda** |
| Cliente | **`rsync`** en la víctima (`rsync://192.168.65.128:9873/share/`) |

> Nota metodológica: el HIDS de **host** no ve el protocolo de red (no hay reglas de red en el
> ruleset base): la detección es el **proceso cliente** (`rsync`) anclado al `cwd` del ataque. La
> **prueba** de que el dato se leyó del recurso es el **`sha256` coincidente** con los ficheros del
> manager.

## 4. Qué hace y dónde escribe

- **Qué hace:** **recolecta** (copia recursivamente) el contenido del recurso compartido remoto
  (`share/`) a la carpeta del ataque (`share_copy/`).
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA039/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Origen remoto (efecto):** el **manager** en VMnet1, **`rsync://192.168.65.128:9873/share/`**.
- **Sin NAT**: el «recurso» es **infraestructura local** (VMnet1). **No** se instala nada.

## 5. Señales esperadas (convención H4)

`ATA039_esperado.csv`:

- `T1039-S1` (**deteccion**) `audit_exe=rsync` — cliente que recolecta el recurso (`80792`).
- `T1039-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA039/*` — ancla H4.

> Sin señales `ambigua`: las escrituras caen bajo `lab-attack/ATA039` (pertenencia automática →
> `artefacto_ataque`). La **red no es visible** para el HIDS de host.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`rsync`** 3.2.7 (víctima y manager), **`find`**, **`sha256sum`** |
| Servicio | daemon `rsync` en el manager (puerto 9873, sin auth) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `rsync` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA039_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el manager**, *antes de `t0`*, levantar el daemon (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA039/`.
3. `cd /home/angel/lab-attack/ATA039/ && bash ATA039_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el daemon tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sha256` de cada fichero copiado en la víctima **coincide** con el `sha256` del fichero homólogo
del recurso en el manager (`sha256sum` en ambos lados) ⇒ los datos se **leyeron del recurso
compartido**. Evidencia en `Logs/ATA039_iter*/` (salida del ataque + `sha256sum` remoto).

## 9. Recurso compartido — cómo se levanta y se retira

```bash
# EN EL MANAGER (192.168.65.128), ANTES de t0:
rsync --daemon --config=/tmp/rsyncd_tfg.conf --detach   # puerto 9873; módulo share (ro) + incoming (rw)
# comprobar desde la víctima:
#   rsync --list-only rsync://192.168.65.128:9873/
# PARAR tras t1 (al cerrar la tanda):
pkill -f rsyncd_tfg.conf
rm -rf /home/angel/lab-share /tmp/rsyncd_tfg.conf /tmp/rsyncd_tfg.log
```

> El daemon y `~/lab-share` se **crean por tanda** y se **retiran al cerrar** (CA-B9). Sin regla de
> firewall.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte, de ahí el **desmontaje explícito** del recurso (§9).
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**. Datos de
  juguete (escena de empresa).

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «recurso compartido» es un
> **servidor `rsync` local** del manager (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa: finanzas/rrhh) pero **no son datos reales**.

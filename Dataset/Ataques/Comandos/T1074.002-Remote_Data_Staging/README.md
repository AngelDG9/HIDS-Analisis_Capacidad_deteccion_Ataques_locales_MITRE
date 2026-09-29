# ATA040 · T1074.002 — Remote Data Staging (staging local → recurso remoto)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda C** (2.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA040** |
| Técnica | **T1074.002 — Remote Data Staging** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica es el **staging REMOTO**: mover/copiar el material **ya recolectado** a un **destino
remoto** antes de exfiltrarlo. Es el hermano «remoto» de `ATA011/T1074.001` (**staging local**). La
biblioteca ART no trae una prueba aplicable sin NAT, así que se escribe a mano. Diferencia con
`ATA039/T1039`: allí se **lee** del recurso (dirección remoto→local); aquí se **escribe** en el
recurso (local→remoto).

## 3. ⚠️ Qué se montó exactamente (paso 0) y por qué

**No se montó ningún sistema de ficheros** (no hay cliente NFS/SMB offline; ver `ATA039` README §3).
El **destino remoto** es el **mismo servidor de ficheros local** del manager, usando el módulo
**escribible `incoming`** del daemon `rsync`:

| Elemento | Valor |
|---|---|
| Qué es | módulo rsync **`incoming`** del manager (`/home/angel/lab-share/incoming`, lectura-escritura) |
| «Montaje» | **arrancar** el daemon `rsync --daemon --config=/tmp/rsyncd_tfg.conf --detach` **antes de `t0`** |
| «Desmontaje» | **parar** el daemon y eliminar `~/lab-share` **al cerrar la tanda** |
| Cliente | **`rsync`** en la víctima (`rsync://192.168.65.128:9873/incoming/ATA040/`) |

## 4. Qué hace y dónde escribe

- **Qué hace:** siembra un *staging* local (datos de juguete) y lo **copia al recurso remoto**
  (`incoming/ATA040/`) — el material queda **estagiado fuera de la víctima**.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA040/`** (**NO** vigilado → detección del
  proceso por **`execve`**).
- **Destino remoto (efecto):** el **manager** en VMnet1, **`rsync://192.168.65.128:9873/incoming/`**.
- **Sin NAT**: el «recurso» es **infraestructura local** (VMnet1). **No** se instala nada.

## 5. Señales esperadas (convención H4)

`ATA040_esperado.csv`:

- `T1074.002-S1` (**deteccion**) `audit_exe=rsync` — cliente que envía el staging al recurso (`80792`).
- `T1074.002-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA040/*` — ancla H4.

> Sin señales `ambigua`: la semilla se escribe bajo `lab-attack/ATA040` (pertenencia automática →
> `artefacto_ataque`). La **red no es visible** para el HIDS de host.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`rsync`** 3.2.7, **`find`**, **`sha256sum`** |
| Servicio | daemon `rsync` en el manager (módulo `incoming`, escritura) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |
| C0 | `rsync` no debe caer en silenciador de fábrica (`Soporte/Ataques/c0/ATA040_logtest.txt`) |

## 7. Cómo se ejecuta

1. **En el manager**, *antes de `t0`*, levantar el daemon (§9).
2. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA040/`.
3. `cd /home/angel/lab-attack/ATA040/ && bash ATA040_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).
4. Parar el daemon tras `t1` (§9).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El `sha256` de cada fichero **enviado** (impreso por el guion) **coincide** con el `sha256` del
fichero homólogo **en el recurso remoto** del manager ⇒ los datos se **estagiaron fuera de la
víctima**. Evidencia en `Logs/ATA040_iter*/` (salida del ataque + `sha256sum` remoto en el manager).

## 9. Recurso compartido — cómo se levanta y se retira

```bash
# EN EL MANAGER (192.168.65.128), ANTES de t0:  (mismo daemon que ATA039)
rsync --daemon --config=/tmp/rsyncd_tfg.conf --detach
# PARAR tras t1 (al cerrar la tanda):
pkill -f rsyncd_tfg.conf
rm -rf /home/angel/lab-share /tmp/rsyncd_tfg.conf /tmp/rsyncd_tfg.log
```

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El **manager NO** se revierte → **desmontaje
  explícito** del recurso y borrado de `~/lab-share` (§9).
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «recurso remoto» es un
> **servidor `rsync` local** del manager (sin NAT, sin nube, sin credenciales); **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos de
> juguete llevan **nombres creíbles** (escena de empresa) pero **no son datos reales**.

# ATA054 · T1498.002 — Reflection Amplification (reflector local acotado, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda C** (1.º de 2). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA054** |
| Técnica | **T1498.002 — Network DoS: Reflection Amplification** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1498) |
| Ejecución | usuario `angel` con **`sudo`** (raw socket + netns) |

## 2. Qué hace y dónde escribe

- **Qué hace:** reproduce el mecanismo de **amplificación por reflexión**: el **spoofer** envía
  peticiones UDP con **fuente falsificada** (= IP de la víctima, `192.168.65.129:5399`) a un
  **reflector local**; el reflector responde con un cuerpo grande **a la fuente falsificada** →
  la víctima recibe **más bytes de los que envió** (factor de amplificación > 1).
- **Topología:** **segmento local AISLADO** (par `veth` + `netns tfgref`, `10.200.0.0/24`) **dentro
  de la víctima**. Refleja el rol de un tercer reflector, pero **no sale a VMnet1**.
- **Prohibiciones respetadas:** **nunca** el manager (`192.168.65.128`), **nunca** el PC
  (`192.168.65.1`), **nunca** amplificadores reales de internet.
- **Capa del HIDS que ejercita:** **`execve`** (`perl`/`ip`). El HIDS de host **no ve la red**; la
  prueba es el `target` (bytes amplificados recibidos).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `perl` (`/usr/bin/perl`), `ip` (`/usr/bin/ip`), `bash` (de serie) |
| Dependencias | ninguna nueva |
| Elevación | **sí** (`sudo`; raw socket + netns) |
| Guardarraíl | reflector FIJO en `10.200.0.0/24`; `COUNT ≤ 40`; `RESP ≤ 8 KiB`; total ≤ **512 KiB**; ≤ **15 s**; limpieza (netns+veth) por `trap` |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio a `/home/angel/lab-attack/ATA054/`.
2. `cd /home/angel/lab-attack/ATA054 && echo '<pw>' | sudo -S bash ATA054_ataque.sh 2>&1 | tee ejecucion.out`.
3. El propio guion crea y **retira** el segmento local; no hay receptor externo.

## 5. Señales esperadas (convención H4)

`ATA054_esperado.csv` (todas `deteccion`):

- `T1498.002-S1` `audit_exe=perl` (`80792`).
- `T1498.002-S2` `audit_exe=ip` (`80792`).
- `T1498.002-S3` `audit_cwd=/home/angel/lab-attack/ATA054/*` — ancla H4.

> **Binario real:** `perl` → `/usr/bin/perl`; `ip` → `/usr/bin/ip` (symlink desde `/usr/sbin/ip`).

## 6. Reflector — cómo se monta y se retira

El reflector **no** es externo: `ATA054_reflector.pl` se levanta **dentro del netns** en
`10.200.0.2:10053` y responde a la fuente falsificada. Se **retira** al terminar (kill + `ip netns
del` + `ip link del`), verificado con `netns_residuales=0` y `veth_residuales=0`.

## 7. Prueba de éxito (independiente de la alerta)

`target.out` registra `target: paquetes=N bytes=B`; con `N=25` y `RESP_BYTES=4096` → **102.400 B
recibidos** frente a **400 B** enviados → **factor ≈ 256**. La víctima recibió la amplificación.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** el segmento local y los procesos se **retiran** al terminar (0 residuos); **sin NAT**;
  **sin** reglas de firewall.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el mecanismo son reales** (peticiones con fuente falsificada + respuesta
> amplificada al origen falsificado); **el alcance es de laboratorio**: el reflector se **monta en
> un segmento local aislado dentro de la víctima** (sustituto declarado de un tercer reflector de
> la red), la amplificación es **acotada** y el **destino nunca** es el manager ni el PC; **no** se
> usan amplificadores reales de internet; **el entorno no tiene usuarios/servicios reales** y **las
> rutas del ataque son conocidas por el analista**.

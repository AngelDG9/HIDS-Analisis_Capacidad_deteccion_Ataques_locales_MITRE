# ATA038 · T1529 — System Shutdown/Reboot (reinicio de la VM víctima)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda B**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA038** |
| Técnica | **T1529 — System Shutdown/Reboot** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **`sudo` solo** para `shutdown -r` |
| Capa del HIDS que ejercita | **`execve`** del comando + **estado del agente** (`503`/`504`) |

## 2. Qué hace y dónde escribe

- **Qué hace:** **reinicia la VM víctima** (`victima-linux`) con `sudo shutdown -r +1`.
- **Destino:** **la propia VM víctima**. **Jamás** el manager (`wazuh-server`) ni el anfitrión.
- **Capa nueva:** el **estado del agente** (el manager ve el cierre/arranque del agente 001),
  además del `execve` del comando.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramienta | `shutdown -r` (**enlace a `/usr/bin/systemctl`**; `systemd 255`) |
| Dependencias | ninguna nueva |
| Elevación | **sí**, `sudo` (por `stdin`), **solo** para `shutdown -r` |
| Guardarraíl | se **exige** `hostname == victima-linux` **y** IP `192.168.65.129`; si aparece la IP del manager → **ABORTA** |

## 4. Cómo se ejecuta (procedimiento, al ser disruptivo)

1. **Snapshot de seguridad:** el punto de retorno es el snapshot ya existente **`lab-listo`**
   (no se crea uno nuevo); la víctima se revierte a `lab-listo` **antes** de cada iteración y
   **después** de la tanda.
2. `mkdir -p /home/angel/lab-attack/ATA038` y `scp -r` del directorio de la técnica ahí.
3. `t0` se sella **tras el asentamiento** (≥ 90 s con el agente `Active`).
4. `cd /home/angel/lab-attack/ATA038 && bash ATA038_ataque.sh` (contraseña por `stdin`). El
   guion **programa el reinicio (+1 min)** e imprime `T0=…`; **no** puede sellar `t1` (la VM se
   reinicia).
5. Se espera a la **reconexión** (SSH), al agente `001` **`Active`** y a un **asentamiento**, y el
   **operador sella `t1`** en la víctima.
6. Se extrae `[t0,t1]` del **fichero diario** del manager.

## 5. Señales esperadas (convención H4)

`ATA038_esperado.csv`:

- `T1529-S1` (**deteccion**) `audit_exe=/usr/bin/systemctl` — el comando de reinicio (`80792`).
  **Binario real** (`shutdown`/`reboot` son enlaces a `systemctl`).
- `T1529-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA038/*` — ancla H4.
- `T1529-S3/S4` (**deteccion**) `rule_id ∈ {503, 504}` — **estado del agente** (iniciado /
  desconectado); **capa nueva**.
- `T1529-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — ficheros (efecto) → `dudosa` →
  veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `systemctl` (`80792`) y, **capa nueva**, por el **estado del
  agente** (`503`/`504`).
- ⚠️ **journald/systemd**: la regla de fábrica `40700` es **`level=0`** (agrupador) → **no**
  alerta por un apagado normal (hallazgo ya documentado en ATA004). No se espera alerta de journald.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: `post_reboot.txt` muestra un **`boot_id` distinto** y un **uptime menor** que el de
`pre_reboot.txt`, y el agente vuelve **`Active`**. Evidencia en `Logs/ATA038_iter*/`.

## 8. Cómo queda el agente tras el arranque (documentado)

- El **agente `wazuh-agent`** de la víctima vuelve a estar **`active`** y el **manager** lo ve
  **`Active`** (agente `001`) tras el arranque; `auditd` recarga `/etc/audit/rules.d/tfg.rules`.
- El **reinicio** es un **`shutdown -r` ordenado** (no `hard`) → el estado de la víctima es
  coherente; el material del ataque desaparece al revertir a `lab-listo`.

## 9. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (red de seguridad; estado limpio). El
  manager **no** se revierte.
- **Higiene:** la contraseña va por `stdin`; **0** residuos (la VM se revierte).

## 10. Alternativa KISS (no aplicada) — declarada

> El plan (§R6) ofrece como **alternativa** sustituir T1529 por **T1074.001 Local Data Staging**
> si el reinicio fuese **demasiado arriesgado** o **ensuciase la medida**. La medida resultó
> **limpia** (el churn de arranque cae en el catálogo `baseline`; solo las reglas de **estado del
> agente** `503`/`504` son `novel` y **se declaran**) → **se ejecuta T1529** (no se sustituye).

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se reinicia **solo** la
> **VM víctima desechable**, restaurable por snapshot); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**.

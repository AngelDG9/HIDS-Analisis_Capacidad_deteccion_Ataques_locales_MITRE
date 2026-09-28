# ATA004 · T1489 — Service Stop (`systemctl stop cron`, control de ART)

> Artefacto **R-13** del bloque `fase-03-piloto-custom`. Redactado el **2026-09-26** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (2º gate, **antes** del primer `t0`). **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA004** |
| Técnica | **T1489 — Service Stop** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **Atomic Red Team** (control) |
| Ejecución | **elevada** (`root`) — ver §4 |

## 2. Fuente de la atómica (Atomic Red Team)

| Campo | Valor |
|---|---|
| Prueba | *Linux - Stop service using systemctl* |
| **GUID** | `42e3a5bd-1e45-427f-aa08-2a65fa29a820` |
| Path en el clon | `atomics/T1489/T1489.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Repo | `https://github.com/redcanaryco/atomic-red-team.git` (MIT) |
| `elevation_required` | **true** (`sudo systemctl stop #{service_name}`) |

Comando original de la atómica (default `service_name=cron`):

```bash
sudo systemctl stop cron
# cleanup_command: sudo systemctl start cron 2> /dev/null
```

## 3. Qué hace y dónde escribe

- **Qué hace:** **para un servicio** (`cron`, fijado en el paso 0; el paso 0 confirmó que `cron`
  está `active`).
- **Dónde:** **no escribe ficheros**; cambia el **estado del servicio** (registrado por
  **journald/systemd**). **Nunca** se para `wazuh-agent`.

## 4. ⚠️ Elevación (declarada, sin secretos)

El script se lanza **ya elevado**; el **ejecutor** hace:

```bash
echo '<contraseña del laboratorio>' | sudo -S bash ATA004_ataque.sh
```

- La contraseña se usa **solo en memoria**, por **`stdin`**; **nunca** en el artefacto, el README
  ni ningún fichero del repo.
- Dentro del script, `systemctl stop cron` corre **como root** → **sin `sudo` anidado**: una sola
  elevación. El script comprueba `id -u` y **aborta** si no es root.
- **Cleanup de ART** (`sudo systemctl start cron`) **no** se ejecuta en el ataque: el **revert a
  `lab-listo`** restaura el servicio (y no añade `execve` de `systemctl` a la ventana).

## 5. Cómo se ejecuta

1. (Fase B, tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA004/`.
2. Desde `/home/angel/lab-attack/ATA004/`, el ejecutor lanza el script **elevado** (ver §4);
   el stdout va a `ejecucion.out`. El script imprime `T0=…`/`T1_LOCAL=…` (UTC).
3. **Paso 0 — dependencias:** `which systemctl` OK y **`systemctl is-active cron` = `active`**
   (si no, se fija otro servicio benigno y se documenta).

## 6. Señales esperadas (convención H4)

`ATA004_esperado.csv`:

- `T1489-S1` (**deteccion**) `audit_exe=systemctl` — parada del servicio (`80792`).
- `T1489-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA004/*` — ancla H4.
- `T1489-A1` (**ambigua**) `audit_exe=sudo` — elevación (parte del ataque, no de la técnica).
- `T1489-A2` (**ambigua**) `rule_id=5402` — `sudo` a root (ruido de elevación).

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md`). Las señales se redactan **antes** de atacar y las
> **valida el humano** (2º gate).

## 7. Hipótesis de detección (control de ART)

- **DETECTADO (con matiz):** `execve systemctl` → `80792` (nivel 3, **no** silenciado: la captura
  C0 `Soporte/Ataques/c0/ATA004_logtest.txt` da ganadora `80792` level 3 → **no avisa**), **+** eventos
  de **elevación/PAM** (`5402`, `5501`, `5502`).
- **NO detectado por journald — hallazgo (`fase-03-cabos`, 2026-09-28):** la parada del *unit* **no**
  generó alerta por el grupo `systemd` (`40700`). La regla `40700` (agrupador de
  `0285-systemd_rules.xml`, Wazuh v4.14.7) es **`level="0"`** → **no emite alerta**; sus hijas
  `40701`–`40705` (level 2/5) **solo** disparan con patrones de **fallo** (`Stale file handle`,
  `entered failed state`, `status=1/FAILURE`…). Una parada **normal** (`systemctl stop cron`,
  `Stopping/Stopped`) no casa ninguna hija → gana `40700` (level 0) → **0 alertas journald**. La
  expectativa de `40700` era **estructuralmente imposible**, no "silenciada": la detección efectiva es
  el **`execve` `80792`**. Para detectar por journald haría falta **regla propia (RS3)** o declarar la
  detección por el `rule_id` del `execve` (ver runbook §8.3).
- **Matiz:** parte del recuento puede venir de la **elevación** → por eso `T1489-A1`/`T1489-A2`
  se declaran **`ambigua`**. Las PAM `5501`/`5502` **no** se auto-excluyen (H3): con este `esperado`
  (declara `rule_id=5402`) `sin_campos` no dispara → salen **`ruido_conocido`/`baseline`** (solo
  caerían a `dudosa` si el `esperado` no declarara ningún campo siempre evaluable).
- **Control de ART:** confirma que la maquinaria de medición sigue funcionando igual con un ataque
  que **no** es manual.

## 8. Reversión

Revertir la víctima a **`lab-listo`** (restaura `cron` y borra `/home/angel/lab-attack/`). El
manager **no** se revierte.

## 9. Higiene

- **Sin contraseñas, claves ni tokens** en el artefacto. La contraseña del laboratorio se usa
  **solo en memoria** al lanzar el script (`sudo -S` por `stdin`) y **jamás** se versiona.
- El material de la atómica vive en `Soporte/Ataques/atomic-red-team/` (ignorado por git).

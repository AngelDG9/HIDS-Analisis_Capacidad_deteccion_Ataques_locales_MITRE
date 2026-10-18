# Instrumentación del denominador `M` — `<logall_json>` (bloque `legitimo-infra`, L0)

> **Especificación congelada:** `Soporte/Metrica/metrica_hids.md` §2 (`R2 §2.2`). L0 la deja
> **lista y probada**; **NO** se activa durante ventanas de ataque. Aquí se documenta el
> **procedimiento**, la **medida** de tamaño/tasa de `archives.json` y la **estimación a 72 h**,
> para que `L1` decida con **dato** (no con intuición). **Regla dura: no se toca `Soporte/Metrica/`.**

## 1. Qué es y qué NO cambia

- **Dónde:** en el **manager** (`wazuh-server`, `.128`), bloque `<global>` de
  `/var/ossec/etc/ossec.conf`: `<logall_json>yes</logall_json>`.
- **Qué hace:** Wazuh escribe **todos** los eventos **decodificados** (hayan disparado o no una
  regla) en `/var/ossec/logs/archives/archives.json`. Mide el **denominador `M`** = nº de eventos
  decodificados.
- **Qué NO cambia:** el **ruleset** ⇒ la **"virgen"** queda preservada; el recuento de
  **detecciones** no se altera. **Se declara.**

## 2. Procedimiento (prueba acotada, fuera de toda ventana)

```powershell
# en el manager (vía ssh): on | off | status | size
bash /tmp/logall_json_ctl.sh on       # activa y REINICIA el manager
bash /tmp/logall_json_ctl.sh size     # tamaño + hora UTC
bash /tmp/logall_json_ctl.sh off      # desactiva y REINICIA (vuelve a 'no')
bash /tmp/logall_json_ctl.sh status   # verifica <logall_json>no</logall_json> y manager 'active'
```

`logall_json_ctl.sh` hace **copia de seguridad** de `ossec.conf`
(`/var/ossec/etc/ossec.conf.tfg-bak`) y **restaura** el valor previo con `off`.

## 3. Medición (2026-10-18, HOST + `wazuh-server`)

Actividad acotada en `victima-linux`: **acciones GHOSTS** (timeline entregada por el servidor en
bucle) + ruido normal del sistema (auditd, syscheck, SCA…). **Ventana de prueba:**
`t0 = 2026-10-18T18:03:34Z` → `t1` (`size`).

| Métrica | Valor |
|---|---|
| `archives.json` **t0** | `96 339` bytes (2026-10-18T18:03:34Z) |
| `archives.json` **t1** | `1 151 095` bytes (2026-10-18T18:18:45Z) |
| **Δ tamaño** | `1 054 756` bytes |
| **Duración** | `911 s` (15 min 11 s) |
| **Tasa** | ≈ **4,17 MB/h** (≈ 3,97 MiB/h) |
| **Estimación a 72 h** | ≈ **300 MB** (≈ 286 MiB) |
| **¿`> ~5 GB`?** | **NO** (300 MB ≪ 5 GB) |

**Estado final:** `<logall_json>no</logall_json>` restaurado, `ossec.conf` **idéntico** a la copia
de seguridad previa (`diff` sin diferencias), `archives.json` **eliminado**, manager **`active`**.
**El ruleset no se modificó** ⇒ la "virgen" queda preservada.

> **Caveat declarado (honestidad de la medida):** la ventana de `911 s` tuvo **actividad GHOSTS
> solo ~17–38 s** (el resto del tiempo la víctima estuvo **sin acciones GHOSTS en ejecución**, solo
> con el **ruido de fondo** del sistema: auditd, syscheck, SCA…). Por tanto los **≈ 4,17 MB/h son
> esencialmente la tasa de fondo**; la actividad GHOSTS solo **añade** volumen ⇒ la proyección a
> 72 h es, si acaso, un **ligero infravalor**. **La conclusión (≈ 300 MB ≪ 5 GB) se mantiene con
> ~17× de margen.** La medición es de **orden de magnitud**; `L1` fijará la tasa real en las 72 h.
> Con este dato, el **titular por evento** es **viable** y **no se prevé activar el fallback**.

## 4. Disparador del fallback (`R2 §2.2`, literal)

> Si `archives.json` de 72 h **> ~5 GB** **o** la decodificación no es fiable ⇒ el **titular cae a
> `FP/acción` + `FP/hora`** y se **documenta como limitación** (caso **L11**).

**Umbral numérico:** **`> 5 GB` en 72 h** (≈ **`> 71 MB/h`**). Si la estimación de L0 queda **muy
por debajo**, el titular por **evento** es viable; si se acerca, se activa el **fallback** en `L1`.

## 5. Higiene

- La prueba va **fuera** de toda ventana de ataque.
- El manager se **restaura** (`<logall_json>no</logall_json>`) y se **verifica**.
- El **ruleset no se modifica**.
- **Alternativa declarada** (si `archives.json` no fuese viable): **contar en el origen**
  (auditd/Sysmon/FIM).

## 6. Referencias

- Especificación: `Soporte/Metrica/metrica_hids.md` §2; `_fases/reencuadre-metrica/plan.md` §2.2.
- Script: `Soporte/Laboratorio/ghosts/logall_json_ctl.sh`.

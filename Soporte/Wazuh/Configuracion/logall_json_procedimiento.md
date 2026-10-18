# Procedimiento `logall_json` (denominador `M`) — bloque `legitimo-infra` (L0)

> **Puntero y resumen.** El procedimiento completo, la **medida** y la **estimación a 72 h** viven
> en **`Soporte/Laboratorio/instrumentacion_denominador.md`**. Aquí queda el procedimiento
> operativo (para el `ossec.conf` del manager) y el estado final.
>
> **⚠️ `logall_json` queda APAGADO por defecto.** Solo se activa en la ventana de medida del
> legítimo (`L1`), **nunca** durante ataques. Tras la prueba de L0, `ossec.conf` quedó
> **idéntico** al original (`diff` sin diferencias).

## Activación / desactivación (manager)

```bash
# subcomandos: on | off | status | size | conf
bash Soporte/Laboratorio/ghosts/logall_json_ctl.sh on     # activa + reinicia el manager
bash Soporte/Laboratorio/ghosts/logall_json_ctl.sh size   # tamaño (bytes) + hora UTC
bash Soporte/Laboratorio/ghosts/logall_json_ctl.sh off    # desactiva + reinicia (vuelve a 'no')
bash Soporte/Laboratorio/ghosts/logall_json_ctl.sh status # verifica el valor y el estado
```

El script edita el bloque `<global>` de `/var/ossec/etc/ossec.conf`
(`<logall_json>yes|no</logall_json>`), guarda copia en
`/var/ossec/etc/ossec.conf.tfg-bak` y borra `archives.json` en cada arranque de la prueba.

## Qué NO cambia

- **No** se toca el **ruleset** ⇒ la **"virgen"** se preserva.
- **No** se altera el recuento de **detecciones** (es solo un *log* adicional).
- Los puertos del manager (`443/1514/1515/55000`) y el resto de su configuración **no se tocan**.

## Resultado de la prueba de L0 (2026-10-18)

- `archives.json`: `96 339` B → `1 151 095` B en `911 s` ⇒ **≈ 4,17 MB/h** ⇒ **≈ 300 MB a 72 h**.
- Umbral de fallback (`R2 §2.2`): **> 5 GB a 72 h** ⇒ **NO** se activa (300 MB ≪ 5 GB).
- Estado final: `<logall_json>no</logall_json>`, `archives.json` eliminado, manager `active`.

## Referencias

- `Soporte/Laboratorio/instrumentacion_denominador.md` (procedimiento + cifras + fallback).
- `Soporte/Metrica/metrica_hids.md` §2 (especificación congelada — **no se modifica**).

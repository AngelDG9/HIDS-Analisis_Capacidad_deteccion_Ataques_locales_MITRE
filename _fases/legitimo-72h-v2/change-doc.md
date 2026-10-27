# change-doc — Bloque `legitimo-72h-v2` (ventana de 72 h) — **ABORTADO POR DECISIÓN HUMANA**

> **Estado:** **ABORTADO** el **2026-10-27 a las ~16:20 local (15:20Z)**, tras **39 h 53 min** de ventana
> (de 72). **La decisión se tomó ANTES de analizar ningún resultado**: solo se habían leído señales de
> funcionamiento (agente vivo, disco, vigilancia). **Los datos no se analizan ni se publican.**

---

## 1. Qué se ejecutó

| Paso | Cuándo (UTC) | Resultado |
|---|---|---|
| E0 (ensayo de armado) | 25/10 20:44–21:39 | **PASA** (`ensayo_E0.md`) |
| `prep` | 25/10 23:15:00 | **Res=0**, 12/12 guardarraíles, 0 abortos |
| `arm` | 25/10 23:40:00 | **Res=0**, timer `NEXT=23:55Z`, cliente arriba |
| Ventana | 26/10 00:00Z → 27/10 15:20Z | **39 h 53 min** |
| Vigilancia | cada 30 min | **79 chequeos**, `Res=0` en todos |

## 2. Qué se observó (solo funcionamiento)

- **0 alarmas reales.** **4 `ALARMA` de borde**, todas falsas y del mismo patrón: el chequeo cae en el
  segundo en que empieza un bloque (08:00Z y 14:00Z) y compara con la acción del bloque anterior.
  Detalle en `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/incidencias.md`.
- Agente `001` **sin caídas** (latido 5–16 s). Manager `active` con 2 daemons en todos los chequeos.
- Disco de la víctima estable en **4,4 GB**. Host **172,6 GB**. **Sin reinicio** del host (uptime 22/10).
- Volumen: **≈383 MB** de `archives` y **≈352 MB** de alertas en 38 h (≈10 MB/h; proyección 724 MB a 72 h).

## 3. Por qué se aborta

**Decisión humana**, registrada antes de analizar: rehacer la ventana con **actividad legítima más
realista** (errores humanos, ritmo irregular pero fijo, más programas/ofimática, GUI ligera) y añadir una
**campaña dirigida de falsos positivos** (acciones benignas que *parecen* ataque, al estilo del TFM
hermano de Velociraptor). El fundamento y las alternativas están en `state.md` y en la conversación del
27/10; la regla aplicada es: *cualquier decisión de repetir una ventana se toma antes de analizar los
resultados*.

## 4. Qué se preserva y qué se descarta

**Preservado** (fuera del repo): `D:\TFG-VMs\legitimo-2026-10-26-piloto\` — **6 ficheros, 331,6 MiB**
(`ossec-archive-26.json.gz`, `ossec-alerts-26.json.gz`, `ossec-archive-27.json`, `ossec-alerts-27.json`,
2 `.sum`) + `MANIFEST.tsv` con bytes y `sha256` (el día 26 verificado contra el `sha256` calculado en el
manager). El día 27 es un **corte temporal** de un fichero vivo.

**Descartado:** `archives.json` quedó **borrado** por `logall_json off` (comportamiento previsto). Los
39 h **no se cuentan ni se publican**; si acaso, quedan como **piloto declarado**.

## 5. Lecciones para la próxima ventana (v3)

1. **Alarma de borde:** el `watch` no debe juzgar la señal 1 en el primer chequeo de un bloque; debe
   esperar a la primera acción (o aplicar una gracia de 15 min). Hoy produce **2 falsas alarmas/día**.
2. **Windows Update se auto-repara** (`wuauserv` volvió a `Running/Manual`): hay que re-pausar justo
   antes de `prep` (G-10 aborta con 47 si no).
3. **Nombres reales** de los ficheros del manager: `ossec-archive-NN.json[.gz]` (singular).
4. **`cleanup` intenta un SSH a la víctima** cuando ya está apagada (hueco inofensivo de 3 min).
5. La extracción debe **copiar antes** de apagar `logall_json` (confirmado: el `off` borra `archives.json`).

## 6. Estado final del laboratorio

**0 VMs** · **0 tareas** `TFG-Legit-*` · **0 reglas** `TFG-*` · `logall_json=no` · `CONFIG_IDENTICA` ·
**5 snapshots** intactos (incluido `lab-listo-legit-v2`) · `TFG_GUEST_PW` conservada ·
`wuauserv` = `Running/Manual` (**no pausado**, se re-pausará antes de la próxima `prep`) · `D:` 181,3 GB.

**No se tocó:** ataques, corpus, `Dataset/`, `Hojas/`, `Soporte/Metrica/`, recetas, ruleset ni snapshots.
**Sin commits ni push** (los hace el orquestador).

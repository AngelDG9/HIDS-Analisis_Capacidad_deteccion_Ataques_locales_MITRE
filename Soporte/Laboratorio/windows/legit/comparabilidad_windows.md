# Comparabilidad Linux ↔ Windows (ventana legítima)

> Documento **vivo** del bloque `windows-legit-prep` (W3-bis). Actualizado en **T3**
> (2026-11-11) con el **ruido medido del operador**, el umbral **5 %** y el **doble FPR**;
> revisado en **T3b** (etiqueta `67028`, keepalive 1–3 y aclaración `sin_operador`).
> **CA-W3b-19**: esta tabla debe quedar firmada antes de `t0`.

## H-COMP-1 — El operador de Linux no se veía por la telemetría, no por diseño

**Comprobado (2026-11-11, solo lectura)** sobre `Dataset/Legitimo/legitimo_72h/alertas_detalle.csv`
(**294.257** filas, ventana de 72 h):

| Comando del vigilante de Linux | Apariciones |
|---|---:|
| `df -P` | **0** |
| `MemAvailable` | **0** |
| `verificar_arreglos` | **0** |
| `verificar_internet_local` | **0** |
| `client_ctl.sh` | **0** |

**Causa:** el controlador de Linux ejecuta en el invitado por **VMware Tools**
(`invoke-OnVm`), y **`auditd` no audita** esos procesos. No es que el método fuera limpio:
es que **la telemetría de Linux no los ve**.

**Consecuencia:**
1. El **FPR canónico de Linux (0,857963) ya está limpio de operador**: no hay nada que separar.
2. **No hay que recalcular** la ventana de Linux.
3. En **Windows** el equivalente **sí se vería**: Sysmon registra los procesos hijos de
   `vmtoolsd.exe` (por eso existe `G-W8`). De ahí el **chivato por red**: 0 procesos y
   0 sesiones dentro del invitado.
4. Ambas ventanas quedan con **0 ruido de operador** ⇒ la comparación de FPR es limpia.

**Lo que sí es "ruido propio" en Linux** (y ya está separado): `wazuh-agentd` ⇒ **51.824**
alertas (`80791`). Es **auto-ruido del HIDS**, no del operador: se publica como sensibilidad
**"sin auto-ruido" = 0,664693** (`227.967 / 342.966`).

> **No confundir:** **0,664693 es `sin auto-ruido`, no `sin_operador`**. En Linux el
> `sin_operador` **no se puede descontar** (el operador es invisible, H-COMP-1), así que
> su valor sería el **canónico: 0,857963** (`294.252 / 342.966`). En Windows sí hay algo
> que descontar (`operador_uni`), y esa es la cifra que se compara con **0,857963**, no
> con 0,664693.

## H-COMP-2 — El ruido del operador de Windows se concentra en `prep`, no en la ventana

**Medido en T3** (2026-11-11, 41,5 min, agente `002`; detalle en
`evidencia/t3/resumen_ruido.md`):

| Fase | Total | Del operador | % del total |
|---|---:|---:|---:|
| `prep` + *setup* SSH (15:00–15:10Z) | 1.068 | **213** | **19,94 %** |
| **Ventana de medida** (15:11:00–15:52:30Z) | **365** | **0** | **0,0000 %** |

- Las 213 de `prep` son **sesiones SSH del propio `prep`/deploy** (`logon_operador` 163,
  `watch` 45, `keepalive` 4, `vmware_tools` 1). En la operación real **viven antes de `t0`**.
- **T3b (corrección de etiqueta):** `67028` (4672) ya **no** se marca por `win_user=angel`
  a secas (el 4672 no trae `logon_type`); se exige `logon_type=3`, IP del operador o
  `sshd_<pid>`. Bajan 34 filas de `prep`: **247 → 213**. La **ventana (365/0) no cambia**.
- El `watch` v4 **no toca el invitado** (`SSH_INVITADO=0` en los 3 chequeos) y el chivato
  `:9095` **no genera alertas** (`185001` es nivel 0; **0** menciones de `9095` en el log).
  Los 3 chequeos de T3 son **ad hoc (18 y 23 min entre ellos, no 30 min)** y con
  **`skip=1` = `G-W7`** (no había `ventana_actual.json` porque **no se ejecutó `arm`**);
  no es fallo: **T4 lo probará en el ensayo del cierre**.
- **Conclusión:** el ruido del operador **no entra en la ventana**; el umbral del **5 %**
  se cumple con **0 %** medido.

## Ruido medido y umbral (CA-W3b-13)

| Fuente del operador | Alertas en 41,5 min | Proyección 72 h |
|---|---:|---:|
| `watch` (sin SSH) | **0** | **0** |
| chivato (`POST :9095`) | **0** | **0** |
| keepalive (bucle persistente) | **0** (arranca en `prep`) | **0** si arranca antes de `t0`; **1–3 por recuperación** (≤ 9 declarado) |
| **Total** | **0** | **0–9** |

**Umbral:** **5 %** del numerador. Medido: **0/365 = 0,0000 %** ⇒ **PASA** con margen total.
Si en la ventana real apareciera ruido por encima del 5 %, **no se maquilla**: se publica
y se abre incidencia.

## Doble FPR (misma unidad que Linux)

Unidad **canónica** (CA-W3b-23): `FP_uni` = **línea de `archives`** con ≥ 1 alerta;
`M` = líneas de `archives` del endpoint `002` (`contar_denominador.py --agent-id 002
--estricto`). `metrica_hids.md:45-54, 86-96`.

```text
FPR_canonico     = FP_uni / M
FPR_sin_operador = (FP_uni - operador_uni) / M
```

- `operador_uni` = líneas de `archives` del agente cuyas `(timestamp, rule_id)` están en
  alertas marcadas `operador_legit=1` (`etiquetar_operador_legit.py --archives`).
- El **denominador no cambia** (igual que la sensibilidad «sin auto-ruido» de Linux).
- **No se calcula el FPR de Windows en T3**: la ventana de 72 h no existe. La función y la
  plantilla (`--plantilla`, `--fpr M FP OP`) están probadas con datos sintéticos
  (`M=1000, FP=200, OP=4 ⇒ 0,2 / 0,196`).
- **Prueba de unidad (Linux):** recalculado desde
  `Dataset/Legitimo/legitimo_72h/analisis/eventos_alerta_72h.csv.gz` (solo lectura):
  **294.252** líneas de alerta / **M=342.966** ⇒ **0,857963**. En Linux ese es también
  su **`sin_operador`** (el operador no se ve: nada que descontar). `auto_ruido=66.285`
  ⇒ **sin auto-ruido = 227.967 ⇒ 0,664693**, que es **otra sensibilidad** (ruido del
  **propio HIDS**) y **no** `sin_operador`. Reproduce las cifras publicadas ⇒ **la unidad
  es la misma** en las dos plataformas.

## Firma (CA-W3b-19)

> **Aprobado por el humano el 2026-11-11**, **antes de `t0`**. Con ello se aceptan:
> (1) unidad de `FP_uni` = **línea de `archives`**; (2) **catálogo autoritativo de 72 h**
> por plataforma; (3) **0 ruido de operador** (medido en Windows: 0/365; invisible en Linux);
> (4) **receta espejo** de 504 acciones; (5) las **diferencias declaradas** (7 vs 9 señales,
> cliente compilado del mismo commit, tarea `Interactive`, `M` de Windows pendiente de WE0-9).
> Las dos cifras se publicarán con el **mismo `M`**: `FPR_canonico` y `FPR_sin_operador`.

## Condiciones de comparabilidad (a mantener)

1. **Misma unidad**: `FP_uni` = **línea de `archives`**, en las dos plataformas.
2. **Mismo legítimo autoritativo**: catálogo de la ventana de 72 h de cada plataforma.
3. **0 ruido de operador** en ambas: **medido** en Windows (T3: 0/365); **no visible**
   en Linux (H-COMP-1) ⇒ **limpio en las dos**.
4. **Mismas técnicas y misma receta** (504 acciones espejo).
5. **Diferencia de canal declarada**: el `watch` de Linux leía el invitado por SSH (`df`);
   el de Windows v2 **no lo toca** (push). Es diferencia de **canal**, no de métrica.
6. **Diferencias declaradas**: 7 señales de vigilancia (Windows) vs 9 (Linux); cliente
   compilado del mismo commit; tarea `Interactive` vs servicio; `M` de Windows hasta WE0-9.

## T4 (2026-11-12) — prueba real de 2 h

La tabla anterior se **confirma** con la prueba de 2 h (11:00–13:00Z, `lab-listo-windows-ataques-gui`
+ cliente 8.3.1), **sin** cambiar la métrica:

| Dato medido | Valor |
|---|---|
| `watch` real | **5/5** chequeos `ok=9 fallos=0 skip=0`; **`SSH_INVITADO=0`**; `G-W7` **sin SKIP** |
| Latidos | **24/24 emitidos**, **23/24 recibidos** (1 ciclo de sink caído declarado); `seq` 3→26 |
| Keepalive | **1** `ka_pid` (256), **1** instancia, **0** procesos por ciclo |
| Recuperación del cliente | **1 ciclo** (5 min 6 s): 11:20:02Z → 11:25:08Z, `win_user=angel` |
| Duplicado | rechazado (`segunda_instancia`; `ka_instancias=1`) |
| Ruido del operador en la ventana | el `watch` **no entra**; el keepalive no crea procesos salvo la recuperación |

**Consecuencia para la comparabilidad:** se mantienen (1) unidad `FP_uni` = línea de `archives`
(`M` de la copia con `boveda_version=3`), (2) patrón de keepalive persistente, (3) `watch` cada
30 min (Windows por push; Linux por SSH, diferencia de canal declarada), (4) etiqueta
`sin_operador` y (5) unidad `FP/acción`/`FP/hora`. **No** se comparan `M` absoluto ni FPR crudo.
El `M` de la ventana de 72 h sigue pendiente de W4/WE0-9.

## Pendiente para T4 / W4

- **Ventana real** de 72 h (fecha la fija el humano): `M`, `FP_uni` y `operador_uni`
  sobre el **crudo** (`archives`) del agente `002`.
- **Ensayo de cierre**: probar `G-W7` con **`arm` real** (en T3 salió `skip=1` por no
  existir `ventana_actual.json`) y **capturar el log del `cleanup`** con las 2 tareas del
  invitado y el `armado.flag` ya retirados (T3 las borró por SSH sin dejar traza en el log
  de control).
- Publicar **las dos cifras** (canónico y `sin_operador`) con el mismo `M`.
- `M` absoluto y FPR crudo **no** se comparan con Linux (telemetrías distintas,
  `metrica_hids.md:66-68, 254-268`); **sí** la tasa (`FP/acción`, `FP/hora`) y el
  `sin_operador`.

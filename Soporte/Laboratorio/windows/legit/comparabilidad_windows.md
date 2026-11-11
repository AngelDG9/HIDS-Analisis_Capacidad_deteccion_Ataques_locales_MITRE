# Comparabilidad Linux ↔ Windows (ventana legítima)

> Nota viva. Se completará en **T3** con las tablas de ruido y el doble FPR.

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
alertas (`80791`). Es **auto-ruido del HIDS**, no del operador; se publica como sensibilidad
"sin auto-ruido" (`0,664693`).

## Condiciones de comparabilidad (a mantener)

1. **Misma unidad**: `FP_uni` = **línea de `archives`**, en las dos plataformas.
2. **Mismo legítimo autoritativo**: catálogo de la ventana de 72 h de cada plataforma.
3. **0 ruido de operador** en ambas (probado en Linux; por diseño en Windows).
4. **Mismas técnicas y misma receta** (504 acciones espejo).
5. **Diferencias declaradas**: 7 señales de vigilancia (Windows) vs 9 (Linux); cliente
   compilado del mismo commit; tarea `Interactive` vs servicio; `M` de Windows hasta WE0-9.

## Pendiente (T3)

- `ruido_watch.csv` / `ruido_keepalive.csv` de Windows.
- Etiquetador `sin_operador` de la ventana legítima.
- Doble FPR (canónico y `sin_operador`) en la misma unidad.
- Tabla final firmada.

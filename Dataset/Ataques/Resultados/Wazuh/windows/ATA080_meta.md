---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA080
tecnica: T1213.006
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA080 - T1213.006 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA080** |
| Tecnica | **T1213.006** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | sqlite3 .dump de una BD de juguete (20 filas) |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1213.006-Data_from_Databases/` |
| `sha256` ataque | `e0fc567f0f78e1277362f7595538cff1f3f0d80518de85dd113ceffd2a1d360f` |
| `sha256` esperado | `0eca337bdd42b8d5673640cf42796d8c2614dbe1894b04bfaef8a36dc7351836` |
| C0 | `Soporte/Ataques/c0/windows/ATA080_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T13:30:02Z` | `2026-11-09T13:30:04Z` | 2 s | 32 | **8** | `67027,92032,92052` | 14 |
| 2 | `2026-11-09T13:35:09Z` | `2026-11-09T13:35:10Z` | 1 s | 30 | **8** | `67027,92032,92052` | 12 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA080\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA080_iter{1,2}/efecto.txt`: dump.sql con 20 INSERT + sha256.

**Iter 1** (`sha256=725fc1003e1c1e19c494062440640badeb623d29b84fc155cdc094faca2b156d`):

```text
# ATA080 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T13:30:02Z t0=2026-11-09T13:30:02Z run=cmd /c C:\lab-attack\ATA080\run.cmd
2026-11-09T13:30:04Z t1=2026-11-09T13:30:04Z

evidencia_local:
  ata=ATA080
  tecnica=T1213.006
  fuente=manual
  t0=2026-11-09T13:30:04Z
  t1=2026-11-09T13:30:04Z
  db=C:\lab-attack\ATA080\datos.db
  dump=C:\lab-attack\ATA080\dump.sql
  filas=20
  sha256=1b81096438fc40a2364d3e211b08c8ca64425d123a9123ae623227ec5088156c

VEREDICTO: EFECTO DEMOSTRADO (dump.sql; 20 filas; sha256=1b81096438fc40a2364d3e211b08c8ca64425d123a9123ae623227ec5088156c)
```

**Iter 2** (`sha256=1f0f63efbc997684d55d20c9096b2397c9b3945ade8f64c9cb91eb41709d9a5a`):

```text
# ATA080 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T13:35:09Z t0=2026-11-09T13:35:09Z run=cmd /c C:\lab-attack\ATA080\run.cmd
2026-11-09T13:35:10Z t1=2026-11-09T13:35:10Z

evidencia_local:
  ata=ATA080
  tecnica=T1213.006
  fuente=manual
  t0=2026-11-09T13:35:10Z
  t1=2026-11-09T13:35:10Z
  db=C:\lab-attack\ATA080\datos.db
  dump=C:\lab-attack\ATA080\dump.sql
  filas=20
  sha256=1b81096438fc40a2364d3e211b08c8ca64425d123a9123ae623227ec5088156c

VEREDICTO: EFECTO DEMOSTRADO (dump.sql; 20 filas; sha256=1b81096438fc40a2364d3e211b08c8ca64425d123a9123ae623227ec5088156c)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA080_iter1-Detalle.csv` | 32 | `7f79070c7feb2381fa64f7a209ad6b62b0a754883ddf8075dd8264c7eb633680` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA080_iter2-Detalle.csv` | 30 | `7038fa43104181a470fcb871e9955965b62bf81fe03e6d77ecde297eafe4673f` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 32 | **8** | 3 | 7 | **0** | 14 | 32 | 0 | 0 | 0 |
| 2 | 30 | **8** | 3 | 8 | **0** | 11 | 30 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 8 | 3 -> `67027,92032,92052` | `2026-11-09T13:30:03.750Z` `rule_id=92052` |
| 2 | 8 | 3 -> `67027,92032,92052` | `2026-11-09T13:35:10.606Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 8 vs 8;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA080** es **manual**: el clon ART `388942ad` no trae T1213.006; se implementa `sqlite3 .dump` sobre una BD de juguete.
2. **Pre-staging**: `sqlite3.exe` se copia en **`C:\tfg-tools\sqlite3`**, fuera del FIM `C:\lab-attack`, para no generar eventos `554` de la copia. El `sqlite3.exe` sigue anclado por `*lab-attack*ATA080*`.
3. El efecto es `dump.sql` con 20 `INSERT` y `filas=20`.

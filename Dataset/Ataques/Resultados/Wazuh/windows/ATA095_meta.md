---
fase: 3b
bloque: B2
tanda: B2.2
ata_id: ATA095
tecnica: T1565.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA095 - T1565.001 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.2**. `esperado` **pre-registrado y sellado** en `a2eca10`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA095** |
| Tecnica | **T1565.001** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | alteracion in situ de libro.csv (A: 5000 -> 9999); sha256 antes != despues |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1565.001-Stored_Data_Manipulation/` |
| `sha256` ataque | `e68cd792a79be1396edc2427eabfaf82ab5ba0d883ec87a25896a26412b4c4da` |
| `sha256` esperado | `daa794f3521404d1e706bc4ee516d5df80cb81c4c2c5bde18819506c8b495855` |
| C0 | `Soporte/Ataques/c0/windows/ATA095_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T19:36:52Z` | `2026-11-09T19:36:57Z` | 5 s | 20 | **5** | `67027,92032,92052` | 5 |
| 2 | `2026-11-09T19:40:53Z` | `2026-11-09T19:40:57Z` | 4 s | 21 | **5** | `67027,92032,92052` | 6 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA095\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA095_iter{1,2}/efecto.txt`: libro.csv alterado; sha256_antes != sha256_despues.

**Iter 1** (`sha256=b18f42d833282407e35e17b6e56086a7e6242a653280d6dc15078a5a07a9b5c1`):

```text
# ATA095 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T19:36:52Z t0=2026-11-09T19:36:52Z run=cmd /c C:\lab-attack\ATA095\run.cmd
2026-11-09T19:36:57Z t1=2026-11-09T19:36:57Z

evidencia_local:
  ata=ATA095
  tecnica=T1565.001
  fuente=manual
  t0=2026-11-09T19:36:56Z
  t1=2026-11-09T19:36:56Z
  libro=C:\lab-attack\ATA095\libro.csv
  sha256_antes=7972e976ff8b9af3803d46a48c35516eefed4631bab790a758a04e3a9943941c
  sha256_despues=28540b793aaad023d36f33c65661143e3bacf445bb6f02cd0c56364fb720f980
  alterado=True

VEREDICTO: EFECTO DEMOSTRADO (libro.csv alterado; 7972e976ff8b... != 28540b793aaa...)
```

**Iter 2** (`sha256=34440b53e04d3b5af8c9d2238ff79adf2b199770e56921a723f4d0f4eced7ede`):

```text
# ATA095 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T19:40:53Z t0=2026-11-09T19:40:53Z run=cmd /c C:\lab-attack\ATA095\run.cmd
2026-11-09T19:40:57Z t1=2026-11-09T19:40:57Z

evidencia_local:
  ata=ATA095
  tecnica=T1565.001
  fuente=manual
  t0=2026-11-09T19:40:56Z
  t1=2026-11-09T19:40:56Z
  libro=C:\lab-attack\ATA095\libro.csv
  sha256_antes=7972e976ff8b9af3803d46a48c35516eefed4631bab790a758a04e3a9943941c
  sha256_despues=28540b793aaad023d36f33c65661143e3bacf445bb6f02cd0c56364fb720f980
  alterado=True

VEREDICTO: EFECTO DEMOSTRADO (libro.csv alterado; 7972e976ff8b... != 28540b793aaa...)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA095_iter1-Detalle.csv` | 20 | `8d5d4a5837684b895bbd440edd7584aecb2bde007d74e22cd97a3586302b465d` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA095_iter2-Detalle.csv` | 21 | `d97dd2c3933a2a75a4a6ccaa46c9db7cd10b907bb72bacf224b7eea1d3bc62ca` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 20 | **5** | 3 | 7 | **0** | 5 | 20 | 0 | 0 | 0 |
| 2 | 21 | **5** | 3 | 7 | **0** | 6 | 21 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:36:53.839Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:40:55.744Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA095** es **manual**: alteracion **in situ** de `libro.csv` (A: 5000 -> 9999); `sha256_antes != sha256_despues`. Pareja Windows de **ATA032**.
2. La huella del ataque es FIM `550`/`554`; el efecto es el `sha256` cambiado. El efecto no es deteccion.

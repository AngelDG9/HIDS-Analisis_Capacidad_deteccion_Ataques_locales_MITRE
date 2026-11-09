---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA084
tecnica: T1657
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA084 - T1657 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA084** |
| Tecnica | **T1657** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | libro local de juguete; transferencia de 1500 de A a B |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1657-Financial_Theft/` |
| `sha256` ataque | `f014d5741e813299f6c9a62353e6563834e3bcfba5496a67cc3997d770c4a1f0` |
| `sha256` esperado | `c4d3b34d7154e0a2fc8adf85bd45f16ce8a856a30b1ed3843894069b76087d6a` |
| C0 | `Soporte/Ataques/c0/windows/ATA084_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T14:42:46Z` | `2026-11-09T14:42:47Z` | 1 s | 20 | **5** | `67027,92032,92052` | 5 |
| 2 | `2026-11-09T14:46:33Z` | `2026-11-09T14:46:34Z` | 1 s | 20 | **5** | `67027,92032,92052` | 5 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA084\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA084_iter{1,2}/efecto.txt`: saldo A=3500 / B=2500; alterado=True.

**Iter 1** (`sha256=381bcebaadf3d39cee718cda7c30baa973d94fcb4aec1d56b6d7cd86f3921ba2`):

```text
# ATA084 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T14:42:46Z t0=2026-11-09T14:42:46Z run=cmd /c C:\lab-attack\ATA084\run.cmd
2026-11-09T14:42:47Z t1=2026-11-09T14:42:47Z

evidencia_local:
  ata=ATA084
  tecnica=T1657
  fuente=manual
  t0=2026-11-09T14:42:47Z
  t1=2026-11-09T14:42:47Z
  libro=C:\lab-attack\ATA084\libro.csv
  libro_after=C:\lab-attack\ATA084\libro_after.csv
  importe=1500
  saldo_A=3500
  saldo_B=2500
  alterado=True

VEREDICTO: EFECTO DEMOSTRADO (transferencia 1500; A=3500 / B=2500)
```

**Iter 2** (`sha256=8c87dcc18eec28871a438fdf28a74cab7ab4adb95167f6d4dd313eae68532aab`):

```text
# ATA084 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T14:46:33Z t0=2026-11-09T14:46:33Z run=cmd /c C:\lab-attack\ATA084\run.cmd
2026-11-09T14:46:34Z t1=2026-11-09T14:46:34Z

evidencia_local:
  ata=ATA084
  tecnica=T1657
  fuente=manual
  t0=2026-11-09T14:46:34Z
  t1=2026-11-09T14:46:34Z
  libro=C:\lab-attack\ATA084\libro.csv
  libro_after=C:\lab-attack\ATA084\libro_after.csv
  importe=1500
  saldo_A=3500
  saldo_B=2500
  alterado=True

VEREDICTO: EFECTO DEMOSTRADO (transferencia 1500; A=3500 / B=2500)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA084_iter1-Detalle.csv` | 20 | `a4ebc019d2dfc2fd1cf0f678ded0a4cca001b176e2b057f7aa55b6dbecb63c37` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA084_iter2-Detalle.csv` | 20 | `9b5e758f27320eba9f1885adceccd21d75273a5087b362e1eb3dfb5ba6fe0b2e` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 20 | **5** | 3 | 7 | **0** | 5 | 20 | 0 | 0 | 0 |
| 2 | 20 | **5** | 3 | 7 | **0** | 5 | 20 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:42:47.472Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:46:34.564Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA084** es **manual**: libro local `libro.csv` (`A=5000`, `B=1000`) y transferencia de **1500** de A a B; `libro_after.csv` con `A=3500`, `B=2500`.
2. El efecto es el saldo alterado (`alterado=True`).

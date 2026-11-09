---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA082
tecnica: T1185
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA082 - T1185 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA082** |
| Tecnica | **T1185** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | perfil de navegador sintetico (Cookies/Login Data) con cabecera SQLite |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1185-Browser_Session_Hijacking/` |
| `sha256` ataque | `74be1a9c44775e301c9cbc69411cc5f34198bd872ad68ebc2843ea3a391de2ac` |
| `sha256` esperado | `d528445d80dfc215b3255e2f6fbf68a2de46a0a30d83edbc1fc2d123dd44cd00` |
| C0 | `Soporte/Ataques/c0/windows/ATA082_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T14:26:58Z` | `2026-11-09T14:27:00Z` | 2 s | 23 | **5** | `67027,92032,92052` | 8 |
| 2 | `2026-11-09T14:31:09Z` | `2026-11-09T14:31:10Z` | 1 s | 23 | **5** | `67027,92032,92052` | 8 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA082\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA082_iter{1,2}/efecto.txt`: Cookies + Login Data copiados; cabecera SQLite format 3.

**Iter 1** (`sha256=2603f6da006ea869db3d5aab3f948c01d8db469d711b8bc85fdc3b9f5a9f0cb2`):

```text
# ATA082 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T14:26:58Z t0=2026-11-09T14:26:58Z run=cmd /c C:\lab-attack\ATA082\run.cmd
2026-11-09T14:27:00Z t1=2026-11-09T14:27:00Z

evidencia_local:
  ata=ATA082
  tecnica=T1185
  fuente=manual
  t0=2026-11-09T14:26:59Z
  t1=2026-11-09T14:27:00Z
  cookies=528
  login=528
  cabecera=SQLite format 3
  cabecera_null=True

VEREDICTO: EFECTO DEMOSTRADO (Cookies + Login Data; cabecera SQLite format 3)
```

**Iter 2** (`sha256=a0b9754cbc6bccabf910c6e7f47454c39a7d2bd6269ba1db0cec515c82871c64`):

```text
# ATA082 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T14:31:09Z t0=2026-11-09T14:31:09Z run=cmd /c C:\lab-attack\ATA082\run.cmd
2026-11-09T14:31:10Z t1=2026-11-09T14:31:10Z

evidencia_local:
  ata=ATA082
  tecnica=T1185
  fuente=manual
  t0=2026-11-09T14:31:10Z
  t1=2026-11-09T14:31:10Z
  cookies=528
  login=528
  cabecera=SQLite format 3
  cabecera_null=True

VEREDICTO: EFECTO DEMOSTRADO (Cookies + Login Data; cabecera SQLite format 3)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA082_iter1-Detalle.csv` | 23 | `19b5b86623f4969deebc93a4d05b7d999e371b79b0ab181b3d3547b004de7453` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA082_iter2-Detalle.csv` | 23 | `3c0f6cf526796a614bf93a5e1f3cd90a25013f002238aa4d44413e9f56349e3d` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 23 | **5** | 3 | 7 | **0** | 8 | 23 | 0 | 0 | 0 |
| 2 | 23 | **5** | 3 | 7 | **0** | 8 | 23 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:27:00.101Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:31:10.891Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA082** es **manual**: no hay navegador real; se crea un perfil sintetico con `Cookies` y `Login Data` (cabecera `SQLite format 3` + NUL) y se copian.
2. El efecto es la cabecera SQLite valida en los ficheros copiados.

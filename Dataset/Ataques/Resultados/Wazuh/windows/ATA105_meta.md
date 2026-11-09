---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA105
tecnica: T1056.003
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA105 - T1056.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA105** |
| Tecnica | **T1056.003** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | portal HttpListener 127.0.0.1:8081; POST de juguete; creds.txt |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1056.003-Web_Portal_Capture/` |
| `sha256` ataque | `ee468bed4db4b031598a0e8677bcdc9e08bbbcafc265e2dcfc782b5b68ae9016` |
| `sha256` esperado | `52e6fe1ef662af0d994b0bffb907ab06f2d94506a9880ce91cd4376ecf941979` |
| C0 | `Soporte/Ataques/c0/windows/ATA105_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:27:18Z` | `2026-11-09T22:27:28Z` | 10 s | 24 | **6** | `67027,92027,92032,92052` | 7 |
| 2 | `2026-11-09T22:31:31Z` | `2026-11-09T22:31:38Z` | 7 s | 22 | **6** | `67027,92027,92032,92052` | 6 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA105\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA105_iter{1,2}/efecto.txt`: creds.txt con usuario tfg_user y longitud de password.

**Iter 1** (`sha256=00a8378b1d2318df88292943a9f7924d5946452ea6be8970e0d54eabec38e990`):

```text
# ATA105 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:27:18Z t0=2026-11-09T22:27:18Z run=cmd /c C:\lab-attack\ATA105\run.cmd
2026-11-09T22:27:28Z t1=2026-11-09T22:27:28Z

evidencia_local:
  ata=ATA105
  tecnica=T1056.003
  fuente=manual
  t0=2026-11-09T22:27:27Z
  t1=2026-11-09T22:27:27Z
  portal=127.0.0.1:8081
  creds=C:\lab-attack\ATA105\creds.txt
  creds_capturadas=True
  usuario=tfg_user
  password_longitud=16

VEREDICTO: EFECTO DEMOSTRADO (creds_capturadas=True; usuario=tfg_user; password_longitud=16)
```

**Iter 2** (`sha256=ddf33fd086f382d25cb97c82e639561c7e2327de5f31075de0d08be2d74201b1`):

```text
# ATA105 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:31:31Z t0=2026-11-09T22:31:31Z run=cmd /c C:\lab-attack\ATA105\run.cmd
2026-11-09T22:31:38Z t1=2026-11-09T22:31:38Z

evidencia_local:
  ata=ATA105
  tecnica=T1056.003
  fuente=manual
  t0=2026-11-09T22:31:38Z
  t1=2026-11-09T22:31:38Z
  portal=127.0.0.1:8081
  creds=C:\lab-attack\ATA105\creds.txt
  creds_capturadas=True
  usuario=tfg_user
  password_longitud=16

VEREDICTO: EFECTO DEMOSTRADO (creds_capturadas=True; usuario=tfg_user; password_longitud=16)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA105_iter1-Detalle.csv` | 24 | `d36ab7d7ed5d29d8194113e8b672c7bf38e73609f9739ff79c39126ab70788eb` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA105_iter2-Detalle.csv` | 22 | `5cb3f57ecf769fc048b921dc53f62d6e2a1df0c68c5a10d6ff6dc90353348fae` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 24 | **6** | 3 | 8 | **0** | 7 | 24 | 0 | 0 | 0 |
| 2 | 22 | **6** | 3 | 7 | **0** | 6 | 22 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T22:27:20.423Z` `rule_id=67027` |
| 2 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T22:31:33.378Z` `rule_id=92032` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA105** es **manual** (no hay test ART para T1056.003). Portal `HttpListener` en `127.0.0.1:8081`; POST de juguete (`tfg_user` / `TFG-DUMMY-PASS`); `creds.txt` con credenciales **de juguete**, no secretos reales. Pareja de **ATA028**.
2. `password_longitud=16` incluye el CRLF del cuerpo; el usuario es `tfg_user`.

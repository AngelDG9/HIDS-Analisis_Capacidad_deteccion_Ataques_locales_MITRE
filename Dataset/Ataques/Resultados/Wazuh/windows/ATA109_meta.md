---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA109
tecnica: T1114.003
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA109 - T1114.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA109** |
| Tecnica | **T1114.003** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | perfil sintetico + regla de reenvio + sink local; .eml |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1114.003-Email_Forwarding_Rule/` |
| `sha256` ataque | `04c4be3c25b1d7a8c84f39d98fa9e11fe04053a76970c72aef15475b4eca5dac` |
| `sha256` esperado | `ceefc8ad362bc0c696202a85f759b61558ee27280036211415e6496e8d5444e2` |
| C0 | `Soporte/Ataques/c0/windows/ATA109_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T23:01:07Z` | `2026-11-09T23:01:10Z` | 3 s | 22 | **5** | `67027,92032,92052` | 7 |
| 2 | `2026-11-09T23:05:04Z` | `2026-11-09T23:05:09Z` | 5 s | 25 | **5** | `67027,92032,92052` | 9 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA109\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA109_iter{1,2}/efecto.txt`: .eml reenviado a sink@tfg.local.

**Iter 1** (`sha256=56ec229b1e214708e7b95d64006ff59e6a55e2e0cf4048ffa873d394684dc482`):

```text
# ATA109 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T23:01:07Z t0=2026-11-09T23:01:07Z run=cmd /c C:\lab-attack\ATA109\run.cmd
2026-11-09T23:01:10Z t1=2026-11-09T23:01:10Z

evidencia_local:
  ata=ATA109
  tecnica=T1114.003
  fuente=manual
  t0=2026-11-09T23:01:10Z
  t1=2026-11-09T23:01:10Z
  perfil=C:\lab-attack\ATA109\perfil
  regla=C:\lab-attack\ATA109\perfil\regla_reenvio.json
  destino=sink@tfg.local
  eml_reenviado=True
  eml_bytes=170

VEREDICTO: EFECTO DEMOSTRADO (eml_reenviado=True; destino=sink@tfg.local; bytes=170)
```

**Iter 2** (`sha256=5bb5131b926f9df765c444ce91665457a4e50b9d64c800c444d6eab49431b229`):

```text
# ATA109 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T23:05:04Z t0=2026-11-09T23:05:04Z run=cmd /c C:\lab-attack\ATA109\run.cmd
2026-11-09T23:05:09Z t1=2026-11-09T23:05:09Z

evidencia_local:
  ata=ATA109
  tecnica=T1114.003
  fuente=manual
  t0=2026-11-09T23:05:08Z
  t1=2026-11-09T23:05:08Z
  perfil=C:\lab-attack\ATA109\perfil
  regla=C:\lab-attack\ATA109\perfil\regla_reenvio.json
  destino=sink@tfg.local
  eml_reenviado=True
  eml_bytes=170

VEREDICTO: EFECTO DEMOSTRADO (eml_reenviado=True; destino=sink@tfg.local; bytes=170)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA109_iter1-Detalle.csv` | 22 | `a65371d41988b5fd466845618a75c96dc9e5d36736644ab215369d82e7b2624f` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA109_iter2-Detalle.csv` | 25 | `876b555c68a5d96aaec9db1446884ac8fe63aad4ea6736d35aa677ff855bd6a0` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 22 | **5** | 3 | 7 | **0** | 7 | 22 | 0 | 0 | 0 |
| 2 | 25 | **5** | 3 | 8 | **0** | 9 | 25 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T23:01:09.052Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T23:05:06.522Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA109** es **manual** (no hay test ART para T1114.003). Perfil sintetico + `regla_reenvio.json` (`sink@tfg.local`) + carpeta sink; `.eml` copiado (`eml_reenviado=True`, 170 B). Pareja de **ATA015**.
2. Sin Outlook/Exchange/SMTP; el reenvio se simula con una carpeta local.

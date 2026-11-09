---
fase: 3b
bloque: B2
tanda: B2.2
ata_id: ATA093
tecnica: T1560.002
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA093 - T1560.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.2**. `esperado` **pre-registrado y sellado** en `a2eca10`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA093** |
| Tecnica | **T1560.002** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | .zip por System.IO.Compression.ZipFile (no Compress-Archive); 20 entradas; sha256 y extraccion verificados |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1560.002-Archive_via_Library/` |
| `sha256` ataque | `305bd28a26f18e85c197ed53bbe4f3b41fe37dc2f95c32e63211fc90ab0639d2` |
| `sha256` esperado | `3e1b90d6424fe8c1d64d4e57e02425bdfb53f98c69fd0cb24b4adfee6ae1ee46` |
| C0 | `Soporte/Ataques/c0/windows/ATA093_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T19:21:22Z` | `2026-11-09T19:21:26Z` | 4 s | 61 | **5** | `67027,92032,92052` | 46 |
| 2 | `2026-11-09T19:25:29Z` | `2026-11-09T19:25:31Z` | 2 s | 60 | **5** | `67027,92032,92052` | 45 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA093\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA093_iter{1,2}/efecto.txt`: archivo.zip con 20 entradas; extraido_ok=True.

**Iter 1** (`sha256=b313d07dfe01d56eebdf3594fdf98d362dc8a5d78a1b13aeda54aa84d33f1a81`):

```text
# ATA093 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T19:21:22Z t0=2026-11-09T19:21:22Z run=cmd /c C:\lab-attack\ATA093\run.cmd
2026-11-09T19:21:26Z t1=2026-11-09T19:21:26Z

evidencia_local:
  ata=ATA093
  tecnica=T1560.002
  fuente=manual
  t0=2026-11-09T19:21:25Z
  t1=2026-11-09T19:21:25Z
  zip=C:\lab-attack\ATA093\archivo.zip
  entradas=20
  zip_sha256=25f4c212e4ae9645e9d0b98922560348718eb95b06af8f6a6a13e29ae7bd8c00
  extraido_ok=True

VEREDICTO: EFECTO DEMOSTRADO (zip con 20 entradas; extraido_ok=True; sha256=25f4c212e4ae9645e9d0b98922560348718eb95b06af8f6a6a13e29ae7bd8c00)
```

**Iter 2** (`sha256=02d1f50bc8ec802d87c4d5b039a71deb278194ebcfdf86e492a41f52ccc01c47`):

```text
# ATA093 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T19:25:29Z t0=2026-11-09T19:25:29Z run=cmd /c C:\lab-attack\ATA093\run.cmd
2026-11-09T19:25:31Z t1=2026-11-09T19:25:31Z

evidencia_local:
  ata=ATA093
  tecnica=T1560.002
  fuente=manual
  t0=2026-11-09T19:25:30Z
  t1=2026-11-09T19:25:30Z
  zip=C:\lab-attack\ATA093\archivo.zip
  entradas=20
  zip_sha256=ed64fe6767d34f33174432038299907918256831a86a044021aa8bc7e281040c
  extraido_ok=True

VEREDICTO: EFECTO DEMOSTRADO (zip con 20 entradas; extraido_ok=True; sha256=ed64fe6767d34f33174432038299907918256831a86a044021aa8bc7e281040c)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA093_iter1-Detalle.csv` | 61 | `0c10636799584a0c5ddce62054a46b55e0984a92f1173f67d44c0014bc59a365` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA093_iter2-Detalle.csv` | 60 | `9098021a03ae614403ad26a4e629afacbbd2d0b886c90b25ca88d1297ced99a4` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 61 | **5** | 3 | 7 | **0** | 46 | 61 | 0 | 0 | 0 |
| 2 | 60 | **5** | 3 | 7 | **0** | 45 | 60 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:21:23.792Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:25:31.269Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA093** es **manual**: `.zip` por **libreria .NET** (`System.IO.Compression.ZipFile`), **no** `Compress-Archive`; 20 entradas; `sha256` del zip y extraccion verificada (`extraido_ok=True`). Pareja Windows de **ATA013** (FN en Linux).
2. Hallazgo: en iter1 disparo **`91846`** ("Powershell used .NET compression method, possible data extraction operation", 4104). **No estaba en el `esperado`**; se clasifico `artefacto_ataque` (no se cambia el sello). Candidata a senal del catalogo v2 / B2.5.
3. El efecto no es deteccion: se prueba en `efecto.txt`.

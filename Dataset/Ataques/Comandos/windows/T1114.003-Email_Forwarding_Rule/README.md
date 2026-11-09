# ATA109 - T1114.003 Email Forwarding Rule (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay test ART para T1114.003 en el clon. Pareja Windows de **ATA015** (Linux).

## 2. Que hace

1. Crea un **perfil de correo sintetico** `perfil\` con `inbox\mensaje.eml` de juguete.
2. Crea la **regla de reenvio** `perfil\regla_reenvio.json` (destino `sink@tfg.local`).
3. `t0`: aplica la regla y copia el `.eml` a `sink\mensaje.eml`.
4. Verifica `eml_reenviado=True` y el tamano.

**Guardarrail**: solo `C:\lab-attack\ATA109\`; <=64 MiB; <=120 s; sin Outlook/Exchange/SMTP.
El sink es una carpeta local; no se envia correo real.

## 3. Prueba de efecto

`efecto_local.txt` con `eml_reenviado=True`, `destino=sink@tfg.local`, `eml_bytes>0`.

## 4. `esperado`

`ATA109_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA109*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA109\run.cmd"
```

## 6. Notas

- Sin Outlook/Exchange; el reenvio se simula con una carpeta sink.
- Si la copia falla, `efecto_parcial` declarado.

# ATA104 - T1056.002 GUI Input Capture (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**ART adaptado**. Test #2 "PowerShell - Prompt User for Password":

| Campo | Valor |
|---|---|
| `guid` | `2b162bfd-0928-4d4c-9ec3-4d9f88374b52` |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1056.002/T1056.002.yaml` |
| Commit | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |

**Adaptacion**: el test abre un `PromptForCredential` y escribe la contrasena. En el
laboratorio se usa un **formulario GUI de juguete** (WinForms), se escribe `TFG-GUI-TEXT` con
`SendKeys` y se captura la pantalla a `captura.png`. Pareja Windows de **ATA053** (Linux).

## 2. Que hace

1. Crea un formulario WinForms con un `TextBox` y lo muestra (`TopMost`).
2. `SendKeys` escribe `TFG-GUI-TEXT`; se lee el texto.
3. Captura la pantalla primaria a `captura.png` (`CopyFromScreen`).
4. Verifica `png_bytes > 0` y `texto == TFG-GUI-TEXT`.

**Guardarrail**: solo `C:\lab-attack\ATA104\`; <=64 MiB; <=120 s; sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `png_bytes>0`, `texto=TFG-GUI-TEXT`, `captura_ok=True`.

## 4. `esperado`

`ATA104_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA104*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista (S1)

- Snapshot **`lab-listo-windows-ataques-gui`** (autologon).
- El runner (`-S1`) crea la tarea **`TFG-Attack-ATA104`** (`InteractiveToken`, trigger
  `t0+30 s`) que ejecuta `cmd /c C:\lab-attack\ATA104\run.cmd`; espera `efecto_local.txt`,
  fija `t1` y borra la tarea.
- Helper manual: `preparar_tarea_s1.ps1` (registra la misma tarea).

## 6. Notas

- Si la sesion no esta desbloqueada o `SendKeys`/captura falla, `efecto_parcial` declarado.
- **S1** es la via principal; **S2** (sin GUI) daria `efecto_parcial`.

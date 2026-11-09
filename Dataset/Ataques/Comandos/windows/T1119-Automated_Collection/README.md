# ATA108 - T1119 Automated Collection (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**ART adaptado**. Test #1 "Automated Collection Command Prompt":

| Campo | Valor |
|---|---|
| `guid` | `cb379146-53f1-43e0-b884-7ce2c635ff5b` |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1119/T1119.yaml` |
| Commit | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |

**Adaptacion**: el test recorre `c:\` buscando `*.docx` y copia a `%temp%`. En el laboratorio
se parametriza a `fuentes\` (20 `doc_XX.docx` de juguete) y `staging\`. Pareja Windows de
**ATA012** (Linux). Rutas parametrizadas; sin tocar el resto del disco.

## 2. Que hace

1. Crea `fuentes\` con 20 ficheros `.docx` de juguete.
2. `t0`: recorre `fuentes\` y copia cada fichero a `staging\`.
3. Verifica 20 ficheros recolectados.

**Guardarrail**: solo `C:\lab-attack\ATA108\`; <=200 ficheros, <=64 MiB, <=120 s; sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros_recolectados=20`, `recoleccion_ok=True`.

## 4. `esperado`

`ATA108_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA108*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA108\run.cmd"
```

## 6. Notas

- La recoleccion es local; no recorre `C:\` ni rutas del sistema.
- Si la copia falla, `efecto_parcial` declarado.

# `PROMOCION.md` — promoción de la ventana `legitimo-v3` a `Dataset/`

> Ventana **2026-11-02T00:00:00Z .. 2026-11-05T00:00:00Z** · veredicto **VÁLIDA CON INCIDENCIA** (V6) ·
> `metrica_version=1`, `boveda_version=2`.
> Copia **desde** `Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/` y
> `Soporte/Laboratorio/legitimo_72h/campana/` (los originales **no** se modifican).
> A cada CSV se le antepone **una línea `#`** de procedencia con
> `t0`/`t1` y el `sha256` del origen; la copia, sin esa línea, es **byte a byte idéntica**
> al origen.

| Fichero | `sha256` origen | `sha256` copia promovida | Bytes |
|---|---|---|---|
| `alertas_detalle.csv` | `cc6af47e8bb4442d792c5121c6c2db34ac78c3c2a69963a35a8fdd24e9a07ec5` | `654f910d85dc46157cdd1f13c97f5d9f705ed14085dd897d04a204ba449a5bd4` | 51489439 |
| `ruleids_legitimos.csv` | `399c4b06a8c799fc2e0de4f060ede51996381efb6d8f3c7d23f104cf8a2ceb65` | `e300ae3c75fd39877e21837a250a3947e4450c6e5238a2d8a4b24ae526069c61` | 1658 |
| `denominador_M.csv` | `109fea517f762082b44f83de0888578dc9c7658f67499dd9921831192e6aec4f` | `0e6753fcdabafa1c14b3383a1a4dc8104ad81c554c6c41f024761566b0a488a1` | 1031 |
| `ghosts_acciones.csv` | `4312d652a9bbecafe5c4a7d71dbf3f28ec1721bee164868baca69fc896d83b0a` | `dc49bca12aff13d9c3889c96f2e29b3157d51bb27f2b7fc9c624eb98c452443f` | 1286 |
| `campana_fp.csv` | `f41ea4ee9bcf9acbdd8ad4bc2d5c8ffbc0d2828dec872a6efc01ff68fc579d20` | `c320264627d59576c0c4b848406f1d11cc8ee9d007b597d79ca88febb37583d3` | 1592 |
| `ventana_meta.md` | `e740c6603edbc0a74b3f87ec685031828b4de86d728799ffaa143abe75d6d179` | `e740c6603edbc0a74b3f87ec685031828b4de86d728799ffaa143abe75d6d179` | 13533 |
| `campana_ventanas.tsv` | `6b07a3506e51211d1a82941145a844f2dfc24c616269eea1d4109f9d6e3e7323` | `b7ff7b173d69f21a3c6179d1ba0e76a5eab56af6637acd4f35f7d5072865ce0f` | 946 |

## Ficha inválida anterior (L1, 19–22/10)

La ficha **PREPARADA** de L1 que ocupaba `Dataset/Legitimo/legitimo_72h/ventana_meta.md`
se **retiró** el 2026-11-05. Su contenido es idéntico (salvo fin de línea CRLF) a
`Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/ventana_meta_INVALIDA_2026-10-19.md`
(LF, `sha256 061d555bebc923369c7a4f48dca6db9be5122324b21c3284beafc1dfe3b2451a`).
Huella de la copia retirada (CRLF): **`1fe77e48bb3e5c99f796e057bdcfaa81848ec23ba43883e64c6826698c9fbd07`**.

## Trazabilidad

- Productos y evidencia: `Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/`.
- Campaña FP: `Soporte/Laboratorio/legitimo_72h/campana/` (`campana_ventanas.tsv`).
- Veredicto literal: `…/veredicto_validez.md`. Ficha: `…/ventana_meta.md`.
- Sellado: `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` (v3) +
  `Soporte/Metrica/boveda_congelacion.md` (v2).

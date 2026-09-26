# Pre-flight anti-enmascaramiento (Fase 3 · A2.2 · R-09/R-13)

> Herramienta: `_artefactos/scripts/preflight_enmascaramiento.py`.
> **Solo `RESULTADO: PASA` (`exit 0`) permite desplegar reglas propias.**

## Entradas

- reglas propias RS3: Soporte/Wazuh/Reglas/local_rules.xml sha256=5f7b1502a8d13fff078ea196e09fc5aeac21ad7bcd0bc248fa28fca365783014 n=0
- reglas propias RS4: Soporte/Wazuh/Reglas/external_reserved.xml sha256=4bb9f674450ed3e953726031c7e7ea5438fe136ed860dc26797877f8a598e7ae
- ruleset base: Soporte/Wazuh/Configuracion/active_ruleset.txt sha256=64213db71cb9497270f6b0281cc806146cb76b81e55781e8289af722678ad72b n=168 rangos
- declaraciones: Soporte/Wazuh/Configuracion/solapamientos_declarados.csv sha256=43ce5a5d329fd9278142434a7a2aec695026d1f1dd86e9335083a00abd63290a n=0
- logtest base: (no aportado)
- logtest candidato: (no aportado)
- logtest base C0: _artefactos/scripts/tests/fixtures/c0_logtest_python3_ls.txt sha256=112c177f3841f35ce9304c274f5b1a06dcc01040e36b303226adc86ef1a7fce8 n=2

## C0 · base-contra-base (empírico, logtest con el ruleset base)

Estado: **EJECUTADO**
Eventos analizados: **2**
Avisos (ganadora de fábrica con `level=0`: no emite alerta -> detección esperada silenciada):
  - evento 1: ganadora `92600` (level 0) -> AVISO: detección esperada silenciada por regla de fábrica `92600`

## C1 · Cadena `<if_sid>`/`<if_matched_sid>` (estático, offline)

Reglas propias analizadas: **0**
  - (ninguna)

Cadenas que alcanzan una base (ENMASCARA):
  - (ninguna)

Ancestros no resolubles:
  - (ninguno)

## C2 · Hermana (empírico, logtest diferencial)

Estado: **NO EJECUTADO**

AVISO: no se aportaron las capturas `--logtest-base` y `--logtest-candidato`; **C2 NO EJECUTADO** (nunca se pasa en silencio) -> resultado **INCOMPLETO**.

## Declaraciones aplicadas

  - (ninguna)

Avisos:
  - 0 reglas propias -> PASA trivial (C2 no se exige)

RESULTADO: PASA (AVISOS: C0=1)

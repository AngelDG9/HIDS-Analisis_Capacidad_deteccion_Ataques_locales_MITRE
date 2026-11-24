# Verificacion independiente de V1 (55 casos x 2, cfgS)

- sha256 del crudo (MANIFEST.tsv): 2158 ficheros OK
- ventanas OK: 110 de 110 esperadas
- recorte EBPF recomputado desde crudo == guardado, y anclas de auditd y de EBPF recomputadas desde el crudo == analisis (regla corregida), y == meta donde la regla antigua coincide, en las 110 ventanas (los fallos, si los hay, se listan abajo)
- determinismo iter1 vs iter2 (anclas auditd y EBPF): 49 de 55 casos IGUALES; difieren 6
  - ATA021: auditd {'T1029-S1': 5, 'T1029-S2': 1, 'T1029-S3': 74} vs {'T1029-S1': 5, 'T1029-S2': 1, 'T1029-S3': 21} | EBPF {'T1029-S1': 5, 'T1029-S2': 1, 'T1029-S3': 74} vs {'T1029-S1': 5, 'T1029-S2': 1, 'T1029-S3': 21}
  - ATA045: auditd {'T1499.001-S1': 1, 'T1499.001-S2': 4, 'T1499.001-S3': 3, 'T1499.001-S4': 2, 'T1499.001-S5': 19} vs {'T1499.001-S1': 1, 'T1499.001-S2': 4, 'T1499.001-S3': 3, 'T1499.001-S4': 1, 'T1499.001-S5': 19} | EBPF {'T1499.001-S1': 1, 'T1499.001-S2': 1, 'T1499.001-S3': 3, 'T1499.001-S4': 2, 'T1499.001-S5': 16} vs {'T1499.001-S1': 1, 'T1499.001-S2': 1, 'T1499.001-S3': 3, 'T1499.001-S4': 1, 'T1499.001-S5': 16}
  - ATA047: auditd {'T1499.002-S1': 402, 'T1499.002-S2': 1201, 'T1499.002-S3': 2, 'T1499.002-S4': 4, 'T1499.002-S5': 1631} vs {'T1499.002-S1': 402, 'T1499.002-S2': 1201, 'T1499.002-S3': 2, 'T1499.002-S4': 4, 'T1499.002-S5': 1631} | EBPF {'T1499.002-S1': 252, 'T1499.002-S2': 1, 'T1499.002-S3': 2, 'T1499.002-S4': 1, 'T1499.002-S5': 275} vs {'T1499.002-S1': 292, 'T1499.002-S2': 1, 'T1499.002-S3': 2, 'T1499.002-S4': 1, 'T1499.002-S5': 315}
  - ATA049: auditd {'T1567.002-S1': 1, 'T1567.002-S2': 13} vs {'T1567.002-S1': 1, 'T1567.002-S2': 13} | EBPF {'T1567.002-S1': 1, 'T1567.002-S2': 12} vs {'T1567.002-S1': 1, 'T1567.002-S2': 13}
  - ATA052: auditd {'T1115-S1': 2, 'T1115-S2': 812} vs {'T1115-S1': 2, 'T1115-S2': 812} | EBPF {'T1115-S1': 2, 'T1115-S2': 219} vs {'T1115-S1': 2, 'T1115-S2': 221}
  - ATA054: auditd {'T1498.002-S1': 3, 'T1498.002-S2': 33, 'T1498.002-S3': 53} vs {'T1498.002-S1': 3, 'T1498.002-S2': 33, 'T1498.002-S3': 53} | EBPF {'T1498.002-S1': 3, 'T1498.002-S2': 22, 'T1498.002-S3': 42} vs {'T1498.002-S1': 3, 'T1498.002-S2': 22, 'T1498.002-S3': 41}

**RESULTADO: OK, sin fallos.**

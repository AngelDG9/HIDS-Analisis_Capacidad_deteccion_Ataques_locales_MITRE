# Verificacion independiente de la pasada de ojos (cfgS)

- sha256 del crudo (MANIFEST.tsv): 472 ficheros OK
- ventanas OK: 18 de 18 esperadas
- recorte EBPF recomputado desde crudo == guardado, y anclas de auditd recomputadas == meta, en las 18 ventanas (ver fallos)
- determinismo iter1 == iter2 (anclas auditd y EBPF) en los 9 casos

**RESULTADO: OK, sin fallos.**

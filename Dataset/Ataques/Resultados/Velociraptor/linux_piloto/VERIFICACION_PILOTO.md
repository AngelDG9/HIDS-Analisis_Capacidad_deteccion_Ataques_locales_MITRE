# Verificacion del piloto V0d de Velociraptor (Linux)

Recomputado desde la copia cruda con codigo independiente del extractor.

- ficheros del crudo verificados contra MANIFEST: 35
- ventanas revisadas: 18
- **fallos: 0**
- diferencias iter1 vs iter2 en 'visto/no visto' de anclas: 0

## Tabla caso x artifact (filas en la ventana; anclas estrictas de EBPF)

| cfg | ventana | EBPF | ProcessExecutions | TrackProcesses | Journal | DNS | anclas estrictas EBPF |
|---|---|---|---|---|---|---|---|
| E | ATA001_iter1 | 9804 | 0 | 0 | 0 | 0 | {"T1486-S1": 2, "T1486-S2": 10} |
| E | ATA001_iter2 | 8953 | 0 | 0 | 0 | 0 | {"T1486-S1": 2, "T1486-S2": 10} |
| E | ATA002_iter1 | 9047 | 0 | 0 | 0 | 0 | {"T1485-S1": 2} |
| E | ATA002_iter2 | 8934 | 0 | 0 | 0 | 0 | {"T1485-S1": 2} |
| E | ATA008_iter1 | 9648 | 0 | 0 | 0 | 0 | {"T1048-S1": 1} |
| E | ATA008_iter2 | 9675 | 0 | 0 | 0 | 0 | {"T1048-S1": 1} |
| E | ATA009_iter1 | 9125 | 0 | 0 | 0 | 0 | {"T1567-S1": 1, "T1567-S2": 6} |
| E | ATA009_iter2 | 8972 | 0 | 0 | 0 | 0 | {"T1567-S1": 1, "T1567-S2": 6} |
| E | ATA011_iter1 | 9068 | 0 | 0 | 0 | 0 | {"T1074-S1": 3, "T1074-S2": 3, "T1074-S3": 12} |
| E | ATA011_iter2 | 8960 | 0 | 0 | 0 | 0 | {"T1074-S1": 3, "T1074-S2": 3, "T1074-S3": 12} |
| E | ATA012_iter1 | 12091 | 0 | 0 | 0 | 0 | {"T1119-S1": 23, "T1119-S2": 1, "T1119-S3": 1, "T1119-S4": 12} |
| E | ATA012_iter2 | 9391 | 0 | 0 | 0 | 0 | {"T1119-S1": 23, "T1119-S2": 1, "T1119-S3": 1, "T1119-S4": 12} |
| O | ATA001_iter1 | 0 | 0 | 0 | 216 | 192 | - |
| O | ATA002_iter1 | 0 | 0 | 0 | 211 | 196 | - |
| O | ATA008_iter1 | 0 | 0 | 0 | 236 | 200 | - |
| O | ATA009_iter1 | 0 | 0 | 0 | 221 | 172 | - |
| O | ATA011_iter1 | 0 | 0 | 0 | 204 | 200 | - |
| O | ATA012_iter1 | 0 | 0 | 0 | 205 | 108 | - |

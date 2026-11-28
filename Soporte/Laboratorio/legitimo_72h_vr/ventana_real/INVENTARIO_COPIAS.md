# Inventario de datos y copias - V1-L (cierre 2026-11-28)

**Regla:** original en `D:` (disco duro HDD) y copia en `C:` (SSD distinto, comprobado: son 2 discos fisicos). Falta la tercera copia **fuera del PC** (disco externo, pendiente).

## Original (D:) -> copia (C:\TFG-copia)
| Que es | Original en D: | Copia en C: (zip, testzip OK) |
|---|---|---|
| **Cosecha V1-L completa** (EBPF + auditd + acciones + evidencia de VM y PC, 1323 ficheros con sha256) | `D:\TFG-VMs\legitimo-vr-2026-11-25` (8,9 GB) | `velociraptor-v1l\V1L_cosecha.zip` (750 MB; MANIFEST igual) |
| Informes pequenos de la ventana (veredicto, denominador, incidencias, meta) + logs del PC | este directorio (git) | `velociraptor-v1l\productos\` |
| Base de datos de GHOSTS (PostgreSQL parado en frio) + logs de GHOSTS | `D:\TFG-VMs\material-ghosts\{pgdata,logs,api}` | `velociraptor-v1l\GHOSTS_pgdata_y_logs.zip` |
| Servidor Velociraptor sin los datos de clientes (server.log y archivados, configs, artefactos de servidor). **Contiene claves: NUNCA a git** | `D:\TFG-VMs\velociraptor-server` | `velociraptor-v1l\VR_servidor_sin_clientes.zip` |
| Logs de laboratorio (web, sinks, vigilancia) | `D:\TFG-VMs\lab-logs` | `velociraptor-v1l\lab-logs_V1L.zip` |
| Ensayo E0 (24/11) | `D:\TFG-VMs\legitimo-vr-ensayo-E0` | `velociraptor-v1l\E0_cosecha.zip` |
| V1 ataques (110/110) | `D:\TFG-VMs\ataques-velociraptor-linux-v1` | `velociraptor-v1\crudo_v1_completo.zip` |
| V1 ojos / piloto | `D:\TFG-VMs\ataques-velociraptor-linux-{ojos,piloto}` | `velociraptor-v1\ataques-velociraptor-linux-{ojos,piloto}.zip` |
| Wazuh (Linux + Windows, ataques y legitimo) | `D:\TFG-VMs\{legitimo-*,ataques-*,crudo-*}` | `wazuh\*.zip` (11) |
| Codigo, planes, resultados, memoria | repo `D:\TFG\HIDS-...` | GitHub (rama main) |

Huellas sha256 de los zips de Velociraptor: `C:\TFG-copia\SHA256_copias_velociraptor.txt` (tambien abajo).

## Maquina virtual
`D:\TFG-VMs\victima-linux` (14 GB, 9 snapshots). El estado final de la ventana esta en el snapshot **`post-legit-vr-2026-11-28`**. **No cabe en C:** (13 GB libres) -> solo se puede copiar al disco externo.

## Huellas sha256 (zips en C:)
```
77c6938206bd51acdf2f8b34b41f0bb1a6f114a143014150454d87fcbeb505f4  velociraptor-v1l/E0_cosecha.zip  44782677
f007985cc88b10157b754b2d32cae53580755e55fbd8e6b23a8dd383ddb2ef57  velociraptor-v1l/GHOSTS_pgdata_y_logs.zip  108158936
133f7896d8a28f8b715d06d90765d9e3d1c5ae7b0cd8730d221a1ed151b30bb8  velociraptor-v1l/V1L_cosecha.zip  786871312
c6a67c693c3d6119411775c87967921d632cdcbe06705304a494fc0a00671bd7  velociraptor-v1l/VR_servidor_sin_clientes.zip  1430046
35d884d063eca58d04a17bd013f702fcc088162773a01bfa8bef7b80f00fca12  velociraptor-v1l/lab-logs_V1L.zip  18445342
1a3ba9dc2645cced78aa8c882203bf4cd40437aea1146a65971648739a856f87  velociraptor-v1/ataques-velociraptor-linux-ojos.zip  83454365
200bb538a58c3f17dc070a2d65400f4a6a544314016354f706d13fec2b262157  velociraptor-v1/ataques-velociraptor-linux-piloto.zip  12993939
b0c59b5bfb0b4ef97140b2412afe2c81ec00ba8f1b40488d2ce0b6c51ccf4bc9  velociraptor-v1/crudo_v1_completo.zip  302258919
```

## Extra (2026-11-28, tras cerrar la ventana)
Logs de la VM no incluidos en la cosecha (`/var/log` sin audit, journal de todos los arranques, dmesg, last, dpkg, servicios): original `D:\TFG-VMs\legitimo-vr-2026-11-25\evidencia_vm_extra` -> copia `C:\TFG-copiaelociraptor-v1l\VM_evidencia_extra_post_ventana.zip`. Se extrajeron encendiendo la VM despues de t1 (servidor VR parado para no ensuciar el datastore); el journal cubre 22/09 -> 28/11 00:36Z. La VM quedo apagada; el estado de referencia sigue siendo el snapshot `post-legit-vr-2026-11-28`.
`a62fa2fd238274696554ad8c1617968db1ef76adf16a9af2f55d52ca14dadadb  VM_evidencia_extra_post_ventana.zip`

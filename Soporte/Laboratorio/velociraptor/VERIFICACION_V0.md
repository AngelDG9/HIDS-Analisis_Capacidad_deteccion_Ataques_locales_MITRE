# Verificación independiente del montaje V0 de Velociraptor (2026-11-21)

Un agente que no vio mis conclusiones comprobó `MONTAJE_V0.md` y el inventario contra la máquina real (solo lectura, sin sudo).

| Comprobación | Resultado |
|---|---|
| v0.77.3 es la última estable (2026-10-05); 0.77.2 y 0.76.7 anteriores | **OK** |
| Tamaños y sha256 de los 2 `.gz` y los 2 binarios (recalculados); el binario de la VM tiene el mismo sha256 | **OK 8/8** |
| VM: versión 0.77.3, `client.config.yaml` 0600, servicio activo y habilitado, 0 paquetes de Wazuh, sin `/var/ossec`, sin procesos Wazuh, auditd activo, kernel 6.8.0-139, Ubuntu 24.04.5 | **OK** |
| `artifacts list`: 441 total, 53 `Linux.*`, 33 `Generic.*`; CSV con 86 filas únicas que coinciden con la VM; los 86 `tipo` coinciden con la definición | **OK** |
| `Linux.Events.ProcessExecutions` instala una regla auditd (`-a exit,always … -k procmon`) y es el único `Linux.*`/`Generic.*` que menciona `auditctl` | **OK** |
| Servidor: `server_urls`, bind del frontend, GUI, API y datastore coinciden con el documento; no hay `velociraptor.exe` corriendo ahora | **OK** |
| Sin secretos (PEM, claves, contraseñas) en lo nuevo ni en los ficheros rastreados | **OK** |
| Clasificación de una muestra de 8 artifacts | 6 razonables, **2 mal** (`Sys.BashShell`, `Remediation.Quarantine`) |

**Discrepancias y qué se hizo:** `modifica_el_sistema` estaba infravalorado (solo 2): se corrigió leyendo los permisos requeridos (`FILESYSTEM_WRITE`, `MACHINE_STATE`…) → ahora 11; se añadió la clase `respuesta` (9) y la detección baja a 8. Menores sin corregir: el `origen_datos` de `PacketCapture` (usa tcpdump, no eBPF), `LogHunter` y `DeadDiskRemapping` es aproximado.

**No pudo comprobar:** el md5 de `tfg.rules` y `auditctl -l` (necesitan sudo; los comprobé yo antes: 5 reglas idénticas a `lab-listo`), el contenido de `client.config.yaml` en la VM, la firma GPG, que revertir a `lab-listo-vr` deje todo activo (lo comprobé yo: sí), y que la causa del timeout sea el cortafuegos del PC (hipótesis: un `python.exe` sí es alcanzable en cualquier puerto y `velociraptor.exe` no).
Nota: durante la verificación el agente creó y borró dos ficheros temporales en la VM (`~/.nope`, `/dev/shm/x_al.txt`); la VM se revierte a snapshot, no quedan.

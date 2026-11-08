# Servicios del host — “internet local” (B-2)

> **Dónde corren:** en el **host** (`192.168.65.1`, VMnet1), **fuera** de las VMs medidas.
> **No** son internet real: no hay salida a internet (NAT off). **Nunca** ocupan
> `443/1514/1515/55000` (manager). **Sin secretos.**

---

## 1. Puertos y procesos

| Puerto | Servicio | Proceso / fichero | Uso en los ataques |
|---|---|---|---|
| **8080** | web estática (intranet/portal + descargas) | `Soporte/Laboratorio/internet_local/serve_site.py` | ATA066 (defacement), navegación legítima |
| **9090** | sink HTTP (paste / C2 / webhook) | `Soporte/Ataques/receiver/sink_http.py` | ATA056/057/059/074/076/079 |
| **9091** | sink TCP crudo | `sink_http.py --tcp-port 9091` | ATA075/077 |
| **9092** | nube WebDAV | `Soporte/Ataques/receiver/sink_webdav.py` | ATA058 (rclone) |

- **Alias** en el invitado (`C:\Windows\System32\drivers\etc\hosts`):
  `192.168.65.1 intranet.local nube.local paste.local hook.local`.
- **Logs**: `D:\TFG-VMs\lab-logs\` (`web_access.log`, `sink_http.log`, `sink_webdav.log`).
- **Bucket WebDAV**: `D:\TFG-VMs\lab-logs\cloud_bucket\`.
- **Firewall**: una regla por puerto, **acotada a `192.168.65.0/24`**:
  `TFG-web-8080`, `TFG-sink-9090`, `TFG-sink-9091`, `TFG-webdav-9092`.

## 2. Arranque / parada (idempotente)

```powershell
# Arrancar (crea reglas y verifica puertos; no duplica procesos)
python _artefactos/scripts/arrancar_servicios_host.py start

# Estado (solo lectura)
python _artefactos/scripts/arrancar_servicios_host.py status

# Parar (solo los procesos que arrancó el script; retira reglas TFG-*)
python _artefactos/scripts/arrancar_servicios_host.py stop
```

- El script guarda los PID en `D:\TFG-VMs\lab-logs\servicios_host.pids.json` (fuera del repo).
- **No** arranca un servicio si el puerto ya está escuchando (idempotente); lo reporta.
- **No** mata procesos ajenos: solo los de su `pidfile`.
- Alternativa histórica (solo 8080/9090/9092): `start_internet_local.ps1` / `stop_internet_local.ps1`.

## 3. Verificación desde el invitado (`victima-windows`)

```cmd
powershell -NoProfile -Command "Test-NetConnection 192.168.65.1 -Port 8080"
powershell -NoProfile -Command "Test-NetConnection 192.168.65.1 -Port 9090"
powershell -NoProfile -Command "Test-NetConnection 192.168.65.1 -Port 9091"
powershell -NoProfile -Command "Test-NetConnection 192.168.65.1 -Port 9092"
```

Prueba funcional mínima (desde el invitado):

```cmd
curl.exe -s -o NUL -w "%%{http_code}\n" http://intranet.local:8080/
curl.exe -s -X POST -d hola http://paste.local:9090/paste
```

## 4. Reglas de uso

1. **Antes de `t0`** se levantan (fuera de la ventana); **después de `t1`** se paran.
2. Un caso que **no** use red puede correr con los servicios parados.
3. El `sink.log` es **prueba de efecto**, no detección (la detección es del HIDS).
4. No se tocan los puertos del manager; no se abre nada a internet.
5. Cierre: `stop` + comprobar que `8080/9090/9091/9092` están **cerrados**.

## 5. Referencias

- Diseño original: `Soporte/Laboratorio/internet_local/README.md` (L0).
- Receptores: `Soporte/Ataques/receiver/README.md`.
- Evidencia B1.0: `Soporte/Laboratorio/windows/ataques/B1.0_infra.md` §4.

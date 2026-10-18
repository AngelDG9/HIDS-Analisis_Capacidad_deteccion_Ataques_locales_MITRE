# "Internet local" — laboratorio aislado (bloque `legitimo-infra`, L0)

> Servicios locales que suplen a **internet real** en el laboratorio aislado, para que el
> cliente **GHOSTS** (u otro cliente legítimo) tenga *webs que visitar*, *ficheros que
> descargar*, una *nube* y un *paste*, **sin salir a internet**. Todo corre en el **HOST**
> (`192.168.65.1`, VMnet1), **fuera** de las VMs medidas. **Nunca** se ocupan los puertos
> del manager de Wazuh (`443/1514/1515/55000`).

## 1. Servicios

| Puerto | Servicio | Implementación | Origen |
|---|---|---|---|
| **8080** | **Web estática** (intranet/portal + descargas) | `serve_site.py` (stdlib) | **NUEVO** (L0) |
| **9090** | *Paste* / C2 / *health check* | `Soporte/Ataques/receiver/sink_http.py` | **REUSO** |
| **9092** | Nube (WebDAV) | `Soporte/Ataques/receiver/sink_webdav.py` | **REUSO** |

## 2. Arranque / parada (HOST, PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\internet_local\start_internet_local.ps1
powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\internet_local\stop_internet_local.ps1
```

Al arrancar se abren reglas de firewall **acotadas a `192.168.65.0/24`** (una por puerto:
`TFG-web-8080`, `TFG-sink-9090`, `TFG-webdav-9092`) y se retiran al parar. Logs en
`D:\TFG-VMs\lab-logs\` (`web_access.log`, `sink_http.log`, `sink_webdav.log`).

## 3. Contenido del sitio

- `site/` — **HTML/CSS/JS** sencillos: `index.html` (portal), `noticias.html`, `ayuda.html`,
  `styles.css`, `portal.js`, `assets/logo.svg`.
- `site/descargas/` — ficheros de juguete **`manual_empleado.pdf`**, **`plantilla_informe.csv`**
  y **`paquete_datos.zip`**, generados de forma determinista con `make_descargas.py`:

  ```powershell
  python Soporte\Laboratorio\internet_local\make_descargas.py --out Soporte\Laboratorio\internet_local\site\descargas
  ```

> El contenido es **de juguete** (sin datos reales ni secretos); simula un portal corporativo.

## 4. Alias de "dominios" en la víctima (`/etc/hosts`)

Para que las URLs parezcan reales sin DNS real, en `victima-linux` se añade:

```text
192.168.65.1  intranet.local portal.local nube.local
```

Esto es **simulación declarada**: no hay DNS ni internet.

## 5. Verificación sin internet (§4.3 del plan)

Script listo para copiar a la víctima y ejecutar:

```powershell
scp Soporte\Laboratorio\internet_local\verificar_internet_local.sh angel@192.168.65.129:/tmp/
ssh angel@192.168.65.129 "bash /tmp/verificar_internet_local.sh"   # (pie /etc/hosts: si pide sudo)
```

Equivalente manual desde `victima-linux` (NAT off):

```bash
# positivas
curl -sS -o /dev/null -w '%{http_code}\n' http://intranet.local:8080/
curl -sS -o /dev/null -w '%{http_code}\n' http://intranet.local:8080/descargas/paquete_datos.zip
curl -sS -X POST -d hola http://intranet.local:9090/paste -w '%{http_code}\n'
curl -sS -T /etc/hostname http://nube.local:9092/nube/hostname -w '%{http_code}\n'
# negativa (debe FALLAR)
curl --max-time 3 http://example.com
ip route            # sin 'default'
```

## 6. Referencias

- Plan del bloque: `plan.md` §4.
- Receptores reutilizados: `Soporte/Ataques/receiver/README.md`.
- Cliente GHOSTS: `Soporte/Laboratorio/ghosts/README.md`.

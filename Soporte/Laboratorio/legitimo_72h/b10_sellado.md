# `b10_sellado.md` — Sidecar del **sellado B10** (config del legítimo), bloque L1

> **Qué es.** Los **valores reales y las huellas** con los que se **sella la bóveda B10**
> (`Soporte/Metrica/boveda_congelacion.md`, "Config del legítimo": GHOSTS + "internet local" +
> instrumentación del denominador). **L1 no puede tocar `Soporte/Metrica/`** (protegido): este
> **sidecar** lo redacta L1 y **el humano/orquestador** aplica la actualización a B10 y recalcula
> `boveda_congelacion.sha256`. **Punto de coordinación declarado** (igual que L0).
>
> Huellas en `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` (`sha256`, minúsculas). Fecha: 2026-10-18.

## B10 — Contenido del sello

| Elemento | Valor / huella |
|---|---|
| **GHOSTS (servidor + cliente)** | `github.com/cmu-sei/GHOSTS` **tag `v8.3.1`** · **commit `4d2e160860f508f699f935472b5515358f534844`** · .NET 8 · PostgreSQL 16.15 (portable, `initdb -A trust`, solo `127.0.0.1`) |
| **Cliente Linux** | `src/ghosts.client.linux` (*self-contained*) desplegado en `victima-linux` (`/home/angel/ghosts-client`); `config/application.json` → `ApiRootUrl=http://192.168.65.1:5000/api` |
| **Timeline de régimen** | **`timeline_72h.json`** · `sha256 = 16c63746bc814f2decc80b5a952aa92e4b4749940c12527f1480a7ccc4581a30` |
| **"Internet local" — web estática (8080)** | `Soporte/Laboratorio/internet_local/serve_site.py` · `sha256 = 3e724df313863baeeaa8615bda87228d5d3f81252175bb78264ed1c18066be50`; arranque `start_internet_local.ps1` · `sha256 = 69d9e9f976981f3f97e73cc4d4896876acaf7d254529588e876617c497114d6a` |
| **"Internet local" — `site/**`** | `index.html` `74284b9d…` · `noticias.html` `abb28ef4…` · `ayuda.html` `5be3f77a…` · `styles.css` `026a46f7…` · `portal.js` `57c4a22b…` · `assets/logo.svg` `3639e656…` · `descargas/{manual_empleado.pdf  a217f1bf… · paquete_datos.zip  02be44e0… · plantilla_informe.csv  93c86588…}` (huecos completos en `sha256sums.txt`) |
| **"Internet local" — ***paste*/C2 (9090)** | `Soporte/Ataques/receiver/sink_http.py` · `sha256 = a577abc00d3c795c376cf59ad3b10a24e100a7ae8fe5c6105672891e070b9968` |
| **"Internet local" — nube WebDAV (9092)** | `Soporte/Ataques/receiver/sink_webdav.py` · `sha256 = dccac9a241c2ec3e3b34da5b691c6a56e180c79984e01acac156a4238bd5a02b` |
| **Puertos** | `5000` (GHOSTS API, `192.168.65.1`) · `8080` (web) · `9090` (paste) · `9092` (nube WebDAV) — firewall acotado a `192.168.65.0/24` |
| **Instrumentación `M`** | `<logall_json>yes</logall_json>` ⇒ `/var/ossec/logs/archives/archives.json` · `Soporte/Laboratorio/ghosts/logall_json_ctl.sh` · `sha256 = 7a3d34ddaea0b30689e33c5c4d899bdc69b51763f742abf7130c44450d5a0969` |
| **Helper del denominador** | `_artefactos/scripts/contar_denominador.py` · `sha256 = f41c5061fd228a836e786753fa6a788d3de3004aefeeed9bd63f443be5867804` |
| **Arranque GHOSTS (host)** | `Soporte/Laboratorio/ghosts/start_ghosts.ps1` · `sha256 = d81398b65594efd838b4124cf9763401bf76dfab3b8fb66b732a93b38eb910f9` |
| **Tarea del invitado** | `guest/tfg-ghosts-legit.{timer,service}` + `guest/tfg_keepalive.sh` (`sha256` en `sha256sums.txt`); arranca a `t0−5min` y mantiene vivo el cliente (73–74 h) |
| **Config de la ventana** | `t0 = 2026-10-19T00:00:00Z` · `t1 = 2026-10-22T00:00:00Z` (72 h) · **Wazuh virgen** `C1 = {RS1,RS2}` (`RS3 = RS4 = 0`); `logall_json` **ON solo** en `[t0,t1]` |

- **`metrica_version`** = `1` · **`boveda_version`** = `1` (L1 **no** cambia la métrica; solo
  **completa** B10, que estaba `pendiente`). Al aplicar B10, el humano/orquestador decide si
  **bump** `boveda_version` a `2` (recalcular `boveda_congelacion.sha256`).
- **Trazabilidad:** L0 dejó montada y *pinneada* la infra (`_fases/legitimo-infra/change-doc.md` §2-3);
  L1 fija la **timeline de régimen** (nueva) y **sella** los valores.

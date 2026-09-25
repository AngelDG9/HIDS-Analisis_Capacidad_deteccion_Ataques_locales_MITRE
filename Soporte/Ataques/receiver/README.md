# Receptor de exfiltración — `sink_http.py` (ATA008 / T1048.002)

> **Dónde vive:** en el **HOST / sobremesa** (Windows 10), **NO** en las VMs.
> **Por qué:** el `wazuh-server` es el **detector** y **no debe ejecutar nada** durante el ataque;
> el receptor tiene que estar **fuera de las dos VMs** (plan `fase-03-piloto` §3/§17.8).
> **Sin secretos.** Solo biblioteca estándar de Python 3.

## 1. Qué hace

`python sink_http.py` levanta un servidor HTTP efímero que:

- escucha en la **IP del host en `VMnet1`** (paso 0 → **`192.168.65.1`**) en el puerto **9090**;
- por cada petición **añade una línea** al log (`--log`, por defecto `sink.log`):

  ```text
  <UTC> <método> <ruta> from=<IP> len=<N> sha256=<hash> content_type=<...>
  ```

- **responde `200 OK`** a `POST`/`PUT` (para que el `POST` de la víctima tenga éxito) y un texto
  mínimo a `GET` (health check);
- **no guarda el cuerpo** en disco: solo sus metadatos y el **`sha256`** (evidencia suficiente y
  sin almacenar datos).

## 2. Cómo se ejecuta (runbook `Soporte/Ataques/piloto_procedimiento.md` §3)

**En el HOST**, *antes de `t0`* (una vez por iteración, con el log de la iteración):

```powershell
python "Soporte\Ataques\receiver\sink_http.py" `
  --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA008_iter1\sink.log"
```

Parar con `Ctrl+C` (o matar el proceso) **después de `t1`**.

## 3. Comprobación de alcance del puerto (paso 0)

Desde la **víctima** (antes de la fase de ataque), con el receptor levantado:

```bash
timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO
```

El firewall de Windows bloqueaba la entrada; se añadió la regla **acotada** al laboratorio:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
```

> ✅ **Retirada al cerrar el piloto (2026-09-26):**
> `netsh advfirewall firewall delete rule name="TFG-sink-9090"` → «Se eliminaron 1 reglas»;
> ausencia verificada. El receptor quedó parado y la regla retirada (se recrean por ventana si el
> escalado retoma ATA008).

Tras añadirla: puerto **OK** y `POST` de prueba desde la víctima → **200**, con `sha256` del cuerpo
coincidente con el del fichero enviado (validación extremo a extremo).

## 4. Fallback cero-dependencias

Si no se pudiera usar `sink_http.py`, sirve el servidor de la stdlib (registra el `POST` aunque
responda `501`):

```powershell
python -m http.server 9090 --bind 192.168.65.1
```

## 5. Interpretación de `sink.log`

- Una línea por petición del ataque; el `POST` con `sha256` del `artifact` de la atómica es la
  **evidencia primaria** de que el dato salió de la víctima.
- Las líneas que empiezan por `#` son marcas de arranque/parada del propio receptor.

## 6. Higiene

- No se versiona ningún `*.log` (`.gitignore`); la evidencia vive en
  `Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA008_iterN/`.
- El script no contiene secretos.

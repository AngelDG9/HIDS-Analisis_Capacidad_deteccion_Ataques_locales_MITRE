---
fase: 3b
bloque: B1
tanda: B1.1
ata_id: ATA061
tecnica: T1486
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA061 - T1486 Data Encrypted for Impact (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.1 (piloto mixto)**. Generada por `tfg-executor`. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`); `t0` >= 90 s tras agente `002` **Active**.
> Metrica v1 (O1 + O2), catalogo provisional v1, `C0` = `C1` = {RS1} (RS2 vacia).

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA061** |
| Tecnica | **T1486 - Data Encrypted for Impact** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, `192.168.65.130`, agente `002`) |
| Via | **manual** - canal **SSH** |
| Capa del HIDS | **proceso** (`4688` / Sysmon 1 / 4104). Sin capa de red ni de recursos |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `propio` |
| Prueba / mecanismo | AES-256-CBC .NET sobre 5 ficheros |
| Adaptacion | manual: el atomic exige GPG4Win/DiskCryptor o solo .akira |
| Motivo (`criterio_ataques`) | `propio_por_diseno` |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1486-Data_Encrypted_for_Impact/` |
| `sha256` ataque | `4676561ea74e859bfdb9fd6d2a0316e0d03809528467c5aa5588ddc52fbc142a` |
| `sha256` esperado | `8953087c46bed443d6e5050a51433e0d00a72ab743c35a349d302388bff9a701` |
| C0 | `Soporte/Ataques/c0/windows/ATA061_c0.md` (`sha256=d075c0a4d04f30ac930b53ae71da6452f5be1c342f42b1cb14be462e72ca41b0`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= **90 s** tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T19:54:01Z` | `2026-11-08T19:54:02Z` | 1 s | 29 | **5** | `67027,92032,92052` | 2 |
| 2 | `2026-11-08T19:57:13Z` | `2026-11-08T19:57:14Z` | 1 s | 29 | **5** | `67027,92032,92052` | 2 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA061\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA061_iter{1,2}/efecto.txt`: 5/5 ficheros: sha256(original)!=sha256(.enc) y descifrado==original.

**Iter 1** (`sha256=b5869a9403a5fa47988dbf409b70e3652f5ee8725dcfd7878daa218d0afe7b48`):

```text
ata=ATA061
tecnica=T1486
fuente=propio
algoritmo=AES-256-CBC
t0=2026-11-08T19:54:02Z
t1=2026-11-08T19:54:02Z
ficheros_total=5
ficheros_cifrados_ok=5
file=empleados.csv.txt before=0bc52130a1106dead5d8d8e690d49b0ba050668999cdc012419962f9fe6170c3 enc=4a696a0c03c0d53059919e71d1fce83dc58a4a8367f054b6760e64a34b591ad2 dec=0bc52130a1106dead5d8d8e690d49b0ba050668999cdc012419962f9fe6170c3 cifrado=True roundtrip=True
file=pedidos.csv.txt before=4cd4a33f5cda22887374c0ac27902689de3a2f473910be96a9b588c5255289fc enc=906bb8383732f729d24a5e5fe450c1a09bbd0672d6ea9bae16201b9211dd48b8 dec=4cd4a33f5cda22887374c0ac27902689de3a2f473910be96a9b588c5255289fc cifrado=True roundtrip=True
file=proveedores.csv.txt before=2a9a3383a0662d1ec47a30596c24eaf6efd3cf4ade3fffedffb1955d1efbfcf0 enc=2bfa76964c8d64eaa74a46820e527ebfffb465475513afcd29b2182c6e23d2cd dec=2a9a3383a0662d1ec47a30596c24eaf6efd3cf4ade3fffedffb1955d1efbfcf0 cifrado=True roundtrip=True
file=servidores.csv.txt before=7499eb9d105edadc074e31e6e6e4f61df188a480e9c4c3c0d02a1b3aaff3d512 enc=6111082daf9c2716efda95375cb1fd74115a41059353c7eb3d16ea68f95dffea dec=7499eb9d105edadc074e31e6e6e4f61df188a480e9c4c3c0d02a1b3aaff3d512 cifrado=True roundtrip=True
file=usuarios.csv.txt before=949c1a13c1fb5a6f47b8684ac4563932401154493271dfaf0716a75e9e2ce308 enc=60a1557457b72dc8bd7cf527d2c508c9d4c842b98c0e0eed7a1fe605c7bbe15b dec=949c1a13c1fb5a6f47b8684ac4563932401154493271dfaf0716a75e9e2ce308 cifrado=True roundtrip=True
```

**Iter 2** (`sha256=1319632723de014b55e7cfa45321ca03620122d18e0818413a30fcff81b71619`):

```text
ata=ATA061
tecnica=T1486
fuente=propio
algoritmo=AES-256-CBC
t0=2026-11-08T19:57:14Z
t1=2026-11-08T19:57:14Z
ficheros_total=5
ficheros_cifrados_ok=5
file=empleados.csv.txt before=0bc52130a1106dead5d8d8e690d49b0ba050668999cdc012419962f9fe6170c3 enc=4a696a0c03c0d53059919e71d1fce83dc58a4a8367f054b6760e64a34b591ad2 dec=0bc52130a1106dead5d8d8e690d49b0ba050668999cdc012419962f9fe6170c3 cifrado=True roundtrip=True
file=pedidos.csv.txt before=4cd4a33f5cda22887374c0ac27902689de3a2f473910be96a9b588c5255289fc enc=906bb8383732f729d24a5e5fe450c1a09bbd0672d6ea9bae16201b9211dd48b8 dec=4cd4a33f5cda22887374c0ac27902689de3a2f473910be96a9b588c5255289fc cifrado=True roundtrip=True
file=proveedores.csv.txt before=2a9a3383a0662d1ec47a30596c24eaf6efd3cf4ade3fffedffb1955d1efbfcf0 enc=2bfa76964c8d64eaa74a46820e527ebfffb465475513afcd29b2182c6e23d2cd dec=2a9a3383a0662d1ec47a30596c24eaf6efd3cf4ade3fffedffb1955d1efbfcf0 cifrado=True roundtrip=True
file=servidores.csv.txt before=7499eb9d105edadc074e31e6e6e4f61df188a480e9c4c3c0d02a1b3aaff3d512 enc=6111082daf9c2716efda95375cb1fd74115a41059353c7eb3d16ea68f95dffea dec=7499eb9d105edadc074e31e6e6e4f61df188a480e9c4c3c0d02a1b3aaff3d512 cifrado=True roundtrip=True
file=usuarios.csv.txt before=949c1a13c1fb5a6f47b8684ac4563932401154493271dfaf0716a75e9e2ce308 enc=60a1557457b72dc8bd7cf527d2c508c9d4c842b98c0e0eed7a1fe605c7bbe15b dec=949c1a13c1fb5a6f47b8684ac4563932401154493271dfaf0716a75e9e2ce308 cifrado=True roundtrip=True
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA061_iter1-Detalle.csv` | 29 | `5cde1a42235e57b01cb2845ebf810b63b9e976819a2c52a21286709ec4777dda` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA061_iter2-Detalle.csv` | 29 | `0a589e6df8b10e5ba41f72a1ee1db6a3eb263a44690f4fb473527943044f1327` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 29 | **5** | 3 | 7 | **0** | 14 | 29 | 0 | 0 | 0 |
| 2 | 29 | **5** | 3 | 7 | **0** | 14 | 29 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:54:02.653Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T19:57:14.719Z` `rule_id=92052` |

- Las detecciones son **procesos del ataque** (`cmd.exe` / `powershell.exe` / `rclone.exe`) anclados
  por `win_command_line` a la carpeta `C:\lab-attack\ATA061` (H4-W) y evento de ejecucion.
- **El efecto no es deteccion**: el sink / la CPU / los `sha256` lo prueban aparte.
- `dudosa=0` en las dos ventanas: las dudosas (Sysmon 11 / 4104 / ruido de catalogo) se resolvieron
  **antes** de T2 (ver `-Revision.csv` y `Bitacora/ATA061.json`).

## 9. Doble iteracion - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0` en ambas. Ver `Bitacora/ATA061.json`.

## 10. Limitaciones y hallazgos

1. **H-B1-5'**: la deteccion es por **proceso**; no hay capa de red (`Sysmon 3` nivel 0) ni de recursos.
2. **Canal SSH**: las filas del canal (`60106/60137/67024/67023/67028`, `sshd.exe`) son `operador`/`auto_ruido`;
   **ninguna** fila del ataque cae en `ruido` (candado de pertenencia).
3. **FIM**: en este filtro congelado es **ancla/artefacto**, no deteccion (H4-W).
4. **AES-256-CBC** con clave/IV fijos de laboratorio (no es criptografia segura; solo demuestra el impacto).
5. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.


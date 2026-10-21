# deploy_client.ps1 - despliega el cliente GHOSTS (Linux, self-contained) en victima-linux.
#
# Bloque `legitimo-fix` (L1-fix). Cambios respecto de L0:
#   - copia `client_config\nlog.config` (consola a WARN + maxArchiveFiles=20)  -> S6.1
#   - copia las 3 recetas a `config/timeline.d{1,2,3}.json` y deja `config/timeline.json` = d1
#   - copia `recetas\bloques.env` + `calendario.json` al invitado (`<remote>/recetas/`),
#     que es la MISMA fuente que usan el keepalive y la vigilancia.
#
# Pre-staging: el cliente ya se publico en el HOST con
#   dotnet publish src/ghosts.client.linux/ghosts.client.linux.csproj -c Release -r linux-x64 --self-contained true
#
# No contiene secretos: la autenticacion es por clave SSH.
# Uso (HOST):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\deploy_client.ps1

$ErrorActionPreference = "Stop"

$Repo    = "D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE"
$Client  = "D:\TFG-VMs\material-ghosts\client-linux"
$Cfg     = Join-Path $Repo "Soporte\Laboratorio\ghosts\client_config"
$Recetas = Join-Path $Repo "Soporte\Laboratorio\legitimo_72h\recetas"
$Ssh     = "C:\Program Files\Git\usr\bin\ssh.exe"
$Scp     = "C:\Program Files\Git\usr\bin\scp.exe"
$Key     = Join-Path $env:USERPROFILE ".ssh\id_ed25519_tfg_lab"
$Victim  = "angel@192.168.65.129"
$Remote  = "/home/angel/ghosts-client"

# 0) comprobaciones de pre-staging (falla ruidosamente: mejor aqui que en la ventana)
foreach ($f in @("nlog.config", "application.json", "timeline.json")) {
    $p = Join-Path $Cfg $f
    if (-not (Test-Path $p)) { throw "falta $p" }
}
foreach ($f in @("d1.json", "d2.json", "d3.json", "bloques.env", "calendario.json")) {
    $p = Join-Path $Recetas $f
    if (-not (Test-Path $p)) { throw "falta $p (ejecuta construir_receta_legitima.py)" }
}

# 1) configuracion del cliente (plantillas del repo -> cliente publicado en el host)
Copy-Item (Join-Path $Cfg "application.json") (Join-Path $Client "config\application.json") -Force
Copy-Item (Join-Path $Cfg "timeline.json")    (Join-Path $Client "config\timeline.json")    -Force
Copy-Item (Join-Path $Cfg "nlog.config")      (Join-Path $Client "nlog.config")             -Force
# client_ctl.sh: el del REPO es la fuente de verdad (v2, con tope de stdout)
Copy-Item (Join-Path $Repo "Soporte\Laboratorio\ghosts\client_ctl.sh") (Join-Path $Client "client_ctl.sh") -Force
Copy-Item (Join-Path $Recetas "d1.json")      (Join-Path $Client "config\timeline.d1.json") -Force
Copy-Item (Join-Path $Recetas "d2.json")      (Join-Path $Client "config\timeline.d2.json") -Force
Copy-Item (Join-Path $Recetas "d3.json")      (Join-Path $Client "config\timeline.d3.json") -Force
# La timeline ACTIVA es d1 (el dia 1 de la ventana); el keepalive la rota a d2/d3.
Copy-Item (Join-Path $Recetas "d1.json")      (Join-Path $Client "config\timeline.json")    -Force

# 2) subida del cliente (sin `logs/`, `instance/` ni residuos de pruebas anteriores)
& $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Victim "mkdir -p $Remote"
$excluir = @("logs", "instance", "client.out", "client.out.1", "ghasts.out", "keepalive.log", "recovery.log")
$items = Get-ChildItem $Client -Force | Where-Object { $excluir -notcontains $_.Name }
foreach ($it in $items) {
    if ($it.PSIsContainer) { & $Scp -i $Key -r "$($it.FullName)" "$Victim`:$Remote/" }
    else                   { & $Scp -i $Key    "$($it.FullName)" "$Victim`:$Remote/" }
}

# 3) recetas y calendario (misma fuente para keepalive y vigilancia)
& $Ssh -i $Key $Victim "mkdir -p $Remote/recetas $Remote/logs $Remote/instance"
& $Scp -i $Key (Join-Path $Recetas "bloques.env")    "$Victim`:$Remote/recetas/"
& $Scp -i $Key (Join-Path $Recetas "calendario.json") "$Victim`:$Remote/recetas/"

# 3b) keepalive v3 (el timer/servicio NO se instalan aqui: los pone `arm`)
& $Scp -i $Key (Join-Path $Repo "Soporte\Laboratorio\legitimo_72h\guest\tfg_keepalive.sh") "$Victim`:$Remote/"
& $Ssh -i $Key $Victim "chmod +x $Remote/tfg_keepalive.sh"
& $Scp -i $Key (Join-Path $Repo "Soporte\Laboratorio\legitimo_72h\guest\verificar_arreglos.sh") "$Victim`:$Remote/"

# 4) carpetas y alias de la "internet local"
& $Ssh -i $Key $Victim "chmod +x $Remote/ghosts.client.linux $Remote/client_ctl.sh; mkdir -p ~/Documentos ~/Descargas ~/.cache/tfg-web"
& $Ssh -i $Key $Victim "grep -q 'intranet.local' /etc/hosts || echo '192.168.65.1  intranet.local portal.local nube.local' | sudo tee -a /etc/hosts"

Write-Host "Despliegue completado (cliente + nlog.config + d1/d2/d3 + calendario)."
Write-Host "Arranque manual: bash $Remote/client_ctl.sh start"

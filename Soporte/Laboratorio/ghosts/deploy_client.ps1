# deploy_client.ps1 — despliega el cliente GHOSTS (Linux, self-contained) en victima-linux (L0)
#
# Pre-staging: el cliente ya se publicó en el HOST con
#   dotnet publish src/ghosts.client.linux/ghosts.client.linux.csproj -c Release -r linux-x64 --self-contained true
# Este script:
#   1) copia las plantillas de configuracion del repo sobre el cliente publicado;
#   2) lo sube por scp a victima-linux (red host-only, NAT off);
#   3) crea carpetas de trabajo y anade los alias de la "internet local" a /etc/hosts.
#
# No contiene secretos: la autenticacion es por clave SSH.
# Uso (HOST):
#   powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\deploy_client.ps1

$ErrorActionPreference = "Stop"

$Repo    = "D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE"
$Client  = "D:\TFG-VMs\material-ghosts\client-linux"
$Cfg     = Join-Path $Repo "Soporte\Laboratorio\ghosts\client_config"
$Ssh     = "C:\Program Files\Git\usr\bin\ssh.exe"
$Scp     = "C:\Program Files\Git\usr\bin\scp.exe"
$Key     = "C:\Users\angel\.ssh\id_ed25519_tfg_lab"
$Victim  = "angel@192.168.65.129"
$Remote  = "/home/angel/ghosts-client"

# 1) configuracion
Copy-Item (Join-Path $Cfg "application.json") (Join-Path $Client "config\application.json") -Force
Copy-Item (Join-Path $Cfg "timeline.json")    (Join-Path $Client "config\timeline.json")    -Force

# 2) subida
& $Ssh -i $Key -o StrictHostKeyChecking=accept-new $Victim "mkdir -p $Remote"
& $Scp -i $Key -r "$Client\*" "$Victim`:$Remote/"

# 3) carpetas y alias
& $Ssh -i $Key $Victim "chmod +x $Remote/ghosts.client.linux; mkdir -p ~/Documentos ~/Descargas ~/ghosts-client/logs ~/ghosts-client/instance"
& $Ssh -i $Key $Victim "grep -q 'intranet.local' /etc/hosts || echo '192.168.65.1  intranet.local portal.local nube.local' | sudo tee -a /etc/hosts"
Write-Host "Despliegue completado. Arranque manual: $Remote/ghosts.client.linux"

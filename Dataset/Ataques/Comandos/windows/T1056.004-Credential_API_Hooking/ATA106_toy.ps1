[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Start-Sleep -Seconds 5
try { Invoke-WebRequest -Uri 'https://127.0.0.1:8443/' -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}

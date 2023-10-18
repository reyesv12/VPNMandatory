#POLITICA DE EJECUCION DE SCRIPTS
Set-ExecutionPolicy ByPass -Force

# Lista de direcciones IP permitidas
$allowedIPs = "192.168.50.9", "192.168.50.8", "201.132.162.101","201.132.162.102", "201.139.98.110", "208.91.112.53","208.91.112.52"
$times=0


$ruleNameIn = "Allow Ping"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
#Ping rule
New-NetFirewallRule -DisplayName "Allow Ping" -Direction Outbound -Protocol ICMPv4 -IcmpType 8 -Action Allow}

#teamviewer rule
$ruleNameIn = "TeamViewerOut"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

 

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
# Crear regla de salida
New-NetFirewallRule -DisplayName "TeamViewerOutTCP" -Direction Outbound -Action Allow -Profile Any -Protocol TCP -LocalPort 5938 -RemoteAddress $allowedIPs
New-NetFirewallRule -DisplayName "TeamViewerOutUDP" -Direction Outbound -Action Allow -Profile Any -Protocol UDP -LocalPort 5938 -RemoteAddress $allowedIPs

 

# Crear regla de entrada
New-NetFirewallRule -DisplayName "TeamViewerINTCP" -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 5938 -RemoteAddress $allowedIPs
New-NetFirewallRule -DisplayName "TeamViewerINUDP" -Direction Inbound -Action Allow -Profile Any -Protocol UDP -LocalPort 5938 -RemoteAddress $allowedIPs


}


while ($true) {

#REGLA DE TELEMETRÍA

$ruleNameIn = "FortiClientTelemetryOUT"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

 

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
# Crear regla de salida
New-NetFirewallRule -DisplayName "FortiClientTelemetryOUT" -Direction Outbound -Action Allow -Profile Any -Protocol TCP -LocalPort 8013 -RemoteAddress $allowedIPs

 

# Crear regla de entrada
New-NetFirewallRule -DisplayName "FortiClientTelemetryIN" -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 8013 -RemoteAddress $allowedIPs

 

}



    # Crear una regla de entrada para permitir el tráfico desde las direcciones IP especificadas

    $ruleNameIn = "Permitir_Trafico_Salida"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall."
New-NetFirewallRule -DisplayName $ruleNameIn -Direction Inbound -Action Allow -Protocol Any -RemoteAddress $allowedIPs -Profile Any }


$ruleNameIn = "Permitir_Trafico_Salida"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
New-NetFirewallRule -DisplayName $ruleNameIn -Direction Outbound -Action Allow -Protocol Any -RemoteAddress $allowedIPs -Profile Any }




$ruleNameIn = "Permitir FortiClient"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
netsh advfirewall firewall add rule name="Permitir FortiClient" dir=in action=allow program="C:\Program Files\Fortinet\FortiClient\FortiClient.exe" enable=yes
       netsh advfirewall firewall add rule name="Permitir FortiClient Salida" dir=out action=allow program="C:\Program Files\Fortinet\FortiClient\FortiClient.exe" enable=yes }


$ruleNameIn = "Permitir ipsec.exe"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
netsh advfirewall firewall add rule name="Permitir ipsec.exe" dir=in action=allow program="C:\Program Files\Fortinet\FortiClient\ipsec.exe" enable=yes
        netsh advfirewall firewall add rule name="Permitir ipsec.exe" dir=out action=allow program="C:\Program Files\Fortinet\FortiClient\ipsec.exe" enable=yes}



    #REGLAS DE FIREWALL (Falta completar)
    

    $ruleNameIn = "Permitir Daemon.exe"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
netsh advfirewall firewall add rule name="Permitir Daemon.exe" dir=in action=allow program="C:\Program Files\Fortinet\FortiClient\FortiSSLVPNdaemon.exe" enable=yes
        netsh advfirewall firewall add rule name="Permitir Daemon.exe" dir=out action=allow program="C:\Program Files\Fortinet\FortiClient\FortiSSLVPNdaemon.exe" enable=yes}


  $ruleNameIn = "VPNTrafficOut"
$ruleExists = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $ruleNameIn }

if ($ruleExists) { Write-Output "La regla '$ruleNameIn' existe en el firewall." }
else { Write-Output "La regla '$ruleNameIn' no existe en el firewall y se creo"
# Crear regla de salida
New-NetFirewallRule -DisplayName "VPNTrafficOut" -Direction Outbound -Action Allow -Profile Private -Protocol Any -LocalPort Any -RemoteAddress Any

# Crear regla de entrada
New-NetFirewallRule -DisplayName "VPNTrafficIn" -Direction Inbound -Action Allow -Profile Private -Protocol Any -LocalPort Any -RemoteAddress Any

}







    #_____________________________________________________________________________________NETWORK PROFILE______________________________________________________________________


    #Setear la conexión actual a privado
    $perfiles = Get-NetConnectionProfile

if ($perfiles.Count -eq 0) {
    Write-Host "No estás conectado a ninguna red."
} else {
    foreach ($perfil in $perfiles) {
        $nombreRed = $perfil.Name
        Set-NetConnectionProfile -Name "$nombreRed" -NetworkCategory Private
        Write-Host "Perfil de red de '$nombreRed' configurado como privado."
    }
}


    #Setear las conexiones entrantes de perfil dominio, publico y privado del firewall
    #Dominio
    Set-NetFirewallProfile -Profile Domain -Enabled True
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Allow
    Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow

    #Publico
    Set-NetFirewallProfile -Profile Public -Enabled True
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Block

    #Privado
    Set-NetFirewallProfile -Profile Private -Enabled True
    Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Block







    #______________________________________________VERIFICACION NIVEL PROCESO________________________________________________________________________




    # Verificar si el proceso "ipsec.exe" está en ejecución
    $process = Get-Process -Name "ipsec" -ErrorAction SilentlyContinue
    $pingResult = Test-Connection -IPAddress "192.168.50.9" -Count 1 -ErrorAction SilentlyContinue
    if ($pingResult) {
            Write-Host "Se puede hacer ping a 192.168.50.9."
            Enable-NetFirewallRule -DisplayName "VPNTrafficOut"
            Enable-NetFirewallRule -DisplayName "VPNTrafficIn"
        } else {
        if ($process) {
        Write-Host "El proceso ipsec.exe está en ejecución."
        Start-Sleep -Seconds 15
        Enable-NetFirewallRule -DisplayName "VPNTrafficOut"
        Enable-NetFirewallRule -DisplayName "VPNTrafficIn"

        
        
    } else {
        Write-Host "El proceso ipsec.exe no está en ejecución ni se puede alcanzar la 50.9"
        Disable-NetFirewallRule -DisplayName "VPNTrafficOut"
        Disable-NetFirewallRule -DisplayName "VPNTrafficIn"
    }
            
        }



    
    $times=$times+1
    Write-Host "Llevas ciclando esto $times"
    # Esperar 5 segundos antes de volver a verificar
    Start-Sleep -Seconds 5

}


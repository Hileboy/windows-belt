function SSH-Setup {
    ## Set network connection protocol to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 
    #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;

    ## Define the OpenSSH latest release url
    $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
    ## Create a web request to retrieve the latest release download link
    $request = [System.Net.WebRequest]::Create($url)
    $request.AllowAutoRedirect=$false
    $response=$request.GetResponse()
    $source = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/OpenSSH-Win64.zip'
    ## Download the latest OpenSSH for Windows package to the current working directory
    $webClient = [System.Net.WebClient]::new()
    $webClient.DownloadFile($source, (Get-Location).Path + '\OpenSSH-Win64.zip')

    # Extract the ZIP to a temporary location
    Expand-Archive -Path .\OpenSSH-Win64.zip -DestinationPath ($env:temp) -Force
    # Move the extracted ZIP contents from the temporary location to C:\Program Files\OpenSSH\
    Move-Item "$($env:temp)\OpenSSH-Win64" -Destination "C:\Program Files\OpenSSH\" -Force
    # Unblock the files in C:\Program Files\OpenSSH\
    Get-ChildItem -Path "C:\Program Files\OpenSSH\" | Unblock-File

    & 'C:\Program Files\OpenSSH\install-sshd.ps1'

    ## changes the sshd service's startup type from manual to automatic.
    Set-Service sshd -StartupType Automatic
    ## starts the sshd service.
    Start-Service sshd

    try {
        New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } catch {
        Write-Host "Firewall rule already exists"
    }

    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    } catch {
        Write-Host "DefaultShell registry key already exists or there are version conflicts"
    }

    $InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $objType = [System.Security.AccessControl.AccessControlType]::Allow 

    $Path = "C:\Program Files\OpenSSH\"

    $acl = Get-Acl $Path
    $permission = "NT Authority\Authenticated Users","ReadAndExecute", $InheritanceFlag, $PropagationFlag, $objType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission

    $acl.SetAccessRule($accessRule)
    Set-Acl $Path $acl
}

function Setup-WingoEDR {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Path "C:\Program Files\wingoEDR" -Force

    $url = "https://github.com/Hunter-Pittman/wingoEDR/releases/download/v0.1.3-alpha/wingoEDR.exe"

    $file = "C:\Program Files\wingoEDR\wingoEDR.exe"

    $webclient = New-Object System.Net.WebClient
    $webclient.DownloadFile($url, $file)

    #Expand-Archive -Path $file2 -DestinationPath "C:\Program Files\wingoEDR" -Force
    
}

function Setup-Service {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Get-Service -Name "wingoEDR" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "wingoEDR"
    }

    New-Service -Name "wingoEDR" -BinaryPathName "C:\Program Files\wingoEDR\wingoEDR.exe" -StartupType Automatic

    $process = Start-Process -FilePath "C:\Program Files\wingoEDR\wingoEDR.exe" -NoNewWindow
    Start-Sleep -Seconds 10

    if(!$process.HasExited){
        Stop-Process -Name wingoEDR
    }

    Start-Service -Name "wingoEDR"
}

SSH-Setup
Setup-WingoEDR
Setup-Service
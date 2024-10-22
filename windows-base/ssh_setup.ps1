param (
    [string]$PublicKey
)

$sshConfig = @"
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_dsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

# For this to work you will also need host keys in %programData%/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	sftp-server.exe

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

#Match Group administrators
#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

"@

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

    ## Configure the OpenSSH server to use public key authentication
    Set-Content -Path "C:\ProgramData\ssh\sshd_config" -Value $sshConfig

    ## Add the provided public key to the server's authorized keys file
    $authorizedKeysPath = "$env:USERPROFILE\.ssh\authorized_keys"
    if (Test-Path $authorizedKeysPath) {
        Add-Content -Path $authorizedKeysPath -Value $PublicKey
    } else {
        New-Item -ItemType Directory -path "$env:USERPROFILE\.ssh\"
        New-Item -ItemType File -Path $authorizedKeysPath
        Add-Content -Path $authorizedKeysPath -Value $PublicKey
    }

    Restart-Service sshd
}

SSH-Setup
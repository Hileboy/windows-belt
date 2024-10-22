#ps upgrade script
# guide https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/setup/install-configure?view=powershell-7.1

$WinServ2012R2= "https://go.microsoft.com/fwlink/?linkid=839516"
$WinServ2012= "https://go.microsoft.com/fwlink/?linkid=839513"
$WinServ2008R2prereq= "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe"
$WinServ2008R2= "https://go.microsoft.com/fwlink/?linkid=839523"
$Win8= "https://go.microsoft.com/fwlink/?linkid=839521"
$Win7prereq=$WinServ2008R2prereq
$Win7= "https://go.microsoft.com/fwlink/?linkid=839522"


function Download-PS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$url,
        [Parameter(Mandatory=$true)]
        [string]$path
    )

    ## Set network connection protocol to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    #[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072 
    #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} ;


    Write-Output "Downloading $url"
    $webclient = New-Object System.Net.WebClient
    $webclient.DownloadFile($url, $path)
}

function main() {
    $os = (Get-WmiObject Win32_OperatingSystem).Caption

    switch -wildcard ($os) {
        '*Windows 10*' { Write-Output "No Powershell update needed" }
        '*Windows 8.1*' { 
            Write-Output "Windows 8.1" 
        }
        '*Windows 8*' { 
            Write-Output "Windows 8" 
        }
        '*Windows 7*' { 
            $path = "C:\Windows\Temp\win7.zip"
            Write-Output "Windows 7" 
            Download-PS -url $Win7 -path $path
            Expand-Archive -Path $path -DestinationPath "C:\Windows\Temp\"
            $path = "C:\Windows\Temp\win7.zip\Win7-KB3191566-x86\Win7-KB3191566-x86.msu"
            Start-Process -wait wusa -ArgumentList "/update $path","/quiet","/promptrestart"
        }
        '*Windows Vista*' { Write-Output "Too old" }
        '*Windows XP*' { Write-Output "Too old" }
        '*Windows Server 2019*' { Write-Output "No PowerShell update needed" }
        '*Windows Server 2016*' { Write-Output "No PowerShell update needed" }
        '*Windows Server 2012*' { 
            $path = "C:\Windows\Temp\winserver2012.msu"
            Write-Output "Windows Server 2012" 
            Download-PS -url $WinServ2012R2 -path $path
            Start-Process -wait wusa -ArgumentList "/update $path","/quiet","/promptrestart"
        }
        '*Windows Server 2008 R2*' { 
            Write-Output "Windows Server 2008 R2" 
        }
        '*Windows Server 2008*' { 
            Write-Output "Windows Server 2008" 
        }
        '*Windows Server 2003*' { Write-Output "Too old" }
        default { Write-Output "Unknown OS: $os" }
}

}

main
$osVersion = [System.Environment]::OSVersion.Version
if (($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1) -or ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 2) -or ($osVersion.Major -lt 6)) {
    $psVersion = $PSVersionTable.PSVersion.major
    if ($psVersion -lt "5") {
        Write-Output "Installing PowerShell 5.1..."

        # Download the PowerShell 5.1 installer
        if ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1) {
            $url = "https://download.microsoft.com/download/3/0/D/30DB904F-E9EB-4C22-9630-A63A84FD7E1D/Win7AndW2K8R2-KB3191566-x64.zip"
        } elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 2) {
            $url = "https://download.microsoft.com/download/3/0/D/30DB904F-E9EB-4C22-9630-A63A84FD7E1D/W2K12-KB3191566-x64.zip"
        } else {
            $url = "https://download.microsoft.com/download/3/0/D/30DB904F-E9EB-4C22-9630-A63A84FD7E1D/W2K12R2-KB3191565-x64.zip"
        }
        $zipfile = "$env:TEMP\PowerShell5.1.zip"
        $webclient = New-Object System.Net.WebClient
        $webclient.DownloadFile($url, $zipfile)

        # Extract the installer files
        $extractPath = "$env:TEMP\PowerShell5.1"
        if (!(Test-Path $extractPath -PathType Container)) {
            New-Item -ItemType Directory -Path $extractPath | Out-Null
        }

        $shellApplication = New-Object -ComObject Shell.Application
        $zipPackage = $shellApplication.NameSpace($zipfile)
        $destinationFolder = $shellApplication.NameSpace($extractPath)
        $destinationFolder.CopyHere($zipPackage.Items(), 0x14)

        # Install PowerShell 5.1
        $msuFile = Get-ChildItem -Path $extractPath -Filter '*.msu' | Select-Object -First 1
        wusa.exe $msuFile.FullName /quiet /norestart

        Write-Output "PowerShell 5.1 installed."
    } else {
        Write-Output "PowerShell 5.1 is already installed."
    }
} else {
    Write-Output "This script is only supported on Windows 7, 8, and Server 2012."
}

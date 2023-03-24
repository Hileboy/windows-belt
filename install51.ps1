$psversion = Get-Host | Select-Object Version | Select-Object -ExpandProperty Version

if ($psversion.Major -lt 5 -or ($psversion.Major -eq 5 -and $psversion.Minor -lt 1)) {

    if (([System.Environment]::OSVersion.Version.Major -ge 6) -and ($psversion.Major -lt 5)) {
        Write-Output "Installing PowerShell 5.1..."

        # Download the PowerShell 5.1 installer
        $url = "https://download.microsoft.com/download/3/0/D/30DB904F-E9EB-4C22-9630-A63A84FD7E1D/Win7AndW2K8R2-KB3191566-x64.zip"
        $zipfile = "$env:TEMP\PowerShell5.1.zip"
        Invoke-WebRequest -Uri $url -OutFile $zipfile

        # Extract the installer files
        $extractPath = "$env:TEMP\PowerShell5.1"
        Expand-Archive -Path $zipfile -DestinationPath $extractPath

        # Install PowerShell 5.1
        $msuFile = Get-ChildItem -Path $extractPath -Filter '*.msu' | Select-Object -First 1
        wusa.exe $msuFile.FullName /quiet /norestart

        Write-Output "PowerShell 5.1 installed."
    } else {
        Write-Output "PowerShell 5.1 cannot be installed on this version of Windows."
    }
} else {
    Write-Output "PowerShell 5.1 is already installed."
}

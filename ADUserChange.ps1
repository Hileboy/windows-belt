# Set the domain name
$domainName = "bobby"

# Get all user accounts in the domain
$users = Get-ADUser -Filter * -SearchBase "DC=$domainName,DC=shmurda"


$UserList = @()


# Loop through each user and generate a random password
foreach ($user in $users) {
    $newPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    
    # Set the new password for the user
    Set-ADAccountPassword -Identity $user -NewPassword (ConvertTo-SecureString -String $newPassword -AsPlainText -Force)
    
    # Enable the user account if it's disabled
    if ($user.Enabled -eq $false) {
        Enable-ADAccount -Identity $user
    }
    

    $FullUser = [PSCustomObject] @{
        "AccountName" = $user.SamAccountName
        "Password"= $newPassword
    }

    $UserList += $FullUser

    # Print out the user's username and new password
    #Write-Output "User $($user.SamAccountName) password set to: $newPassword"
    Write-Host "User $($user.SamAccountName) changed! "
}

$UserList | Export-Csv -Path "C:\Users.csv" -NoTypeInformation


# Define the list of groups to be processed
$groupList = @("Domain Admins", "Enterprise Admins", "Account Operators", "Backup Operators", "Print Operators", "Guests")

# Process each group in the list
foreach ($groupName in $groupList) {

    # Get the current group
    $group = Get-ADGroup -Identity $groupName

    # Get all members of the current group
    $members = Get-ADGroupMember -Identity $group | Select-Object -ExpandProperty SamAccountName

    # Remove all members from the current group except for the default administrator account
    foreach ($member in $members) {
        if ($member -ne "Administrator") {
            Write-Host "$member removed from $group"
            Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
        }
    }
}
# Get the domain admins group
$domainAdmins = Get-ADGroup -Identity "Domain Admins"

# Get all members of the domain admins group
$members = Get-ADGroupMember -Identity $domainAdmins | Select-Object -ExpandProperty SamAccountName

# Remove all members from the domain admins group except for the default administrator account
foreach ($member in $members) {
    if ($member -ne "Administrator") {
        Remove-ADGroupMember -Identity $domainAdmins -Members $member -Confirm:$false
    }
}

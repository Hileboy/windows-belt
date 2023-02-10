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
            Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
        }
    }
}
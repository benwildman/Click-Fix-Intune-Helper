<#
.SYNOPSIS
    Group management module for ClickFix Intune Protection.

.DESCRIPTION
    Handles creation of Entra ID security groups for policy assignment
    and provides group lookup/validation utilities.
#>

function New-ProtectionGroup {
    <#
    .SYNOPSIS
        Creates an Entra ID security group for ClickFix protection policy assignment.

    .DESCRIPTION
        Creates an assigned-membership security group in Entra ID via Microsoft Graph.
        If a group with the same display name already exists, returns the existing group
        instead of creating a duplicate.

    .PARAMETER Config
        The parsed policy-config.json object.

    .PARAMETER WhatIf
        If set, logs what would be created without calling Graph.

    .OUTPUTS
        [PSCustomObject] with Id and DisplayName of the group (created or existing).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $groupName = $Config.group.groupName
    $groupDesc = $Config.group.groupDescription

    Write-Host "`n[*] Security Group: $groupName" -ForegroundColor Yellow

    if (-not $Config.group.createGroup) {
        Write-Host "    Group creation is disabled in config." -ForegroundColor Gray
        Write-Host "    Checking if group already exists..." -ForegroundColor Gray

        $existing = Find-ExistingGroup -GroupName $groupName
        if ($existing) {
            Write-Host "    [+] Found existing group: $groupName (ID: $($existing.Id))" -ForegroundColor Green
            return $existing
        }
        else {
            Write-Host "    [!] Group '$groupName' does not exist. Policies will be created without assignment." -ForegroundColor DarkYellow
            Write-Host "    [!] Create this group manually or set createGroup=true in config." -ForegroundColor DarkYellow
            return $null
        }
    }

    # Check for existing group first to avoid duplicates
    $existing = Find-ExistingGroup -GroupName $groupName
    if ($existing) {
        Write-Host "    [+] Group already exists: $groupName (ID: $($existing.Id))" -ForegroundColor Green
        return $existing
    }

    # Create the group
    $body = @{
        displayName     = $groupName
        description     = $groupDesc
        mailEnabled     = $false
        mailNickname    = ($groupName -replace '[^a-zA-Z0-9]', '')
        securityEnabled = $true
        groupTypes      = @()  # Empty = assigned membership (not dynamic)
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($groupName, "Create Entra ID security group")) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups"
            $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
            Write-Host "    [+] Created group: $groupName (ID: $($result.id))" -ForegroundColor Green
            return [PSCustomObject]@{
                Id          = $result.id
                DisplayName = $groupName
            }
        }
        catch {
            Write-Error "Failed to create Entra ID group '$groupName': $_"
            return $null
        }
    }
    else {
        Write-Host "    [WhatIf] Would create Entra ID security group: $groupName" -ForegroundColor Cyan
        return [PSCustomObject]@{ Id = "WhatIf"; DisplayName = $groupName }
    }
}

function Find-ExistingGroup {
    <#
    .SYNOPSIS
        Searches for an existing Entra ID group by exact display name.

    .PARAMETER GroupName
        The display name to search for.

    .OUTPUTS
        [PSCustomObject] with Id and DisplayName, or $null if not found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupName
    )

    try {
        $escapedName = $GroupName -replace "'", "''"
        $filter = "displayName eq '$escapedName'"
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName"
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri

        if ($result.value -and $result.value.Count -gt 0) {
            $group = $result.value[0]
            return [PSCustomObject]@{
                Id          = $group.id
                DisplayName = $group.displayName
            }
        }
    }
    catch {
        Write-Warning "Error searching for group '$GroupName': $_"
    }

    return $null
}

Export-ModuleMember -Function New-ProtectionGroup, Find-ExistingGroup

<#
.SYNOPSIS
    Authentication module for ClickFix Intune Protection deployment.

.DESCRIPTION
    Handles interactive delegated authentication to Microsoft Graph API
    with the scopes required for Intune policy and group management.
#>

# Required Graph scopes — least privilege for policy + group operations
$script:RequiredScopes = @(
    "DeviceManagementConfiguration.ReadWrite.All"   # Create, assign, list, delete configurationPolicies
    "Group.ReadWrite.All"                            # Create, find, delete Entra ID security groups
)

function Connect-ClickFixGraph {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph with required Intune scopes.

    .DESCRIPTION
        Checks for the Microsoft.Graph.Authentication module, installs it if missing,
        then initiates an interactive browser-based delegated auth flow targeting
        a Global Admin. Validates connection after auth completes.

    .OUTPUTS
        [Microsoft.Graph.PowerShell.Authentication.AuthContext] The active Graph context.

    .EXAMPLE
        $ctx = Connect-ClickFixGraph
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "  ClickFix Protection - Graph Auth"     -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan

    # --- Ensure Microsoft.Graph.Authentication is available ---
    $moduleName = "Microsoft.Graph.Authentication"
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Host "`n[*] Module '$moduleName' not found. Installing from PSGallery..." -ForegroundColor Yellow
        try {
            Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "[+] Module installed successfully." -ForegroundColor Green
        }
        catch {
            throw "Failed to install '$moduleName'. Install it manually: Install-Module $moduleName -Scope CurrentUser`nError: $_"
        }
    }

    Import-Module $moduleName -ErrorAction Stop

    # --- Disconnect any stale session ---
    try {
        $existingCtx = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingCtx) {
            Write-Host "[*] Disconnecting existing Graph session for $($existingCtx.Account)..." -ForegroundColor Yellow
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {
        # No existing session — continue
    }

    # --- Connect with required scopes ---
    Write-Host "`n[*] Launching interactive login..." -ForegroundColor Yellow
    Write-Host "    Required scopes:" -ForegroundColor Gray
    foreach ($scope in $script:RequiredScopes) {
        Write-Host "      - $scope" -ForegroundColor Gray
    }
    Write-Host "`n    A browser window will open. Sign in with a Global Admin account." -ForegroundColor White

    try {
        Connect-MgGraph -Scopes $script:RequiredScopes -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Graph authentication failed. Ensure you have Global Admin credentials and the required licenses.`nError: $_"
    }

    # --- Validate ---
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.Account) {
        throw "Graph authentication succeeded but context is empty. Re-run the script."
    }

    Write-Host "`n[+] Authenticated successfully." -ForegroundColor Green
    Write-Host "    Account : $($ctx.Account)"    -ForegroundColor Gray
    Write-Host "    Tenant  : $($ctx.TenantId)"   -ForegroundColor Gray
    Write-Host "    Scopes  : $($ctx.Scopes -join ', ')" -ForegroundColor Gray

    return $ctx
}

function Disconnect-ClickFixGraph {
    <#
    .SYNOPSIS
        Cleanly disconnects from Microsoft Graph.
    #>
    [CmdletBinding()]
    param()

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[*] Disconnected from Microsoft Graph." -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Graph disconnect encountered an error: $_"
    }
}

Export-ModuleMember -Function Connect-ClickFixGraph, Disconnect-ClickFixGraph

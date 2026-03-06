<#
.SYNOPSIS
    ClickFix Intune Protection Rollback Script.

.DESCRIPTION
    Discovers and removes all ClickFix protection policies deployed by
    Deploy-ClickFixProtection.ps1. Handles all three policy layers:

      1. Settings Catalog           — Block CMD prompt and Registry Editor
      2. ASR Rules                   — Defense-in-depth (Settings Catalog-based)
      3. App Control for Business    — WDAC policy (Endpoint Security > Application Control)

    All three layers use the configurationPolicies Graph API endpoint.
    Optionally removes the Entra ID security group created for policy assignment.

    Policies are identified by the display name prefix defined in the config file
    (default: "ClickFix Protection - ").

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to ./config/policy-config.json.

.PARAMETER IncludeGroup
    If specified, also deletes the Entra ID security group associated with the policies.

.PARAMETER Force
    Skips all confirmation prompts and deletes immediately. Use with caution.

.PARAMETER WhatIf
    Shows what would be removed without making any changes.

.EXAMPLE
    .\Remove-ClickFixProtection.ps1
    # Interactive — lists discovered policies, asks for confirmation, then removes.

.EXAMPLE
    .\Remove-ClickFixProtection.ps1 -Force
    # Removes all ClickFix policies without confirmation prompts.

.EXAMPLE
    .\Remove-ClickFixProtection.ps1 -IncludeGroup
    # Removes policies AND the Entra ID security group.

.EXAMPLE
    .\Remove-ClickFixProtection.ps1 -WhatIf
    # Dry run — shows what would be removed without deleting anything.

.NOTES
    Prerequisites:
      - PowerShell 5.1+ or PowerShell 7+
      - Microsoft.Graph.Authentication module (auto-installed if missing)
      - Global Administrator or Intune Administrator role
      - Microsoft Intune license on target tenant
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "config" "policy-config.json"),

    [Parameter()]
    [switch]$IncludeGroup,

    [Parameter()]
    [switch]$Force
)

#region ── Banner ─────────────────────────────────────────────────────────────

$banner = @"

   _____ _ _      _     ______ _        ____        _ _ _                _
  / ____| (_)    | |   |  ____(_)      |  _ \      | | | |              | |
 | |    | |_  ___| | __| |__   ___  __ | |_) | ___ | | | |__   __ _  ___| | __
 | |    | | |/ __| |/ /|  __| | \ \/ / |  _ < / _ \| | | '_ \ / _`` |/ __| |/ /
 | |____| | | (__|   < | |    | |>  <  | |_) | (_) | | | |_) | (_| | (__|   <
  \_____|_|_|\___|_|\_\|_|    |_/_/\_\ |____/ \___/|_|_|_.__/ \__,_|\___|_|\_\

  Intune Policy Rollback Tool — Remove ClickFix Protection Policies
  ──────────────────────────────────────────────────────────────────

"@
Write-Host $banner -ForegroundColor Red

#endregion

#region ── Load Configuration ─────────────────────────────────────────────────

Write-Host "[*] Loading configuration from: $ConfigPath" -ForegroundColor Yellow

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found: $ConfigPath"
    Write-Error "The config file is needed to identify which policies to remove."
    exit 1
}

try {
    $configRaw = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
    $config    = $configRaw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "Failed to parse configuration file: $_"
    exit 1
}

Write-Host "[+] Configuration loaded." -ForegroundColor Green

#endregion

#region ── Import Modules & Authenticate ──────────────────────────────────────

$modulesPath = Join-Path $PSScriptRoot "modules"

try {
    Import-Module (Join-Path $modulesPath "Auth.psm1")             -Force -ErrorAction Stop
    Import-Module (Join-Path $modulesPath "GroupManagement.psm1")  -Force -ErrorAction Stop
    Write-Host "[+] Modules loaded." -ForegroundColor Green
}
catch {
    Write-Error "Failed to import modules from '$modulesPath': $_"
    exit 1
}

try {
    $graphCtx = Connect-ClickFixGraph
}
catch {
    Write-Error "Authentication failed: $_"
    exit 1
}

$tenantId = $graphCtx.TenantId

#endregion

#region ── Discover Existing Policies ─────────────────────────────────────────

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║      DISCOVERING CLICKFIX POLICIES       ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Red

# Collect all the display names from config to build the search list
$policyNames = @()
if ($config.policies.blockCmdPrompt.displayName)     { $policyNames += $config.policies.blockCmdPrompt.displayName }
if ($config.policies.blockRegistryEditor.displayName) { $policyNames += $config.policies.blockRegistryEditor.displayName }
if ($config.policies.asrRules.displayName)            { $policyNames += $config.policies.asrRules.displayName }
if ($config.policies.wdac.displayName)                { $policyNames += $config.policies.wdac.displayName }

$discoveredPolicies = @()

# --- Settings Catalog policies (CMD, Regedit, ASR) ---
Write-Host "`n[*] Searching Settings Catalog policies..." -ForegroundColor Yellow

try {
    $scPolicies = @()
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$top=200"
    
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $scPolicies += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    $matchedSc = $scPolicies | Where-Object { $_.name -in $policyNames }

    foreach ($policy in $matchedSc) {
        Write-Host "    Found: $($policy.name)" -ForegroundColor Gray
        Write-Host "           ID: $($policy.id)  Created: $($policy.createdDateTime)" -ForegroundColor DarkGray
        $discoveredPolicies += [PSCustomObject]@{
            Id          = $policy.id
            DisplayName = $policy.name
            Type        = "ConfigurationPolicy"
            Created     = $policy.createdDateTime
        }
    }

    if (-not $matchedSc) {
        Write-Host "    No Settings Catalog policies found." -ForegroundColor DarkGray
    }
}
catch {
    Write-Error "Failed to query Settings Catalog policies: $_"
}

# Note: WDAC policies now use the native App Control for Business template,
# which is also under configurationPolicies — already covered by the search above.

# --- Entra ID Group ---
$discoveredGroup = $null
if ($IncludeGroup) {
    Write-Host "`n[*] Searching for Entra ID group: $($config.group.groupName)..." -ForegroundColor Yellow
    $discoveredGroup = Find-ExistingGroup -GroupName $config.group.groupName
    if ($discoveredGroup) {
        Write-Host "    Found: $($config.group.groupName)" -ForegroundColor Gray
        Write-Host "           ID: $($discoveredGroup.Id)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "    Group not found." -ForegroundColor DarkGray
    }
}

#endregion

#region ── Summary & Confirmation ─────────────────────────────────────────────

$totalItems = $discoveredPolicies.Count + $(if ($discoveredGroup) { 1 } else { 0 })

if ($totalItems -eq 0) {
    Write-Host "`n[+] No ClickFix policies found in this tenant. Nothing to remove." -ForegroundColor Green
    Disconnect-ClickFixGraph
    exit 0
}

Write-Host "`n── Items to Remove ─────────────────────────" -ForegroundColor Red
$itemIndex = 0
foreach ($policy in $discoveredPolicies) {
    $itemIndex++
    Write-Host "  $itemIndex. [$($policy.Type)] $($policy.DisplayName)" -ForegroundColor White
    Write-Host "     ID: $($policy.Id)" -ForegroundColor DarkGray
}
if ($discoveredGroup) {
    $itemIndex++
    Write-Host "  $itemIndex. [EntraIDGroup] $($config.group.groupName)" -ForegroundColor White
    Write-Host "     ID: $($discoveredGroup.Id)" -ForegroundColor DarkGray
}
Write-Host "────────────────────────────────────────────" -ForegroundColor Red
Write-Host "  Total: $totalItems item(s) will be deleted" -ForegroundColor Yellow

# Confirmation
if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "  ⚠  WARNING: This action cannot be undone!" -ForegroundColor Red
    Write-Host "     Devices will no longer be protected once policies are removed." -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Type 'REMOVE' to confirm deletion (or anything else to cancel)"
    if ($confirm -ne 'REMOVE') {
        Write-Host "`n[*] Rollback cancelled by user." -ForegroundColor Yellow
        Disconnect-ClickFixGraph
        exit 0
    }
}

#endregion

#region ── Delete Policies ────────────────────────────────────────────────────

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║        REMOVING CLICKFIX POLICIES        ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor Red

$removedCount   = 0
$failedCount    = 0
$removeStart    = Get-Date
$removedItems   = @()
$failedItems    = @()

foreach ($policy in $discoveredPolicies) {
    $displayLabel = "$($policy.DisplayName) ($($policy.Id))"

    if ($WhatIfPreference) {
        Write-Host "`n    [WhatIf] Would delete: $($policy.DisplayName)" -ForegroundColor Cyan
        Write-Host "             Type: $($policy.Type)  ID: $($policy.Id)" -ForegroundColor Cyan
        $removedCount++
        $removedItems += $policy
        continue
    }

    Write-Host "`n[*] Deleting: $($policy.DisplayName)..." -ForegroundColor Yellow

    # All ClickFix policies use the configurationPolicies endpoint
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($policy.Id)')"

    try {
        Invoke-MgGraphRequest -Method DELETE -Uri $uri -ErrorAction Stop
        Write-Host "    [+] Deleted: $($policy.DisplayName)" -ForegroundColor Green
        $removedCount++
        $removedItems += $policy
    }
    catch {
        Write-Error "    [-] Failed to delete $displayLabel : $_"
        $failedCount++
        $failedItems += $policy
    }
}

# --- Delete group if requested ---
if ($discoveredGroup) {
    if ($WhatIfPreference) {
        Write-Host "`n    [WhatIf] Would delete Entra ID group: $($config.group.groupName)" -ForegroundColor Cyan
        $removedCount++
    }
    else {
        Write-Host "`n[*] Deleting Entra ID group: $($config.group.groupName)..." -ForegroundColor Yellow
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups/$($discoveredGroup.Id)"
            Invoke-MgGraphRequest -Method DELETE -Uri $uri -ErrorAction Stop
            Write-Host "    [+] Deleted group: $($config.group.groupName)" -ForegroundColor Green
            $removedCount++
        }
        catch {
            Write-Error "    [-] Failed to delete group: $_"
            $failedCount++
        }
    }
}

$removeEnd      = Get-Date
$removeDuration = $removeEnd - $removeStart

#endregion

#region ── Write Rollback Log ─────────────────────────────────────────────────

$logPath = $config.outputLogPath
if (-not [System.IO.Path]::IsPathRooted($logPath)) {
    $logPath = Join-Path $PSScriptRoot $logPath
}
# Use a separate log file so we don't overwrite the deployment log
$rollbackLogPath = $logPath -replace '\.txt$', '-rollback.txt'

$logContent = @"
═══════════════════════════════════════════════════════════════════
  ClickFix Intune Protection — Rollback Log
═══════════════════════════════════════════════════════════════════

  Timestamp   : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC)
  Tenant ID   : $tenantId
  Account     : $($graphCtx.Account)
  Duration    : $([math]::Round($removeDuration.TotalSeconds, 1)) seconds
  Mode        : $(if ($WhatIfPreference) { "DRY RUN (WhatIf)" } else { "LIVE ROLLBACK" })

── Removed Policies ───────────────────────────────────────────────

"@

foreach ($item in $removedItems) {
    $logContent += "  [$($item.Type)] $($item.DisplayName)`n"
    $logContent += "    ID: $($item.Id)`n`n"
}

if ($discoveredGroup -and (-not $failedItems -or $failedItems.Id -notcontains $discoveredGroup.Id)) {
    $logContent += "  [EntraIDGroup] $($config.group.groupName)`n"
    $logContent += "    ID: $($discoveredGroup.Id)`n`n"
}

if ($failedItems.Count -gt 0) {
    $logContent += "`n── Failed Deletions ───────────────────────────────────────────────`n`n"
    foreach ($item in $failedItems) {
        $logContent += "  [$($item.Type)] $($item.DisplayName)`n"
        $logContent += "    ID: $($item.Id)`n`n"
    }
}

$logContent += @"
── Summary ────────────────────────────────────────────────────────

  Removed   : $removedCount
  Failed    : $failedCount
  Total     : $totalItems

═══════════════════════════════════════════════════════════════════
"@

try {
    $logContent | Out-File -FilePath $rollbackLogPath -Encoding UTF8 -Force
    Write-Host "`n[+] Rollback log written to: $rollbackLogPath" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to write rollback log to '$rollbackLogPath': $_"
    Write-Host $logContent
}

#endregion

#region ── Final Summary ──────────────────────────────────────────────────────

Write-Host "`n╔══════════════════════════════════════════╗" -ForegroundColor $(if ($failedCount -eq 0) { 'Green' } else { 'Red' })
Write-Host "║          ROLLBACK COMPLETE               ║" -ForegroundColor $(if ($failedCount -eq 0) { 'Green' } else { 'Red' })
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor $(if ($failedCount -eq 0) { 'Green' } else { 'Red' })

Write-Host "`n  Removed  : $removedCount" -ForegroundColor Green
if ($failedCount -gt 0) {
    Write-Host "  Failed   : $failedCount" -ForegroundColor Red
}
Write-Host "  Log file : $rollbackLogPath" -ForegroundColor White

if ($failedCount -eq 0 -and -not $WhatIfPreference) {
    Write-Host "`n  All ClickFix protection policies have been removed from this tenant." -ForegroundColor Green
    Write-Host "  Devices will revert to their default policy state after the next Intune sync." -ForegroundColor Yellow
    Write-Host "  Force a sync from Intune portal or run 'Sync-IntuneDevice' on endpoints." -ForegroundColor Yellow
}

Write-Host ""

#endregion

#region ── Cleanup ────────────────────────────────────────────────────────────

Disconnect-ClickFixGraph

#endregion

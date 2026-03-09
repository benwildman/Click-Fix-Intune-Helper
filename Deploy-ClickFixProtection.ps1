<#
.SYNOPSIS
    ClickFix Intune Protection Deployment Script.

.DESCRIPTION
    Deploys a layered set of Intune policies to mitigate the ClickFix social engineering
    attack tradecraft (Win+X > I > wt.exe > PowerShell). Creates three policy layers:

      1. Settings Catalog           -- Blocks CMD prompt and Registry Editor
      2. ASR Rules                     -- Defense-in-depth against obfuscated scripts and untrusted executables
      3. App Control for Business      -- Kernel-level WDAC block of powershell.exe, pwsh.exe, wt.exe, cmd.exe, etc.

    WDAC works on Pro, Enterprise, and Education editions (unlike AppLocker which
    requires Enterprise/Education). Deployed as a native App Control for Business
    policy (Endpoint Security > Application Control) with direct XML upload.
    WDAC is device-scoped -- admin exemption is handled via Intune group targeting.

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to ./config/policy-config.json.

.PARAMETER CreateGroup
    When specified, creates the Entra ID security group defined in config and assigns
    all deployed policies to it -- even if createGroup is false in policy-config.json.

.PARAMETER WhatIf
    Validates configuration and authenticates, but does not create any policies.
    Logs what would be created.

.EXAMPLE
    .\Deploy-ClickFixProtection.ps1
    # Runs with default config, creates all enabled policies.

.EXAMPLE
    .\Deploy-ClickFixProtection.ps1 -CreateGroup
    # Creates policies AND the Entra ID security group, then assigns policies to it.

.EXAMPLE
    .\Deploy-ClickFixProtection.ps1 -WhatIf
    # Dry run -- shows what would be created without making changes.

.EXAMPLE
    .\Deploy-ClickFixProtection.ps1 -ConfigPath ".\config\custom-config.json"
    # Uses a custom configuration file.

.NOTES
    Prerequisites:
      - PowerShell 7+ (PowerShell 5.1 is not supported)
      - Microsoft.Graph.Authentication module (auto-installed if missing)
      - Global Administrator or Intune Administrator role
      - Microsoft Intune license on target tenant
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path (Join-Path $PSScriptRoot "config") "policy-config.json"),

    [Parameter()]
    [switch]$CreateGroup
)

#region -- Banner -------------------------------------------------------------

$banner = @"

   _____ _ _      _     ______ _        _____           _            _   _
  / ____| (_)    | |   |  ____(_)      |  __ \         | |          | | (_)
 | |    | |_  ___| | __| |__   ___  __ | |__) | __ ___ | |_ ___  ___| |_ _  ___  _ __
 | |    | | |/ __| |/ /|  __| | \ \/ / |  ___/ '__/ _ \| __/ _ \/ __| __| |/ _ \| '_ \
 | |____| | | (__|   < | |    | |>  <  | |   | | | (_) | ||  __/ (__| |_| | (_) | | | |
  \_____|_|_|\___|_|\_\|_|    |_/_/\_\ |_|   |_|  \___/ \__\___|\___|\__|_|\___/|_| |_|

  Intune Policy Deployment Tool -- Mitigate ClickFix Social Engineering
  ---------------------------------------------------------------------

"@
Write-Host $banner -ForegroundColor Cyan

#endregion

#region -- PowerShell Version Check -------------------------------------------

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 or later. You are running PowerShell $($PSVersionTable.PSVersion)."
    Write-Error "Install PowerShell 7+: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows"
    exit 1
}

#endregion

#region -- Load Configuration -------------------------------------------------

Write-Host "[*] Loading configuration from: $ConfigPath" -ForegroundColor Yellow

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Configuration file not found: $ConfigPath"
    Write-Error "Copy config/policy-config.json and customize it for your environment."
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

# --- Validate required config sections ---
$requiredSections = @("policies", "group", "outputLogPath")
foreach ($section in $requiredSections) {
    if (-not $config.PSObject.Properties[$section]) {
        Write-Error "Configuration missing required section: '$section'"
        exit 1
    }
}

$requiredPolicySections = @("blockCmdPrompt", "blockRegistryEditor", "asrRules", "wdac")
foreach ($section in $requiredPolicySections) {
    if (-not $config.policies.PSObject.Properties[$section]) {
        Write-Error "Configuration missing required policy section: 'policies.$section'"
        exit 1
    }
}

# Validate ASR rule GUIDs are well-formed
$guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
foreach ($rule in $config.policies.asrRules.rules) {
    if ($rule.guid -notmatch $guidPattern) {
        Write-Error "Invalid ASR rule GUID: '$($rule.guid)' for rule '$($rule.name)'"
        exit 1
    }
    if ($rule.mode -notin @("Block", "Audit", "Warn", "Off")) {
        Write-Error "Invalid ASR rule mode: '$($rule.mode)' for rule '$($rule.name)'. Must be Block, Audit, Warn, or Off."
        exit 1
    }
}

Write-Host "[+] Configuration validated successfully." -ForegroundColor Green

# Override config group setting if -CreateGroup switch is used
if ($CreateGroup.IsPresent) {
    $config.group.createGroup = $true
    Write-Host "`n[*] -CreateGroup switch: group creation enabled (overrides config)." -ForegroundColor Yellow
}

# Print summary of enabled policies
Write-Host "`n-- Policy Summary --------------------------" -ForegroundColor White
Write-Host "  CMD Prompt Block  : $(if ($config.policies.blockCmdPrompt.enabled) { 'ENABLED' } else { 'disabled' })" -ForegroundColor $(if ($config.policies.blockCmdPrompt.enabled) { 'Green' } else { 'Gray' })
Write-Host "  Registry Editor   : $(if ($config.policies.blockRegistryEditor.enabled) { 'ENABLED' } else { 'disabled' })" -ForegroundColor $(if ($config.policies.blockRegistryEditor.enabled) { 'Green' } else { 'Gray' })
Write-Host "  ASR Rules         : $(if ($config.policies.asrRules.enabled) { 'ENABLED (' + $config.policies.asrRules.rules.Count + ' rules)' } else { 'disabled' })" -ForegroundColor $(if ($config.policies.asrRules.enabled) { 'Green' } else { 'Gray' })
Write-Host "  WDAC Block        : $(if ($config.policies.wdac.enabled) { 'ENABLED (' + $config.policies.wdac.blockedApps.Count + ' apps) [' + $config.policies.wdac.mode + ']' } else { 'disabled' })" -ForegroundColor $(if ($config.policies.wdac.enabled) { 'Green' } else { 'Gray' })
Write-Host "  Group Creation    : $(if ($config.group.createGroup) { 'YES' } else { 'NO (manual)' })" -ForegroundColor $(if ($config.group.createGroup) { 'Green' } else { 'DarkYellow' })
Write-Host "  Target Group      : $($config.group.groupName)" -ForegroundColor White
Write-Host "--------------------------------------------" -ForegroundColor White

#endregion

#region -- Import Modules -----------------------------------------------------

$modulesPath = Join-Path $PSScriptRoot "modules"

try {
    Import-Module (Join-Path $modulesPath "Auth.psm1")             -Force -ErrorAction Stop
    Import-Module (Join-Path $modulesPath "PolicyDeployment.psm1") -Force -ErrorAction Stop
    Import-Module (Join-Path $modulesPath "GroupManagement.psm1")  -Force -ErrorAction Stop
    Write-Host "`n[+] Modules loaded." -ForegroundColor Green
}
catch {
    Write-Error "Failed to import modules from '$modulesPath': $_"
    exit 1
}

#endregion

#region -- Authenticate -------------------------------------------------------

try {
    $graphCtx = Connect-ClickFixGraph
}
catch {
    Write-Error "Authentication failed: $_"
    exit 1
}

$tenantId = $graphCtx.TenantId

#endregion

#region -- Deploy Policies ----------------------------------------------------

$deployedPolicies = @()
$deployStart = Get-Date

Write-Host "`n+==========================================+" -ForegroundColor Cyan
Write-Host "|       DEPLOYING INTUNE POLICIES          |" -ForegroundColor Cyan
Write-Host "+==========================================+" -ForegroundColor Cyan

# 1. Settings Catalog -- CMD & Regedit restrictions
$whatIfParams = @{}
if ($WhatIfPreference) { $whatIfParams['WhatIf'] = $true }

$cmdRegeditPolicies = New-CmdRegeditRestrictionPolicy -Config $config @whatIfParams
if ($cmdRegeditPolicies) {
    $deployedPolicies += $cmdRegeditPolicies
}

# 2. ASR Rules
$asrPolicy = New-AsrRulesPolicy -Config $config @whatIfParams
if ($asrPolicy) {
    $deployedPolicies += $asrPolicy
}

# 3. App Control for Business (WDAC)
$wdacPolicy = New-WdacPolicy -Config $config @whatIfParams
if ($wdacPolicy) {
    $deployedPolicies += $wdacPolicy
}

$deployEnd = Get-Date
$deployDuration = $deployEnd - $deployStart

Write-Host "`n[+] Policy deployment complete. $($deployedPolicies.Count) policies created in $([math]::Round($deployDuration.TotalSeconds, 1))s." -ForegroundColor Green

#endregion

#region -- Group Management & Assignment --------------------------------------

$groupResult = New-ProtectionGroup -Config $config @whatIfParams
$groupAssigned = $false

if ($groupResult -and $groupResult.Id -and $groupResult.Id -ne "WhatIf") {
    Write-Host "`n[*] Assigning policies to group: $($groupResult.DisplayName)" -ForegroundColor Yellow

    foreach ($policy in $deployedPolicies) {
        if ($policy.Id -and $policy.Id -ne "WhatIf") {
            Set-PolicyAssignment -PolicyId $policy.Id -PolicyType $policy.Type -GroupId $groupResult.Id @whatIfParams
        }
    }
    $groupAssigned = $true
}
elseif ($groupResult -and $groupResult.Id -eq "WhatIf") {
    foreach ($policy in $deployedPolicies) {
        Set-PolicyAssignment -PolicyId $policy.Id -PolicyType $policy.Type -GroupId "WhatIf" @whatIfParams
    }
}
else {
    Write-Host "`n[!] No group available for assignment. Policies created without assignment." -ForegroundColor DarkYellow
}

#endregion

#region -- Write Deployment Log -----------------------------------------------

$logPath = $config.outputLogPath
if (-not [System.IO.Path]::IsPathRooted($logPath)) {
    $logPath = Join-Path $PSScriptRoot $logPath
}

$logContent = @"
===================================================================
  ClickFix Intune Protection -- Deployment Log
===================================================================

  Timestamp   : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC)
  Tenant ID   : $tenantId
  Account     : $($graphCtx.Account)
  Duration    : $([math]::Round($deployDuration.TotalSeconds, 1)) seconds
  Mode        : $(if ($WhatIfPreference) { "DRY RUN (WhatIf)" } else { "LIVE DEPLOYMENT" })

-- Created Policies -----------------------------------------------

"@

foreach ($policy in $deployedPolicies) {
    $logContent += "  [$($policy.Type)] $($policy.DisplayName)`n"
    $logContent += "    ID: $($policy.Id)`n`n"
}

if ($deployedPolicies.Count -eq 0) {
    $logContent += "  (No policies were created -- all disabled in config or errors occurred)`n`n"
}

$logContent += @"
-- Group Assignment -----------------------------------------------

  Group Name  : $($config.group.groupName)
  Group ID    : $(if ($groupResult) { $groupResult.Id } else { "NOT CREATED / NOT FOUND" })
  Assigned    : $(if ($groupAssigned) { "YES" } else { "NO" })

  +=============================================================+
  |  IMPORTANT: Devices must be added to the group             |
  |  '$($config.group.groupName)'          |
  |  for these policies to take effect.                        |
  |                                                            |
  |  Navigate to: Entra ID > Groups > $($config.group.groupName)  |
  |  Add device objects that should receive ClickFix protection|
  +=============================================================+

-- Verification Steps ---------------------------------------------

  1. Intune Portal > Devices > Configuration profiles
     Confirm all created policies appear and show "Assigned"

  2. On a test device (added to the group), logged in as a STANDARD user:
     - Win+R > cmd > Should show "disabled by administrator"
     - Win+R > regedit > Should be blocked
     - Win+X > I > wt.exe > Should be blocked by WDAC
     - PowerShell > Should be blocked by WDAC
     - All above should work on DEVICES NOT IN the target group

  3. Windows Event Log > Microsoft-Windows-Windows Defender/Operational
     Check for ASR event IDs 1121 (block) and 1122 (audit)

  4. Windows Event Log > Microsoft-Windows-CodeIntegrity/Operational
     Check for WDAC block events (Event ID 3077 enforce, 3076 audit)

===================================================================
"@

try {
    $logContent | Out-File -FilePath $logPath -Encoding UTF8 -Force
    Write-Host "`n[+] Deployment log written to: $logPath" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to write deployment log to '$logPath': $_"
    Write-Host $logContent
}

#endregion

#region -- Final Summary ------------------------------------------------------

Write-Host "`n+==========================================+" -ForegroundColor Cyan
Write-Host "|          DEPLOYMENT COMPLETE             |" -ForegroundColor Cyan
Write-Host "+==========================================+" -ForegroundColor Cyan

Write-Host "`n  Policies created : $($deployedPolicies.Count)" -ForegroundColor White
Write-Host "  Group name       : $($config.group.groupName)" -ForegroundColor White
Write-Host "  Group assigned   : $(if ($groupAssigned) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($groupAssigned) { 'Green' } else { 'DarkYellow' })
Write-Host "  Log file         : $logPath" -ForegroundColor White

if (-not $groupAssigned) {
    Write-Host "`n  [!]  IMPORTANT: Devices must be added to group '$($config.group.groupName)'" -ForegroundColor Yellow
    Write-Host "     for policies to take effect." -ForegroundColor Yellow
}

Write-Host ""

#endregion

#region -- Cleanup ------------------------------------------------------------

Disconnect-ClickFixGraph

#endregion

<#
.SYNOPSIS
    Policy deployment module for ClickFix Intune Protection.

.DESCRIPTION
    Creates Intune configuration policies via Microsoft Graph:
      - Settings Catalog policy to block CMD and Registry Editor
      - Endpoint Security ASR rules for script/executable defense-in-depth
      - App Control for Business (WDAC) policy to block PowerShell, wt.exe, cmd.exe etc.
#>

#region ── Settings Catalog: Block CMD & Regedit ──────────────────────────────

function New-CmdRegeditRestrictionPolicy {
    <#
    .SYNOPSIS
        Creates a Settings Catalog policy that disables CMD prompt and Registry Editor.

    .PARAMETER Config
        The parsed policy-config.json object.

    .PARAMETER WhatIf
        If set, logs what would be created without calling Graph.

    .OUTPUTS
        [PSCustomObject] with Id, DisplayName, and Type of the created policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $cmdCfg    = $Config.policies.blockCmdPrompt
    $regCfg    = $Config.policies.blockRegistryEditor
    $policies  = @()

    # --- Block CMD Prompt ---
    if ($cmdCfg.enabled) {
        $displayName = $cmdCfg.displayName
        $description = $cmdCfg.description

        Write-Host "`n[*] Creating Settings Catalog policy: $displayName" -ForegroundColor Yellow

        # Settings Catalog payload — ADMX-backed DisableCMD
        $body = @{
            name         = $displayName
            description  = $description
            platforms    = "windows10"
            technologies = "mdm"
            settings     = @(
                @{
                    "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
                    settingInstance = @{
                        "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                        settingDefinitionId = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disablecmd"
                        choiceSettingValue  = @{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                            value         = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disablecmd_1"
                            children      = @(
                                @{
                                    "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    settingDefinitionId = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disablecmd_disablecmdscripts"
                                    choiceSettingValue  = @{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                                        # 1 = Yes (also disable batch file processing)
                                        value         = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disablecmd_disablecmdscripts_1"
                                        children      = @()
                                    }
                                }
                            )
                        }
                    }
                }
            )
        } | ConvertTo-Json -Depth 20

        if ($PSCmdlet.ShouldProcess($displayName, "Create Settings Catalog policy")) {
            try {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
                Write-Host "[+] Created: $displayName (ID: $($result.id))" -ForegroundColor Green
                $policies += [PSCustomObject]@{
                    Id          = $result.id
                    DisplayName = $displayName
                    Type        = "SettingsCatalog-BlockCMD"
                }
            }
            catch {
                Write-Error "Failed to create CMD restriction policy: $_"
            }
        }
        else {
            Write-Host "    [WhatIf] Would create Settings Catalog policy: $displayName" -ForegroundColor Cyan
            $policies += [PSCustomObject]@{ Id = "WhatIf"; DisplayName = $displayName; Type = "SettingsCatalog-BlockCMD" }
        }
    }

    # --- Block Registry Editor ---
    if ($regCfg.enabled) {
        $displayName = $regCfg.displayName
        $description = $regCfg.description

        Write-Host "`n[*] Creating Settings Catalog policy: $displayName" -ForegroundColor Yellow

        $body = @{
            name         = $displayName
            description  = $description
            platforms    = "windows10"
            technologies = "mdm"
            settings     = @(
                @{
                    "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
                    settingInstance = @{
                        "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                        settingDefinitionId = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disableregedit"
                        choiceSettingValue  = @{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                            value         = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disableregedit_1"
                            children      = @(
                                @{
                                    "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    settingDefinitionId = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disableregedit_disableregeditmode"
                                    choiceSettingValue  = @{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                                        # 2 = Yes (also prevent running regedit silently)
                                        value         = "user_vendor_msft_policy_config_admx_shellcommandpromptregedittools_disableregedit_disableregeditmode_2"
                                        children      = @()
                                    }
                                }
                            )
                        }
                    }
                }
            )
        } | ConvertTo-Json -Depth 20

        if ($PSCmdlet.ShouldProcess($displayName, "Create Settings Catalog policy")) {
            try {
                $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
                $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
                Write-Host "[+] Created: $displayName (ID: $($result.id))" -ForegroundColor Green
                $policies += [PSCustomObject]@{
                    Id          = $result.id
                    DisplayName = $displayName
                    Type        = "SettingsCatalog-BlockRegedit"
                }
            }
            catch {
                Write-Error "Failed to create Registry Editor restriction policy: $_"
            }
        }
        else {
            Write-Host "    [WhatIf] Would create Settings Catalog policy: $displayName" -ForegroundColor Cyan
            $policies += [PSCustomObject]@{ Id = "WhatIf"; DisplayName = $displayName; Type = "SettingsCatalog-BlockRegedit" }
        }
    }

    return $policies
}

#endregion

#region ── Endpoint Security: ASR Rules ───────────────────────────────────────

function New-AsrRulesPolicy {
    <#
    .SYNOPSIS
        Creates an Endpoint Security Attack Surface Reduction rules policy.

    .PARAMETER Config
        The parsed policy-config.json object.

    .PARAMETER WhatIf
        If set, logs what would be created without calling Graph.

    .OUTPUTS
        [PSCustomObject] with Id, DisplayName, and Type of the created policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $asrCfg = $Config.policies.asrRules
    if (-not $asrCfg.enabled) {
        Write-Host "[*] ASR rules policy is disabled in config — skipping." -ForegroundColor Gray
        return $null
    }

    $displayName = $asrCfg.displayName
    $description = $asrCfg.description

    Write-Host "`n[*] Creating Endpoint Security ASR policy: $displayName" -ForegroundColor Yellow

    # Map mode strings to the integer values the Graph API expects
    $modeMap = @{
        "Block" = "block"
        "Audit" = "audit"
        "Warn"  = "warn"
        "Off"   = "off"
    }

    # Build the ASR rule settings array for Settings Catalog approach
    # Each ASR rule maps to a specific settingDefinitionId

    # ASR rule GUID → settingDefinitionId mapping (discovered from Settings Catalog API)
    $guidToSettingId = @{
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands"
    }

    foreach ($rule in $asrCfg.rules) {
        $mode = $modeMap[$rule.mode]
        if (-not $mode) {
            Write-Warning "Unknown mode '$($rule.mode)' for ASR rule $($rule.guid) — defaulting to 'audit'."
            $mode = "audit"
        }
        Write-Host "    Rule: $($rule.name) → $mode" -ForegroundColor Gray
    }

    # Build the Settings Catalog payload for ASR rules
    # ASR rules require a parent settingGroupCollectionInstance wrapping the individual rule choices
    $groupChildren = @()
    foreach ($rule in $asrCfg.rules) {
        $mode = $modeMap[$rule.mode]
        if (-not $mode) { $mode = "audit" }

        $settingId = $guidToSettingId[$rule.guid]
        if (-not $settingId) {
            Write-Warning "No known settingDefinitionId for ASR rule GUID $($rule.guid) — skipping."
            continue
        }

        $groupChildren += @{
            "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
            settingDefinitionId = $settingId
            choiceSettingValue  = @{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                value         = "${settingId}_${mode}"
                children      = @()
            }
        }
    }

    $settingsArray = @(
        @{
            "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
            settingInstance = @{
                "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
                settingDefinitionId = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules"
                groupSettingCollectionValue = @(
                    @{
                        children = $groupChildren
                    }
                )
            }
        }
    )

    $body = @{
        name         = $displayName
        description  = $description
        platforms    = "windows10"
        technologies = "mdm,microsoftSense"
        settings     = $settingsArray
    } | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($displayName, "Create ASR rules policy")) {
        try {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
            Write-Host "[+] Created: $displayName (ID: $($result.id))" -ForegroundColor Green
            return [PSCustomObject]@{
                Id          = $result.id
                DisplayName = $displayName
                Type        = "EndpointSecurity-ASR"
            }
        }
        catch {
            Write-Error "Failed to create ASR rules policy: $_"
            return $null
        }
    }
    else {
        Write-Host "    [WhatIf] Would create ASR rules policy: $displayName" -ForegroundColor Cyan
        return [PSCustomObject]@{ Id = "WhatIf"; DisplayName = $displayName; Type = "EndpointSecurity-ASR" }
    }
}

#endregion

#region ── App Control for Business: WDAC Policy ─────────────────────────────

function New-WdacPolicy {
    <#
    .SYNOPSIS
        Creates an App Control for Business (WDAC) policy using the native
        Intune Endpoint Security template with XML upload.

    .DESCRIPTION
        WDAC enforces code integrity at the kernel level and works on Windows
        Pro, Enterprise, and Education editions — unlike AppLocker which only
        enforces on Enterprise/Education.

        This function generates a SiPolicy XML with deny rules for specified
        binaries and uploads it directly via the native "App Control for
        Business" template (endpointSecurityApplicationControl).

        Benefits over custom OMA-URI approach:
          - No local ConvertFrom-CIPolicy compilation needed
          - Appears in Endpoint Security > Application Control in Intune
          - Intune handles XML-to-binary conversion server-side
          - Runs from any machine (no ConfigCI module dependency)

        Policy features:
          - Deny rules use OriginalFileName from PE headers (tamper-resistant)
          - Supports Enforce and Audit modes
          - Device-scoped (admin exemption via group targeting)

    .PARAMETER Config
        The parsed policy-config.json object.

    .PARAMETER WhatIf
        If set, logs what would be created without calling Graph.

    .OUTPUTS
        [PSCustomObject] with Id, DisplayName, and Type of the created policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $wdacCfg = $Config.policies.wdac
    if (-not $wdacCfg.enabled) {
        Write-Host "[*] WDAC policy is disabled in config — skipping." -ForegroundColor Gray
        return $null
    }

    $displayName = $wdacCfg.displayName
    $description = $wdacCfg.description
    $policyMode  = $wdacCfg.mode  # Enforce or Audit

    Write-Host "`n[*] Creating App Control for Business policy: $displayName" -ForegroundColor Yellow
    Write-Host "    Mode: $policyMode" -ForegroundColor Gray
    Write-Host "    Type: Endpoint Security > Application Control (native)" -ForegroundColor Gray

    # --- Generate a Policy ID GUID for the SiPolicy ---
    $policyId = [guid]::NewGuid().ToString()
    $policyIdBraces = "{$policyId}"

    # --- Build deny FileRule entries ---
    $fileRulesXml = ""
    $denyRuleRefsXml = ""
    $ruleIndex = 0

    foreach ($app in $wdacCfg.blockedApps) {
        $ruleIndex++
        $denyId    = "ID_DENY_D_$($ruleIndex)"
        $fileName  = $app.originalFileName
        $friendlyName = "$($app.name) - $($app.description)"

        $fileRulesXml += "      <Deny ID=`"$denyId`" FriendlyName=`"$friendlyName`" FileName=`"$fileName`" MinimumFileVersion=`"0.0.0.0`" />`n"

        $denyRuleRefsXml += "          <FileRuleRef RuleID=`"$denyId`" />`n"

        Write-Host "    Block: $($app.name) (OriginalFileName: $fileName)" -ForegroundColor Gray
    }

    # --- Determine audit mode option ---
    $auditModeOption = ""
    if ($policyMode -eq "Audit") {
        $auditModeOption = @"
    <Rule>
      <Option>Enabled:Audit Mode</Option>
    </Rule>
"@
        Write-Host "    [!] Policy will be deployed in AUDIT mode (logging only, not blocking)" -ForegroundColor DarkYellow
    }

    # --- Build full WDAC CI Policy XML ---
    $wdacXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.1.0</VersionEx>
  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
  <PolicyID>$policyIdBraces</PolicyID>
  <BasePolicyID>$policyIdBraces</BasePolicyID>
  <Rules>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Advanced Boot Options Menu</Option>
    </Rule>
    <Rule>
      <Option>Required:Enforce Store Applications</Option>
    </Rule>
$auditModeOption  </Rules>
  <EKUs />
  <FileRules>
$fileRulesXml  </FileRules>
  <Signers />
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS" FriendlyName="Driver Signing">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USERMODE" FriendlyName="User Mode Signing">
      <ProductSigners>
        <FileRulesRef>
$denyRuleRefsXml        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value>
        <String>$displayName</String>
      </Value>
    </Setting>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Id">
      <Value>
        <String>ClickFixProtection</String>
      </Value>
    </Setting>
  </Settings>
</SiPolicy>
"@

    Write-Host "    [+] Generated SiPolicy XML ($($wdacXml.Length) chars, GUID: $policyIdBraces)" -ForegroundColor Green

    # --- Deploy via native App Control for Business template ---
    # Template: 4321b946-b76b-4450-8afd-769c08b16ffc_1 (endpointSecurityApplicationControl)
    # Uses XML upload mode — Intune handles compilation server-side
    $body = @{
        name         = $displayName
        description  = $description
        platforms    = "windows10"
        technologies = "mdm"
        templateReference = @{
            templateId = "4321b946-b76b-4450-8afd-769c08b16ffc_1"
        }
        settings     = @(
            @{
                "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
                settingInstance = @{
                    "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions"
                    settingInstanceTemplateReference = @{
                        settingInstanceTemplateId = "1de98212-6949-42dc-a89c-e0ff6e5da04b"
                    }
                    choiceSettingValue  = @{
                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                        value         = "device_vendor_msft_policy_config_applicationcontrol_configure_xml_selected"
                        settingValueTemplateReference = @{
                            settingValueTemplateId = "b28c7dc4-c7b2-4ce2-8f51-6ebfd3ea69d3"
                        }
                        children      = @(
                            @{
                                "@odata.type"       = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                settingDefinitionId = "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml"
                                settingInstanceTemplateReference = @{
                                    settingInstanceTemplateId = "4d709667-63d7-42f2-8e1b-b780f6c3c9c7"
                                }
                                simpleSettingValue  = @{
                                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    value         = $wdacXml
                                    settingValueTemplateReference = @{
                                        settingValueTemplateId = "88f6f096-dedb-4cf1-ac2f-4b41e303adb5"
                                    }
                                }
                            }
                        )
                    }
                }
            }
        )
    } | ConvertTo-Json -Depth 20

    if ($PSCmdlet.ShouldProcess($displayName, "Create App Control for Business policy")) {
        try {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
            $result = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
            Write-Host "[+] Created: $displayName (ID: $($result.id))" -ForegroundColor Green
            Write-Host "    WDAC Policy GUID: $policyIdBraces" -ForegroundColor Gray
            Write-Host "    Location: Endpoint Security > Application Control" -ForegroundColor Gray
            return [PSCustomObject]@{
                Id             = $result.id
                DisplayName    = $displayName
                Type           = "AppControlForBusiness-WDAC"
                WdacPolicyGuid = $policyIdBraces
            }
        }
        catch {
            Write-Error "Failed to create App Control for Business policy: $_"
            return $null
        }
    }
    else {
        Write-Host "    [WhatIf] Would create App Control for Business policy: $displayName" -ForegroundColor Cyan
        Write-Host "    [WhatIf] WDAC Policy GUID: $policyIdBraces" -ForegroundColor Cyan
        return [PSCustomObject]@{ Id = "WhatIf"; DisplayName = $displayName; Type = "AppControlForBusiness-WDAC"; WdacPolicyGuid = $policyIdBraces }
    }
}

#endregion

#region ── Policy Assignment Helper ───────────────────────────────────────────

function Set-PolicyAssignment {
    <#
    .SYNOPSIS
        Assigns a created policy to a target Entra ID group.

    .PARAMETER PolicyId
        The Intune policy ID.

    .PARAMETER PolicyType
        The type of policy (determines the Graph endpoint used).

    .PARAMETER GroupId
        The Entra ID group ID to assign to.

    .PARAMETER WhatIf
        If set, logs what would be assigned without calling Graph.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][string]$PolicyType,
        [Parameter(Mandatory)][string]$GroupId
    )

    if ($PolicyId -eq "WhatIf") {
        Write-Host "    [WhatIf] Would assign policy to group $GroupId" -ForegroundColor Cyan
        return
    }

    $assignmentBody = @{
        assignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $GroupId
                }
            }
        )
    } | ConvertTo-Json -Depth 10

    # All policy types now use configurationPolicies (Settings Catalog, ASR, and App Control for Business)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/assign"

    if ($PSCmdlet.ShouldProcess("Policy $PolicyId", "Assign to group $GroupId")) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $assignmentBody -ContentType "application/json" | Out-Null
            Write-Host "    [+] Assigned policy $PolicyId to group $GroupId" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to assign policy $PolicyId to group ${GroupId}: $_"
        }
    }
}

#endregion

Export-ModuleMember -Function New-CmdRegeditRestrictionPolicy, New-AsrRulesPolicy, New-WdacPolicy, Set-PolicyAssignment

function Get-ADLabHardeningDomainDn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    return ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Ensure-ADLabHardeningGpoLinked {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$GpoName,
        [Parameter(Mandatory)]
        [string]$Target,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $existingLink = (Get-GPInheritance -Target $Target -ErrorAction SilentlyContinue).GpoLinks |
            Where-Object { $_.DisplayName -eq $GpoName } |
            Select-Object -First 1

        if ($existingLink) {
            Write-Host "[OK] GPO link exists: $GpoName" -ForegroundColor Green
            Write-ADSetupLog -Message "GPO link already exists: $GpoName -> $Target." -Level Success -LogPath $LogPath
            return
        }

        if ($PSCmdlet.ShouldProcess($Target, "Link GPO $GpoName")) {
            New-GPLink -Name $GpoName -Target $Target -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Host "[LINK] GPO linked: $GpoName" -ForegroundColor Cyan
            Write-ADSetupLog -Message "Linked GPO $GpoName to $Target." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Failed to link hardening GPO $GpoName to $Target. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Write-ADLabHardeningSecurityTemplate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [Guid]$GpoId,
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $securityTemplateFolder = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($GpoId.ToString())}\Machine\Microsoft\Windows NT\SecEdit"
        $securityTemplatePath = Join-Path $securityTemplateFolder 'GptTmpl.inf'

        $template = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
EnableGuestAccount = 0
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-113,*S-1-5-114
SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114
'@

        if ($PSCmdlet.ShouldProcess($securityTemplatePath, 'Write CIS-style security template')) {
            if (-not (Test-Path -LiteralPath $securityTemplateFolder)) {
                New-Item -Path $securityTemplateFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            Set-Content -Path $securityTemplatePath -Value $template -Encoding Unicode -ErrorAction Stop
            Write-Host '[SECURITY] CIS-style security template prepared' -ForegroundColor Cyan
            Write-ADSetupLog -Message "Prepared CIS-style security template at $securityTemplatePath." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Failed to write CIS-style security template. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Enable-ADLabCISHardening {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        $gpoName = 'LAB - CIS-Style Security Hardening'
        $target = Get-ADLabHardeningDomainDn -DomainName $DomainName
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

        if (-not $gpo) {
            if ($PSCmdlet.ShouldProcess($gpoName, 'Create CIS-style security hardening GPO')) {
                $gpo = New-GPO -Name $gpoName -Comment 'Active Directory Auto Deployment Lab CIS-style security hardening baseline.' -ErrorAction Stop
                Write-Host "[CREATE] GPO created: $gpoName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created CIS-style security hardening GPO: $gpoName." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] GPO exists: $gpoName" -ForegroundColor Green
            Write-ADSetupLog -Message "CIS-style hardening GPO already exists: $gpoName." -Level Success -LogPath $LogPath
        }

        if (-not $gpo) {
            return
        }

        $registrySettings = @(
            @{ Area = 'SMB signing'; Key = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 },
            @{ Area = 'SMB signing'; Key = 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'EnableSecuritySignature'; Type = 'DWord'; Value = 1 },
            @{ Area = 'SMB signing'; Key = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 },
            @{ Area = 'SMB signing'; Key = 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'EnableSecuritySignature'; Type = 'DWord'; Value = 1 },
            @{ Area = 'NTLM restrictions'; Key = 'HKLM\System\CurrentControlSet\Control\Lsa'; ValueName = 'LMCompatibilityLevel'; Type = 'DWord'; Value = 5 },
            @{ Area = 'NTLM restrictions'; Key = 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0'; ValueName = 'RestrictSendingNTLMTraffic'; Type = 'DWord'; Value = 2 },
            @{ Area = 'NTLM restrictions'; Key = 'HKLM\Software\ADLab\SecurityHardening'; ValueName = 'NTLMRestrictionNote'; Type = 'String'; Value = 'Review NTLM dependencies before enforcing in non-lab environments.' },
            @{ Area = 'Windows Defender'; Key = 'HKLM\Software\Policies\Microsoft\Windows Defender'; ValueName = 'DisableAntiSpyware'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Windows Defender'; Key = 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName = 'DisableRealtimeMonitoring'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Windows Defender'; Key = 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName = 'DisableBehaviorMonitoring'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Windows Defender'; Key = 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName = 'DisableIOAVProtection'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Windows Defender'; Key = 'HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine'; ValueName = 'MpEnablePus'; Type = 'DWord'; Value = 1 },
            @{ Area = 'Firewall baseline'; Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 },
            @{ Area = 'Firewall baseline'; Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName = 'DefaultInboundAction'; Type = 'DWord'; Value = 1 },
            @{ Area = 'Firewall baseline'; Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName = 'DefaultOutboundAction'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Firewall baseline'; Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 },
            @{ Area = 'Firewall baseline'; Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 },
            @{ Area = 'PowerShell logging'; Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1 },
            @{ Area = 'PowerShell logging'; Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; ValueName = 'EnableModuleLogging'; Type = 'DWord'; Value = 1 },
            @{ Area = 'PowerShell logging'; Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; ValueName = '*'; Type = 'String'; Value = '*' },
            @{ Area = 'PowerShell logging'; Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'EnableTranscripting'; Type = 'DWord'; Value = 1 },
            @{ Area = 'PowerShell logging'; Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'OutputDirectory'; Type = 'String'; Value = 'C:\AD_Setup\SecurityMonitoring\PowerShellTranscripts' },
            @{ Area = 'Local admin restrictions'; Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'LocalAccountTokenFilterPolicy'; Type = 'DWord'; Value = 0 },
            @{ Area = 'Local admin restrictions'; Key = 'HKLM\Software\ADLab\SecurityHardening'; ValueName = 'LocalAdminRestrictionNote'; Type = 'String'; Value = "Deny network and RDP logon for local accounts is prepared in the security template. Domain admin principal: $NetBIOSName\Domain Admins." }
        )

        foreach ($setting in $registrySettings) {
            if ($PSCmdlet.ShouldProcess($gpoName, "Set $($setting.Area) policy $($setting.Key)\$($setting.ValueName)")) {
                Set-GPRegistryValue -Name $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -ErrorAction Stop
                Write-ADSetupLog -Message "Set $($setting.Area) policy value $($setting.Key)\$($setting.ValueName)." -Level Success -LogPath $LogPath
            }
        }

        Write-ADLabHardeningSecurityTemplate -GpoId $gpo.Id -DomainName $DomainName -LogPath $LogPath -WhatIf:$WhatIfPreference
        Ensure-ADLabHardeningGpoLinked -GpoName $gpoName -Target $target -LogPath $LogPath -WhatIf:$WhatIfPreference
    } catch {
        Write-ADSetupLog -Message "CIS-style security hardening failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Enable-ADLabBlueTeamMode {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [Parameter(Mandatory)]
        [string]$CollectorFqdn,
        [string]$SysmonStubPath = 'C:\AD_Setup\SecurityMonitoring\Sysmon',
        [string]$LAPSManagedOU = 'Computers',
        [switch]$ExtendLAPSSchema,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Write-ADSetupLog -Message 'Starting Blue Team Mode orchestration.' -Level Info -LogPath $LogPath

        if ($PSCmdlet.ShouldProcess($DomainName, 'Prepare audit policy GPO')) {
            New-ADLabAuditPolicyGPO -DomainName $DomainName -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if ($PSCmdlet.ShouldProcess($DomainName, 'Prepare Windows Event Forwarding')) {
            Enable-ADLabWindowsEventForwarding -DomainName $DomainName -NetBIOSName $NetBIOSName -CollectorFqdn $CollectorFqdn -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if ($PSCmdlet.ShouldProcess($SysmonStubPath, 'Prepare Sysmon deployment stub')) {
            New-ADLabSysmonDeploymentStub -StubPath $SysmonStubPath -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if ($PSCmdlet.ShouldProcess($DomainName, 'Apply CIS-style security hardening')) {
            Enable-ADLabCISHardening -DomainName $DomainName -NetBIOSName $NetBIOSName -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if ($PSCmdlet.ShouldProcess($DomainName, 'Prepare Windows LAPS prerequisites')) {
            Install-ADLabWindowsLAPS -ExtendSchema:$ExtendLAPSSchema -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if ($PSCmdlet.ShouldProcess($DomainName, 'Configure Windows LAPS policy')) {
            Set-ADLabLAPSConfiguration -DomainName $DomainName -NetBIOSName $NetBIOSName -ManagedOU $LAPSManagedOU -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        Write-ADSetupLog -Message 'Blue Team Mode orchestration completed.' -Level Success -LogPath $LogPath
    } catch {
        Write-ADSetupLog -Message "Blue Team Mode failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function Enable-ADLabCISHardening, Enable-ADLabBlueTeamMode

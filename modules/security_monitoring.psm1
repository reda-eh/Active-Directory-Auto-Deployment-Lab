function Get-ADLabGpoLinkTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    return Get-DomainDistinguishedName -DomainName $DomainName
}

function Ensure-ADLabGpoLinked {
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
        Write-ADSetupLog -Message "Failed to link GPO $GpoName to $Target. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function New-ADLabAuditPolicyGPO {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop

        $gpoName = 'LAB - Security Monitoring Audit Policy'
        $target = Get-ADLabGpoLinkTarget -DomainName $DomainName
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

        if (-not $gpo) {
            if ($PSCmdlet.ShouldProcess($gpoName, 'Create audit policy GPO')) {
                $gpo = New-GPO -Name $gpoName -Comment 'Active Directory Auto Deployment Lab audit policy baseline.' -ErrorAction Stop
                Write-Host "[CREATE] GPO created: $gpoName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created audit policy GPO: $gpoName." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] GPO exists: $gpoName" -ForegroundColor Green
            Write-ADSetupLog -Message "Audit policy GPO already exists: $gpoName." -Level Success -LogPath $LogPath
        }

        if (-not $gpo) {
            return
        }

        # Advanced audit policy settings are represented in the GPO audit.csv file.
        $auditCsv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success,,1
,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,,1
'@

        $gpoGuid = $gpo.Id.Guid
        $auditFolder = "\\$DomainName\SYSVOL\$DomainName\Policies\{$gpoGuid}\Machine\Microsoft\Windows NT\Audit"
        $auditPath = Join-Path $auditFolder 'audit.csv'

        if ($PSCmdlet.ShouldProcess($auditPath, 'Write advanced audit policy CSV')) {
            if (-not (Test-Path -LiteralPath $auditFolder)) {
                New-Item -Path $auditFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            Set-Content -Path $auditPath -Value $auditCsv -Encoding ASCII -ErrorAction Stop
            Write-Host "[AUDIT] Advanced audit policy CSV prepared" -ForegroundColor Cyan
            Write-ADSetupLog -Message "Prepared advanced audit policy CSV at $auditPath." -Level Success -LogPath $LogPath
        }

        $registrySettings = @(
            @{
                Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
                Type = 'DWord'
                Value = 1
            },
            @{
                Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                ValueName = 'EnableScriptBlockLogging'
                Type = 'DWord'
                Value = 1
            },
            @{
                Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
                ValueName = 'EnableModuleLogging'
                Type = 'DWord'
                Value = 1
            },
            @{
                Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
                ValueName = '*'
                Type = 'String'
                Value = '*'
            },
            @{
                Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
                ValueName = 'EnableTranscripting'
                Type = 'DWord'
                Value = 1
            },
            @{
                Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
                ValueName = 'OutputDirectory'
                Type = 'String'
                Value = 'C:\AD_Setup\SecurityMonitoring\PowerShellTranscripts'
            }
        )

        foreach ($setting in $registrySettings) {
            if ($PSCmdlet.ShouldProcess($gpoName, "Set registry policy $($setting.Key)\$($setting.ValueName)")) {
                Set-GPRegistryValue -Name $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -ErrorAction Stop
                Write-ADSetupLog -Message "Set audit policy registry value $($setting.Key)\$($setting.ValueName)." -Level Success -LogPath $LogPath
            }
        }

        Ensure-ADLabGpoLinked -GpoName $gpoName -Target $target -LogPath $LogPath -WhatIf:$WhatIfPreference
    } catch {
        Write-ADSetupLog -Message "Audit Policy GPO setup failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Enable-ADLabWindowsEventForwarding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [Parameter(Mandatory)]
        [string]$CollectorFqdn,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop

        $domainDn = Get-DomainDistinguishedName -DomainName $DomainName
        $gpoName = 'LAB - Windows Event Forwarding Preparation'
        $collectorGroupName = 'WEF_Event_Log_Readers'
        $eventLogReadersGroup = "CN=Event Log Readers,CN=Builtin,$domainDn"
        $target = Get-ADLabGpoLinkTarget -DomainName $DomainName

        $collectorGroup = Get-ADGroup -Filter "SamAccountName -eq '$collectorGroupName'" -ErrorAction SilentlyContinue
        if (-not $collectorGroup) {
            if ($PSCmdlet.ShouldProcess($collectorGroupName, 'Create WEF Event Log Readers helper group')) {
                $collectorGroup = New-ADGroup `
                    -Name $collectorGroupName `
                    -SamAccountName $collectorGroupName `
                    -GroupScope Global `
                    -GroupCategory Security `
                    -Path "CN=Users,$domainDn" `
                    -PassThru `
                    -ErrorAction Stop

                Write-Host "[CREATE] Group created: $collectorGroupName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created WEF helper group: $collectorGroupName." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] Group exists: $collectorGroupName" -ForegroundColor Green
            Write-ADSetupLog -Message "WEF helper group already exists: $collectorGroupName." -Level Success -LogPath $LogPath
        }

        if ($collectorGroup) {
            $existingMembership = Get-ADGroupMember -Identity $eventLogReadersGroup -Recursive -ErrorAction SilentlyContinue |
                Where-Object { $_.SamAccountName -eq $collectorGroupName } |
                Select-Object -First 1

            if (-not $existingMembership) {
                if ($PSCmdlet.ShouldProcess('Event Log Readers', "Add $collectorGroupName")) {
                    Add-ADGroupMember -Identity $eventLogReadersGroup -Members $collectorGroupName -ErrorAction Stop
                    Write-Host "[ADD] $collectorGroupName -> Event Log Readers" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Added $collectorGroupName to Builtin Event Log Readers." -Level Success -LogPath $LogPath
                }
            } else {
                Write-Host "[OK] $collectorGroupName already in Event Log Readers" -ForegroundColor Green
                Write-ADSetupLog -Message "$collectorGroupName is already a member of Builtin Event Log Readers." -Level Success -LogPath $LogPath
            }
        }

        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            if ($PSCmdlet.ShouldProcess($gpoName, 'Create WEF preparation GPO')) {
                $gpo = New-GPO -Name $gpoName -Comment 'Active Directory Auto Deployment Lab Windows Event Forwarding preparation policy.' -ErrorAction Stop
                Write-Host "[CREATE] GPO created: $gpoName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created WEF preparation GPO: $gpoName." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] GPO exists: $gpoName" -ForegroundColor Green
            Write-ADSetupLog -Message "WEF preparation GPO already exists: $gpoName." -Level Success -LogPath $LogPath
        }

        if ($gpo) {
            $subscriptionManager = "Server=http://$CollectorFqdn`:5985/wsman/SubscriptionManager/WEC,Refresh=60"
            $registrySettings = @(
                @{
                    Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service'
                    ValueName = 'AllowAutoConfig'
                    Type = 'DWord'
                    Value = 1
                },
                @{
                    Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service'
                    ValueName = 'IPv4Filter'
                    Type = 'String'
                    Value = '*'
                },
                @{
                    Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service'
                    ValueName = 'IPv6Filter'
                    Type = 'String'
                    Value = '*'
                },
                @{
                    Key = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
                    ValueName = '1'
                    Type = 'String'
                    Value = $subscriptionManager
                },
                @{
                    Key = 'HKLM\Software\ADLab\SecurityMonitoring'
                    ValueName = 'CollectorServicePreparation'
                    Type = 'String'
                    Value = 'Run wecutil qc on the collector and create source-initiated subscriptions after reviewing lab scope.'
                }
            )

            foreach ($setting in $registrySettings) {
                if ($PSCmdlet.ShouldProcess($gpoName, "Set WEF registry policy $($setting.Key)\$($setting.ValueName)")) {
                    Set-GPRegistryValue -Name $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -ErrorAction Stop
                    Write-ADSetupLog -Message "Set WEF registry policy $($setting.Key)\$($setting.ValueName)." -Level Success -LogPath $LogPath
                }
            }

            Ensure-ADLabGpoLinked -GpoName $gpoName -Target $target -LogPath $LogPath -WhatIf:$WhatIfPreference
        }
    } catch {
        Write-ADSetupLog -Message "Windows Event Forwarding preparation failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function New-ADLabSysmonDeploymentStub {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$StubPath = 'C:\AD_Setup\SecurityMonitoring\Sysmon',
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        if (-not (Test-Path -LiteralPath $StubPath)) {
            if ($PSCmdlet.ShouldProcess($StubPath, 'Create Sysmon deployment stub folder')) {
                New-Item -Path $StubPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Host "[CREATE] Sysmon stub folder created: $StubPath" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created Sysmon deployment stub folder: $StubPath." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] Sysmon stub folder exists: $StubPath" -ForegroundColor Green
            Write-ADSetupLog -Message "Sysmon deployment stub folder already exists: $StubPath." -Level Success -LogPath $LogPath
        }

        $readmePath = Join-Path $StubPath 'README-Sysmon-Deployment.txt'
        $deployScriptPath = Join-Path $StubPath 'Install-Sysmon-LabStub.ps1'

        $readmeContent = @'
Active Directory Auto Deployment Lab - Sysmon Deployment Stub

Place these user-provided files in this folder before using the deployment stub:

- Sysmon.exe
- sysmon-config.xml

This project does not download Sysmon, does not embed external binaries, and does not provide a third-party Sysmon configuration.
Download Sysmon only from a trusted Microsoft Sysinternals source and review any Sysmon configuration before deploying it.

Suggested lab flow:

1. Place Sysmon.exe and sysmon-config.xml in this folder.
2. Review Install-Sysmon-LabStub.ps1.
3. Deploy through your preferred lab software deployment method or adapt the script into a reviewed startup script GPO.
'@

        $deployScript = @'
[CmdletBinding(SupportsShouldProcess = $true)]
param()

$sysmonExe = Join-Path $PSScriptRoot 'Sysmon.exe'
$sysmonConfig = Join-Path $PSScriptRoot 'sysmon-config.xml'

if (-not (Test-Path -LiteralPath $sysmonExe)) {
    throw "Sysmon.exe was not found in $PSScriptRoot."
}

if (-not (Test-Path -LiteralPath $sysmonConfig)) {
    throw "sysmon-config.xml was not found in $PSScriptRoot."
}

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install or update Sysmon with the provided lab configuration')) {
    & $sysmonExe -accepteula -i $sysmonConfig
}
'@

        if ($PSCmdlet.ShouldProcess($readmePath, 'Write Sysmon deployment README')) {
            Set-Content -Path $readmePath -Value $readmeContent -Encoding UTF8 -ErrorAction Stop
            Write-ADSetupLog -Message "Wrote Sysmon deployment notes to $readmePath." -Level Success -LogPath $LogPath
        }

        if ($PSCmdlet.ShouldProcess($deployScriptPath, 'Write Sysmon deployment stub script')) {
            Set-Content -Path $deployScriptPath -Value $deployScript -Encoding UTF8 -ErrorAction Stop
            Write-ADSetupLog -Message "Wrote Sysmon deployment stub script to $deployScriptPath." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Sysmon deployment stub preparation failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function New-ADLabAuditPolicyGPO, Enable-ADLabWindowsEventForwarding, New-ADLabSysmonDeploymentStub

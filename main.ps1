# Enterprise Active Directory Automation & Security Lab
# Creator: Rida Elhammioui
# Purpose: Lab-focused Active Directory automation, security hardening, monitoring, and reporting.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DomainName,
    [string]$NetBIOSName,
    [string]$UserCsvPath,
    [switch]$ForcePasswordChangeAtLogon,
    [switch]$DisableImportedUsers,
    [switch]$SkipPromotion,
    [switch]$SkipGpo,
    [switch]$RunHealthCheckOnly,
    [switch]$ConfigureDepartmentAccessControl,
    [switch]$ConfigureSecurityMonitoring,
    [string]$SecurityMonitoringCollector,
    [switch]$ConfigureWindowsLAPS,
    [switch]$ExtendLAPSSchema,
    [string]$LAPSManagedOU,
    [switch]$GenerateHtmlReport,
    [switch]$Menu
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\config.ps1"

Import-Module "$PSScriptRoot\modules\checks.psm1" -Force
Import-Module "$PSScriptRoot\modules\install_ad.psm1" -Force
Import-Module "$PSScriptRoot\modules\create_ous.psm1" -Force
Import-Module "$PSScriptRoot\modules\create_groups.psm1" -Force
Import-Module "$PSScriptRoot\modules\create_users.psm1" -Force
Import-Module "$PSScriptRoot\modules\gpo_setup.psm1" -Force
Import-Module "$PSScriptRoot\modules\access_control.psm1" -Force
Import-Module "$PSScriptRoot\modules\security_monitoring.psm1" -Force
Import-Module "$PSScriptRoot\modules\laps.psm1" -Force
Import-Module "$PSScriptRoot\modules\reporting.psm1" -Force

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        default { 'Cyan' }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $color
    Write-ADSetupLog -Message $Message -Level $Level -LogPath $script:ADSetupConfig.LogPath
}

function Read-RequiredValue {
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CurrentValue
    )

    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        return Read-Host $Prompt
    }

    return $CurrentValue
}

function Show-ADAutoDeploymentMenu {
    Write-Host ''
    Write-Host 'Enterprise Active Directory Automation & Security Lab' -ForegroundColor Magenta
    Write-Host 'Creator: Rida Elhammioui' -ForegroundColor DarkCyan
    Write-Host '-----------------------------------------------------' -ForegroundColor Magenta
    Write-Host '1. Run full lab setup'
    Write-Host '2. Run health check only'
    Write-Host '3. Configure Department Access Control'
    Write-Host '4. Configure Security Monitoring'
    Write-Host '5. Configure Windows LAPS'
    Write-Host '6. Generate HTML Report'
    Write-Host '7. Exit'
    Write-Host ''

    return Read-Host 'Select an option'
}

function Show-ExecutionPlan {
    param(
        [Parameter(Mandatory)]
        [string]$TargetDomain,
        [Parameter(Mandatory)]
        [string]$TargetNetBIOS,
        [Parameter(Mandatory)]
        [string]$CsvPath,
        [Parameter(Mandatory)]
        [bool]$UsersEnabled,
        [Parameter(Mandatory)]
        [bool]$PasswordChangeAtLogon
    )

    Write-Host ''
    Write-Host 'Enterprise Active Directory Automation & Security Lab execution plan' -ForegroundColor Magenta
    Write-Host 'Creator: Rida Elhammioui' -ForegroundColor DarkCyan
    Write-Host '----------------------------------------------------' -ForegroundColor Magenta
    Write-Host "Domain/FQDN:                  $TargetDomain"
    Write-Host "NetBIOS name:                 $TargetNetBIOS"
    Write-Host "Install AD DS/DNS features:    Yes, if missing"
    Write-Host "Promote to new forest:         $(-not $SkipPromotion)"
    Write-Host "Create default OUs:            $($script:ADSetupConfig.DefaultOUs -join ', ')"
    Write-Host "Create default groups:         $($script:ADSetupConfig.DefaultGroups -join ', ')"
    Write-Host "Import users CSV:              $CsvPath"
    Write-Host "Imported users enabled:        $UsersEnabled"
    Write-Host "Password change at logon:      $PasswordChangeAtLogon"
    Write-Host "Apply lab GPOs:                $(-not $SkipGpo)"
    Write-Host "Run health checks/report:      Yes"
    Write-Host "Log file:                      $($script:ADSetupConfig.LogPath)"
    Write-Host "Report file:                   $($script:ADSetupConfig.ReportPath)"
    Write-Host ''
}

try {
    Initialize-ADSetupFolders -RootPath $script:ADSetupConfig.RootPath
    Write-Status 'Starting Active Directory Auto Deployment Lab.'

    Assert-RunningAsAdministrator

    if ($Menu) {
        switch (Show-ADAutoDeploymentMenu) {
            '1' { }
            '2' { $RunHealthCheckOnly = $true }
            '3' { $ConfigureDepartmentAccessControl = $true }
            '4' { $ConfigureSecurityMonitoring = $true }
            '5' { $ConfigureWindowsLAPS = $true }
            '6' { $GenerateHtmlReport = $true }
            '7' {
                Write-Status 'Menu exit selected.' -Level Warning
                return
            }
            default {
                Write-Status 'Invalid menu option selected.' -Level Warning
                return
            }
        }
    }

    $UserCsvPath = if ([string]::IsNullOrWhiteSpace($UserCsvPath)) {
        $script:ADSetupConfig.UserCsvPath
    } else {
        $UserCsvPath
    }

    $isDc = Test-IsDomainController
    $adInstalled = Test-ADDSInstalled

    if ($RunHealthCheckOnly) {
        $DomainName = Read-RequiredValue -Prompt 'Enter domain FQDN, example lab.local' -CurrentValue $DomainName
        Invoke-ADLabHealthCheck -DomainName $DomainName -ReportPath $script:ADSetupConfig.ReportPath -LogPath $script:ADSetupConfig.LogPath
        Write-Status 'Health check completed.' -Level Success
        return
    }

    $DomainName = Read-RequiredValue -Prompt 'Enter domain FQDN, example lab.local' -CurrentValue $DomainName
    $NetBIOSName = Read-RequiredValue -Prompt 'Enter NetBIOS name, example LAB' -CurrentValue $NetBIOSName

    if (-not (Test-DomainName -DomainName $DomainName)) {
        throw "Invalid domain name: $DomainName"
    }

    if (-not (Test-NetBIOSName -NetBIOSName $NetBIOSName)) {
        throw "Invalid NetBIOS name: $NetBIOSName. Use 1-15 letters, numbers, or hyphens."
    }

    if ($ConfigureDepartmentAccessControl) {
        New-ADLabDepartmentShares `
            -DomainName $DomainName `
            -NetBIOSName $NetBIOSName `
            -RootPath $script:ADSetupConfig.DepartmentShareRootPath `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Write-Status 'Department-Based Access Control configuration completed.' -Level Success
        return
    }

    if ($ConfigureSecurityMonitoring) {
        $collectorFqdn = if ([string]::IsNullOrWhiteSpace($SecurityMonitoringCollector)) {
            Read-Host 'Enter Windows Event Forwarding collector FQDN, example dc01.lab.local'
        } else {
            $SecurityMonitoringCollector
        }

        if ([string]::IsNullOrWhiteSpace($collectorFqdn)) {
            throw 'Windows Event Forwarding collector FQDN is required for security monitoring configuration.'
        }

        New-ADLabAuditPolicyGPO `
            -DomainName $DomainName `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Enable-ADLabWindowsEventForwarding `
            -DomainName $DomainName `
            -NetBIOSName $NetBIOSName `
            -CollectorFqdn $collectorFqdn `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        New-ADLabSysmonDeploymentStub `
            -StubPath $script:ADSetupConfig.SysmonStubPath `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Write-Status 'Security monitoring configuration completed.' -Level Success
        return
    }

    if ($ConfigureWindowsLAPS) {
        $targetLapsOu = if ([string]::IsNullOrWhiteSpace($LAPSManagedOU)) {
            $script:ADSetupConfig.LAPSManagedOU
        } else {
            $LAPSManagedOU
        }

        Install-ADLabWindowsLAPS `
            -ExtendSchema:$ExtendLAPSSchema `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Set-ADLabLAPSConfiguration `
            -DomainName $DomainName `
            -NetBIOSName $NetBIOSName `
            -ManagedOU $targetLapsOu `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Write-Status 'Windows LAPS configuration completed.' -Level Success
        return
    }

    if ($GenerateHtmlReport) {
        New-ADLabHtmlReport `
            -DomainName $DomainName `
            -ReportPath $script:ADSetupConfig.HtmlReportPath `
            -TextHealthReportPath $script:ADSetupConfig.ReportPath `
            -DepartmentShareRootPath $script:ADSetupConfig.DepartmentShareRootPath `
            -SysmonStubPath $script:ADSetupConfig.SysmonStubPath `
            -LogPath $script:ADSetupConfig.LogPath `
            -WhatIf:$WhatIfPreference

        Write-Status 'HTML Health and Security Report generation completed.' -Level Success
        return
    }

    if (-not (Test-Path -LiteralPath $UserCsvPath)) {
        throw "CSV file not found: $UserCsvPath"
    }

    $usersEnabled = -not $DisableImportedUsers
    $passwordChangeAtLogon = if ($PSBoundParameters.ContainsKey('ForcePasswordChangeAtLogon')) {
        [bool]$ForcePasswordChangeAtLogon
    } else {
        [bool]$script:ADSetupConfig.DefaultUserPasswordChangeAtLogon
    }

    Show-ExecutionPlan -TargetDomain $DomainName -TargetNetBIOS $NetBIOSName -CsvPath $UserCsvPath -UsersEnabled $usersEnabled -PasswordChangeAtLogon $passwordChangeAtLogon

    if (-not $WhatIfPreference) {
        $confirmation = Read-Host 'Continue with these changes? Type YES to continue'
        if ($confirmation -ne 'YES') {
            Write-Status 'Setup cancelled by user.' -Level Warning
            return
        }
    }

    Install-ADLabWindowsFeatures -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference

    if (-not $isDc -and -not $SkipPromotion) {
        $domainAdminPassword = Read-Host 'Enter the new domain Administrator password' -AsSecureString
        $safeModePassword = Read-Host 'Enter Directory Services Restore Mode password' -AsSecureString

        if (-not (Test-PasswordComplexity -Password $domainAdminPassword)) {
            throw 'The domain Administrator password does not meet baseline complexity requirements.'
        }

        if (-not (Test-PasswordComplexity -Password $safeModePassword)) {
            throw 'The DSRM password does not meet baseline complexity requirements.'
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Promote to new forest $DomainName")) {
            Set-ADLabLocalAdministratorPassword -Password $domainAdminPassword -LogPath $script:ADSetupConfig.LogPath
            Install-ADLabForest -DomainName $DomainName -NetBIOSName $NetBIOSName -SafeModeAdministratorPassword $safeModePassword -LogPath $script:ADSetupConfig.LogPath
            Write-Status 'Promotion command submitted. A restart is normally required before continuing domain object creation.' -Level Warning
            Write-Status 'After reboot, run main.ps1 again with the same domain and NetBIOS values.' -Level Warning
            return
        }
    } elseif ($isDc) {
        Write-Status 'Machine is already a Domain Controller. Promotion step skipped.' -Level Success
    } else {
        Write-Status 'Promotion skipped by parameter.' -Level Warning
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    Set-ADLabDnsBasics -DomainName $DomainName -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference
    New-ADLabOrganizationalUnits -DomainName $DomainName -OUList $script:ADSetupConfig.DefaultOUs -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference
    New-ADLabGroups -DomainName $DomainName -GroupList $script:ADSetupConfig.DefaultGroups -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference
    New-ADLabUsersFromCsv -DomainName $DomainName -CsvPath $UserCsvPath -Enabled:$usersEnabled -ChangePasswordAtLogon:$passwordChangeAtLogon -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference

    if (-not $SkipGpo) {
        Set-ADLabBasicGpos -DomainName $DomainName -LogPath $script:ADSetupConfig.LogPath -WhatIf:$WhatIfPreference
    }

    Invoke-ADLabHealthCheck -DomainName $DomainName -ReportPath $script:ADSetupConfig.ReportPath -LogPath $script:ADSetupConfig.LogPath
    Write-Status 'AD lab setup completed. Review the final report and log file.' -Level Success
} catch {
    Write-Status $_.Exception.Message -Level Error
    throw
}

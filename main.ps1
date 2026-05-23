[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DomainName,
    [string]$NetBIOSName,
    [string]$UserCsvPath,
    [switch]$ForcePasswordChangeAtLogon,
    [switch]$DisableImportedUsers,
    [switch]$SkipPromotion,
    [switch]$SkipGpo,
    [switch]$RunHealthCheckOnly
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
    Write-Host 'Active Directory Auto Deployment Lab execution plan' -ForegroundColor Magenta
    Write-Host '-----------------------------------' -ForegroundColor Magenta
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

    $UserCsvPath = if ([string]::IsNullOrWhiteSpace($UserCsvPath)) {
        $script:ADSetupConfig.UserCsvPath
    } else {
        $UserCsvPath
    }

    if (-not (Test-Path -LiteralPath $UserCsvPath)) {
        throw "CSV file not found: $UserCsvPath"
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

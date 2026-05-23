# Active Directory Auto Deployment Lab configuration.
# Values here are safe defaults for a lab and can be overridden from main.ps1 prompts.

$script:ADSetupConfig = @{
    RootPath = 'C:\AD_Setup'
    LogPath = 'C:\AD_Setup\Logs\setup.log'
    ReportPath = 'C:\AD_Setup\Reports\final-report.txt'
    UserCsvPath = Join-Path $PSScriptRoot 'data\users.csv'

    DefaultOUs = @(
        'Users'
        'Admins'
        'IT'
        'HR'
        'Finance'
        'Computers'
        'Servers'
        'Disabled Users'
    )

    DefaultGroups = @(
        'IT_Admins'
        'HR_Users'
        'Finance_Users'
        'Helpdesk'
        'Remote_Desktop_Users'
    )

    # Lab-oriented defaults. Review before using in any non-lab environment.
    DefaultUserPasswordChangeAtLogon = $true
    DefaultUserEnabled = $true
    DomainControllerInstallTimeoutSeconds = 3600
}

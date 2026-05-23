function Initialize-ADSetupFolders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath
    )

    foreach ($path in @($RootPath, (Join-Path $RootPath 'Logs'), (Join-Path $RootPath 'Reports'))) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }
    }
}

function Write-ADSetupLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info',
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $folder = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.ToUpperInvariant(), $Message
    Add-Content -Path $LogPath -Value $line
}

function Assert-RunningAsAdministrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Active Directory Auto Deployment Lab must be run from an elevated PowerShell session.'
    }
}

function Test-ADDSInstalled {
    [CmdletBinding()]
    param()

    try {
        $feature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
        return [bool]$feature.Installed
    } catch {
        return $false
    }
}

function Test-IsDomainController {
    [CmdletBinding()]
    param()

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return ($computerSystem.DomainRole -in 4, 5)
    } catch {
        return $false
    }
}

function Test-DomainName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    return ($DomainName -match '^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
}

function Test-NetBIOSName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NetBIOSName
    )

    return ($NetBIOSName -match '^[A-Za-z0-9-]{1,15}$')
}

function Convert-SecureStringToPlainText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [securestring]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Test-PasswordComplexity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [securestring]$Password
    )

    $plain = Convert-SecureStringToPlainText -SecureString $Password
    try {
        if ($plain.Length -lt 8) { return $false }

        $categories = 0
        if ($plain -cmatch '[A-Z]') { $categories++ }
        if ($plain -cmatch '[a-z]') { $categories++ }
        if ($plain -match '\d') { $categories++ }
        if ($plain -match '[^a-zA-Z0-9]') { $categories++ }

        return ($categories -ge 3)
    } finally {
        $plain = $null
    }
}

function Get-DomainDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Invoke-CommandWithReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )

    $output = New-Object System.Collections.Generic.List[string]
    $output.Add('')
    $output.Add("## $Title")

    try {
        $result = & $ScriptBlock 2>&1 | Out-String
        $output.Add($result.Trim())
    } catch {
        $output.Add("ERROR: $($_.Exception.Message)")
    }

    return $output
}

function Invoke-ADLabHealthCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$ReportPath,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    Write-ADSetupLog -Message 'Starting post-setup health checks.' -Level Info -LogPath $LogPath

    $reportFolder = Split-Path -Parent $ReportPath
    if (-not (Test-Path -LiteralPath $reportFolder)) {
        New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
    }

    $report = New-Object System.Collections.Generic.List[string]
    $report.Add('Active Directory Auto Deployment Lab Final Report')
    $report.Add(('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $report.Add(('Computer: {0}' -f $env:COMPUTERNAME))
    $report.Add(('Domain: {0}' -f $DomainName))

    $report.AddRange((Invoke-CommandWithReport -Title 'dcdiag' -ScriptBlock { dcdiag }))
    $report.AddRange((Invoke-CommandWithReport -Title 'repadmin /replsummary' -ScriptBlock { repadmin /replsummary }))
    $report.AddRange((Invoke-CommandWithReport -Title "nslookup $DomainName" -ScriptBlock { nslookup $DomainName }))

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $report.AddRange((Invoke-CommandWithReport -Title 'Get-ADDomain' -ScriptBlock { Get-ADDomain | Format-List | Out-String }))
        $report.AddRange((Invoke-CommandWithReport -Title 'Get-ADUser count' -ScriptBlock { (Get-ADUser -Filter *).Count }))
        $report.AddRange((Invoke-CommandWithReport -Title 'Get-ADGroup count' -ScriptBlock { (Get-ADGroup -Filter *).Count }))
    } catch {
        $report.Add('')
        $report.Add('## ActiveDirectory module checks')
        $report.Add("ERROR: $($_.Exception.Message)")
    }

    Set-Content -Path $ReportPath -Value $report -Encoding UTF8
    Write-ADSetupLog -Message "Health check report written to $ReportPath." -Level Success -LogPath $LogPath
}

Export-ModuleMember -Function Initialize-ADSetupFolders, Write-ADSetupLog, Assert-RunningAsAdministrator, Test-ADDSInstalled, Test-IsDomainController, Test-DomainName, Test-NetBIOSName, Test-PasswordComplexity, Get-DomainDistinguishedName, Invoke-ADLabHealthCheck

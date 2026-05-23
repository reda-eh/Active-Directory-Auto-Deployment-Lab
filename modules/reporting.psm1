function ConvertTo-ADLabHtmlText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-ADLabReportSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,
        [Parameter(Mandatory)]
        [string]$Body
    )

    return "<section><h2>$(ConvertTo-ADLabHtmlText $Title)</h2>$Body</section>"
}

function New-ADLabHtmlTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rows,
        [Parameter(Mandatory)]
        [string[]]$Columns
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        return '<p class="muted">No data available.</p>'
    }

    $html = New-Object System.Collections.Generic.List[string]
    $html.Add('<table>')
    $html.Add('<thead><tr>')

    foreach ($column in $Columns) {
        $html.Add("<th>$(ConvertTo-ADLabHtmlText $column)</th>")
    }

    $html.Add('</tr></thead>')
    $html.Add('<tbody>')

    foreach ($row in $Rows) {
        $html.Add('<tr>')
        foreach ($column in $Columns) {
            $value = if ($row.PSObject.Properties.Name -contains $column) { $row.$column } else { '' }
            $html.Add("<td>$(ConvertTo-ADLabHtmlText $value)</td>")
        }
        $html.Add('</tr>')
    }

    $html.Add('</tbody></table>')
    return ($html -join [Environment]::NewLine)
}

function Add-ADLabReportWarning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $Warnings.Add($Message)
    Write-ADSetupLog -Message $Message -Level Warning -LogPath $LogPath
}

function Get-ADLabReportDomainSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop

        return [pscustomobject]@{
            DomainName = $domain.DNSRoot
            NetBIOSName = $domain.NetBIOSName
            Forest = $domain.Forest
            DomainMode = $domain.DomainMode
            InfrastructureMaster = $domain.InfrastructureMaster
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
        }
    } catch {
        Add-ADLabReportWarning -Warnings $Warnings -Message "Domain information unavailable: $($_.Exception.Message)" -LogPath $LogPath
        return [pscustomobject]@{
            DomainName = 'Unavailable'
            NetBIOSName = 'Unavailable'
            Forest = 'Unavailable'
            DomainMode = 'Unavailable'
            InfrastructureMaster = 'Unavailable'
            PDCEmulator = 'Unavailable'
            RIDMaster = 'Unavailable'
        }
    }
}

function Get-ADLabReportCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        return [pscustomobject]@{
            OUs = (Get-ADOrganizationalUnit -Filter * -ErrorAction Stop).Count
            Users = (Get-ADUser -Filter * -ErrorAction Stop).Count
            Groups = (Get-ADGroup -Filter * -ErrorAction Stop).Count
        }
    } catch {
        Add-ADLabReportWarning -Warnings $Warnings -Message "Directory object counts unavailable: $($_.Exception.Message)" -LogPath $LogPath
        return [pscustomobject]@{
            OUs = 'Unavailable'
            Users = 'Unavailable'
            Groups = 'Unavailable'
        }
    }
}

function Get-ADLabReportGpoSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        return @(Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName | Select-Object DisplayName, Owner, GpoStatus, CreationTime, ModificationTime)
    } catch {
        Add-ADLabReportWarning -Warnings $Warnings -Message "GPO summary unavailable: $($_.Exception.Message)" -LogPath $LogPath
        return @()
    }
}

function Get-ADLabReportShareSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ShareRootPath,
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $shareNames = @('HR$', 'Finance$', 'IT$', 'Public$')
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($shareName in $shareNames) {
        try {
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            $expectedFolder = Join-Path $ShareRootPath ($shareName.TrimEnd('$'))

            if ($share) {
                $rows.Add([pscustomobject]@{
                    Share = $shareName
                    Status = 'Present'
                    Path = $share.Path
                    FolderExists = [bool](Test-Path -LiteralPath $share.Path)
                })
            } else {
                $rows.Add([pscustomobject]@{
                    Share = $shareName
                    Status = 'Missing'
                    Path = $expectedFolder
                    FolderExists = [bool](Test-Path -LiteralPath $expectedFolder)
                })
            }
        } catch {
            Add-ADLabReportWarning -Warnings $Warnings -Message "Department share summary unavailable for $shareName. $($_.Exception.Message)" -LogPath $LogPath
        }
    }

    return $rows
}

function Get-ADLabReportLapsSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $lapsModule = Get-Module -ListAvailable -Name LAPS | Select-Object -First 1
        $schemaStatus = 'Unknown'

        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $rootDse = Get-ADRootDSE -ErrorAction Stop
            $schemaBase = $rootDse.schemaNamingContext
            $lapsAttribute = Get-ADObject -SearchBase $schemaBase -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -ErrorAction SilentlyContinue
            $schemaStatus = if ($lapsAttribute) { 'Windows LAPS schema attributes detected' } else { 'Windows LAPS schema attributes not detected' }
        } catch {
            $schemaStatus = "Schema check unavailable: $($_.Exception.Message)"
        }

        $gpoStatus = 'Unavailable'
        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpo = Get-GPO -Name 'LAB - Windows LAPS Policy' -ErrorAction SilentlyContinue
            $gpoStatus = if ($gpo) { 'LAB - Windows LAPS Policy found' } else { 'LAB - Windows LAPS Policy not found' }
        } catch {
            $gpoStatus = "GPO check unavailable: $($_.Exception.Message)"
        }

        return @(
            [pscustomobject]@{ Item = 'LAPS PowerShell module'; Status = if ($lapsModule) { "Found $($lapsModule.Version)" } else { 'Not found' } },
            [pscustomobject]@{ Item = 'Schema'; Status = $schemaStatus },
            [pscustomobject]@{ Item = 'GPO'; Status = $gpoStatus }
        )
    } catch {
        Add-ADLabReportWarning -Warnings $Warnings -Message "LAPS summary unavailable: $($_.Exception.Message)" -LogPath $LogPath
        return @()
    }
}

function Get-ADLabReportSecurityMonitoringSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SysmonStubPath,
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $auditGpoStatus = 'Unavailable'
        $wefGpoStatus = 'Unavailable'

        try {
            Import-Module GroupPolicy -ErrorAction Stop
            $auditGpoStatus = if (Get-GPO -Name 'LAB - Security Monitoring Audit Policy' -ErrorAction SilentlyContinue) { 'Found' } else { 'Not found' }
            $wefGpoStatus = if (Get-GPO -Name 'LAB - Windows Event Forwarding Preparation' -ErrorAction SilentlyContinue) { 'Found' } else { 'Not found' }
        } catch {
            $auditGpoStatus = "GPO check unavailable: $($_.Exception.Message)"
            $wefGpoStatus = "GPO check unavailable: $($_.Exception.Message)"
        }

        return @(
            [pscustomobject]@{ Item = 'Audit Policy GPO'; Status = $auditGpoStatus },
            [pscustomobject]@{ Item = 'Windows Event Forwarding GPO'; Status = $wefGpoStatus },
            [pscustomobject]@{ Item = 'Sysmon stub folder'; Status = if (Test-Path -LiteralPath $SysmonStubPath) { "Present: $SysmonStubPath" } else { "Missing: $SysmonStubPath" } },
            [pscustomobject]@{ Item = 'Sysmon.exe'; Status = if (Test-Path -LiteralPath (Join-Path $SysmonStubPath 'Sysmon.exe')) { 'Present' } else { 'User-provided file not found' } },
            [pscustomobject]@{ Item = 'sysmon-config.xml'; Status = if (Test-Path -LiteralPath (Join-Path $SysmonStubPath 'sysmon-config.xml')) { 'Present' } else { 'User-provided file not found' } }
        )
    } catch {
        Add-ADLabReportWarning -Warnings $Warnings -Message "Security monitoring summary unavailable: $($_.Exception.Message)" -LogPath $LogPath
        return @()
    }
}

function Get-ADLabReportHealthSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TextReportPath,
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[string]]$Warnings,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    if (Test-Path -LiteralPath $TextReportPath) {
        try {
            $content = Get-Content -Path $TextReportPath -Raw -ErrorAction Stop
            return "<pre>$(ConvertTo-ADLabHtmlText $content)</pre>"
        } catch {
            Add-ADLabReportWarning -Warnings $Warnings -Message "Health check report could not be read: $($_.Exception.Message)" -LogPath $LogPath
            return '<p class="muted">Health check report could not be read.</p>'
        }
    }

    Add-ADLabReportWarning -Warnings $Warnings -Message "Health check report not found at $TextReportPath." -LogPath $LogPath
    return '<p class="muted">No health check report found. Run the health check feature to populate this section.</p>'
}

function Get-ADLabReportLogWarnings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    if (-not (Test-Path -LiteralPath $LogPath)) {
        return @([pscustomobject]@{ Type = 'Warning'; Message = "Log file not found: $LogPath" })
    }

    try {
        return @(Get-Content -Path $LogPath -ErrorAction Stop |
            Where-Object { $_ -match '\[(WARNING|ERROR)\]' } |
            Select-Object -Last 50 |
            ForEach-Object {
                [pscustomobject]@{
                    Type = if ($_ -match '\[ERROR\]') { 'Error' } else { 'Warning' }
                    Message = $_
                }
            })
    } catch {
        return @([pscustomobject]@{ Type = 'Warning'; Message = "Log warnings could not be read: $($_.Exception.Message)" })
    }
}

function New-ADLabHtmlReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [string]$ReportPath = 'C:\AD_Setup\Reports\ADLab_Report.html',
        [string]$TextHealthReportPath = 'C:\AD_Setup\Reports\final-report.txt',
        [string]$DepartmentShareRootPath = 'C:\AD_Lab_Shares',
        [string]$SysmonStubPath = 'C:\AD_Setup\SecurityMonitoring\Sysmon',
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $warnings = [System.Collections.Generic.List[string]]::new()

    try {
        Write-ADSetupLog -Message 'Starting HTML Health and Security Report generation.' -Level Info -LogPath $LogPath

        $reportFolder = Split-Path -Parent $ReportPath
        if (-not (Test-Path -LiteralPath $reportFolder)) {
            if ($PSCmdlet.ShouldProcess($reportFolder, 'Create HTML report folder')) {
                New-Item -Path $reportFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-ADSetupLog -Message "Created HTML report folder: $reportFolder." -Level Success -LogPath $LogPath
            }
        }

        $domainSummary = Get-ADLabReportDomainSummary -Warnings $warnings -LogPath $LogPath
        $counts = Get-ADLabReportCounts -Warnings $warnings -LogPath $LogPath
        $gpos = Get-ADLabReportGpoSummary -Warnings $warnings -LogPath $LogPath
        $shares = Get-ADLabReportShareSummary -ShareRootPath $DepartmentShareRootPath -Warnings $warnings -LogPath $LogPath
        $laps = Get-ADLabReportLapsSummary -Warnings $warnings -LogPath $LogPath
        $securityMonitoring = Get-ADLabReportSecurityMonitoringSummary -SysmonStubPath $SysmonStubPath -Warnings $warnings -LogPath $LogPath
        $health = Get-ADLabReportHealthSummary -TextReportPath $TextHealthReportPath -Warnings $warnings -LogPath $LogPath
        $logWarnings = Get-ADLabReportLogWarnings -LogPath $LogPath

        $domainTable = New-ADLabHtmlTable -Rows @($domainSummary) -Columns @('DomainName', 'NetBIOSName', 'Forest', 'DomainMode', 'InfrastructureMaster', 'PDCEmulator', 'RIDMaster')
        $countsTable = New-ADLabHtmlTable -Rows @($counts) -Columns @('OUs', 'Users', 'Groups')
        $gpoTable = New-ADLabHtmlTable -Rows $gpos -Columns @('DisplayName', 'Owner', 'GpoStatus', 'CreationTime', 'ModificationTime')
        $shareTable = New-ADLabHtmlTable -Rows $shares -Columns @('Share', 'Status', 'Path', 'FolderExists')
        $lapsTable = New-ADLabHtmlTable -Rows $laps -Columns @('Item', 'Status')
        $securityMonitoringTable = New-ADLabHtmlTable -Rows $securityMonitoring -Columns @('Item', 'Status')
        $logWarningTable = New-ADLabHtmlTable -Rows $logWarnings -Columns @('Type', 'Message')
        $runtimeWarningsTable = New-ADLabHtmlTable -Rows @($warnings | ForEach-Object { [pscustomobject]@{ Type = 'Runtime Warning'; Message = $_ } }) -Columns @('Type', 'Message')

        $sections = @(
            (New-ADLabReportSection -Title 'Domain Information' -Body $domainTable),
            (New-ADLabReportSection -Title 'Directory Object Counts' -Body $countsTable),
            (New-ADLabReportSection -Title 'GPO Summary' -Body $gpoTable),
            (New-ADLabReportSection -Title 'Department Shares Summary' -Body $shareTable),
            (New-ADLabReportSection -Title 'LAPS Status Summary' -Body $lapsTable),
            (New-ADLabReportSection -Title 'Security Monitoring Summary' -Body $securityMonitoringTable),
            (New-ADLabReportSection -Title 'Health Check Results' -Body $health),
            (New-ADLabReportSection -Title 'Errors and Warnings' -Body ($runtimeWarningsTable + $logWarningTable))
        )

        $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enterprise Active Directory Automation & Security Lab Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --text: #172033;
      --muted: #667085;
      --border: #d9e0ea;
      --accent: #2563eb;
      --heading: #0f172a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.45;
    }
    header {
      padding: 28px 36px;
      background: #111827;
      color: #ffffff;
      border-bottom: 4px solid var(--accent);
    }
    header h1 {
      margin: 0 0 6px;
      font-size: 28px;
      letter-spacing: 0;
    }
    header p {
      margin: 0;
      color: #cbd5e1;
    }
    main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-bottom: 18px;
      padding: 18px;
    }
    h2 {
      margin: 0 0 14px;
      color: var(--heading);
      font-size: 18px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      border-bottom: 1px solid var(--border);
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      background: #eef2f7;
      color: #1f2937;
      font-weight: 600;
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #0f172a;
      color: #dbeafe;
      padding: 14px;
      border-radius: 6px;
      max-height: 520px;
      overflow: auto;
    }
    .muted {
      color: var(--muted);
      margin: 0;
    }
  </style>
</head>
<body>
  <header>
    <h1>Enterprise Active Directory Automation & Security Lab Report</h1>
    <p>Creator: Rida Elhammioui | Domain: $(ConvertTo-ADLabHtmlText $DomainName) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
  </header>
  <main>
    $($sections -join [Environment]::NewLine)
  </main>
</body>
</html>
"@

        if ($PSCmdlet.ShouldProcess($ReportPath, 'Write HTML Health and Security Report')) {
            Set-Content -Path $ReportPath -Value $html -Encoding UTF8 -ErrorAction Stop
            Write-Host "[REPORT] HTML report written: $ReportPath" -ForegroundColor Cyan
            Write-ADSetupLog -Message "HTML Health and Security Report written to $ReportPath." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "HTML report generation failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function New-ADLabHtmlReport

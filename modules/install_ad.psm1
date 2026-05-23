function Install-ADLabWindowsFeatures {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $features = @(
        'AD-Domain-Services',
        'DNS',
        'GPMC',
        'RSAT-AD-Tools',
        'RSAT-DNS-Server'
    )

    foreach ($featureName in $features) {
        try {
            $feature = Get-WindowsFeature -Name $featureName -ErrorAction Stop
            if ($feature.Installed) {
                Write-Host "[OK] Feature already installed: $featureName" -ForegroundColor Green
                Write-ADSetupLog -Message "Feature already installed: $featureName" -Level Success -LogPath $LogPath
                continue
            }

            if ($PSCmdlet.ShouldProcess($featureName, 'Install Windows feature')) {
                Write-Host "[INSTALL] Installing feature: $featureName" -ForegroundColor Cyan
                Install-WindowsFeature -Name $featureName -IncludeManagementTools -ErrorAction Stop | Out-Null
                Write-ADSetupLog -Message "Installed Windows feature: $featureName" -Level Success -LogPath $LogPath
            }
        } catch {
            Write-ADSetupLog -Message "Failed to install feature $featureName. $($_.Exception.Message)" -Level Error -LogPath $LogPath
            throw
        }
    }
}

function Install-ADLabForest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [Parameter(Mandatory)]
        [securestring]$SafeModeAdministratorPassword,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ADDSDeployment -ErrorAction Stop

        Write-Host "[PROMOTE] Creating new forest: $DomainName" -ForegroundColor Yellow
        Write-ADSetupLog -Message "Starting forest creation for $DomainName." -Level Info -LogPath $LogPath

        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $NetBIOSName `
            -SafeModeAdministratorPassword $SafeModeAdministratorPassword `
            -InstallDns `
            -CreateDnsDelegation:$false `
            -DatabasePath 'C:\Windows\NTDS' `
            -LogPath 'C:\Windows\NTDS' `
            -SysvolPath 'C:\Windows\SYSVOL' `
            -Force:$true `
            -NoRebootOnCompletion:$false `
            -ErrorAction Stop
    } catch {
        Write-ADSetupLog -Message "Forest promotion failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Set-ADLabLocalAdministratorPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [securestring]$Password,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $localAdministrator = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        if (-not $localAdministrator) {
            Write-ADSetupLog -Message 'Built-in local Administrator account was not found; password update skipped.' -Level Warning -LogPath $LogPath
            return
        }

        Set-LocalUser -Name 'Administrator' -Password $Password -ErrorAction Stop
        Write-ADSetupLog -Message 'Local Administrator password updated before domain promotion.' -Level Success -LogPath $LogPath
    } catch {
        Write-ADSetupLog -Message "Failed to set local Administrator password. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Set-ADLabDnsBasics {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        if ($dnsService -and $dnsService.Status -ne 'Running') {
            if ($PSCmdlet.ShouldProcess('DNS service', 'Start service')) {
                Start-Service -Name DNS -ErrorAction Stop
                Write-ADSetupLog -Message 'DNS service started.' -Level Success -LogPath $LogPath
            }
        }

        $activeAdapters = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.ServerAddresses -notcontains '127.0.0.1' }

        foreach ($adapter in $activeAdapters) {
            if ($PSCmdlet.ShouldProcess($adapter.InterfaceAlias, 'Set DNS client server to 127.0.0.1')) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
                Write-ADSetupLog -Message "Set DNS client server to 127.0.0.1 on $($adapter.InterfaceAlias)." -Level Success -LogPath $LogPath
            }
        }

        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            $zone = Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue
            if ($zone) {
                Write-Host "[OK] DNS zone exists: $DomainName" -ForegroundColor Green
                Write-ADSetupLog -Message "DNS zone exists: $DomainName" -Level Success -LogPath $LogPath
            } else {
                Write-ADSetupLog -Message "DNS zone not found yet: $DomainName. AD DS normally creates it during promotion." -Level Warning -LogPath $LogPath
            }
        }
    } catch {
        Write-ADSetupLog -Message "DNS basics configuration failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function Install-ADLabWindowsFeatures, Install-ADLabForest, Set-ADLabLocalAdministratorPassword, Set-ADLabDnsBasics

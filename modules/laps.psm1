function Get-ADLabLapsDomainDn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    return ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
}

function Get-ADLabLapsPolicyTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$ManagedOU,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $domainDn = Get-ADLabLapsDomainDn -DomainName $DomainName
    $ouDn = "OU=$ManagedOU,$domainDn"

    try {
        $ou = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDn)" -ErrorAction SilentlyContinue
        if ($ou) {
            return $ouDn
        }

        Write-ADSetupLog -Message "LAPS managed OU was not found: $ouDn. Falling back to domain root." -Level Warning -LogPath $LogPath
        return $domainDn
    } catch {
        Write-ADSetupLog -Message "Unable to check LAPS managed OU $ouDn. Falling back to domain root. $($_.Exception.Message)" -Level Warning -LogPath $LogPath
        return $domainDn
    }
}

function Ensure-ADLabLapsGpoLinked {
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
        Write-ADSetupLog -Message "Failed to link LAPS GPO $GpoName to $Target. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Test-ADLabLapsSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $schemaBase = $rootDse.schemaNamingContext
        $requiredAttributes = @(
            'msLAPS-PasswordExpirationTime',
            'msLAPS-Password',
            'msLAPS-EncryptedPassword',
            'msLAPS-EncryptedPasswordHistory',
            'msLAPS-EncryptedDSRMPassword',
            'msLAPS-EncryptedDSRMPasswordHistory'
        )

        $missingAttributes = @()
        foreach ($attributeName in $requiredAttributes) {
            $attribute = Get-ADObject -SearchBase $schemaBase -LDAPFilter "(lDAPDisplayName=$attributeName)" -ErrorAction SilentlyContinue
            if (-not $attribute) {
                $missingAttributes += $attributeName
            }
        }

        if ($missingAttributes.Count -eq 0) {
            Write-Host '[OK] Windows LAPS schema attributes found' -ForegroundColor Green
            Write-ADSetupLog -Message 'Windows LAPS schema attributes were found.' -Level Success -LogPath $LogPath
            return $true
        }

        Write-Host '[WARN] Windows LAPS schema attributes are missing' -ForegroundColor Yellow
        Write-ADSetupLog -Message "Windows LAPS schema attributes missing: $($missingAttributes -join ', ')." -Level Warning -LogPath $LogPath
        return $false
    } catch {
        Write-ADSetupLog -Message "Windows LAPS schema check failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Install-ADLabWindowsLAPS {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$ExtendSchema,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $lapsModule = Get-Module -ListAvailable -Name LAPS | Select-Object -First 1
        if (-not $lapsModule) {
            Write-Host '[WARN] Windows LAPS PowerShell module was not found' -ForegroundColor Yellow
            Write-ADSetupLog -Message 'Windows LAPS PowerShell module was not found. Install current Windows updates or RSAT tools before configuring LAPS.' -Level Warning -LogPath $LogPath
            return $false
        }

        Import-Module LAPS -ErrorAction Stop
        Write-Host "[OK] Windows LAPS module found: $($lapsModule.Version)" -ForegroundColor Green
        Write-ADSetupLog -Message "Windows LAPS module found: $($lapsModule.Version)." -Level Success -LogPath $LogPath

        $schemaReady = Test-ADLabLapsSchema -LogPath $LogPath
        if (-not $schemaReady -and $ExtendSchema) {
            if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) {
                throw 'Update-LapsADSchema cmdlet was not found. Cannot extend schema.'
            }

            if ($PSCmdlet.ShouldProcess('Active Directory schema', 'Extend for Windows LAPS')) {
                Update-LapsADSchema -ErrorAction Stop
                Write-Host '[SCHEMA] Windows LAPS schema extension completed' -ForegroundColor Cyan
                Write-ADSetupLog -Message 'Windows LAPS schema extension completed.' -Level Success -LogPath $LogPath
            }
        } elseif (-not $schemaReady) {
            Write-ADSetupLog -Message 'Windows LAPS schema is not ready. Re-run with -ExtendLAPSSchema after reviewing schema-change requirements.' -Level Warning -LogPath $LogPath
        }

        return $true
    } catch {
        Write-ADSetupLog -Message "Windows LAPS prerequisite preparation failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Set-ADLabLAPSConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [string]$ManagedOU = 'Computers',
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop

        if (Get-Module -ListAvailable -Name LAPS) {
            Import-Module LAPS -ErrorAction Stop
        } else {
            Write-ADSetupLog -Message 'Windows LAPS PowerShell module is not available; permission delegation cmdlets will be skipped.' -Level Warning -LogPath $LogPath
        }

        $domainDn = Get-ADLabLapsDomainDn -DomainName $DomainName
        $target = Get-ADLabLapsPolicyTarget -DomainName $DomainName -ManagedOU $ManagedOU -LogPath $LogPath
        $gpoName = 'LAB - Windows LAPS Policy'
        $domainAdmins = "$NetBIOSName\Domain Admins"

        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            if ($PSCmdlet.ShouldProcess($gpoName, 'Create Windows LAPS GPO')) {
                $gpo = New-GPO -Name $gpoName -Comment 'Active Directory Auto Deployment Lab Windows LAPS policy.' -ErrorAction Stop
                Write-Host "[CREATE] GPO created: $gpoName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created Windows LAPS GPO: $gpoName." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] GPO exists: $gpoName" -ForegroundColor Green
            Write-ADSetupLog -Message "Windows LAPS GPO already exists: $gpoName." -Level Success -LogPath $LogPath
        }

        if ($gpo) {
            $registrySettings = @(
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'BackupDirectory'
                    Type = 'DWord'
                    Value = 2
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'PasswordAgeDays'
                    Type = 'DWord'
                    Value = 30
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'PasswordLength'
                    Type = 'DWord'
                    Value = 16
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'PasswordComplexity'
                    Type = 'DWord'
                    Value = 4
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'ADPasswordEncryptionEnabled'
                    Type = 'DWord'
                    Value = 1
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'ADPasswordEncryptionPrincipal'
                    Type = 'String'
                    Value = $domainAdmins
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'PostAuthenticationActions'
                    Type = 'DWord'
                    Value = 3
                },
                @{
                    Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
                    ValueName = 'PostAuthenticationResetDelay'
                    Type = 'DWord'
                    Value = 8
                }
            )

            foreach ($setting in $registrySettings) {
                if ($PSCmdlet.ShouldProcess($gpoName, "Set Windows LAPS registry policy $($setting.Key)\$($setting.ValueName)")) {
                    Set-GPRegistryValue -Name $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -ErrorAction Stop
                    Write-ADSetupLog -Message "Set Windows LAPS policy value $($setting.Key)\$($setting.ValueName)." -Level Success -LogPath $LogPath
                }
            }

            Ensure-ADLabLapsGpoLinked -GpoName $gpoName -Target $target -LogPath $LogPath -WhatIf:$WhatIfPreference
        }

        if (Get-Command Set-LapsADComputerSelfPermission -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($target, 'Delegate Windows LAPS computer self permissions')) {
                Set-LapsADComputerSelfPermission -Identity $target -ErrorAction Stop | Out-Null
                Write-Host "[LAPS] Computer self permissions delegated on $target" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Delegated Windows LAPS computer self permissions on $target." -Level Success -LogPath $LogPath
            }
        }

        if (Get-Command Set-LapsADReadPasswordPermission -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($target, "Delegate Windows LAPS read password permission to $domainAdmins")) {
                Set-LapsADReadPasswordPermission -Identity $target -AllowedPrincipals $domainAdmins -ErrorAction Stop | Out-Null
                Write-Host "[LAPS] Read password permissions delegated to $domainAdmins" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Delegated Windows LAPS read password permission on $target to $domainAdmins." -Level Success -LogPath $LogPath
            }
        }

        if (Get-Command Set-LapsADResetPasswordPermission -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($target, "Delegate Windows LAPS reset password permission to $domainAdmins")) {
                Set-LapsADResetPasswordPermission -Identity $target -AllowedPrincipals $domainAdmins -ErrorAction Stop | Out-Null
                Write-Host "[LAPS] Reset password permissions delegated to $domainAdmins" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Delegated Windows LAPS reset password permission on $target to $domainAdmins." -Level Success -LogPath $LogPath
            }
        }

        if ($target -eq $domainDn) {
            Write-ADSetupLog -Message 'Windows LAPS GPO was linked at the domain root because the requested managed OU was not found.' -Level Warning -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Windows LAPS configuration failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function Install-ADLabWindowsLAPS, Set-ADLabLAPSConfiguration

function Test-PlainTextPasswordComplexity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Password
    )

    if ($Password.Length -lt 8) { return $false }

    $categories = 0
    if ($Password -cmatch '[A-Z]') { $categories++ }
    if ($Password -cmatch '[a-z]') { $categories++ }
    if ($Password -match '\d') { $categories++ }
    if ($Password -match '[^a-zA-Z0-9]') { $categories++ }

    return ($categories -ge 3)
}

function Get-TargetOuPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$OuValue
    )

    $domainDn = Get-DomainDistinguishedName -DomainName $DomainName

    if ([string]::IsNullOrWhiteSpace($OuValue)) {
        return "OU=Users,$domainDn"
    }

    if ($OuValue -like 'OU=*') {
        if ($OuValue -like "*,DC=*") {
            return $OuValue
        }

        return "$OuValue,$domainDn"
    }

    return "OU=$OuValue,$domainDn"
}

function Split-CsvGroups {
    [CmdletBinding()]
    param(
        [string]$Groups
    )

    if ([string]::IsNullOrWhiteSpace($Groups)) {
        return @()
    }

    return $Groups.Split(';', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

function ConvertTo-ADFilterLiteral {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Value
    )

    return ($Value -replace "'", "''")
}

function New-ADLabUsersFromCsv {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$CsvPath,
        [Parameter(Mandatory)]
        [bool]$Enabled,
        [Parameter(Mandatory)]
        [bool]$ChangePasswordAtLogon,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $requiredColumns = @('FirstName', 'LastName', 'Username', 'Password', 'OU', 'Groups', 'Department', 'Title')
    $users = @(Import-Csv -Path $CsvPath)

    if (-not $users -or $users.Count -eq 0) {
        Write-ADSetupLog -Message "No users found in CSV: $CsvPath" -Level Warning -LogPath $LogPath
        return
    }

    foreach ($column in $requiredColumns) {
        if (-not ($users[0].PSObject.Properties.Name -contains $column)) {
            throw "CSV is missing required column: $column"
        }
    }

    foreach ($user in $users) {
        try {
            if ([string]::IsNullOrWhiteSpace($user.Username)) {
                Write-ADSetupLog -Message 'Skipped CSV row with blank Username.' -Level Warning -LogPath $LogPath
                continue
            }

            if (-not (Test-PlainTextPasswordComplexity -Password $user.Password)) {
                Write-ADSetupLog -Message "Skipped user $($user.Username): password does not meet baseline complexity." -Level Warning -LogPath $LogPath
                Write-Host "[SKIP] Weak password for user: $($user.Username)" -ForegroundColor Yellow
                continue
            }

            $escapedUsername = ConvertTo-ADFilterLiteral -Value $user.Username
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$escapedUsername'" -ErrorAction SilentlyContinue
            $ouPath = Get-TargetOuPath -DomainName $DomainName -OuValue $user.OU

            if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouPath)" -ErrorAction SilentlyContinue)) {
                Write-ADSetupLog -Message "Skipped user $($user.Username): target OU not found: $ouPath" -Level Warning -LogPath $LogPath
                Write-Host "[SKIP] OU not found for user $($user.Username): $ouPath" -ForegroundColor Yellow
                continue
            }

            if ($existingUser) {
                Write-Host "[OK] User exists: $($user.Username)" -ForegroundColor Green
                Write-ADSetupLog -Message "User already exists: $($user.Username)" -Level Success -LogPath $LogPath
            } else {
                $securePassword = ConvertTo-SecureString -String $user.Password -AsPlainText -Force
                $displayName = "$($user.FirstName) $($user.LastName)".Trim()
                $upnSuffix = $DomainName
                $userPrincipalName = "$($user.Username)@$upnSuffix"

                if ($PSCmdlet.ShouldProcess($user.Username, 'Create AD user')) {
                    New-ADUser `
                        -Name $displayName `
                        -GivenName $user.FirstName `
                        -Surname $user.LastName `
                        -SamAccountName $user.Username `
                        -UserPrincipalName $userPrincipalName `
                        -DisplayName $displayName `
                        -Department $user.Department `
                        -Title $user.Title `
                        -Path $ouPath `
                        -AccountPassword $securePassword `
                        -Enabled:$Enabled `
                        -ChangePasswordAtLogon:$ChangePasswordAtLogon `
                        -ErrorAction Stop

                    Write-Host "[CREATE] User created: $($user.Username)" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Created user: $($user.Username)" -Level Success -LogPath $LogPath
                }
            }

            foreach ($groupName in (Split-CsvGroups -Groups $user.Groups)) {
                $escapedGroupName = ConvertTo-ADFilterLiteral -Value $groupName
                $group = Get-ADGroup -Filter "SamAccountName -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
                if (-not $group) {
                    Write-ADSetupLog -Message "Group not found for user $($user.Username): $groupName" -Level Warning -LogPath $LogPath
                    Write-Host "[WARN] Group not found: $groupName" -ForegroundColor Yellow
                    continue
                }

                $membership = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop | Where-Object { $_.SamAccountName -eq $user.Username }
                if ($membership) {
                    Write-Host "[OK] $($user.Username) already in $groupName" -ForegroundColor Green
                    continue
                }

                if ($PSCmdlet.ShouldProcess($groupName, "Add $($user.Username) to group")) {
                    Add-ADGroupMember -Identity $groupName -Members $user.Username -ErrorAction Stop
                    Write-Host "[ADD] $($user.Username) -> $groupName" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Added $($user.Username) to group $groupName." -Level Success -LogPath $LogPath
                }
            }
        } catch {
            Write-ADSetupLog -Message "Failed processing user $($user.Username). $($_.Exception.Message)" -Level Error -LogPath $LogPath
            throw
        }
    }
}

Export-ModuleMember -Function New-ADLabUsersFromCsv

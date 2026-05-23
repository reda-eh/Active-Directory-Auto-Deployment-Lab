function Get-ADLabPrincipalName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [Parameter(Mandatory)]
        [string]$Name
    )

    return "$NetBIOSName\$Name"
}

function Add-ADLabNtfsAccessRule {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Identity,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow

        $existingRule = $acl.Access | Where-Object {
            $_.IdentityReference.Value -ieq $Identity -and
            $_.AccessControlType -eq $accessType -and
            (($_.FileSystemRights -band $Rights) -eq $Rights)
        } | Select-Object -First 1

        if ($existingRule) {
            Write-Host "[OK] NTFS permission exists: $Identity -> $Path" -ForegroundColor Green
            Write-ADSetupLog -Message "NTFS permission already exists: $Identity has $Rights on $Path." -Level Success -LogPath $LogPath
            return
        }

        if ($PSCmdlet.ShouldProcess($Path, "Grant NTFS $Rights to $Identity")) {
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                $Rights,
                $inheritanceFlags,
                $propagationFlags,
                $accessType
            )

            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
            Write-Host "[ACL] $Identity -> $Path ($Rights)" -ForegroundColor Cyan
            Write-ADSetupLog -Message "Granted NTFS $Rights to $Identity on $Path." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Failed to apply NTFS permission for $Identity on $Path. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function Add-ADLabSmbShareAccess {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ShareName,
        [Parameter(Mandatory)]
        [string]$Identity,
        [Parameter(Mandatory)]
        [ValidateSet('Read', 'Change', 'Full')]
        [string]$AccessRight,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        $existingAccess = Get-SmbShareAccess -Name $ShareName -ErrorAction Stop |
            Where-Object { $_.AccountName -ieq $Identity -and $_.AccessControlType -eq 'Allow' -and $_.AccessRight -eq $AccessRight } |
            Select-Object -First 1

        if ($existingAccess) {
            Write-Host "[OK] SMB permission exists: $Identity -> $ShareName" -ForegroundColor Green
            Write-ADSetupLog -Message "SMB permission already exists: $Identity has $AccessRight on $ShareName." -Level Success -LogPath $LogPath
            return
        }

        if ($PSCmdlet.ShouldProcess($ShareName, "Grant SMB $AccessRight to $Identity")) {
            Grant-SmbShareAccess -Name $ShareName -AccountName $Identity -AccessRight $AccessRight -Force -ErrorAction Stop | Out-Null
            Write-Host "[SHARE ACL] $Identity -> $ShareName ($AccessRight)" -ForegroundColor Cyan
            Write-ADSetupLog -Message "Granted SMB $AccessRight to $Identity on $ShareName." -Level Success -LogPath $LogPath
        }
    } catch {
        Write-ADSetupLog -Message "Failed to apply SMB permission for $Identity on $ShareName. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

function New-ADLabDepartmentShares {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$NetBIOSName,
        [string]$RootPath = 'C:\AD_Lab_Shares',
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $domainAdmins = Get-ADLabPrincipalName -NetBIOSName $NetBIOSName -Name 'Domain Admins'
    $domainUsers = Get-ADLabPrincipalName -NetBIOSName $NetBIOSName -Name 'Domain Users'

    $definitions = @(
        @{
            Name = 'HR'
            ShareName = 'HR$'
            DepartmentPrincipal = Get-ADLabPrincipalName -NetBIOSName $NetBIOSName -Name 'HR_Users'
            DepartmentNtfsRight = [System.Security.AccessControl.FileSystemRights]::Modify
            DepartmentShareRight = 'Change'
        },
        @{
            Name = 'Finance'
            ShareName = 'Finance$'
            DepartmentPrincipal = Get-ADLabPrincipalName -NetBIOSName $NetBIOSName -Name 'Finance_Users'
            DepartmentNtfsRight = [System.Security.AccessControl.FileSystemRights]::Modify
            DepartmentShareRight = 'Change'
        },
        @{
            Name = 'IT'
            ShareName = 'IT$'
            DepartmentPrincipal = Get-ADLabPrincipalName -NetBIOSName $NetBIOSName -Name 'IT_Admins'
            DepartmentNtfsRight = [System.Security.AccessControl.FileSystemRights]::Modify
            DepartmentShareRight = 'Change'
        },
        @{
            Name = 'Public'
            ShareName = 'Public$'
            DepartmentPrincipal = $domainUsers
            DepartmentNtfsRight = [System.Security.AccessControl.FileSystemRights]::Read
            DepartmentShareRight = 'Read'
        }
    )

    try {
        if (-not (Test-Path -LiteralPath $RootPath)) {
            if ($PSCmdlet.ShouldProcess($RootPath, 'Create department share root folder')) {
                New-Item -Path $RootPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Host "[CREATE] Folder created: $RootPath" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created department share root folder: $RootPath." -Level Success -LogPath $LogPath
            }
        } else {
            Write-Host "[OK] Folder exists: $RootPath" -ForegroundColor Green
            Write-ADSetupLog -Message "Department share root folder already exists: $RootPath." -Level Success -LogPath $LogPath
        }

        foreach ($definition in $definitions) {
            $folderPath = Join-Path $RootPath $definition.Name

            if (-not (Test-Path -LiteralPath $folderPath)) {
                if ($PSCmdlet.ShouldProcess($folderPath, 'Create department folder')) {
                    New-Item -Path $folderPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Write-Host "[CREATE] Folder created: $folderPath" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Created department folder: $folderPath." -Level Success -LogPath $LogPath
                }
            } else {
                Write-Host "[OK] Folder exists: $folderPath" -ForegroundColor Green
                Write-ADSetupLog -Message "Department folder already exists: $folderPath." -Level Success -LogPath $LogPath
            }

            Add-ADLabNtfsAccessRule -Path $folderPath -Identity $domainAdmins -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) -LogPath $LogPath -WhatIf:$WhatIfPreference
            Add-ADLabNtfsAccessRule -Path $folderPath -Identity $definition.DepartmentPrincipal -Rights $definition.DepartmentNtfsRight -LogPath $LogPath -WhatIf:$WhatIfPreference

            $existingShare = Get-SmbShare -Name $definition.ShareName -ErrorAction SilentlyContinue
            if ($existingShare) {
                Write-Host "[OK] SMB share exists: $($definition.ShareName)" -ForegroundColor Green
                Write-ADSetupLog -Message "SMB share already exists: $($definition.ShareName)." -Level Success -LogPath $LogPath

                if ($existingShare.Path -ne $folderPath) {
                    Write-Host "[WARN] Share $($definition.ShareName) points to $($existingShare.Path), expected $folderPath" -ForegroundColor Yellow
                    Write-ADSetupLog -Message "Share $($definition.ShareName) points to $($existingShare.Path), expected $folderPath." -Level Warning -LogPath $LogPath
                }
            } else {
                if ($PSCmdlet.ShouldProcess($definition.ShareName, "Create hidden SMB share for $folderPath")) {
                    $shareParameters = @{
                        Name = $definition.ShareName
                        Path = $folderPath
                        FullAccess = $domainAdmins
                        CachingMode = 'None'
                        Description = "Active Directory Auto Deployment Lab $($definition.Name) share for $DomainName"
                        ErrorAction = 'Stop'
                    }

                    switch ($definition.DepartmentShareRight) {
                        'Read' { $shareParameters.ReadAccess = $definition.DepartmentPrincipal }
                        'Change' { $shareParameters.ChangeAccess = $definition.DepartmentPrincipal }
                        'Full' { $shareParameters.FullAccess = @($domainAdmins, $definition.DepartmentPrincipal) }
                    }

                    New-SmbShare @shareParameters | Out-Null

                    Write-Host "[SHARE] Created hidden SMB share: $($definition.ShareName)" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Created hidden SMB share $($definition.ShareName) for $folderPath." -Level Success -LogPath $LogPath
                }
            }

            Add-ADLabSmbShareAccess -ShareName $definition.ShareName -Identity $domainAdmins -AccessRight Full -LogPath $LogPath -WhatIf:$WhatIfPreference
            Add-ADLabSmbShareAccess -ShareName $definition.ShareName -Identity $definition.DepartmentPrincipal -AccessRight $definition.DepartmentShareRight -LogPath $LogPath -WhatIf:$WhatIfPreference
        }
    } catch {
        Write-ADSetupLog -Message "Department-Based Access Control setup failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function New-ADLabDepartmentShares

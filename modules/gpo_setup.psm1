function Set-ADLabBasicGpos {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $domainDn = Get-DomainDistinguishedName -DomainName $DomainName

        $gpos = @(
            @{
                Name = 'LAB - Baseline Password Policy Notes'
                Comment = 'Lab baseline GPO. Domain password policy is normally managed through Default Domain Policy.'
                Target = $domainDn
                RegistrySettings = @(
                    @{
                        Key = 'HKLM\Software\ADLab'
                        ValueName = 'AutoDeploymentLabApplied'
                        Type = 'String'
                        Value = 'True'
                    }
                )
            },
            @{
                Name = 'LAB - Disable Control Panel for Standard Users'
                Comment = 'Lab example user policy. Review before broad use.'
                Target = "OU=Users,$domainDn"
                RegistrySettings = @(
                    @{
                        Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                        ValueName = 'NoControlPanel'
                        Type = 'DWord'
                        Value = 1
                    }
                )
            }
        )

        foreach ($gpoDefinition in $gpos) {
            $gpo = Get-GPO -Name $gpoDefinition.Name -ErrorAction SilentlyContinue
            if (-not $gpo) {
                if ($PSCmdlet.ShouldProcess($gpoDefinition.Name, 'Create GPO')) {
                    $gpo = New-GPO -Name $gpoDefinition.Name -Comment $gpoDefinition.Comment -ErrorAction Stop
                    Write-Host "[CREATE] GPO created: $($gpoDefinition.Name)" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Created GPO: $($gpoDefinition.Name)" -Level Success -LogPath $LogPath
                }
            } else {
                Write-Host "[OK] GPO exists: $($gpoDefinition.Name)" -ForegroundColor Green
                Write-ADSetupLog -Message "GPO already exists: $($gpoDefinition.Name)" -Level Success -LogPath $LogPath
            }

            foreach ($setting in $gpoDefinition.RegistrySettings) {
                if ($PSCmdlet.ShouldProcess($gpoDefinition.Name, "Set registry policy $($setting.Key)\$($setting.ValueName)")) {
                    Set-GPRegistryValue -Name $gpoDefinition.Name -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -ErrorAction Stop
                }
            }

            $targetExists = $true
            if ($gpoDefinition.Target -like 'OU=*') {
                $targetExists = [bool](Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$($gpoDefinition.Target))" -ErrorAction SilentlyContinue)
            }

            if ($targetExists) {
                $existingLink = (Get-GPInheritance -Target $gpoDefinition.Target -ErrorAction SilentlyContinue).GpoLinks | Where-Object { $_.DisplayName -eq $gpoDefinition.Name }
                if (-not $existingLink -and $PSCmdlet.ShouldProcess($gpoDefinition.Target, "Link GPO $($gpoDefinition.Name)")) {
                    New-GPLink -Name $gpoDefinition.Name -Target $gpoDefinition.Target -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    Write-Host "[LINK] GPO linked: $($gpoDefinition.Name)" -ForegroundColor Cyan
                    Write-ADSetupLog -Message "Linked GPO $($gpoDefinition.Name) to $($gpoDefinition.Target)." -Level Success -LogPath $LogPath
                }
            } else {
                Write-ADSetupLog -Message "Skipped GPO link because target does not exist: $($gpoDefinition.Target)" -Level Warning -LogPath $LogPath
            }
        }
    } catch {
        Write-ADSetupLog -Message "GPO setup failed. $($_.Exception.Message)" -Level Error -LogPath $LogPath
        throw
    }
}

Export-ModuleMember -Function Set-ADLabBasicGpos

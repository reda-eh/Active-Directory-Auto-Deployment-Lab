function New-ADLabGroups {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string[]]$GroupList,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $domainDn = Get-DomainDistinguishedName -DomainName $DomainName
    $defaultOu = "OU=Users,$domainDn"

    foreach ($groupName in $GroupList) {
        try {
            $existing = Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "[OK] Group exists: $groupName" -ForegroundColor Green
                Write-ADSetupLog -Message "Group already exists: $groupName" -Level Success -LogPath $LogPath
                continue
            }

            if ($PSCmdlet.ShouldProcess($groupName, 'Create security group')) {
                New-ADGroup -Name $groupName -SamAccountName $groupName -GroupScope Global -GroupCategory Security -Path $defaultOu -ErrorAction Stop
                Write-Host "[CREATE] Group created: $groupName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created group: $groupName" -Level Success -LogPath $LogPath
            }
        } catch {
            Write-ADSetupLog -Message "Failed to create group $groupName. $($_.Exception.Message)" -Level Error -LogPath $LogPath
            throw
        }
    }
}

Export-ModuleMember -Function New-ADLabGroups

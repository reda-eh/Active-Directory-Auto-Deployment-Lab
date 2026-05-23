function New-ADLabOrganizationalUnits {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        [Parameter(Mandatory)]
        [string[]]$OUList,
        [Parameter(Mandatory)]
        [string]$LogPath
    )

    $domainDn = Get-DomainDistinguishedName -DomainName $DomainName

    foreach ($ouName in $OUList) {
        $ouDn = "OU=$ouName,$domainDn"

        try {
            $existing = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDn)" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "[OK] OU exists: $ouName" -ForegroundColor Green
                Write-ADSetupLog -Message "OU already exists: $ouDn" -Level Success -LogPath $LogPath
                continue
            }

            if ($PSCmdlet.ShouldProcess($ouDn, 'Create OU')) {
                New-ADOrganizationalUnit -Name $ouName -Path $domainDn -ProtectedFromAccidentalDeletion:$false -ErrorAction Stop
                Write-Host "[CREATE] OU created: $ouName" -ForegroundColor Cyan
                Write-ADSetupLog -Message "Created OU: $ouDn" -Level Success -LogPath $LogPath
            }
        } catch {
            Write-ADSetupLog -Message "Failed to create OU $ouDn. $($_.Exception.Message)" -Level Error -LogPath $LogPath
            throw
        }
    }
}

Export-ModuleMember -Function New-ADLabOrganizationalUnits

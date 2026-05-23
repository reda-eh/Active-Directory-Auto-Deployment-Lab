# Active Directory Auto Deployment Lab

PowerShell-only automation project for building a Windows Server Active Directory lab from a clean machine to a basic domain with DNS, OUs, groups, users, starter GPOs, logs, and a final health report.

Active Directory Auto Deployment Lab is designed for lab environments. Review every setting before using it anywhere else.

## Files

- `main.ps1` - entry point and orchestration.
- `config.ps1` - paths, default OUs, default groups, and lab defaults.
- `modules/install_ad.psm1` - installs AD DS, DNS, RSAT/GPMC features and promotes a new forest.
- `modules/create_ous.psm1` - creates default OUs safely.
- `modules/create_groups.psm1` - creates default security groups safely.
- `modules/create_users.psm1` - imports users from CSV and adds group membership.
- `modules/gpo_setup.psm1` - creates and links basic lab GPO examples.
- `modules/checks.psm1` - admin checks, AD detection, password validation, logging, and health report.
- `data/users.csv` - sample user import file.

## What It Does

Active Directory Auto Deployment Lab can:

- Install AD DS, DNS, GPMC, and AD/DNS management tools.
- Detect whether AD DS is already installed.
- Detect whether the server is already a Domain Controller.
- Promote the server to a new forest/domain.
- Create default Organizational Units.
- Create default security groups.
- Import users from CSV.
- Add users to groups from the CSV.
- Optionally force password change at first login.
- Optionally create imported users as disabled.
- Apply starter lab GPOs.
- Run health checks and generate a report.
- Log actions to `C:\AD_Setup\Logs\setup.log`.
- Write the final report to `C:\AD_Setup\Reports\final-report.txt`.

## Requirements

- Windows Server.
- Elevated PowerShell session.
- Local Administrator rights.
- Network configuration appropriate for a Domain Controller lab.
- PowerShell execution policy allowing local scripts, for example:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process
```

## Quick Start

Open PowerShell as Administrator, go to the Active Directory Auto Deployment Lab folder, and run:

```powershell
.\main.ps1
```

The script asks for:

- Domain FQDN, for example `lab.local`.
- NetBIOS name, for example `LAB`.
- New domain Administrator password.
- Directory Services Restore Mode password.

The promotion step usually restarts the server. After the restart, run the same command again to create OUs, groups, users, GPOs, and the final report:

```powershell
.\main.ps1 -DomainName lab.local -NetBIOSName LAB
```

## Preview Changes

Use PowerShell `-WhatIf` support to preview supported changes:

```powershell
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -WhatIf
```

Some Windows Server promotion behavior is handled by Microsoft AD DS deployment cmdlets and should still be reviewed carefully before running.

## CSV Format

User CSV files must include these headers:

```csv
FirstName,LastName,Username,Password,OU,Groups,Department,Title
```

Example:

```csv
Alice,Admin,aadmin,LabP@ssw0rd!01,Admins,IT_Admins;Remote_Desktop_Users,IT,System Administrator
```

Notes:

- `OU` can be a simple OU name like `IT`, a relative DN like `OU=IT`, or a full DN.
- `Groups` uses semicolons for multiple groups.
- Passwords are read from CSV only for lab import automation. Do not use real passwords in this file.
- Passwords must be at least 8 characters and include at least 3 of these: uppercase, lowercase, digit, symbol.

## Useful Parameters

```powershell
.\main.ps1 -DomainName lab.local -NetBIOSName LAB
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -UserCsvPath .\data\users.csv
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -DisableImportedUsers
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -ForcePasswordChangeAtLogon
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -SkipPromotion
.\main.ps1 -DomainName lab.local -NetBIOSName LAB -SkipGpo
.\main.ps1 -DomainName lab.local -RunHealthCheckOnly
```

## Default OUs

- `OU=Users`
- `OU=Admins`
- `OU=IT`
- `OU=HR`
- `OU=Finance`
- `OU=Computers`
- `OU=Servers`
- `OU=Disabled Users`

## Default Groups

- `IT_Admins`
- `HR_Users`
- `Finance_Users`
- `Helpdesk`
- `Remote_Desktop_Users`

## Health Checks

The final report includes:

- `dcdiag`
- `repadmin /replsummary`
- `nslookup <domain>`
- `Get-ADDomain`
- `Get-ADUser` count
- `Get-ADGroup` count

Run health checks only:

```powershell
.\main.ps1 -DomainName lab.local -RunHealthCheckOnly
```

## Safety and Re-run Behavior

Active Directory Auto Deployment Lab is intended to be safe to re-run:

- Existing Windows features are skipped.
- Existing OUs are skipped.
- Existing groups are skipped.
- Existing users are skipped.
- Existing group memberships are skipped.
- Existing GPOs are reused and relinked only when needed.

The script prints an execution plan before making changes and asks for `YES` before continuing unless running in `-WhatIf` mode.

## Important Lab Notes

- Do not hardcode real passwords.
- Do not use production domain names unless you fully understand DNS consequences.
- Review the sample GPOs before enabling them broadly.
- Test with snapshots/checkpoints in a disposable lab VM.

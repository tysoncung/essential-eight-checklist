# 📋 Essential Eight - Maturity Level 2 Checklist

## Objective
Mostly mitigate cyber security incidents from adversaries with moderate capabilities and resources.

---

## 1. Application Control

### ML2 Requirements (in addition to ML1)
- [ ] Application control is implemented on servers
- [ ] Application control is configured based on publisher certificates
- [ ] Allowed and blocked executions are centrally logged
- [ ] Application control policies are reviewed and updated monthly
- [ ] Microsoft's recommended driver block rules are implemented

### Implementation
```powershell
# Configure WDAC policy for servers
New-CIPolicy -Level Publisher -FilePath ".\ServerPolicy.xml" -UserPEs
ConvertFrom-CIPolicy -XmlFilePath ".\ServerPolicy.xml" -BinaryFilePath ".\ServerPolicy.bin"

# Deploy to servers
Invoke-Command -ComputerName Server01 -ScriptBlock {
    Copy-Item "\\share\ServerPolicy.bin" "$env:windir\system32\CodeIntegrity\SIPolicy.p7b"
    Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update
}
```

### Advanced Controls
- [ ] Path-based rules for approved directories
- [ ] Hash rules for unsigned applications
- [ ] Certificate rules for signed applications
- [ ] Network zone rules

### Verification
- [ ] Test application control on all servers
- [ ] Review centralized logs weekly
- [ ] Verify driver blocking is active
- [ ] Document policy exceptions

---

## 2. Patch Applications

### ML2 Requirements (in addition to ML1)
- [ ] Security vulnerabilities in internet-facing services are patched within 48 hours
- [ ] Security vulnerabilities in office productivity suites are patched within 2 weeks
- [ ] Security vulnerabilities in web browsers and email clients are patched within 48 hours
- [ ] Adobe Acrobat Reader is updated within 2 weeks
- [ ] Unsupported applications are removed or upgraded

### Automated Patching Implementation
```powershell
# Configure automatic approval rules in WSUS
$wsus = Get-WsusServer
$approvalRule = $wsus.CreateInstallApprovalRule("Critical and Security Updates")
$approvalRule.Enabled = $true
$approvalRule.Categories.Add((Get-WsusCategory | Where {$_.Title -eq "Critical Updates"}))
$approvalRule.Save()
```

### Patch Management Process
- [ ] Automated deployment for critical patches
- [ ] Staged rollout (pilot → production)
- [ ] Rollback procedures documented
- [ ] Change advisory board approval for emergency patches

### Verification
- [ ] Weekly patch compliance reports
- [ ] Vulnerability scanning post-patching
- [ ] Application functionality testing
- [ ] Zero-day response procedures tested

---

## 3. Configure Microsoft Office Macro Settings

### ML2 Requirements (in addition to ML1)
- [ ] Microsoft Office macro antivirus scanning is enabled
- [ ] Microsoft Office macro settings are centrally managed via GPO/Intune
- [ ] Macro-enabled files from the internet are opened in Protected View
- [ ] Users cannot change macro security settings

### Advanced Configuration
```powershell
# Registry settings for enhanced macro protection
@"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Security]
"MacroRuntimeScanScope"=dword:00000002
"EnableAMSI"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Excel\Security]
"ProtectedView"=dword:00000002
"DisableInternetFilesInPV"=dword:00000000
"@
```

### Monitoring
- [ ] Log all macro execution attempts
- [ ] Alert on unsigned macro execution
- [ ] Track macro-enabled file downloads
- [ ] Review macro usage monthly

---

## 4. User Application Hardening

### ML2 Requirements (in addition to ML1)
- [ ] Microsoft Office is configured to prevent activation of OLE packages
- [ ] PowerShell is configured to use Constrained Language Mode
- [ ] Command line tools are restricted for standard users
- [ ] Script execution is controlled and logged

### PowerShell Hardening
```powershell
# Enable Constrained Language Mode
[System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy','4','Machine')

# Configure PowerShell logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

### Application Restrictions
- [ ] Disable Windows Script Host
- [ ] Block command prompt for standard users
- [ ] Restrict access to Task Manager
- [ ] Control registry editing tools

### Verification
- [ ] Test OLE blocking
- [ ] Verify PowerShell restrictions
- [ ] Check script execution policies
- [ ] Review application logs

---

## 5. Restrict Administrative Privileges

### ML2 Requirements (in addition to ML1)
- [ ] Privileged accounts cannot access email, web, and documents
- [ ] Administrative privileges are validated monthly
- [ ] Just-in-time administration is implemented
- [ ] Privileged session monitoring is enabled

### Implementation
```powershell
# Implement Microsoft PAM (Privileged Access Management)
# Configure PIM (Privileged Identity Management) in Azure AD
Connect-AzureAD
$role = Get-AzureADDirectoryRole | Where {$_.DisplayName -eq "Global Administrator"}
$setting = Get-AzureADMSPrivilegedRoleSetting -ProviderId "azureAD" -Filter "ResourceId eq '$($role.ObjectId)'"
```

### Controls
- [ ] Implement privileged access workstations (PAWs)
- [ ] Deploy credential guard
- [ ] Enable remote credential guard
- [ ] Implement LAPS on all workstations

### Verification
- [ ] Monthly privilege audit reports
- [ ] Test JIT access procedures
- [ ] Review privileged session recordings
- [ ] Validate PAW configurations

---

## 6. Patch Operating Systems

### ML2 Requirements (in addition to ML1)
- [ ] Security vulnerabilities in operating systems are patched within 2 weeks
- [ ] Security vulnerabilities in firmware are addressed
- [ ] Automated patch deployment is configured
- [ ] Patch testing procedures are documented

### Automation Setup
```bash
# Configure automatic updates on Linux
# Ubuntu/Debian
apt install unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# RHEL/CentOS
yum install yum-cron
systemctl enable --now yum-cron
```

### Firmware Updates
- [ ] BIOS/UEFI updates scheduled quarterly
- [ ] Network device firmware updates
- [ ] Storage controller firmware updates
- [ ] Out-of-band management updates

### Verification
- [ ] Automated compliance reporting
- [ ] Firmware version inventory
- [ ] Patch failure alerting
- [ ] Rollback testing

---

## 7. Multi-factor Authentication

### ML2 Requirements (in addition to ML1)
- [ ] MFA is implemented for all privileged accounts
- [ ] MFA is implemented for all remote access
- [ ] MFA is resistant to phishing attacks (not SMS-based)
- [ ] MFA is required for sensitive data access

### Advanced MFA Implementation
```powershell
# Configure Azure AD Conditional Access for MFA
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeGroups = "All"

$grantControls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$grantControls.BuiltInControls = "MFA"
```

### MFA Methods (Phishing-Resistant)
- [ ] FIDO2 security keys
- [ ] Windows Hello for Business
- [ ] Certificate-based authentication
- [ ] Authenticator app with number matching

### Verification
- [ ] MFA enrollment reports
- [ ] Authentication method usage analytics
- [ ] Failed MFA attempt monitoring
- [ ] Bypass request auditing

---

## 8. Regular Backups

### ML2 Requirements (in addition to ML1)
- [ ] Backups are encrypted at rest and in transit
- [ ] Backup accounts are protected with MFA
- [ ] Backups are immutable/write-once-read-many (WORM)
- [ ] Automated backup testing is performed monthly

### Advanced Backup Configuration
```powershell
# Configure encrypted backups with Azure Backup
$vault = Get-AzRecoveryServicesVault -Name "BackupVault"
Set-AzRecoveryServicesBackupProperty -Vault $vault -BackupStorageRedundancy GeoRedundant
Set-AzRecoveryServicesVaultProperty -VaultId $vault.ID -SoftDelete Enable -SoftDeleteRetentionInDays 30
```

### Ransomware Protection
- [ ] Air-gapped backup copies
- [ ] Immutable storage configured
- [ ] Backup anomaly detection
- [ ] Isolated recovery environment

### Verification
- [ ] Monthly automated restoration tests
- [ ] Encryption key management audit
- [ ] Backup integrity verification
- [ ] Recovery time objective (RTO) testing

---

## 📊 ML2 Completion Tracking

| Control | ML1 Complete | ML2 Implementation | Testing | Documentation | Sign-off |
|---------|:------------:|:-----------------:|:-------:|:-------------:|:--------:|
| Application Control | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Applications | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Configure Office Macros | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| User App Hardening | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Restrict Admin Privileges | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Operating Systems | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Multi-factor Authentication | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Regular Backups | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |

## Key Differences from ML1
- **Faster patching timelines** (48 hours for critical)
- **Server application control** implementation
- **Phishing-resistant MFA** requirements
- **Automated processes** for patching and backups
- **Enhanced logging and monitoring** across all controls

## Next Steps
Once ML2 is fully implemented and tested, proceed to [ML3 Checklist](ML3-CHECKLIST.md)

---

**Note**: This checklist is based on the ACSC Essential Eight Maturity Model. Always refer to the [official ACSC documentation](https://www.cyber.gov.au/essential-eight) for the most current requirements.
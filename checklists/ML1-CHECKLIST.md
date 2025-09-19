# 📋 Essential Eight - Maturity Level 1 Checklist

## Objective

Partially mitigate attempts by adversaries using commodity tradecraft that is widely available on the internet.

---

## 1. Application Control

### Requirements

- [ ] Application control is implemented on workstations
- [ ] Application control is configured to allow only approved executables
- [ ] Microsoft's recommended block rules are implemented
- [ ] Application control rules are centrally managed

### Implementation

```powershell
# Example: Enable AppLocker on Windows
Get-AppLockerPolicy -Effective
Set-AppLockerPolicy -PolicyObject $Policy
```

### Tools

- Windows: AppLocker, Windows Defender Application Control (WDAC)
- Linux: SELinux, AppArmor
- Third-party: Carbon Black, CrowdStrike Falcon

### Verification

- [ ] Test blocked executable from temp directory
- [ ] Verify logging of blocked attempts
- [ ] Document approved application list

---

## 2. Patch Applications

### Requirements

- [ ] Security vulnerabilities in internet-facing services are patched within 2 weeks
- [ ] Security vulnerabilities in office productivity suites are patched within 1 month
- [ ] Security vulnerabilities in web browsers are patched within 2 weeks
- [ ] Security vulnerabilities in email clients are patched within 2 weeks
- [ ] Adobe Flash Player is removed from all systems

### Implementation

```bash
# Example: Check for missing patches on Windows
wmic qfe list
Get-HotFix | Sort-Object -Property InstalledOn
```

### Tools

- WSUS (Windows Server Update Services)
- SCCM (System Center Configuration Manager)
- Intune for cloud-managed devices
- Patch My PC for third-party patching

### Verification

- [ ] Run vulnerability scan to identify missing patches
- [ ] Review patch deployment reports
- [ ] Test critical application functionality post-patching

---

## 3. Configure Microsoft Office Macro Settings

### Requirements

- [ ] Microsoft Office macros are disabled for users that don't require them
- [ ] Microsoft Office macros in files from the internet are blocked
- [ ] Only signed macros are allowed to execute (for users who need macros)

### Implementation

```powershell
# Group Policy settings for macro control
# User Configuration > Policies > Administrative Templates > Microsoft Office 2016 > Security Settings
# - Block macros from running in Office files from the Internet
# - Disable VBA for Office applications
```

### Registry Keys

```reg
[HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Excel\Security]
"BlockContentExecutionFromInternet"=dword:00000001
"VBAWarnings"=dword:00000004
```

### Verification

- [ ] Test macro blocking with sample file from internet
- [ ] Verify GPO application on workstations
- [ ] Document users with macro exceptions

---

## 4. User Application Hardening

### Requirements

- [ ] Web browsers are configured to block or disable Java
- [ ] Web browser security settings cannot be changed by users
- [ ] Internet Explorer 11 is disabled or removed
- [ ] .NET Framework 3.5 (and below) is disabled or removed

### Implementation

```powershell
# Disable Java in browsers via Group Policy
# Block Flash content
# Enable Enhanced Protected Mode in IE
```

### Browser Hardening Checklist

- [ ] Java disabled/blocked
- [ ] Flash disabled/blocked
- [ ] ActiveX filtering enabled
- [ ] SmartScreen Filter enabled
- [ ] Pop-up blocker enabled

### Verification

- [ ] Test Java applet blocking
- [ ] Verify browser settings are enforced
- [ ] Check for outdated plugins

---

## 5. Restrict Administrative Privileges

### Requirements

- [ ] Administrative privileges are restricted to personnel whose role requires them
- [ ] Administrative accounts are not used for email and web browsing
- [ ] Privileged access management solution is implemented

### Implementation

```powershell
# Review local administrators group
Get-LocalGroupMember -Group "Administrators"

# Implement LAPS (Local Administrator Password Solution)
Install-WindowsFeature -Name RSAT-LAPS
```

### Verification

- [ ] Audit all administrative accounts
- [ ] Verify separate admin accounts for privileged users
- [ ] Test standard user limitations

---

## 6. Patch Operating Systems

### Requirements

- [ ] Security vulnerabilities in operating systems are patched within 1 month
- [ ] Operating systems that are no longer supported are upgraded or replaced

### Implementation

```bash
# Windows Update via PowerShell
Install-WindowsUpdate -AcceptAll -AutoReboot

# Linux patching
sudo apt update && sudo apt upgrade -y  # Debian/Ubuntu
sudo yum update -y  # RHEL/CentOS
```

### Verification

- [ ] Run OS vulnerability scan
- [ ] Check for EOL operating systems
- [ ] Review patch compliance reports

---

## 7. Multi-factor Authentication

### Requirements

- [ ] Multi-factor authentication is used for VPN access
- [ ] Multi-factor authentication is used for remote access to corporate resources
- [ ] Multi-factor authentication is used for cloud services storing corporate data

### Implementation Options

- Azure MFA
- Duo Security
- RSA SecurID
- Google Authenticator
- YubiKey hardware tokens

### Verification

- [ ] Test MFA on all remote access points
- [ ] Verify MFA enrollment for all users
- [ ] Document MFA bypass procedures

---

## 8. Regular Backups

### Requirements

- [ ] Backups of important data are performed daily
- [ ] Backups are stored offline or in a separated network environment
- [ ] Restoration of backups is tested at least quarterly

### Implementation

```powershell
# Windows Server Backup example
wbadmin start backup -backupTarget:E: -include:C: -allCritical -quiet

# Verify backup
wbadmin get versions
```

### Backup Checklist

- [ ] Identify critical data and systems
- [ ] Configure automated daily backups
- [ ] Implement 3-2-1 backup rule
- [ ] Document restoration procedures
- [ ] Schedule quarterly restoration tests

### Verification

- [ ] Review backup logs daily
- [ ] Test file restoration
- [ ] Test full system restoration
- [ ] Verify offline/air-gapped copies

---

## 📊 ML1 Completion Tracking

| Control | Implementation | Testing | Documentation | Sign-off |
|---------|:-------------:|:-------:|:-------------:|:--------:|
| Application Control | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Applications | ⬜ | ⬜ | ⬜ | ⬜ |
| Configure Office Macros | ⬜ | ⬜ | ⬜ | ⬜ |
| User App Hardening | ⬜ | ⬜ | ⬜ | ⬜ |
| Restrict Admin Privileges | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Operating Systems | ⬜ | ⬜ | ⬜ | ⬜ |
| Multi-factor Authentication | ⬜ | ⬜ | ⬜ | ⬜ |
| Regular Backups | ⬜ | ⬜ | ⬜ | ⬜ |

## Next Steps

Once ML1 is fully implemented and tested, proceed to [ML2 Checklist](ML2-CHECKLIST.md)

---

**Note**: This checklist is based on the ACSC Essential Eight Maturity Model. Always refer to the [official ACSC documentation](https://www.cyber.gov.au/essential-eight) for the most current requirements.

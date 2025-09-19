# Application Control Tools & Implementation Guide

## Windows Solutions

### AppLocker

**Cost**: Free (included in Windows Enterprise)
**Complexity**: Medium
**Best for**: ML1-ML2

#### Setup Guide

```powershell
# Enable AppLocker service
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# Create default rules
Get-AppLockerPolicy -Effective | Set-AppLockerPolicy -XMLPolicy

# Create publisher rule for signed applications
$Rule = New-AppLockerPolicy -FilePublisherRule -Path "C:\Program Files\Application\*.exe" -Publisher "*" -User Everyone -Action Allow
```

**Pros**:

- Native Windows integration
- Group Policy management
- No additional cost

**Cons**:

- Limited to Enterprise editions
- Can be bypassed via certain methods
- Basic reporting capabilities

---

### Windows Defender Application Control (WDAC)

**Cost**: Free (included in Windows 10/11)
**Complexity**: High
**Best for**: ML2-ML3

#### Implementation

```powershell
# Scan system and create policy
New-CIPolicy -Level Publisher -FilePath ".\WDAC-Policy.xml" -ScanPath C:\ -UserPEs

# Convert to binary
ConvertFrom-CIPolicy -XmlFilePath ".\WDAC-Policy.xml" -BinaryFilePath ".\WDAC-Policy.bin"

# Deploy policy
Copy-Item ".\WDAC-Policy.bin" "$env:windir\system32\CodeIntegrity\SIPolicy.p7b"
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update
```

**Features**:

- Kernel-level protection
- HVCI support
- Managed installer
- ISG integration

---

## Linux Solutions

### SELinux

**Cost**: Free (open source)
**Complexity**: High
**Best for**: ML1-ML3

#### Configuration

```bash
# Check SELinux status
sestatus

# Set to enforcing mode
setenforce 1

# Make permanent
sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# Create custom policy module
audit2allow -M myapp -l -i /var/log/audit/audit.log
semodule -i myapp.pp
```

**Benefits**:

- Mandatory access control
- Fine-grained permissions
- Extensive policy library

---

### AppArmor

**Cost**: Free (open source)
**Complexity**: Medium
**Best for**: ML1-ML2

#### Setup

```bash
# Install AppArmor
apt-get install apparmor apparmor-utils

# Create profile
aa-genprof /usr/bin/application

# Put profile in enforce mode
aa-enforce /usr/bin/application

# Monitor violations
tail -f /var/log/syslog | grep apparmor
```

---

## macOS Solutions

### Gatekeeper

**Cost**: Free (built-in)
**Complexity**: Low
**Best for**: ML1

#### Configuration

```bash
# Check Gatekeeper status
spctl --status

# Enable Gatekeeper
sudo spctl --master-enable

# Add assessment rule
sudo spctl --add --label "Approved Apps" /Applications/YourApp.app
```

---

### Santa (Google)

**Cost**: Free (open source)
**Complexity**: Medium
**Best for**: ML2-ML3

#### Deployment

```bash
# Install Santa
installer -pkg santa.pkg -target /

# Configure sync server
sudo santactl sync --set-sync-url https://santa-server.company.com

# Check status
sudo santactl status
```

**Features**:

- Binary whitelisting/blacklisting
- Certificate-based rules
- Central management
- Real-time monitoring

---

## Enterprise Solutions

### CrowdStrike Falcon

**Cost**: $$$$ (per endpoint)
**Complexity**: Medium
**Best for**: ML2-ML3

**Features**:

- Cloud-native architecture
- Machine learning detection
- EDR capabilities
- Zero-trust application control

---

### Carbon Black

**Cost**: $$$$ (per endpoint)
**Complexity**: Medium
**Best for**: ML2-ML3

**Features**:

- Reputation-based blocking
- Behavioral analysis
- Cloud or on-premise
- Extensive reporting

---

## Implementation Checklist

### ML1 Requirements

- [ ] Block execution from user-writable directories
- [ ] Implement Microsoft recommended block rules
- [ ] Log blocked execution attempts
- [ ] Create approved application inventory

### ML2 Requirements

- [ ] Extend to servers
- [ ] Implement publisher certificate rules
- [ ] Central logging to SIEM
- [ ] Monthly policy reviews

### ML3 Requirements

- [ ] Driver and firmware control
- [ ] Script and installer validation
- [ ] Cannot be bypassed by local admins
- [ ] Real-time policy updates

---

## Monitoring & Reporting

### PowerShell Script for AppLocker Events

```powershell
# Get AppLocker block events
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" | 
    Where-Object {$_.Id -eq 8004} |
    Select-Object TimeCreated, Message |
    Export-Csv "AppLocker-Blocks.csv"
```

### WDAC Event Collection

```powershell
# Query WDAC events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object {$_.Id -in @(3076, 3077)} |
    Format-Table TimeCreated, Id, Message
```

---

## Common Issues & Solutions

### Issue: Legacy applications failing

**Solution**: Create publisher or hash rules for unsigned applications

### Issue: Performance impact

**Solution**: Use publisher rules instead of hash rules, implement caching

### Issue: User productivity impact

**Solution**: Implement in audit mode first, gradually transition to enforce

---

## Best Practices

1. **Start in Audit Mode**: Monitor before blocking
2. **Create Baseline**: Inventory all legitimate applications
3. **Use Publisher Rules**: More maintainable than hash rules
4. **Regular Reviews**: Update policies monthly
5. **Test Updates**: Verify patches don't break rules
6. **Emergency Bypass**: Document break-glass procedures

---

## Resources

- [Microsoft AppLocker Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
- [WDAC Deployment Guide](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
- [SELinux Project](https://selinuxproject.org/)
- [Google Santa](https://github.com/google/santa)

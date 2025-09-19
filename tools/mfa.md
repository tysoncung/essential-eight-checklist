# Multi-Factor Authentication (MFA) Implementation Guide

## Overview

MFA is critical for protecting against credential-based attacks. This guide covers implementation across ML1-ML3 requirements.

## Maturity Level Requirements

### ML1 - Basic MFA

- ✅ VPN access
- ✅ Remote desktop access  
- ✅ Cloud services with corporate data

### ML2 - Enhanced MFA

- ✅ All ML1 requirements
- ✅ All privileged accounts
- ✅ Phishing-resistant methods (no SMS)
- ✅ All remote access points

### ML3 - Advanced MFA

- ✅ All ML2 requirements
- ✅ All user accounts
- ✅ Risk-based authentication
- ✅ Passwordless authentication
- ✅ Continuous verification

---

## Cloud-Based MFA Solutions

### Microsoft Azure MFA / Entra ID

**Cost**: $$ ($6/user/month for P1)
**Complexity**: Medium
**Best for**: Microsoft 365 environments

#### Implementation

```powershell
# Enable MFA for all users via Conditional Access
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$params = @{
    DisplayName = "Require MFA for All Users"
    State = "enabled"
    Conditions = @{
        Applications = @{
            IncludeApplications = @("All")
        }
        Users = @{
            IncludeUsers = @("All")
            ExcludeGroups = @("emergency-access-accounts")
        }
        Locations = @{
            IncludeLocations = @("All")
            ExcludeLocations = @("AllTrusted")
        }
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("mfa")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

#### Passwordless Configuration

```powershell
# Enable FIDO2 security keys
$methodId = "fido2"
$params = @{
    "@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
    State = "enabled"
    IsAttestationEnforced = $true
    IsSelfServiceRegistrationAllowed = $true
}

Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodId $methodId -BodyParameter $params
```

---

### Okta

**Cost**: $$$ ($5-15/user/month)
**Complexity**: Medium
**Best for**: Multi-cloud environments

#### API Configuration

```python
import okta
from okta.client import Client as OktaClient

config = {
    'orgUrl': 'https://your-org.okta.com',
    'token': 'your-api-token'
}

client = OktaClient(config)

# Create MFA policy
policy = {
    'name': 'Essential Eight ML2 MFA',
    'type': 'MFA_ENROLL',
    'status': 'ACTIVE',
    'settings': {
        'factors': {
            'okta_verify': {'enroll': 'REQUIRED', 'consent': 'NONE'},
            'fido2': {'enroll': 'REQUIRED', 'consent': 'NONE'},
            'okta_sms': {'enroll': 'NOT_ALLOWED'},  # ML2: No SMS
        }
    },
    'conditions': {
        'people': {'groups': {'include': ['00g1234567']}},
        'network': {'connection': 'ANYWHERE'}
    }
}

client.create_policy(policy)
```

---

### Duo Security (Cisco)

**Cost**: $$ ($3-9/user/month)
**Complexity**: Low
**Best for**: Hybrid environments

#### Integration Script

```bash
#!/bin/bash
# Duo Unix/Linux PAM integration

# Install Duo
wget https://dl.duosecurity.com/duo_unix-latest.tar.gz
tar zxf duo_unix-latest.tar.gz
cd duo_unix-*
./configure --with-pam --prefix=/usr
make && sudo make install

# Configure /etc/duo/pam_duo.conf
cat > /etc/duo/pam_duo.conf << EOF
[duo]
host = api-XXXXXXXX.duosecurity.com
ikey = DIXXXXXXXXXXXXXXXXXX
skey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
groups = users,!nologin
failmode = secure
autopush = yes
prompts = 3
EOF

# Update PAM configuration
echo "auth required pam_duo.so" >> /etc/pam.d/sshd
```

---

## On-Premise MFA Solutions

### FreeIPA with FreeOTP

**Cost**: Free (open source)
**Complexity**: High
**Best for**: Linux environments

#### Setup Script

```bash
# Install FreeIPA with OTP support
dnf install -y freeipa-server freeipa-server-dns

# Initialize IPA server with OTP
ipa-server-install --setup-dns --allow-zone-overlap \
    --enable-compat --setup-adtrust --enable-otp

# Add OTP tokens for users
ipa otptoken-add --type=totp --owner=username \
    --algo=sha256 --digits=6 --interval=30

# Configure SSSD for OTP authentication
cat >> /etc/sssd/sssd.conf << EOF
[domain/example.com]
auth_provider = ipa
ipa_server = ipa.example.com
krb5_use_enterprise_principal = True
krb5_auth_timeout = 30
krb5_renewable_lifetime = 7d
krb5_renew_interval = 3600
EOF

systemctl restart sssd
```

---

### privacyIDEA

**Cost**: Free (open source, enterprise support available)
**Complexity**: Medium
**Best for**: Custom requirements

#### Docker Deployment

```yaml
version: '3.7'

services:
  privacyidea:
    image: privacyidea/privacyidea:latest
    container_name: privacyidea
    ports:
      - "443:443"
    environment:
      - PI_PEPPER=superSecretPepper
      - PI_SECRET_KEY=superSecretKey
      - PI_DATABASE_URI=postgresql://pi:password@postgres/pi
      - PI_AUDIT_SQL_URI=postgresql://pi:password@postgres/piaudit
    volumes:
      - ./config:/etc/privacyidea
      - ./logs:/var/log/privacyidea
    depends_on:
      - postgres
      
  postgres:
    image: postgres:13
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_USER=pi
      - POSTGRES_DB=pi
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

---

## Hardware Token Solutions

### YubiKey Implementation

**Cost**: $$ ($45-70 per key)
**Complexity**: Low
**Best for**: High-security requirements

#### Windows Configuration

```powershell
# Configure YubiKey for Windows Hello for Business
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
    -Name "AllowSecurityKeySignIn" -Value 1

# Configure smart card removal behavior
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "ScRemoveOption" -Value 2  # Lock workstation

# Enable FIDO2 for Azure AD
$uri = "https://graph.microsoft.com/beta/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2"
$body = @{
    state = "enabled"
    isSelfServiceRegistrationAllowed = $true
    isAttestationEnforced = $true
    keyRestrictions = @{
        isEnforced = $true
        enforcementType = "allow"
        aaGuids = @(
            "cb69481e-8ff7-4039-93ec-0a2729a154a8",  # YubiKey 5 NFC
            "ee882879-721c-4913-9775-3dfcce97072a"   # YubiKey 5Ci
        )
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri $uri -Method Patch -Body $body -Headers @{Authorization = "Bearer $token"}
```

---

## Risk-Based Authentication (ML3)

### Adaptive Authentication Implementation

```python
import hashlib
import json
from datetime import datetime, timedelta

class RiskBasedAuth:
    def __init__(self):
        self.risk_factors = {
            'new_device': 30,
            'new_location': 25,
            'impossible_travel': 50,
            'anonymous_proxy': 40,
            'failed_attempts': 20,
            'unusual_time': 15,
            'privilege_escalation': 35
        }
        
    def calculate_risk_score(self, auth_context):
        """Calculate risk score based on multiple factors"""
        score = 0
        
        # Device trust
        if not self.is_trusted_device(auth_context['device_id']):
            score += self.risk_factors['new_device']
            
        # Location analysis
        if self.is_new_location(auth_context['ip_address'], auth_context['user']):
            score += self.risk_factors['new_location']
            
        # Impossible travel detection
        if self.detect_impossible_travel(auth_context):
            score += self.risk_factors['impossible_travel']
            
        # Time-based risk
        if self.is_unusual_time(auth_context['timestamp'], auth_context['user']):
            score += self.risk_factors['unusual_time']
            
        return score
    
    def determine_auth_requirements(self, risk_score):
        """Determine authentication requirements based on risk"""
        if risk_score < 20:
            return {'mfa_required': False, 'methods': ['password']}
        elif risk_score < 50:
            return {'mfa_required': True, 'methods': ['totp', 'push']}
        elif risk_score < 75:
            return {'mfa_required': True, 'methods': ['fido2', 'biometric']}
        else:
            return {'mfa_required': True, 'methods': ['fido2'], 
                   'additional': 'manager_approval'}
    
    def detect_impossible_travel(self, context):
        """Detect physically impossible travel between locations"""
        last_auth = self.get_last_authentication(context['user'])
        if not last_auth:
            return False
            
        time_diff = (context['timestamp'] - last_auth['timestamp']).seconds / 3600
        distance = self.calculate_distance(
            last_auth['location'], 
            context['location']
        )
        
        # Assume max travel speed of 900 km/h (jet travel)
        max_distance = time_diff * 900
        
        return distance > max_distance
```

---

## MFA Bypass & Emergency Access

### Break-Glass Procedures

```powershell
# Create emergency access accounts
$emergencyUser = @{
    DisplayName = "Emergency Access 01"
    UserPrincipalName = "emergency01@company.com"
    PasswordProfile = @{
        Password = (New-Guid).ToString() + "!Aa1"
        ForceChangePasswordNextSignIn = $false
    }
    AccountEnabled = $true
}

$user = New-MgUser @emergencyUser

# Exclude from MFA policies
$group = New-MgGroup -DisplayName "Emergency Access Accounts" `
    -SecurityEnabled $true -MailEnabled $false `
    -MailNickname "emergency-access"

New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id

# Configure monitoring
$alert = @{
    DisplayName = "Emergency Account Usage"
    Severity = "High"
    Enabled = $true
    Query = "SigninLogs | where UserPrincipalName startswith 'emergency'"
    QueryFrequency = "PT5M"
    QueryPeriod = "PT5M"
    TriggerOperator = "GreaterThan"
    TriggerThreshold = 0
    Actions = @{
        EmailRecipients = @("security@company.com")
        CustomWebhookPayload = '{"alert": "Emergency account used"}'
    }
}
```

---

## MFA Reporting & Monitoring

### PowerShell MFA Coverage Report

```powershell
# Generate MFA enrollment and usage report
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "AuditLog.Read.All"

$users = Get-MgUser -All
$report = @()

foreach ($user in $users) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    
    $mfaMethods = $methods | Where-Object { 
        $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
    }
    
    $report += [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName = $user.DisplayName
        MFAEnabled = $mfaMethods.Count -gt 0
        Methods = ($mfaMethods.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '') -join ', '
        PhishingResistant = $mfaMethods.AdditionalProperties.'@odata.type' -match 'fido2|windowsHello'
        LastSignIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 1).CreatedDateTime
    }
}

$report | Export-Csv "MFA-Coverage-Report.csv" -NoTypeInformation

# Calculate metrics
$metrics = @{
    TotalUsers = $report.Count
    MFAEnabled = ($report | Where-Object { $_.MFAEnabled }).Count
    PhishingResistant = ($report | Where-Object { $_.PhishingResistant }).Count
    CoveragePercent = [math]::Round((($report | Where-Object { $_.MFAEnabled }).Count / $report.Count) * 100, 2)
}

$metrics | ConvertTo-Json | Out-File "MFA-Metrics.json"
```

---

## Common MFA Implementation Issues

### Issue: User Resistance

**Solution**:

- Phased rollout with pilot groups
- User training sessions
- Self-service enrollment portal
- Clear communication of benefits

### Issue: Account Lockouts

**Solution**:

```powershell
# Implement smart lockout policies
$policy = @{
    LockoutThreshold = 5
    LockoutDuration = "00:01:00"
    LockoutWindow = "00:05:00"
    EnableCustomBannedPasswords = $true
}
Update-MgDomain -DomainId "company.com" -PasswordPolicy $policy
```

### Issue: Legacy Application Support

**Solution**:

- App passwords for legacy apps (temporary)
- Modern authentication migration plan
- Application proxy with pre-authentication

---

## Testing & Validation

### MFA Test Script

```bash
#!/bin/bash
# Test MFA implementation across services

services=("vpn.company.com" "remote.company.com" "portal.company.com")
test_users=("testuser1" "testuser2" "testadmin")

for service in "${services[@]}"; do
    for user in "${test_users[@]}"; do
        echo "Testing $user on $service"
        
        # Attempt authentication without MFA
        result=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "$user:password" "https://$service/api/test")
        
        if [ "$result" -eq "401" ]; then
            echo "✅ MFA required for $user on $service"
        else
            echo "❌ WARNING: MFA not enforced for $user on $service"
        fi
    done
done
```

---

## Resources

- [NIST SP 800-63B - Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [FIDO Alliance Specifications](https://fidoalliance.org/specifications/)
- [Microsoft Entra ID MFA Documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/)
- [ACSC MFA Guidance](https://www.cyber.gov.au/mfa)

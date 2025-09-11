# 📋 Essential Eight - Maturity Level 3 Checklist

## Objective
Significantly harder for adversaries to compromise systems, suitable for organizations that are likely targets of sophisticated adversaries.

---

## 1. Application Control

### ML3 Requirements (in addition to ML2)
- [ ] Application control restricts all drivers and firmware to approved versions
- [ ] Application control validates all scripts and installers
- [ ] Centralized application control management with real-time updates
- [ ] Application control cannot be bypassed by users or local administrators
- [ ] All execution attempts (allowed and blocked) are logged and analyzed

### Enterprise Implementation
```powershell
# Implement Windows Defender Application Control with managed installer
$PolicyPath = ".\ML3-WDAC-Policy.xml"
New-CIPolicy -Level Publisher -FilePath $PolicyPath -UserPEs -Rules ManagedInstaller

# Add intelligent security graph authorization
Add-CIPolicyRule -FilePath $PolicyPath -ISG

# Configure for hypervisor-protected code integrity (HVCI)
Set-HVCIOptions -Enabled -Policy $PolicyPath
```

### Zero Trust Application Control
- [ ] Implement runtime application self-protection (RASP)
- [ ] Deploy endpoint detection and response (EDR)
- [ ] Configure exploit protection settings
- [ ] Enable attack surface reduction rules

### Verification
- [ ] Continuous compliance monitoring dashboard
- [ ] Real-time alerting on policy violations
- [ ] Machine learning-based anomaly detection
- [ ] Threat hunting on application control logs

---

## 2. Patch Applications

### ML3 Requirements (in addition to ML2)
- [ ] Security vulnerabilities in internet-facing services are patched within 48 hours or mitigated
- [ ] Security vulnerabilities in all applications are patched within 48 hours of release
- [ ] Automated vulnerability scanning runs continuously
- [ ] Virtual patching is implemented where immediate patching isn't possible
- [ ] Zero-day mitigation strategies are in place

### Continuous Patch Management
```python
# Automated patch orchestration script
import requests
from datetime import datetime, timedelta

class PatchOrchestrator:
    def __init__(self):
        self.critical_threshold = timedelta(hours=48)
        self.high_threshold = timedelta(hours=72)
    
    def assess_vulnerability(self, cve):
        # Check CVSS score and exploitability
        if cve.cvss >= 9.0 or cve.actively_exploited:
            return "CRITICAL"
        elif cve.cvss >= 7.0:
            return "HIGH"
        return "MEDIUM"
    
    def deploy_patch(self, systems, patch, priority):
        if priority == "CRITICAL":
            # Immediate deployment with automated rollback
            self.emergency_deploy(systems, patch)
        else:
            # Staged deployment through rings
            self.staged_deploy(systems, patch)
```

### Advanced Mitigation
- [ ] Web application firewall (WAF) with virtual patching
- [ ] Runtime application security protection
- [ ] Micro-segmentation for lateral movement prevention
- [ ] Deception technology for zero-day detection

### Verification
- [ ] Real-time patch compliance dashboard
- [ ] Automated penetration testing post-patching
- [ ] Vulnerability correlation with threat intelligence
- [ ] Mean time to remediation (MTTR) < 48 hours

---

## 3. Configure Microsoft Office Macro Settings

### ML3 Requirements (in addition to ML2)
- [ ] Only macros digitally signed by trusted publishers can execute
- [ ] Macros are subject to application control policies
- [ ] All macro execution is logged with full audit trail
- [ ] Behavioral analysis of macro execution
- [ ] Sandboxing for suspicious macros

### Advanced Macro Protection
```powershell
# Configure advanced macro protection with AMSI
$AMSISettings = @{
    "EnableAMSI" = 1
    "MacroRuntimeScanScope" = 2  # All documents
    "TrustCenter" = @{
        "TrustedLocations" = @()  # No trusted locations
        "TrustedPublishers" = @("CN=YourOrganization")
    }
}

# Deploy via Intune configuration profile
New-IntuneDeviceConfigurationPolicy -Windows10GeneralConfiguration -OmaSettings $AMSISettings
```

### Macro Analysis Pipeline
- [ ] Static analysis of macro code
- [ ] Dynamic analysis in sandbox
- [ ] Machine learning-based detection
- [ ] Integration with threat intelligence

### Verification
- [ ] Zero unauthorized macro executions
- [ ] Complete audit trail of all macro activity
- [ ] Regular red team exercises testing macro controls
- [ ] Automated reporting of macro risk metrics

---

## 4. User Application Hardening

### ML3 Requirements (in addition to ML2)
- [ ] All unnecessary features in applications are disabled
- [ ] Application sandboxing is implemented
- [ ] Just-in-time application access is configured
- [ ] Browser isolation for high-risk browsing
- [ ] Container-based application delivery

### Advanced Hardening Configuration
```yaml
# Kubernetes pod security policy for application containers
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### Application Isolation
- [ ] Remote browser isolation for internet access
- [ ] Application virtualization for legacy apps
- [ ] Secure coding practices enforced
- [ ] Content disarm and reconstruction (CDR)

### Verification
- [ ] Application attack surface analysis
- [ ] Continuous security testing
- [ ] User behavior analytics
- [ ] Zero-trust network access validation

---

## 5. Restrict Administrative Privileges

### ML3 Requirements (in addition to ML2)
- [ ] Zero standing administrative privileges
- [ ] All administrative actions require approval and are time-bound
- [ ] Privileged access from dedicated secure admin workstations only
- [ ] Continuous privileged account discovery and management
- [ ] Biometric authentication for privileged access

### Zero Standing Privilege Architecture
```python
# Privileged access broker implementation
class PrivilegedAccessBroker:
    def request_access(self, user, resource, justification):
        # Multi-factor authentication
        if not self.verify_mfa(user, methods=['biometric', 'hardware_token']):
            return False
        
        # Risk scoring
        risk_score = self.calculate_risk(user, resource, context)
        if risk_score > threshold:
            approval = self.request_approval(user.manager, justification)
            if not approval:
                return False
        
        # Grant time-limited access
        access_token = self.create_temporal_access(
            user=user,
            resource=resource,
            duration=minutes(30),
            permissions=self.least_privilege(resource)
        )
        
        # Enable session recording
        self.start_session_recording(access_token)
        
        return access_token
```

### Privileged Access Workstations (PAWs)
- [ ] Dedicated hardware for administrative tasks
- [ ] No internet access or email on PAWs
- [ ] Hardware-based attestation
- [ ] Shielded VMs for cloud administration

### Verification
- [ ] Zero persistent admin accounts
- [ ] Complete audit trail of all privileged actions
- [ ] Regular privilege access reviews
- [ ] Privileged account analytics and anomaly detection

---

## 6. Patch Operating Systems

### ML3 Requirements (in addition to ML2)
- [ ] Security vulnerabilities are patched within 48 hours of release
- [ ] Automated patch deployment with zero downtime
- [ ] Kernel live patching for critical systems
- [ ] Immutable infrastructure with automated rebuilds
- [ ] Security configuration compliance continuously enforced

### Infrastructure as Code Patching
```terraform
# Automated OS deployment with latest patches
resource "aws_launch_template" "secure_instance" {
  name_prefix   = "ml3-hardened-"
  image_id      = data.aws_ami.latest_hardened.id
  instance_type = "t3.medium"
  
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # Apply latest security updates
    yum update -y --security
    
    # Apply CIS benchmarks
    oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
      --results scan-results.xml \
      /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
    
    # Enable automated patching
    systemctl enable --now dnf-automatic.timer
  EOF)
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"  # IMDSv2 only
  }
}
```

### Verification
- [ ] Real-time OS compliance monitoring
- [ ] Automated configuration drift remediation
- [ ] Continuous vulnerability assessment
- [ ] Patch deployment success rate > 99.9%

---

## 7. Multi-factor Authentication

### ML3 Requirements (in addition to ML2)
- [ ] Phishing-resistant MFA for all users and all access
- [ ] Risk-based authentication with continuous verification
- [ ] Passwordless authentication implementation
- [ ] Hardware security keys required for privileged accounts
- [ ] Biometric authentication where appropriate

### Passwordless Implementation
```javascript
// WebAuthn implementation for passwordless
async function authenticateUser() {
  const credentialRequestOptions = {
    challenge: new Uint8Array(32),
    allowCredentials: [{
      id: savedCredentialId,
      type: 'public-key',
      transports: ['usb', 'nfc', 'ble', 'internal']
    }],
    userVerification: "required",
    extensions: {
      devicePubKey: true,
      credProps: true
    }
  };
  
  const assertion = await navigator.credentials.get({
    publicKey: credentialRequestOptions
  });
  
  // Verify with continuous risk assessment
  const riskScore = await assessAuthenticationRisk(assertion);
  if (riskScore > threshold) {
    return requestAdditionalVerification();
  }
  
  return verifyAssertion(assertion);
}
```

### Continuous Authentication
- [ ] Behavioral biometrics monitoring
- [ ] Device trust verification
- [ ] Location and network analysis
- [ ] Session risk scoring

### Verification
- [ ] 100% MFA coverage
- [ ] Zero password-based authentication
- [ ] Authentication event correlation
- [ ] Regular phishing simulation tests

---

## 8. Regular Backups

### ML3 Requirements (in addition to ML2)
- [ ] Continuous data protection with near-zero RPO
- [ ] Automated backup integrity verification
- [ ] Geographically distributed immutable backups
- [ ] Orchestrated disaster recovery with < 1 hour RTO
- [ ] Ransomware-proof backup architecture

### Advanced Backup Architecture
```yaml
# Kubernetes backup strategy with Velero
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: ml3-immutable-backup
spec:
  provider: aws
  objectStorage:
    bucket: ml3-backup-immutable
    config:
      region: us-east-1
      s3ForcePathStyle: "false"
      s3Url: "https://s3.us-east-1.amazonaws.com"
      objectLockEnabled: "true"  # WORM storage
  config:
    kmsKeyId: "arn:aws:kms:us-east-1:123456789:key/backup-key"
---
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: continuous-backup
spec:
  schedule: "*/15 * * * *"  # Every 15 minutes
  template:
    hooks:
      resources:
        - name: database-checkpoint
          includedNamespaces:
            - production
          pre:
            - exec:
                command: ["/bin/sh", "-c", "pg_dump > /backup/db.sql"]
    ttl: 720h  # 30 days retention
    includedNamespaces:
      - production
    storageLocation: ml3-immutable-backup
```

### Disaster Recovery Orchestration
- [ ] Automated failover procedures
- [ ] Cross-region replication
- [ ] Backup encryption with key rotation
- [ ] Air-gapped backup validation lab

### Verification
- [ ] Weekly automated DR drills
- [ ] Backup immutability testing
- [ ] Recovery point objective (RPO) < 15 minutes
- [ ] Recovery time objective (RTO) < 1 hour
- [ ] Ransomware recovery simulation monthly

---

## 📊 ML3 Completion Tracking

| Control | ML2 Complete | ML3 Implementation | Testing | Audit | Sign-off |
|---------|:------------:|:-----------------:|:-------:|:-----:|:--------:|
| Application Control | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Applications | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Configure Office Macros | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| User App Hardening | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Restrict Admin Privileges | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Patch Operating Systems | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Multi-factor Authentication | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |
| Regular Backups | ✅ | ⬜ | ⬜ | ⬜ | ⬜ |

## Key Differences from ML2
- **48-hour patching** for all vulnerabilities
- **Zero standing privileges** architecture
- **Passwordless authentication** implementation
- **Continuous monitoring** and automated response
- **Immutable infrastructure** patterns
- **Advanced threat detection** and response

## Continuous Improvement
- Regular red team exercises
- Threat hunting operations
- Security architecture reviews
- Compliance automation
- Incident response optimization

---

**Note**: ML3 represents a significant investment in security controls and is designed for organizations facing sophisticated threats. Always refer to the [official ACSC documentation](https://www.cyber.gov.au/essential-eight) for the most current requirements.
# Patch Management Tools & Solutions

## Enterprise Solutions

### Microsoft SCCM/MECM
**Cost**: $$$ (included with Enterprise Agreement)
**Complexity**: High
**Best for**: Large Windows environments

#### Key Features
- Comprehensive patch management
- Third-party patching support
- Detailed reporting
- Phased deployments
- Automatic deployment rules

#### Implementation
```powershell
# Create automatic deployment rule for critical updates
$DeploymentRule = @{
    Name = "Critical and Security Updates"
    CollectionName = "All Workstations"
    DeploymentPackageName = "Monthly Updates"
    EnabledAfterCreate = $true
    RunType = "RunTheRuleAfterAnySoftwareUpdatePointSynchronization"
}
New-CMSoftwareUpdateAutoDeploymentRule @DeploymentRule
```

---

### Microsoft Intune
**Cost**: $$ (per user/month)
**Complexity**: Medium
**Best for**: Cloud-managed devices

#### Configuration
```powershell
# Configure Windows Update for Business rings
$UpdateRing = @{
    DisplayName = "Production Ring"
    DeferQualityUpdatesPeriodInDays = 7
    DeferFeatureUpdatesPeriodInDays = 30
    AutomaticUpdateMode = "AutoInstallAtMaintenanceTime"
}
New-IntuneDeviceConfigurationPolicy @UpdateRing
```

---

### WSUS (Windows Server Update Services)
**Cost**: Free (Windows Server role)
**Complexity**: Medium
**Best for**: ML1-ML2 Windows environments

#### Setup Script
```powershell
# Install WSUS role
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools

# Configure WSUS
$wsus = Get-WsusServer
$wsusConfig = $wsus.GetConfiguration()
$wsusConfig.TargetingMode = "Client"
$wsusConfig.Save()

# Create automatic approval rule
$rule = $wsus.CreateInstallApprovalRule("AutoApprove-Critical")
$rule.SetCategories("Critical Updates")
$rule.SetComputerTargetGroups("Workstations")
$rule.Enabled = $true
$rule.Save()
```

---

## Open Source Solutions

### Ansible
**Cost**: Free (Red Hat Ansible = $$)
**Complexity**: Medium
**Best for**: Linux/Unix environments

#### Playbook Example
```yaml
---
- name: Patch Management Playbook
  hosts: all
  become: yes
  
  tasks:
    - name: Update package cache (Debian/Ubuntu)
      apt:
        update_cache: yes
      when: ansible_os_family == "Debian"
    
    - name: Upgrade all packages (Debian/Ubuntu)
      apt:
        upgrade: dist
        autoremove: yes
        autoclean: yes
      when: ansible_os_family == "Debian"
    
    - name: Update all packages (RHEL/CentOS)
      yum:
        name: '*'
        state: latest
      when: ansible_os_family == "RedHat"
    
    - name: Check if reboot required
      stat:
        path: /var/run/reboot-required
      register: reboot_required
    
    - name: Reboot if required
      reboot:
        msg: "Reboot initiated by Ansible for kernel updates"
      when: reboot_required.stat.exists
```

---

### Puppet
**Cost**: Free (Enterprise = $$$)
**Complexity**: High
**Best for**: Large-scale automation

#### Manifest Example
```puppet
class patch_management {
  # Schedule updates
  schedule { 'maintenance_window':
    period => weekly,
    range  => '2:00 - 4:00',
    repeat => 1,
  }
  
  # Ensure packages are updated
  exec { 'apt-update':
    command  => '/usr/bin/apt-get update',
    schedule => 'maintenance_window',
  }
  
  exec { 'apt-upgrade':
    command  => '/usr/bin/apt-get upgrade -y',
    require  => Exec['apt-update'],
    schedule => 'maintenance_window',
  }
}
```

---

## Cloud-Native Solutions

### AWS Systems Manager Patch Manager
**Cost**: $ (per instance)
**Complexity**: Medium
**Best for**: AWS environments

#### Implementation
```python
import boto3

ssm = boto3.client('ssm')

# Create patch baseline
baseline = ssm.create_patch_baseline(
    Name='ML2-Baseline',
    OperatingSystem='WINDOWS',
    ApprovalRules={
        'PatchRules': [{
            'PatchFilterGroup': {
                'PatchFilters': [
                    {'Key': 'CLASSIFICATION', 'Values': ['Critical', 'Security']},
                    {'Key': 'SEVERITY', 'Values': ['Critical', 'Important']}
                ]
            },
            'ApproveAfterDays': 0,
            'EnableNonSecurity': False
        }]
    }
)

# Create maintenance window
window = ssm.create_maintenance_window(
    Name='PatchingWindow',
    Schedule='cron(0 2 ? * SUN *)',
    Duration=4,
    Cutoff=1
)
```

---

### Azure Update Management
**Cost**: $ (per node)
**Complexity**: Low
**Best for**: Azure/Hybrid environments

#### ARM Template
```json
{
  "type": "Microsoft.Automation/automationAccounts/softwareUpdateConfigurations",
  "apiVersion": "2019-06-01",
  "name": "[concat(parameters('automationAccountName'), '/ML2-Updates')]",
  "properties": {
    "updateConfiguration": {
      "operatingSystem": "Windows",
      "windows": {
        "includedUpdateClassifications": "Critical, Security",
        "rebootSetting": "IfRequired"
      },
      "duration": "PT2H"
    },
    "scheduleInfo": {
      "frequency": "Week",
      "interval": 1,
      "timeZone": "UTC",
      "advancedSchedule": {
        "weekDays": ["Sunday"]
      }
    }
  }
}
```

---

## Third-Party Patch Management

### Patch My PC
**Cost**: $$ (per device)
**Complexity**: Low
**Best for**: Third-party Windows applications

**Supported Applications**:
- Adobe products
- Chrome, Firefox
- Java, .NET
- 700+ applications

---

### Ivanti Patch
**Cost**: $$$ (per device)
**Complexity**: Medium
**Best for**: Enterprise environments

**Features**:
- Cross-platform support
- Virtual patching
- Automated testing
- Rollback capabilities

---

## Vulnerability Scanning Integration

### Nessus + Patch Management
```python
import requests
from datetime import datetime, timedelta

class VulnerabilityPatcher:
    def __init__(self, nessus_url, patch_system):
        self.nessus = nessus_url
        self.patcher = patch_system
        
    def get_critical_vulns(self):
        # Query Nessus for critical vulnerabilities
        response = requests.get(f"{self.nessus}/scans/latest")
        vulns = response.json()['vulnerabilities']
        
        critical = [v for v in vulns if v['severity'] >= 9.0]
        return critical
    
    def create_patch_job(self, vulns):
        patches = []
        for vuln in vulns:
            if vuln['solution']:
                patches.append({
                    'cve': vuln['cve'],
                    'patch_id': vuln['solution']['patch_id'],
                    'priority': 'CRITICAL',
                    'deadline': datetime.now() + timedelta(hours=48)
                })
        
        return self.patcher.schedule_patches(patches)
```

---

## Patch Testing Strategies

### Ring Deployment Model
```mermaid
graph LR
    A[Canary: 1%] --> B[Pilot: 10%]
    B --> C[UAT: 25%]
    C --> D[Production: 100%]
```

### Automated Testing Framework
```bash
#!/bin/bash
# Patch validation script

# Apply patches to test environment
ansible-playbook -i test-inventory patch.yml

# Run automated tests
pytest tests/system_tests.py
pytest tests/application_tests.py

# Validate services
for service in httpd mysql nginx; do
    systemctl is-active $service || exit 1
done

# Check system stability
uptime | grep -q "load average: [0-9]" || exit 1

# If all tests pass, approve for production
if [ $? -eq 0 ]; then
    echo "Patches validated - approving for production"
    ansible-playbook -i prod-inventory patch.yml
fi
```

---

## Reporting & Compliance

### PowerShell Compliance Report
```powershell
# Generate patch compliance report
$computers = Get-ADComputer -Filter * | Select -ExpandProperty Name
$report = @()

foreach ($computer in $computers) {
    $updates = Get-HotFix -ComputerName $computer -ErrorAction SilentlyContinue
    $lastPatch = $updates | Sort InstalledOn -Descending | Select -First 1
    
    $report += [PSCustomObject]@{
        ComputerName = $computer
        LastPatchDate = $lastPatch.InstalledOn
        DaysSinceLastPatch = (New-TimeSpan -Start $lastPatch.InstalledOn).Days
        TotalPatches = $updates.Count
        Compliant = (New-TimeSpan -Start $lastPatch.InstalledOn).Days -le 30
    }
}

$report | Export-Csv "PatchCompliance.csv" -NoTypeInformation
```

---

## Best Practices by Maturity Level

### ML1 (1 month patching)
1. Manual approval process
2. Monthly maintenance windows
3. Basic reporting
4. Test on non-critical systems

### ML2 (2 weeks patching)
1. Automated approval for critical patches
2. Ring deployment model
3. Automated testing
4. Integration with vulnerability scanning

### ML3 (48 hours patching)
1. Fully automated pipeline
2. Continuous deployment
3. Virtual patching for gaps
4. Real-time compliance monitoring

---

## Emergency Patching Procedures

### Zero-Day Response Playbook
1. **Assess** - Determine affected systems
2. **Mitigate** - Apply virtual patches/WAF rules
3. **Test** - Validate patch in isolated environment
4. **Deploy** - Emergency change approval
5. **Verify** - Confirm successful remediation

---

## Resources
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/)
- [NIST Patch Management](https://nvd.nist.gov/)
- [ACSC Patch Management Guidance](https://www.cyber.gov.au/patching)
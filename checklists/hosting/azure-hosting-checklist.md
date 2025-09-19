# Azure Cloud Hosting Security Checklist

## Essential Eight Implementation for Azure Infrastructure

This checklist maps Essential Eight controls to Azure services and best practices.

### 1. Application Control

- [ ] **ML1: Basic Application Control**
  - [ ] Use Azure Policy for application governance
  - [ ] Implement Adaptive Application Controls in Defender
  - [ ] Configure Azure Virtual Desktop app policies
  - [ ] Use Azure Functions for controlled execution
  - [ ] Enable Microsoft Defender for Cloud
- [ ] **ML2: Enhanced Control**
  - [ ] Implement Application Gateway WAF rules
  - [ ] Use Azure Container Registry scanning
  - [ ] Configure Conditional Access app control
  - [ ] Implement Azure Firewall application rules
- [ ] **ML3: Advanced Protection**
  - [ ] Use Azure Confidential Computing
  - [ ] Implement runtime protection with Defender
  - [ ] Enable advanced threat protection

### 2. Patch Applications

- [ ] **ML1: Regular Patching**
  - [ ] Configure Azure Update Management
  - [ ] Set up update schedules
  - [ ] Use Azure Automation for patch deployment
  - [ ] Enable vulnerability assessment
- [ ] **ML2: Automated Patching**
  - [ ] Implement automatic VM updates
  - [ ] Use Update Management Center
  - [ ] Configure patch orchestration
  - [ ] Enable automatic security updates
- [ ] **ML3: Continuous Updates**
  - [ ] Implement blue-green deployments
  - [ ] Use Azure DevOps for CI/CD
  - [ ] Enable automatic platform updates

### 3. Configure Microsoft Office Macro Settings

- [ ] **ML1: Macro Restrictions**
  - [ ] Configure Intune policies for Office
  - [ ] Use Conditional Access for Office 365
  - [ ] Implement Attack Surface Reduction rules
- [ ] **ML2: Enhanced Restrictions**
  - [ ] Block macros via Azure AD policies
  - [ ] Configure Microsoft Defender for Office 365
  - [ ] Implement Safe Attachments policies
- [ ] **ML3: Complete Control**
  - [ ] Use Azure Information Protection
  - [ ] Implement Zero Trust application access
  - [ ] Enable Advanced Threat Analytics

### 4. User Application Hardening

- [ ] **ML1: Basic Hardening**
  - [ ] Configure Network Security Groups (NSGs)
  - [ ] Implement Azure Firewall
  - [ ] Use Application Security Groups
  - [ ] Enable Azure Monitor logging
- [ ] **ML2: Enhanced Hardening**
  - [ ] Implement Azure Private Endpoints
  - [ ] Use Azure Private Link
  - [ ] Configure Azure Front Door WAF
  - [ ] Enable NSG Flow Logs
- [ ] **ML3: Maximum Hardening**
  - [ ] Implement Azure Bastion for RDP/SSH
  - [ ] Use Azure Virtual WAN
  - [ ] Enable Microsoft Sentinel

### 5. Restrict Administrative Privileges

- [ ] **ML1: Azure AD Best Practices**
  - [ ] Enforce MFA for all admin accounts
  - [ ] Implement Azure RBAC
  - [ ] Use Azure AD PIM for just-in-time access
  - [ ] Regular access reviews
  - [ ] Enable Azure AD audit logs
- [ ] **ML2: Advanced Azure AD**
  - [ ] Configure Conditional Access policies
  - [ ] Implement administrative units
  - [ ] Use custom RBAC roles
  - [ ] Configure session controls
  - [ ] Enable Identity Protection
- [ ] **ML3: Zero Standing Privileges**
  - [ ] Full PIM implementation
  - [ ] Time-bound admin access only
  - [ ] Use managed identities exclusively
  - [ ] Implement emergency access accounts

### 6. Patch Operating Systems

- [ ] **ML1: OS Patching**
  - [ ] Configure Update Management
  - [ ] Use Azure-provided images
  - [ ] Implement maintenance schedules
  - [ ] Track update compliance
- [ ] **ML2: Automated OS Updates**
  - [ ] Automate VM replacements
  - [ ] Use VM Scale Sets with updates
  - [ ] Implement immutable infrastructure
  - [ ] Configure automatic OS upgrades
- [ ] **ML3: Continuous OS Security**
  - [ ] Use Azure Kubernetes Service patches
  - [ ] Implement Container Instances
  - [ ] Enable automatic security updates
  - [ ] Use Azure Functions for serverless

### 7. Multi-factor Authentication

- [ ] **ML1: Basic MFA**
  - [ ] Enable Azure AD MFA
  - [ ] Require MFA for administrators
  - [ ] Configure MFA for Azure Portal
  - [ ] Use Microsoft Authenticator
- [ ] **ML2: Enhanced MFA**
  - [ ] Require hardware tokens for privileged users
  - [ ] Implement FIDO2 security keys
  - [ ] Configure risk-based MFA
  - [ ] Enable passwordless authentication
- [ ] **ML3: Advanced Authentication**
  - [ ] Implement Windows Hello for Business
  - [ ] Use Azure AD Certificate-based auth
  - [ ] Configure continuous access evaluation
  - [ ] Implement phishing-resistant MFA

### 8. Regular Backups

- [ ] **ML1: Basic Backups**
  - [ ] Enable Azure Backup
  - [ ] Configure VM backup policies
  - [ ] Use Azure Site Recovery
  - [ ] Implement geo-redundant storage
- [ ] **ML2: Enhanced Backups**
  - [ ] Configure backup encryption
  - [ ] Implement soft delete
  - [ ] Use backup policies and retention
  - [ ] Enable cross-region backup
- [ ] **ML3: Immutable Backups**
  - [ ] Enable immutable blob storage
  - [ ] Configure legal hold policies
  - [ ] Use time-based retention
  - [ ] Implement WORM storage

## Azure-Specific Security Controls

### Tenant & Subscription Security

- [ ] **Azure AD Tenant**
  - [ ] Configure tenant restrictions
  - [ ] Enable security defaults
  - [ ] Implement named locations
  - [ ] Configure external collaboration settings
  - [ ] Enable unified audit log

- [ ] **Management Groups**
  - [ ] Implement management group hierarchy
  - [ ] Apply Azure Policies at scale
  - [ ] Configure subscription governance
  - [ ] Implement cost management
  - [ ] Enable Azure Blueprints

### Network Security

- [ ] **Virtual Network Security**
  - [ ] Implement hub-spoke topology
  - [ ] Configure VNet peering securely
  - [ ] Enable DDoS Protection Standard
  - [ ] Use Network Watcher
  - [ ] Implement service endpoints

- [ ] **Perimeter Security**
  - [ ] Configure Azure Firewall
  - [ ] Implement Azure Front Door
  - [ ] Use Azure Application Gateway
  - [ ] Enable Azure DDoS Protection
  - [ ] Configure ExpressRoute

- [ ] **Zero Trust Networking**
  - [ ] Implement Private Endpoints
  - [ ] Use Azure Private Link
  - [ ] Configure service firewalls
  - [ ] Disable public endpoints
  - [ ] Implement micro-segmentation

### Data Security

- [ ] **Encryption**
  - [ ] Enable Storage Service Encryption
  - [ ] Use Azure Key Vault
  - [ ] Implement customer-managed keys
  - [ ] Configure Azure Disk Encryption
  - [ ] Enable SQL Database TDE

- [ ] **Data Protection**
  - [ ] Configure Azure Information Protection
  - [ ] Implement Microsoft Purview
  - [ ] Use Azure Confidential Computing
  - [ ] Enable sensitivity labels
  - [ ] Configure data loss prevention

- [ ] **Secrets Management**
  - [ ] Use Azure Key Vault
  - [ ] Implement managed identities
  - [ ] Configure secret rotation
  - [ ] Enable soft delete and purge protection
  - [ ] Audit secret access

### Compute Security

- [ ] **Virtual Machine Security**
  - [ ] Use Azure Security Center recommendations
  - [ ] Enable endpoint protection
  - [ ] Configure Just-In-Time VM access
  - [ ] Implement Azure Bastion
  - [ ] Use Azure Dedicated Hosts

- [ ] **Container Security**
  - [ ] Scan images in Container Registry
  - [ ] Use Azure Kubernetes Service policies
  - [ ] Implement pod security policies
  - [ ] Configure network policies
  - [ ] Enable container insights

- [ ] **Serverless Security**
  - [ ] Configure Function App authentication
  - [ ] Use managed identities for Functions
  - [ ] Implement API Management
  - [ ] Configure CORS policies
  - [ ] Enable Application Insights

### Monitoring & Compliance

- [ ] **Security Monitoring**
  - [ ] Enable Microsoft Defender for Cloud
  - [ ] Configure Microsoft Sentinel
  - [ ] Implement Azure Monitor
  - [ ] Use Log Analytics workspaces
  - [ ] Configure alert rules

- [ ] **Compliance Management**
  - [ ] Enable Regulatory Compliance dashboard
  - [ ] Configure Azure Policy
  - [ ] Use Azure Blueprints
  - [ ] Implement Microsoft Purview
  - [ ] Generate compliance reports

- [ ] **Incident Response**
  - [ ] Configure incident workflows
  - [ ] Enable automated response
  - [ ] Implement Logic Apps for automation
  - [ ] Configure notification channels
  - [ ] Document response procedures

### Identity & Access Management

- [ ] **Azure AD Security**
  - [ ] Implement Identity Protection
  - [ ] Configure risk policies
  - [ ] Enable sign-in risk detection
  - [ ] Implement user risk policies
  - [ ] Configure identity governance

- [ ] **Conditional Access**
  - [ ] Require MFA for risky sign-ins
  - [ ] Block legacy authentication
  - [ ] Implement device compliance
  - [ ] Configure session controls
  - [ ] Enable continuous access evaluation

- [ ] **Privileged Access**
  - [ ] Implement Azure AD PIM
  - [ ] Configure approval workflows
  - [ ] Enable access reviews
  - [ ] Implement separation of duties
  - [ ] Configure emergency access

## Implementation Roadmap

### Week 1-2: Foundation

1. Set up Azure AD and subscriptions
2. Configure Microsoft Defender for Cloud
3. Enable Azure Policy and Blueprints
4. Implement RBAC and PIM
5. Configure MFA for all users

### Week 3-4: Network & Access

1. Design Virtual Network architecture
2. Configure NSGs and ASGs
3. Set up Azure Firewall
4. Implement Azure Bastion
5. Configure Private Endpoints

### Week 5-6: Data & Compute

1. Enable encryption everywhere
2. Configure Azure Backup
3. Implement Update Management
4. Set up monitoring and alerting
5. Configure WAF and DDoS protection

### Week 7-8: Advanced Security

1. Implement compliance frameworks
2. Configure Microsoft Sentinel
3. Set up automated remediation
4. Conduct security assessment
5. Document configurations

### Ongoing: Operations

1. Regular security assessments
2. Update and patch cycles
3. Access reviews and audits
4. Cost optimization
5. Continuous improvement

## PowerShell Automation Scripts

### Enable Security Features

```powershell
# Enable Microsoft Defender for Cloud
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"

# Enable Azure AD MFA
$MFAPolicy = New-AzureADMSConditionalAccessPolicy

# Configure Update Management
New-AzAutomationSchedule -ResourceGroupName "RG" -AutomationAccountName "AA"
```

### Security Audit

```powershell
# Check for users without MFA
Get-MsolUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0}

# List admin role assignments
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -like "*admin*"}

# Check for public IP addresses
Get-AzPublicIpAddress | Select Name, IpAddress, ResourceGroupName
```

## Azure CLI Scripts

### Security Configuration

```bash
# Enable Security Center Standard tier
az security pricing create --name VirtualMachines --tier standard

# Create Network Security Group rule
az network nsg rule create --name DenyInternet --nsg-name MyNSG

# Enable Azure Backup
az backup protection enable-for-vm --vault-name MyVault
```

## Compliance Frameworks

### Applicable Standards

- [ ] Azure Security Benchmark
- [ ] CIS Microsoft Azure Foundations Benchmark
- [ ] Azure Security Center Regulatory Compliance
- [ ] ISO 27001/27017/27018
- [ ] SOC 1/2/3
- [ ] HIPAA/HITRUST
- [ ] PCI DSS
- [ ] Australian Government ISM

## Azure Security Resources

- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/fundamentals/best-practices-and-patterns)
- [Azure Well-Architected Framework](https://docs.microsoft.com/azure/architecture/framework/)
- [Microsoft Defender for Cloud](https://docs.microsoft.com/azure/defender-for-cloud/)
- [Azure Compliance Documentation](https://docs.microsoft.com/azure/compliance/)
- [Azure Security Benchmark](https://docs.microsoft.com/security/benchmark/azure/)

## Support & Training

- Azure Support Plans (Professional/Premier)
- Microsoft Learn Security Paths
- Azure Security Center recommendations
- Microsoft Security workshops
- Azure Security community

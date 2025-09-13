# Google Cloud Platform (GCP) Hosting Security Checklist

## Essential Eight Implementation for GCP Infrastructure

This checklist maps Essential Eight controls to Google Cloud services and best practices.

### 1. Application Control
- [ ] **ML1: Basic Application Control**
  - [ ] Use Binary Authorization for container deployments
  - [ ] Implement Cloud Asset Inventory
  - [ ] Configure OS Config for application management
  - [ ] Use Cloud Functions for controlled execution
  - [ ] Enable Security Command Center
- [ ] **ML2: Enhanced Control**
  - [ ] Implement Cloud Armor WAF rules
  - [ ] Use Container Analysis for vulnerability scanning
  - [ ] Configure Workload Identity
  - [ ] Implement VPC Service Controls
- [ ] **ML3: Advanced Protection**
  - [ ] Use Confidential Computing
  - [ ] Implement Assured Workloads
  - [ ] Enable advanced threat detection

### 2. Patch Applications
- [ ] **ML1: Regular Patching**
  - [ ] Configure OS Patch Management
  - [ ] Set up patch deployment schedules
  - [ ] Use Cloud Build for automated updates
  - [ ] Enable vulnerability scanning
- [ ] **ML2: Automated Patching**
  - [ ] Implement automatic VM patching
  - [ ] Use managed instance groups
  - [ ] Configure patch policies
  - [ ] Enable Container-Optimized OS auto-updates
- [ ] **ML3: Continuous Updates**
  - [ ] Implement blue-green deployments
  - [ ] Use Cloud Deploy for continuous delivery
  - [ ] Enable automatic security updates

### 3. Configure Microsoft Office Macro Settings
- [ ] **ML1: Macro Restrictions**
  - [ ] Configure Chrome Enterprise policies
  - [ ] Use Context-Aware Access for Google Workspace
  - [ ] Implement Drive file restrictions
- [ ] **ML2: Enhanced Restrictions**
  - [ ] Block macros via Workspace policies
  - [ ] Configure Gmail advanced protection
  - [ ] Implement attachment sandboxing
- [ ] **ML3: Complete Control**
  - [ ] Use Data Loss Prevention API
  - [ ] Implement BeyondCorp Enterprise
  - [ ] Enable threat detection

### 4. User Application Hardening
- [ ] **ML1: Basic Hardening**
  - [ ] Configure VPC firewall rules
  - [ ] Implement Cloud NAT
  - [ ] Use Cloud Load Balancing
  - [ ] Enable Cloud Logging
- [ ] **ML2: Enhanced Hardening**
  - [ ] Implement Private Google Access
  - [ ] Use Private Service Connect
  - [ ] Configure Cloud Armor DDoS protection
  - [ ] Enable VPC Flow Logs
- [ ] **ML3: Maximum Hardening**
  - [ ] Implement Identity-Aware Proxy
  - [ ] Use Shared VPC for isolation
  - [ ] Enable Chronicle Security Operations

### 5. Restrict Administrative Privileges
- [ ] **ML1: IAM Best Practices**
  - [ ] Enforce MFA for all admin accounts
  - [ ] Implement least privilege IAM policies
  - [ ] Use service accounts properly
  - [ ] Regular IAM policy reviews
  - [ ] Enable Cloud Audit Logs
- [ ] **ML2: Advanced IAM**
  - [ ] Configure Organization Policies
  - [ ] Implement custom IAM roles
  - [ ] Use Workload Identity Federation
  - [ ] Configure IAM Conditions
  - [ ] Enable Policy Intelligence
- [ ] **ML3: Zero Standing Privileges**
  - [ ] Implement just-in-time access
  - [ ] Use temporary elevated privileges
  - [ ] Configure break-glass procedures
  - [ ] Implement approval workflows

### 6. Patch Operating Systems
- [ ] **ML1: OS Patching**
  - [ ] Configure OS Patch Management service
  - [ ] Use Google-provided images
  - [ ] Implement patch deployment windows
  - [ ] Track patch compliance
- [ ] **ML2: Automated OS Updates**
  - [ ] Automate instance replacement
  - [ ] Use managed instance groups
  - [ ] Implement immutable infrastructure
  - [ ] Configure automatic OS upgrades
- [ ] **ML3: Continuous OS Security**
  - [ ] Use GKE Autopilot
  - [ ] Implement Cloud Run
  - [ ] Enable automatic security patches
  - [ ] Use Anthos for hybrid deployments

### 7. Multi-factor Authentication
- [ ] **ML1: Basic MFA**
  - [ ] Enable 2-Step Verification
  - [ ] Require MFA for Cloud Console
  - [ ] Configure Google Authenticator
  - [ ] Use backup codes
- [ ] **ML2: Enhanced MFA**
  - [ ] Require security keys for privileged users
  - [ ] Implement FIDO Universal 2nd Factor
  - [ ] Configure risk-based access
  - [ ] Enable Advanced Protection Program
- [ ] **ML3: Advanced Authentication**
  - [ ] Implement passwordless authentication
  - [ ] Use Titan Security Keys
  - [ ] Configure continuous verification
  - [ ] Implement phishing-resistant MFA

### 8. Regular Backups
- [ ] **ML1: Basic Backups**
  - [ ] Enable Cloud Storage versioning
  - [ ] Configure persistent disk snapshots
  - [ ] Use Cloud SQL automated backups
  - [ ] Implement cross-region replication
- [ ] **ML2: Enhanced Backups**
  - [ ] Configure backup encryption with CMEK
  - [ ] Implement retention policies
  - [ ] Use point-in-time recovery
  - [ ] Enable soft delete
- [ ] **ML3: Immutable Backups**
  - [ ] Configure Bucket Lock
  - [ ] Implement retention policies
  - [ ] Use Object Lifecycle Management
  - [ ] Enable compliance mode

## GCP-Specific Security Controls

### Organization & Project Security
- [ ] **Organization Structure**
  - [ ] Implement resource hierarchy
  - [ ] Use separate projects for environments
  - [ ] Configure Organization Policies
  - [ ] Enable Security Command Center
  - [ ] Implement consolidated billing

- [ ] **Organization Policies**
  - [ ] Restrict resource locations
  - [ ] Enforce encryption requirements
  - [ ] Control service usage
  - [ ] Require specific labels
  - [ ] Restrict external IPs

### Network Security
- [ ] **VPC Security**
  - [ ] Use custom mode VPCs
  - [ ] Implement Shared VPC
  - [ ] Configure VPC Flow Logs
  - [ ] Use Private Google Access
  - [ ] Enable DNS Security

- [ ] **Perimeter Security**
  - [ ] Configure Cloud Armor
  - [ ] Implement Cloud CDN
  - [ ] Use Cloud Load Balancing
  - [ ] Enable DDoS protection
  - [ ] Configure Cloud Interconnect

- [ ] **Zero Trust Architecture**
  - [ ] Implement BeyondCorp Enterprise
  - [ ] Use Identity-Aware Proxy
  - [ ] Configure VPC Service Controls
  - [ ] Implement Private Service Connect
  - [ ] Enable micro-segmentation

### Data Security
- [ ] **Encryption**
  - [ ] Enable default encryption
  - [ ] Use Cloud KMS
  - [ ] Implement customer-managed keys (CMEK)
  - [ ] Configure Application-layer Secrets Encryption
  - [ ] Enable Confidential Computing

- [ ] **Data Protection**
  - [ ] Configure Cloud Data Loss Prevention
  - [ ] Implement sensitive data discovery
  - [ ] Use Cloud HSM
  - [ ] Enable data residency controls
  - [ ] Configure access transparency

- [ ] **Secrets Management**
  - [ ] Use Secret Manager
  - [ ] Implement automatic rotation
  - [ ] Configure secret versions
  - [ ] Enable audit logging
  - [ ] Use Workload Identity

### Compute Security
- [ ] **Compute Engine Security**
  - [ ] Use Shielded VMs
  - [ ] Enable OS Login
  - [ ] Configure Instance Metadata Service v2
  - [ ] Implement Sole-tenant nodes
  - [ ] Use Confidential VMs

- [ ] **Container Security**
  - [ ] Scan images with Container Analysis
  - [ ] Use GKE security features
  - [ ] Implement Workload Identity
  - [ ] Configure Binary Authorization
  - [ ] Enable GKE Autopilot

- [ ] **Serverless Security**
  - [ ] Configure Cloud Functions security
  - [ ] Use Cloud Run authentication
  - [ ] Implement API Gateway
  - [ ] Configure Eventarc security
  - [ ] Enable VPC connectors

### Monitoring & Compliance
- [ ] **Security Monitoring**
  - [ ] Enable Security Command Center
  - [ ] Configure Cloud IDS
  - [ ] Implement Chronicle SIEM
  - [ ] Use Cloud Monitoring
  - [ ] Configure alert policies

- [ ] **Compliance Management**
  - [ ] Enable Assured Workloads
  - [ ] Configure Access Approval
  - [ ] Use Policy Intelligence
  - [ ] Implement compliance reports
  - [ ] Enable Access Transparency

- [ ] **Incident Response**
  - [ ] Configure incident workflows
  - [ ] Enable automated response
  - [ ] Implement Cloud Functions for automation
  - [ ] Configure notification channels
  - [ ] Document response procedures

### Identity & Access Management
- [ ] **Cloud Identity**
  - [ ] Configure Cloud Identity
  - [ ] Implement groups and organizational units
  - [ ] Enable password policies
  - [ ] Configure session controls
  - [ ] Implement device management

- [ ] **Context-Aware Access**
  - [ ] Configure access levels
  - [ ] Implement device policies
  - [ ] Set up IP restrictions
  - [ ] Configure risk assessment
  - [ ] Enable continuous verification

- [ ] **Privileged Access**
  - [ ] Implement PAM solutions
  - [ ] Configure approval workflows
  - [ ] Enable access reviews
  - [ ] Implement separation of duties
  - [ ] Configure emergency access

## Implementation Roadmap

### Week 1-2: Foundation
1. Set up Organization and projects
2. Configure Cloud Identity
3. Enable Security Command Center
4. Implement IAM best practices
5. Configure MFA for all users

### Week 3-4: Network & Access
1. Design VPC architecture
2. Configure firewall rules
3. Set up Cloud Armor
4. Implement Identity-Aware Proxy
5. Configure Private Google Access

### Week 5-6: Data & Compute
1. Enable encryption everywhere
2. Configure backup strategies
3. Implement OS Patch Management
4. Set up monitoring and alerting
5. Configure Cloud Armor and DDoS

### Week 7-8: Advanced Security
1. Implement compliance frameworks
2. Configure Chronicle or SIEM
3. Set up automated remediation
4. Conduct security assessment
5. Document configurations

### Ongoing: Operations
1. Regular security assessments
2. Patch and update cycles
3. Access reviews and audits
4. Cost optimization
5. Continuous improvement

## gcloud CLI Scripts

### Enable Security Services
```bash
# Enable Security Command Center
gcloud scc sources create --display-name="Security Scanner"

# Enable Cloud Audit Logs
gcloud logging sinks create audit-logs

# Configure Organization Policies
gcloud resource-manager org-policies allow
```

### Security Audit
```bash
# List users without MFA
gcloud identity groups memberships list

# Check for external IPs
gcloud compute addresses list

# List IAM policy bindings
gcloud projects get-iam-policy PROJECT_ID

# Check for default service accounts
gcloud iam service-accounts list
```

### Terraform Examples
```hcl
# Enable APIs
resource "google_project_service" "security" {
  service = "securitycenter.googleapis.com"
}

# Configure VPC
resource "google_compute_network" "vpc" {
  name                    = "secure-vpc"
  auto_create_subnetworks = false
}

# Set Organization Policy
resource "google_organization_policy" "policy" {
  org_id     = "123456789"
  constraint = "compute.requireShieldedVm"
}
```

## Compliance Frameworks

### Applicable Standards
- [ ] Google Cloud Security Foundations Blueprint
- [ ] CIS Google Cloud Platform Foundation Benchmark
- [ ] PCI DSS on Google Cloud
- [ ] HIPAA on Google Cloud
- [ ] SOC 1/2/3 compliance
- [ ] ISO 27001/27017/27018
- [ ] FedRAMP compliance
- [ ] Australian Government ISM

## Security Best Practices

### Network Architecture
1. Hub-and-spoke VPC design
2. Shared VPC for multi-project
3. VPC Service Controls for data protection
4. Private Google Access for services
5. Cloud Interconnect for hybrid

### Data Governance
1. Data classification with DLP
2. Encryption with CMEK/CSEK
3. Data residency controls
4. Access transparency logs
5. VPC Service Controls perimeters

### Operational Excellence
1. Infrastructure as Code (Terraform)
2. Policy as Code
3. Automated compliance scanning
4. Continuous security monitoring
5. Automated incident response

## GCP Security Resources

- [Google Cloud Security Best Practices](https://cloud.google.com/security/best-practices)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework)
- [Security Command Center](https://cloud.google.com/security-command-center)
- [Google Cloud Compliance](https://cloud.google.com/security/compliance)
- [Chronicle Security Operations](https://chronicle.security)

## Support & Training

- Google Cloud Support (Standard/Enhanced/Premium)
- Google Cloud Skills Boost
- Security workshops and labs
- Google Cloud Next sessions
- Professional certifications

## Monitoring Dashboard Setup

### Key Metrics to Monitor
- [ ] Failed authentication attempts
- [ ] Privilege escalations
- [ ] Network anomalies
- [ ] Resource modifications
- [ ] Data access patterns
- [ ] API usage anomalies
- [ ] Cost anomalies
- [ ] Compliance violations

### Alert Configuration
- [ ] Security findings (Critical/High)
- [ ] IAM changes
- [ ] Firewall rule modifications
- [ ] Unusual API activity
- [ ] Budget thresholds
- [ ] Resource quota limits
- [ ] Backup failures
- [ ] Patch compliance

## Automation Opportunities

1. **Security Automation**
   - Auto-remediation of findings
   - Automated patch deployment
   - Incident response workflows
   - Compliance reporting

2. **Cost Optimization**
   - Rightsizing recommendations
   - Idle resource cleanup
   - Committed use discounts
   - Budget alerts

3. **Operational Automation**
   - Infrastructure provisioning
   - Backup automation
   - Monitoring setup
   - Documentation generation
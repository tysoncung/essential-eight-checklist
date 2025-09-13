# Infrastructure Hosting Security Checklists

## Essential Eight Implementation for Different Hosting Environments

This directory contains comprehensive security checklists for implementing the Essential Eight Maturity Model across various hosting platforms. Each checklist is tailored to the specific features and services of its respective platform while maintaining alignment with the Essential Eight framework.

## Available Checklists

### 🏢 [On-Premise Hosting](./on-premise-hosting-checklist.md)
Complete security checklist for organizations managing their own physical infrastructure, including:
- Physical security controls
- Network infrastructure
- Server room/data center requirements
- Disaster recovery planning
- Hardware lifecycle management

### ☁️ [AWS Cloud Hosting](./aws-hosting-checklist.md)
Comprehensive guide for securing Amazon Web Services infrastructure:
- AWS-specific service configurations
- IAM and access management
- VPC and network security
- Compliance frameworks (CIS, Well-Architected)
- Cost optimization with security

### ☁️ [Azure Cloud Hosting](./azure-hosting-checklist.md)
Detailed checklist for Microsoft Azure deployments:
- Azure AD and identity management
- Microsoft Defender for Cloud
- Network security with NSGs and Azure Firewall
- Compliance with Azure Security Benchmark
- Integration with Microsoft 365 security

### ☁️ [Google Cloud Platform](./gcp-hosting-checklist.md)
Security implementation guide for GCP:
- Cloud Identity and IAM
- VPC Service Controls
- Security Command Center
- BeyondCorp and Zero Trust
- Compliance with Google Cloud security best practices

## How to Use These Checklists

### 1. Select Your Platform
Choose the checklist that matches your hosting environment. If you use multiple platforms, review each relevant checklist.

### 2. Assess Current State
Go through each item and mark your current compliance level:
- ✅ Implemented
- 🔄 In Progress
- ❌ Not Started
- N/A Not Applicable

### 3. Prioritize Implementation
Each checklist includes implementation phases:
- **Phase 1**: Critical security controls (Immediate)
- **Phase 2**: High priority items (30 days)
- **Phase 3**: Medium priority items (90 days)
- **Phase 4**: Ongoing improvements

### 4. Map to Maturity Levels
All checklists are organized by Essential Eight Maturity Levels:
- **ML1**: Basic cyber hygiene
- **ML2**: Enhanced security posture
- **ML3**: Advanced protection against sophisticated threats

## Comparison Matrix

| Feature | On-Premise | AWS | Azure | GCP |
|---------|------------|-----|-------|-----|
| **Physical Security** | Full Control | AWS Managed | Microsoft Managed | Google Managed |
| **Network Control** | Complete | VPC-based | VNet-based | VPC-based |
| **Identity Provider** | AD/LDAP | IAM/SSO | Azure AD | Cloud Identity |
| **Patch Management** | Manual/SCCM | Systems Manager | Update Management | OS Config |
| **Backup Solution** | Third-party | AWS Backup | Azure Backup | Cloud Storage |
| **Compliance Tools** | Third-party | Security Hub | Defender for Cloud | Security Command Center |
| **Cost Model** | CapEx | OpEx | OpEx | OpEx |
| **Shared Responsibility** | Full | Shared | Shared | Shared |

## Common Security Controls Across All Platforms

### Essential Eight Controls
1. **Application Control** - Whitelisting and execution control
2. **Patch Applications** - Regular security updates
3. **Configure Office Macros** - Restrict macro execution
4. **User Application Hardening** - Browser and application security
5. **Restrict Admin Privileges** - Least privilege access
6. **Patch Operating Systems** - OS security updates
7. **Multi-factor Authentication** - Strong authentication
8. **Regular Backups** - Data protection and recovery

### Additional Security Layers
- Network segmentation
- Encryption at rest and in transit
- Security monitoring and SIEM
- Incident response planning
- Compliance management
- Vulnerability management
- Security awareness training

## Hybrid and Multi-Cloud Considerations

If you're using multiple platforms:

1. **Consistent Security Policies**
   - Standardize security controls across platforms
   - Use cloud-agnostic tools where possible
   - Maintain unified compliance reporting

2. **Centralized Management**
   - Consider CSPM (Cloud Security Posture Management) tools
   - Implement unified SIEM/SOAR
   - Centralize identity management

3. **Network Connectivity**
   - Secure interconnections between platforms
   - Consistent network security policies
   - Unified threat detection

## Automation and Infrastructure as Code

Each checklist includes automation examples:
- **On-Premise**: PowerShell, Ansible, Puppet
- **AWS**: CloudFormation, Terraform, AWS CLI
- **Azure**: ARM Templates, Terraform, Azure CLI
- **GCP**: Deployment Manager, Terraform, gcloud

## Compliance and Regulatory Alignment

All checklists align with:
- Australian Government Information Security Manual (ISM)
- NIST Cybersecurity Framework
- CIS Controls
- ISO 27001/27002
- Industry-specific requirements (PCI DSS, HIPAA, etc.)

## Regular Review and Updates

Security is an ongoing process:
1. Review checklists quarterly
2. Update based on new threats
3. Incorporate platform updates
4. Adjust for compliance changes
5. Learn from security incidents

## Contributing

We welcome contributions to improve these checklists:
- Report issues or gaps
- Submit pull requests with improvements
- Share implementation experiences
- Suggest new platform checklists

## Resources

### General Security
- [ACSC Essential Eight](https://www.cyber.gov.au/acsc/view-all-content/essential-eight)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

### Platform-Specific
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Azure Security Documentation](https://docs.microsoft.com/azure/security/)
- [Google Cloud Security](https://cloud.google.com/security)

### Tools and Automation
- [Terraform](https://www.terraform.io/)
- [Ansible](https://www.ansible.com/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)

## Support

For questions or assistance:
- Open an issue in the repository
- Consult platform-specific support channels
- Engage with the security community
- Consider professional security consulting

---

Remember: Security is a journey, not a destination. These checklists provide a framework, but must be adapted to your specific needs, risk profile, and compliance requirements.
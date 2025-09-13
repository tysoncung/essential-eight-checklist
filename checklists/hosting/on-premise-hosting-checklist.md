# On-Premise Hosting Security Checklist

## Essential Eight Implementation for On-Premise Infrastructure

This checklist aligns on-premise hosting security with the Essential Eight Maturity Model.

### 1. Application Control
- [ ] **ML1: Whitelisting**
  - [ ] Implement application whitelisting on all servers
  - [ ] Block execution from temporary folders
  - [ ] Restrict script execution (PowerShell, cmd, bash)
  - [ ] Control access to system utilities
- [ ] **ML2: Enhanced Controls**
  - [ ] Implement path-based application control rules
  - [ ] Use cryptographic hash rules for critical applications
  - [ ] Block unapproved installers and packages
- [ ] **ML3: Advanced Protection**
  - [ ] Implement driver and kernel-level protection
  - [ ] Use certificate-based application control
  - [ ] Enable exploit protection features

### 2. Patch Applications
- [ ] **ML1: Monthly Patching**
  - [ ] Establish monthly patching schedule
  - [ ] Document all installed applications
  - [ ] Test patches in isolated environment
  - [ ] Maintain patch deployment logs
- [ ] **ML2: Rapid Patching**
  - [ ] Patch critical vulnerabilities within 48 hours
  - [ ] Automate patch deployment where possible
  - [ ] Implement rollback procedures
- [ ] **ML3: Continuous Updates**
  - [ ] Real-time vulnerability scanning
  - [ ] Automated patch testing and deployment
  - [ ] Zero-day vulnerability response plan

### 3. Configure Microsoft Office Macro Settings
- [ ] **ML1: Macro Restrictions**
  - [ ] Disable macros from the internet
  - [ ] Block macros in Office files from email
  - [ ] Warn users about macro risks
- [ ] **ML2: Enhanced Restrictions**
  - [ ] Only allow digitally signed macros
  - [ ] Implement macro logging
  - [ ] Block specific macro behaviors
- [ ] **ML3: Complete Control**
  - [ ] Disable all macros except in trusted locations
  - [ ] Implement application control for Office
  - [ ] Monitor and alert on macro execution

### 4. User Application Hardening
- [ ] **ML1: Basic Hardening**
  - [ ] Disable unnecessary browser plugins
  - [ ] Block ads and Java on the internet
  - [ ] Configure secure PDF settings
- [ ] **ML2: Enhanced Hardening**
  - [ ] Implement browser isolation
  - [ ] Block PowerShell for standard users
  - [ ] Restrict .NET Framework usage
- [ ] **ML3: Maximum Hardening**
  - [ ] Implement application sandboxing
  - [ ] Use virtualization for risky applications
  - [ ] Enable advanced exploit protections

### 5. Restrict Administrative Privileges
- [ ] **ML1: Basic Restrictions**
  - [ ] Document all admin accounts
  - [ ] Separate admin and user accounts
  - [ ] Implement least privilege principle
  - [ ] Regular admin account audits
- [ ] **ML2: Enhanced Controls**
  - [ ] Implement just-in-time admin access
  - [ ] Use privileged access workstations
  - [ ] Enable admin account monitoring
- [ ] **ML3: Zero Standing Privileges**
  - [ ] No permanent admin accounts
  - [ ] Time-bound privileged access
  - [ ] Complete audit trail of admin actions

### 6. Patch Operating Systems
- [ ] **ML1: Monthly OS Patching**
  - [ ] Monthly Windows/Linux updates
  - [ ] Firmware updates quarterly
  - [ ] BIOS/UEFI security updates
- [ ] **ML2: Rapid OS Patching**
  - [ ] Critical patches within 48 hours
  - [ ] Automated OS update deployment
  - [ ] Patch compliance monitoring
- [ ] **ML3: Continuous OS Updates**
  - [ ] Real-time OS vulnerability management
  - [ ] Automated testing and deployment
  - [ ] Kernel-level protection updates

### 7. Multi-factor Authentication
- [ ] **ML1: Critical System MFA**
  - [ ] MFA for all admin accounts
  - [ ] MFA for remote access (VPN, RDP)
  - [ ] MFA for critical applications
- [ ] **ML2: Expanded MFA**
  - [ ] MFA for all user accounts
  - [ ] MFA for email and collaboration tools
  - [ ] Hardware tokens for high-privilege users
- [ ] **ML3: Universal MFA**
  - [ ] Phishing-resistant MFA (FIDO2)
  - [ ] Passwordless authentication
  - [ ] Continuous authentication monitoring

### 8. Regular Backups
- [ ] **ML1: Basic Backups**
  - [ ] Daily incremental backups
  - [ ] Weekly full backups
  - [ ] Monthly backup testing
  - [ ] Offsite backup storage
- [ ] **ML2: Enhanced Backups**
  - [ ] Automated backup verification
  - [ ] Encrypted backup storage
  - [ ] Version control and retention policies
  - [ ] Documented restore procedures
- [ ] **ML3: Resilient Backups**
  - [ ] Immutable backups
  - [ ] Air-gapped backup copies
  - [ ] Real-time replication
  - [ ] Automated recovery testing

## Physical Infrastructure Security

### Server Room/Data Center
- [ ] **Physical Access Control**
  - [ ] Biometric access controls
  - [ ] Security cameras with 90-day retention
  - [ ] Access logs and audit trails
  - [ ] Visitor escort procedures
  - [ ] Mantrap/airlock entry systems

- [ ] **Environmental Controls**
  - [ ] Redundant cooling systems
  - [ ] UPS with generator backup
  - [ ] Fire suppression systems
  - [ ] Water leak detection
  - [ ] Temperature/humidity monitoring
  - [ ] Seismic bracing (if applicable)

- [ ] **Hardware Security**
  - [ ] Asset tagging and inventory
  - [ ] Secure equipment disposal
  - [ ] Cable management and labeling
  - [ ] Locked server racks
  - [ ] BIOS/UEFI passwords
  - [ ] TPM chip utilization

### Network Security
- [ ] **Perimeter Security**
  - [ ] Enterprise firewall with IPS/IDS
  - [ ] DMZ for public-facing services
  - [ ] Network segmentation (VLANs)
  - [ ] Guest network isolation
  - [ ] DDoS protection

- [ ] **Internal Network**
  - [ ] 802.1X authentication
  - [ ] Network access control (NAC)
  - [ ] Port security on switches
  - [ ] Disable unused ports
  - [ ] MAC address filtering

- [ ] **Monitoring**
  - [ ] SIEM implementation
  - [ ] NetFlow/sFlow monitoring
  - [ ] Intrusion detection systems
  - [ ] File integrity monitoring
  - [ ] Log aggregation and analysis

### Storage Security
- [ ] **Data Protection**
  - [ ] Encryption at rest (full disk)
  - [ ] Encryption in transit (TLS/SSL)
  - [ ] Secure key management
  - [ ] Data classification policies
  - [ ] Data loss prevention (DLP)

- [ ] **Storage Infrastructure**
  - [ ] RAID configuration for redundancy
  - [ ] SAN/NAS security hardening
  - [ ] Storage access controls
  - [ ] Capacity monitoring
  - [ ] Performance monitoring

### Virtualization Security
- [ ] **Hypervisor Security**
  - [ ] Hypervisor hardening
  - [ ] Regular hypervisor updates
  - [ ] Resource allocation limits
  - [ ] VM escape prevention
  - [ ] Virtual network segmentation

- [ ] **VM Management**
  - [ ] VM template security
  - [ ] Secure VM provisioning
  - [ ] VM sprawl prevention
  - [ ] Regular VM audits
  - [ ] Snapshot management

### Disaster Recovery
- [ ] **Planning**
  - [ ] Documented DR plan
  - [ ] Recovery time objectives (RTO)
  - [ ] Recovery point objectives (RPO)
  - [ ] Business impact analysis
  - [ ] Regular DR testing

- [ ] **Implementation**
  - [ ] Hot/warm/cold sites
  - [ ] Data replication strategy
  - [ ] Failover procedures
  - [ ] Communication plan
  - [ ] Vendor contact list

### Compliance & Governance
- [ ] **Documentation**
  - [ ] Network diagrams
  - [ ] Asset inventory
  - [ ] Configuration standards
  - [ ] Change management procedures
  - [ ] Incident response plan

- [ ] **Auditing**
  - [ ] Regular security audits
  - [ ] Compliance assessments
  - [ ] Vulnerability assessments
  - [ ] Penetration testing
  - [ ] Risk assessments

### Operational Security
- [ ] **Monitoring & Alerting**
  - [ ] 24/7 monitoring capability
  - [ ] Automated alerting system
  - [ ] Escalation procedures
  - [ ] Performance baselines
  - [ ] Capacity planning

- [ ] **Maintenance**
  - [ ] Maintenance windows
  - [ ] Change control board
  - [ ] Testing procedures
  - [ ] Rollback plans
  - [ ] Documentation updates

## Implementation Priority

### Phase 1: Critical (Immediate)
1. Physical access control
2. Admin privilege restrictions
3. Backup implementation
4. Firewall configuration
5. Critical system patching

### Phase 2: High (30 days)
1. Application control
2. MFA implementation
3. Network segmentation
4. Encryption deployment
5. Monitoring setup

### Phase 3: Medium (90 days)
1. Full Essential Eight ML1
2. DR plan implementation
3. Vulnerability management
4. Compliance framework
5. Advanced monitoring

### Phase 4: Ongoing
1. Progress to ML2/ML3
2. Continuous improvement
3. Regular testing
4. Staff training
5. Documentation updates

## Resources

- [ACSC Essential Eight](https://www.cyber.gov.au/acsc/view-all-content/essential-eight)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)
- [ISO 27001/27002](https://www.iso.org/isoiec-27001-information-security.html)

## Notes

- Customize this checklist based on your specific infrastructure
- Regular reviews and updates are essential
- Consider engaging security professionals for implementation
- Document all decisions and exceptions
- Maintain evidence for compliance purposes
# AWS Cloud Hosting Security Checklist

## Essential Eight Implementation for AWS Infrastructure

This checklist maps Essential Eight controls to AWS services and best practices.

### 1. Application Control
- [ ] **ML1: Basic Application Control**
  - [ ] Use AWS Systems Manager to inventory applications
  - [ ] Implement AWS AppStream 2.0 for controlled desktop apps
  - [ ] Configure EC2 instance user data scripts securely
  - [ ] Use AWS Lambda for serverless execution control
  - [ ] Enable GuardDuty for threat detection
- [ ] **ML2: Enhanced Control**
  - [ ] Implement AWS Systems Manager Run Command restrictions
  - [ ] Use AWS Config rules for compliance checking
  - [ ] Configure AWS WAF for web application protection
  - [ ] Implement container image scanning in ECR
- [ ] **ML3: Advanced Protection**
  - [ ] Use AWS Nitro Enclaves for sensitive workloads
  - [ ] Implement runtime application self-protection (RASP)
  - [ ] Enable AWS Shield Advanced for DDoS protection

### 2. Patch Applications
- [ ] **ML1: Regular Patching**
  - [ ] Enable AWS Systems Manager Patch Manager
  - [ ] Configure maintenance windows
  - [ ] Use AWS Inspector for vulnerability scanning
  - [ ] Implement patch baselines for EC2 instances
- [ ] **ML2: Automated Patching**
  - [ ] Automate patching with Systems Manager
  - [ ] Use AWS Lambda for patch orchestration
  - [ ] Implement patch compliance reporting
  - [ ] Configure automatic AMI updates
- [ ] **ML3: Continuous Updates**
  - [ ] Implement blue-green deployments for updates
  - [ ] Use AWS CodePipeline for continuous deployment
  - [ ] Enable automatic security updates for managed services

### 3. Configure Microsoft Office Macro Settings
- [ ] **ML1: Macro Restrictions**
  - [ ] Configure AppStream 2.0 application settings
  - [ ] Use Group Policy with AWS Directory Service
  - [ ] Implement email filtering with WorkMail
- [ ] **ML2: Enhanced Restrictions**
  - [ ] Block macro execution in WorkSpaces
  - [ ] Configure AWS WAF rules for Office documents
  - [ ] Implement content filtering in Amazon WorkDocs
- [ ] **ML3: Complete Control**
  - [ ] Use AWS Lambda for document sanitization
  - [ ] Implement sandboxing for document analysis
  - [ ] Enable threat detection in Amazon Macie

### 4. User Application Hardening
- [ ] **ML1: Basic Hardening**
  - [ ] Configure security groups restrictively
  - [ ] Implement NACLs for network isolation
  - [ ] Use AWS Web Application Firewall (WAF)
  - [ ] Enable CloudTrail for API logging
- [ ] **ML2: Enhanced Hardening**
  - [ ] Implement AWS PrivateLink for service access
  - [ ] Use VPC endpoints to avoid internet routing
  - [ ] Configure AWS Network Firewall
  - [ ] Enable VPC Flow Logs
- [ ] **ML3: Maximum Hardening**
  - [ ] Implement AWS Outposts for on-premise control
  - [ ] Use AWS Transit Gateway for network segmentation
  - [ ] Enable AWS Security Hub for centralized security

### 5. Restrict Administrative Privileges
- [ ] **ML1: IAM Best Practices**
  - [ ] Enforce MFA for all IAM users
  - [ ] Implement least privilege IAM policies
  - [ ] Use IAM roles instead of access keys
  - [ ] Regular access key rotation
  - [ ] Enable AWS CloudTrail for audit logging
- [ ] **ML2: Advanced IAM**
  - [ ] Implement AWS SSO for centralized access
  - [ ] Use Service Control Policies (SCPs)
  - [ ] Configure permission boundaries
  - [ ] Implement session policies
  - [ ] Use AWS IAM Access Analyzer
- [ ] **ML3: Zero Standing Privileges**
  - [ ] Implement just-in-time access with AWS SSO
  - [ ] Use temporary credentials exclusively
  - [ ] Configure AWS Organizations for account isolation
  - [ ] Implement break-glass procedures

### 6. Patch Operating Systems
- [ ] **ML1: OS Patching**
  - [ ] Configure Systems Manager Patch Manager
  - [ ] Use AWS-provided AMIs with latest patches
  - [ ] Implement patch groups and baselines
  - [ ] Schedule maintenance windows
- [ ] **ML2: Automated OS Updates**
  - [ ] Automate EC2 instance replacement
  - [ ] Use Auto Scaling with updated AMIs
  - [ ] Implement immutable infrastructure
  - [ ] Configure automatic kernel updates
- [ ] **ML3: Continuous OS Security**
  - [ ] Use AWS Bottlerocket for containers
  - [ ] Implement Nitro System security features
  - [ ] Enable automatic security patching
  - [ ] Use AWS Fargate for serverless containers

### 7. Multi-factor Authentication
- [ ] **ML1: Basic MFA**
  - [ ] Enable MFA for root account
  - [ ] Require MFA for IAM users
  - [ ] Configure MFA for AWS SSO
  - [ ] Use virtual MFA devices
- [ ] **ML2: Enhanced MFA**
  - [ ] Require hardware MFA for privileged users
  - [ ] Implement U2F security keys
  - [ ] Configure MFA for API access
  - [ ] Enable MFA delete for S3 buckets
- [ ] **ML3: Advanced Authentication**
  - [ ] Implement FIDO2/WebAuthn
  - [ ] Use AWS IAM Identity Center
  - [ ] Configure adaptive authentication
  - [ ] Implement continuous verification

### 8. Regular Backups
- [ ] **ML1: Basic Backups**
  - [ ] Enable automated EBS snapshots
  - [ ] Configure RDS automated backups
  - [ ] Use AWS Backup for centralized management
  - [ ] Implement cross-region backup copying
- [ ] **ML2: Enhanced Backups**
  - [ ] Configure AWS Backup vault lock
  - [ ] Implement backup encryption
  - [ ] Use point-in-time recovery for databases
  - [ ] Configure lifecycle policies
- [ ] **ML3: Immutable Backups**
  - [ ] Enable S3 Object Lock for immutability
  - [ ] Implement AWS Backup Vault Lock
  - [ ] Use glacier vault lock for archives
  - [ ] Configure compliance mode retention

## AWS-Specific Security Controls

### Account & Organization Security
- [ ] **Account Structure**
  - [ ] Implement AWS Organizations
  - [ ] Use separate accounts for prod/dev/test
  - [ ] Configure AWS Control Tower
  - [ ] Enable AWS CloudTrail organization trail
  - [ ] Implement consolidated billing

- [ ] **Service Control Policies**
  - [ ] Restrict region usage
  - [ ] Prevent disabling of security services
  - [ ] Enforce encryption requirements
  - [ ] Limit service usage
  - [ ] Require specific tags

### Network Security
- [ ] **VPC Security**
  - [ ] Use private subnets for resources
  - [ ] Implement VPC peering securely
  - [ ] Configure VPC Flow Logs
  - [ ] Use AWS PrivateLink
  - [ ] Enable DNS query logging

- [ ] **Edge Security**
  - [ ] Configure CloudFront with WAF
  - [ ] Enable AWS Shield Standard
  - [ ] Consider Shield Advanced for DDoS
  - [ ] Use Route 53 health checks
  - [ ] Implement geo-restriction

- [ ] **Network Segmentation**
  - [ ] Use multiple VPCs for isolation
  - [ ] Implement Transit Gateway
  - [ ] Configure AWS Network Firewall
  - [ ] Use security groups as firewalls
  - [ ] Implement NACLs for subnet protection

### Data Security
- [ ] **Encryption**
  - [ ] Enable S3 default encryption
  - [ ] Use KMS for key management
  - [ ] Implement envelope encryption
  - [ ] Configure EBS encryption by default
  - [ ] Enable RDS encryption

- [ ] **Data Loss Prevention**
  - [ ] Configure Amazon Macie
  - [ ] Implement S3 bucket policies
  - [ ] Use S3 Block Public Access
  - [ ] Configure bucket versioning
  - [ ] Enable MFA delete

- [ ] **Secrets Management**
  - [ ] Use AWS Secrets Manager
  - [ ] Implement automatic rotation
  - [ ] Configure Parameter Store
  - [ ] Encrypt secrets at rest
  - [ ] Audit secret access

### Compute Security
- [ ] **EC2 Security**
  - [ ] Use IMDSv2 exclusively
  - [ ] Configure EC2 Instance Connect
  - [ ] Implement Session Manager
  - [ ] Use Nitro System features
  - [ ] Enable detailed monitoring

- [ ] **Container Security**
  - [ ] Scan images in ECR
  - [ ] Use ECS with Fargate
  - [ ] Implement EKS security best practices
  - [ ] Configure task IAM roles
  - [ ] Enable container insights

- [ ] **Serverless Security**
  - [ ] Configure Lambda function permissions
  - [ ] Use Lambda layers for shared code
  - [ ] Implement API Gateway authentication
  - [ ] Configure Lambda@Edge securely
  - [ ] Enable X-Ray tracing

### Monitoring & Compliance
- [ ] **Security Monitoring**
  - [ ] Enable AWS Security Hub
  - [ ] Configure GuardDuty
  - [ ] Implement Detective for investigation
  - [ ] Use CloudWatch Logs Insights
  - [ ] Configure CloudWatch alarms

- [ ] **Compliance**
  - [ ] Enable AWS Config
  - [ ] Configure Config rules
  - [ ] Use AWS Audit Manager
  - [ ] Implement compliance frameworks
  - [ ] Generate compliance reports

- [ ] **Incident Response**
  - [ ] Configure AWS incident response
  - [ ] Enable forensic capabilities
  - [ ] Implement automated remediation
  - [ ] Configure SNS notifications
  - [ ] Document runbooks

### Cost & Resource Optimization
- [ ] **Cost Security**
  - [ ] Enable AWS Budgets alerts
  - [ ] Configure Cost Anomaly Detection
  - [ ] Implement tagging strategy
  - [ ] Use Reserved Instances/Savings Plans
  - [ ] Regular cost optimization reviews

- [ ] **Resource Management**
  - [ ] Configure Service Quotas monitoring
  - [ ] Implement AWS Compute Optimizer
  - [ ] Use Trusted Advisor checks
  - [ ] Configure auto-scaling policies
  - [ ] Regular resource cleanup

## Implementation Roadmap

### Week 1-2: Foundation
1. Set up AWS Organizations and accounts
2. Configure CloudTrail and Config
3. Enable GuardDuty and Security Hub
4. Implement IAM best practices
5. Configure MFA for all users

### Week 3-4: Network & Access
1. Design and implement VPC architecture
2. Configure security groups and NACLs
3. Set up VPN or Direct Connect
4. Implement AWS SSO
5. Configure Systems Manager

### Week 5-6: Data & Compute
1. Enable encryption everywhere
2. Configure backup strategies
3. Implement patch management
4. Set up monitoring and alerting
5. Configure WAF and Shield

### Week 7-8: Advanced Security
1. Implement compliance frameworks
2. Configure automated remediation
3. Set up incident response procedures
4. Conduct security assessment
5. Document all configurations

### Ongoing: Operations
1. Regular security reviews
2. Patch and update cycles
3. Access reviews and audits
4. Cost optimization
5. Continuous improvement

## Automation Scripts

### Enable Security Services
```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# Enable Security Hub
aws securityhub enable-security-hub

# Enable Config
aws configservice put-configuration-recorder
aws configservice start-configuration-recorder
```

### Security Audit
```bash
# Check for root account MFA
aws iam get-account-summary

# List users without MFA
aws iam list-virtual-mfa-devices

# Check for unused access keys
aws iam list-access-keys
```

## Compliance Frameworks

### Applicable Standards
- [ ] AWS Well-Architected Framework
- [ ] CIS AWS Foundations Benchmark
- [ ] PCI DSS on AWS
- [ ] HIPAA on AWS
- [ ] SOC 2 compliance
- [ ] ISO 27001/27017/27018
- [ ] NIST Cybersecurity Framework
- [ ] Australian Government ISM

## Resources

- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Security Hub](https://aws.amazon.com/security-hub/)
- [AWS Compliance Programs](https://aws.amazon.com/compliance/programs/)
- [Essential Eight on Cloud](https://www.cyber.gov.au/acsc/view-all-content/publications/cloud-security-guidance)

## Support & Training

- AWS Support Plans (Business/Enterprise)
- AWS Training and Certification
- AWS Security workshops
- AWS re:Invent security sessions
- AWS Security Blog
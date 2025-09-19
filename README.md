# 🛡️ Essential Eight Maturity Model Checklist

A comprehensive implementation checklist and toolkit for the Australian Cyber Security Centre's (ACSC) Essential Eight Maturity Model.

[![Essential Eight](https://img.shields.io/badge/Essential%20Eight-ACSC-blue)](https://www.cyber.gov.au/essential-eight)
[![Maturity Levels](https://img.shields.io/badge/Maturity%20Levels-1--3-green)](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/tysoncung/essential-eight-checklist/graphs/commit-activity)

## 📋 Quick Navigation

- [Overview](#overview)
- [Maturity Levels](#maturity-levels)
- [Implementation Checklists](#implementation-checklists)
- [Tools & Resources](#tools--resources)
- [Assessment Guide](#assessment-guide)

## 🔥 Recent Updates

- **Sept 2025**: Enhanced documentation with platform-specific guides
- **Sept 2025**: Added cloud hosting security checklists (AWS, Azure, GCP)
- **Sept 2025**: Improved badge system and maintenance tracking
- **Sept 2025**: Active community contributions welcomed

## Overview

The Essential Eight are baseline mitigation strategies recommended by the Australian Cyber Security Centre (ACSC) to help organizations protect against cyber threats. This repository provides practical checklists, tools, and implementation guides for achieving maturity levels 1, 2, and 3.

### The Essential Eight Strategies

1. **Application Control** - Prevent execution of unapproved/malicious programs
2. **Patch Applications** - Patch applications like Flash, web browsers, Microsoft Office, Java and PDF viewers
3. **Configure Microsoft Office Macro Settings** - Block macros from the internet and only allow vetted macros
4. **User Application Hardening** - Configure web browsers to block Flash, ads and Java on the internet
5. **Restrict Administrative Privileges** - Limit administrative privileges to operating systems and applications
6. **Patch Operating Systems** - Patch operating system vulnerabilities
7. **Multi-factor Authentication** - Implement MFA for all users
8. **Regular Backups** - Daily backups of important data with quarterly restoration tests

## Maturity Levels

### 🎯 Maturity Level 1 (ML1)

**Objective**: Partially mitigate attempts by adversaries using commodity tradecraft

### 🎯 Maturity Level 2 (ML2)  

**Objective**: Mostly mitigate the majority of cyber security incidents

### 🎯 Maturity Level 3 (ML3)

**Objective**: Significantly harder for adversaries to compromise systems

## Implementation Checklists

### Quick Start

1. [Complete the ML1 Checklist](checklists/ML1-CHECKLIST.md)
2. [Progress to ML2 Checklist](checklists/ML2-CHECKLIST.md)
3. [Achieve ML3 Checklist](checklists/ML3-CHECKLIST.md)

### 🆕 Infrastructure Hosting Checklists

Platform-specific security implementation guides:

- [🏢 On-Premise Hosting Security](checklists/hosting/on-premise-hosting-checklist.md)
- [☁️ AWS Cloud Hosting Security](checklists/hosting/aws-hosting-checklist.md)
- [☁️ Azure Cloud Hosting Security](checklists/hosting/azure-hosting-checklist.md)
- [☁️ Google Cloud Platform Security](checklists/hosting/gcp-hosting-checklist.md)
- [📚 Hosting Security Overview](checklists/hosting/README.md)

### Assessment Templates

- [Self-Assessment Template](templates/self-assessment.xlsx)
- [Gap Analysis Template](templates/gap-analysis.xlsx)
- [Implementation Roadmap](templates/roadmap.xlsx)

## 🔧 Tools & Resources

### Application Control Tools

- **Windows**: [AppLocker](tools/application-control.md#applocker), [Windows Defender Application Control](tools/application-control.md#wdac)
- **Linux**: [SELinux](tools/application-control.md#selinux), [AppArmor](tools/application-control.md#apparmor)
- **macOS**: [Gatekeeper](tools/application-control.md#gatekeeper), [Santa](tools/application-control.md#santa)

### Patch Management Solutions

- **Enterprise**: [WSUS](tools/patch-management.md#wsus), [SCCM](tools/patch-management.md#sccm), [Intune](tools/patch-management.md#intune)
- **Open Source**: [WSUS Offline](tools/patch-management.md#wsus-offline), [Ansible](tools/patch-management.md#ansible)

### Multi-factor Authentication

- **Cloud**: [Azure MFA](tools/mfa.md#azure-mfa), [Okta](tools/mfa.md#okta), [Duo](tools/mfa.md#duo)
- **On-Premise**: [FreeIPA](tools/mfa.md#freeipa), [privacyIDEA](tools/mfa.md#privacyidea)

### Backup Solutions

- **Enterprise**: [Veeam](tools/backup.md#veeam), [Commvault](tools/backup.md#commvault)
- **Open Source**: [Bacula](tools/backup.md#bacula), [Amanda](tools/backup.md#amanda)

## 📊 Implementation Progress Tracker

Track your organization's progress across all Essential Eight strategies:

| Strategy | ML1 | ML2 | ML3 | Tools | Documentation |
|----------|:---:|:---:|:---:|:-----:|:-------------:|
| Application Control | ⬜ | ⬜ | ⬜ | [View](tools/application-control.md) | [Guide](docs/application-control-guide.md) |
| Patch Applications | ⬜ | ⬜ | ⬜ | [View](tools/patch-management.md) | [Guide](docs/patch-applications-guide.md) |
| Configure MS Office Macros | ⬜ | ⬜ | ⬜ | [View](tools/macro-settings.md) | [Guide](docs/macro-settings-guide.md) |
| User Application Hardening | ⬜ | ⬜ | ⬜ | [View](tools/app-hardening.md) | [Guide](docs/app-hardening-guide.md) |
| Restrict Admin Privileges | ⬜ | ⬜ | ⬜ | [View](tools/privilege-management.md) | [Guide](docs/admin-privileges-guide.md) |
| Patch Operating Systems | ⬜ | ⬜ | ⬜ | [View](tools/os-patching.md) | [Guide](docs/os-patching-guide.md) |
| Multi-factor Authentication | ⬜ | ⬜ | ⬜ | [View](tools/mfa.md) | [Guide](docs/mfa-guide.md) |
| Regular Backups | ⬜ | ⬜ | ⬜ | [View](tools/backup.md) | [Guide](docs/backup-guide.md) |

## 🚀 Getting Started

### For Small Organizations (< 100 users)

1. Start with [ML1 Quick Wins](guides/small-org-ml1.md)
2. Focus on high-impact, low-cost controls
3. Use cloud-based solutions where possible

### For Medium Organizations (100-1000 users)

1. Follow the [ML2 Implementation Plan](guides/medium-org-ml2.md)
2. Implement centralized management tools
3. Establish security operations procedures

### For Large Organizations (> 1000 users)

1. Target [ML3 Compliance](guides/large-org-ml3.md)
2. Deploy enterprise-grade solutions
3. Implement continuous monitoring

## 📈 Assessment Guide

### Self-Assessment Process

1. **Current State Analysis** - Document existing controls
2. **Gap Assessment** - Identify missing controls per maturity level
3. **Risk Prioritization** - Focus on highest risk gaps
4. **Implementation Planning** - Create roadmap with timelines
5. **Continuous Monitoring** - Regular reassessment

### Key Performance Indicators (KPIs)

- Percentage of systems with application control
- Mean time to patch critical vulnerabilities
- MFA coverage across privileged accounts
- Backup success rate and restoration time

## 🔗 Additional Resources

### Official Documentation

- [ACSC Essential Eight](https://www.cyber.gov.au/essential-eight)
- [Essential Eight Maturity Model](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model)
- [Essential Eight Assessment Process Guide](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-assessment-process-guide)

### Community Resources

- [Scripts and Automation](scripts/)
- [Policy Templates](templates/policies/)
- [Training Materials](training/)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This repository is a community resource and is not officially endorsed by the Australian Cyber Security Centre (ACSC). Always refer to the official ACSC documentation for authoritative guidance.

---

**Last Updated**: 2024-01-11 | **Version**: 1.0.0

For questions or support, please [open an issue](https://github.com/tysoncung/essential-eight-checklist/issues).

# Backup and Recovery Solutions Guide

## Overview
Regular backups are the last line of defense against ransomware and data loss. This guide covers implementation from ML1 to ML3.

## Maturity Level Requirements

### ML1 - Basic Backups
- ✅ Daily backups of important data
- ✅ Offline or segregated storage
- ✅ Quarterly restoration testing

### ML2 - Enhanced Backups  
- ✅ All ML1 requirements
- ✅ Encrypted backups (at rest and transit)
- ✅ MFA-protected backup accounts
- ✅ Immutable/WORM storage
- ✅ Monthly automated testing

### ML3 - Advanced Backups
- ✅ All ML2 requirements
- ✅ Continuous data protection (CDP)
- ✅ Near-zero RPO (< 15 minutes)
- ✅ Orchestrated DR (< 1 hour RTO)
- ✅ Ransomware-proof architecture

---

## Enterprise Backup Solutions

### Veeam Backup & Replication
**Cost**: $$$ ($500-2000 per socket)
**Complexity**: Medium
**Best for**: VMware/Hyper-V environments

#### PowerShell Configuration
```powershell
# Configure Veeam backup job with immutability
Add-PSSnapin VeeamPSSnapin

# Create backup repository with immutability
$repo = Add-VBRBackupRepository -Name "Immutable-Repo" `
    -Type "AmazonS3Compatible" `
    -AmazonS3Folder "veeam-backups" `
    -EnableImmutability `
    -ImmutabilityPeriod 30

# Create backup job
$job = Add-VBRViBackupJob -Name "Critical-VMs" `
    -BackupRepository $repo `
    -Entity (Find-VBRViEntity -VMNames "DC01", "SQL01", "APP01")

# Configure encryption
Set-VBRJobAdvancedStorageOptions -Job $job `
    -EnableEncryption `
    -EncryptionKey (Get-VBREncryptionKey -Name "MasterKey")

# Set retention with GFS
Set-VBRJobAdvancedBackupOptions -Job $job `
    -RetainCycles 31 `
    -EnableGFS `
    -GFSWeeklyBackups 4 `
    -GFSMonthlyBackups 12 `
    -GFSYearlyBackups 7

# Enable backup copy job for air-gap
$copyJob = Add-VBRBackupCopyJob -Name "Offsite-Copy" `
    -Source $job `
    -Repository (Get-VBRBackupRepository -Name "Air-Gap-Repo")
```

---

### Commvault
**Cost**: $$$$ (enterprise pricing)
**Complexity**: High
**Best for**: Large heterogeneous environments

#### REST API Automation
```python
import requests
import json

class CommvaultBackup:
    def __init__(self, server, username, password):
        self.server = server
        self.token = self.authenticate(username, password)
    
    def create_backup_plan(self):
        """Create ML3-compliant backup plan"""
        plan = {
            "planName": "Essential-Eight-ML3",
            "backupDestinations": [{
                "destinationName": "Primary-Storage",
                "storagePool": "Immutable-Pool",
                "retentionPeriodDays": 30,
                "extendedRetentionRules": {
                    "weekly": 4,
                    "monthly": 12,
                    "yearly": 7
                }
            }],
            "rpo": {
                "backupFrequency": {
                    "schedulePattern": "Continuous",
                    "frequency": 15  # minutes
                }
            },
            "snapshotOptions": {
                "enableHardwareSnapshot": True,
                "enableBackupCopy": True,
                "backupCopyRPO": 60  # minutes
            },
            "securityOptions": {
                "enableEncryption": True,
                "encryptionType": "AES-256",
                "enableAnomalyDetection": True
            }
        }
        
        response = requests.post(
            f"{self.server}/api/v2/Plan",
            headers={"Authorization": f"Bearer {self.token}"},
            json=plan
        )
        return response.json()
```

---

### Azure Backup
**Cost**: $$ (pay per GB)
**Complexity**: Low
**Best for**: Azure/hybrid environments

#### ARM Template
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.RecoveryServices/vaults",
      "apiVersion": "2022-10-01",
      "name": "ML3-BackupVault",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "RS0",
        "tier": "Standard"
      },
      "properties": {
        "securitySettings": {
          "softDelete": {
            "state": "Enabled",
            "retentionDurationInDays": 30
          },
          "immutabilitySettings": {
            "state": "Enabled"
          }
        },
        "encryption": {
          "keyVaultProperties": {
            "keyUri": "[parameters('keyVaultKeyUri')]"
          },
          "infrastructureEncryption": "Enabled"
        }
      }
    },
    {
      "type": "Microsoft.RecoveryServices/vaults/backupPolicies",
      "apiVersion": "2022-10-01",
      "name": "[concat('ML3-BackupVault', '/ContinuousProtection')]",
      "properties": {
        "backupManagementType": "AzureIaasVM",
        "schedulePolicy": {
          "scheduleRunFrequency": "Hourly",
          "hourlySchedule": {
            "interval": 1,
            "scheduleWindowStartTime": "00:00",
            "scheduleWindowDuration": 24
          }
        },
        "retentionPolicy": {
          "dailySchedule": {
            "retentionTimes": ["19:00"],
            "retentionDuration": {
              "count": 30,
              "durationType": "Days"
            }
          }
        }
      }
    }
  ]
}
```

---

## Open Source Solutions

### Bacula
**Cost**: Free (enterprise support available)
**Complexity**: High
**Best for**: Linux environments

#### Configuration Script
```bash
#!/bin/bash
# Bacula configuration for ML2 compliance

# Director configuration
cat > /etc/bacula/bacula-dir.conf << EOF
Director {
  Name = bacula-dir
  Password = "$(openssl rand -base64 32)"
  Messages = Daemon
  WorkingDirectory = /var/lib/bacula
  PidDirectory = /run/bacula
  QueryFile = /etc/bacula/scripts/query.sql
  Maximum Concurrent Jobs = 20
  Heartbeat Interval = 1 minute
}

# Storage daemon with encryption
Storage {
  Name = encrypted-storage
  Address = storage.company.com
  Password = "$(openssl rand -base64 32)"
  Device = ImmutableDevice
  Media Type = File
  Maximum Concurrent Jobs = 10
  TLS Enable = yes
  TLS Require = yes
  TLS Certificate = /etc/bacula/certs/storage.crt
  TLS Key = /etc/bacula/certs/storage.key
  TLS CA Certificate File = /etc/bacula/certs/ca.crt
}

# Job definition with encryption
Job {
  Name = "CriticalDataBackup"
  Type = Backup
  Level = Incremental
  Client = client-fd
  FileSet = "Critical Data"
  Schedule = "DailyCycle"
  Storage = encrypted-storage
  Messages = Standard
  Pool = ImmutablePool
  Priority = 10
  Write Bootstrap = /var/lib/bacula/%c_%n.bsr
  Encryption Cipher = AES256
}

# Immutable pool configuration
Pool {
  Name = ImmutablePool
  Pool Type = Backup
  Recycle = no
  AutoPrune = no
  Volume Retention = 365 days
  Maximum Volume Jobs = 1
  Label Format = "Immutable-\${Year}-\${Month:p/2/0/r}-\${Day:p/2/0/r}-\${NumVols}"
  Volume Use Duration = 23 hours
  Action On Purge = Truncate
}

# Schedule for continuous protection
Schedule {
  Name = "DailyCycle"
  Run = Level=Full 1st sun at 23:05
  Run = Level=Differential 2nd-5th sun at 23:05
  Run = Level=Incremental mon-sat at 23:05
  Run = Level=Incremental hourly at 0:15
}
EOF

# Configure WORM storage
mount -o ro,remount /mnt/backup-immutable
chattr +i /mnt/backup-immutable/*
```

---

### Restic
**Cost**: Free (open source)
**Complexity**: Low
**Best for**: Cloud storage backends

#### Automated Backup Script
```bash
#!/bin/bash
# Restic backup with immutability for S3

# Initialize repository with encryption
export RESTIC_PASSWORD="$(head -c 32 /dev/urandom | base64)"
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

restic init --repo s3:s3.amazonaws.com/backup-bucket

# Backup function with integrity check
backup_with_verification() {
    local source=$1
    local tag=$2
    
    # Create backup
    restic backup "$source" \
        --repo s3:s3.amazonaws.com/backup-bucket \
        --tag "$tag" \
        --tag "$(date +%Y-%m-%d)" \
        --exclude-file=/etc/restic/excludes.txt
    
    # Verify integrity
    restic check --repo s3:s3.amazonaws.com/backup-bucket
    
    # Prune old backups (keep ML2 retention)
    restic forget \
        --repo s3:s3.amazonaws.com/backup-bucket \
        --keep-daily 30 \
        --keep-weekly 12 \
        --keep-monthly 12 \
        --keep-yearly 7 \
        --prune
}

# Enable S3 object lock for immutability
aws s3api put-object-lock-configuration \
    --bucket backup-bucket \
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",
                "Days": 30
            }
        }
    }'

# Schedule continuous backups
while true; do
    backup_with_verification "/critical/data" "continuous"
    sleep 900  # 15 minutes for ML3
done
```

---

## Ransomware Protection Strategies

### Air-Gapped Backup Implementation
```python
#!/usr/bin/env python3
import os
import subprocess
import time
from datetime import datetime

class AirGapBackup:
    def __init__(self, source_path, air_gap_device):
        self.source = source_path
        self.device = air_gap_device
        self.mount_point = "/mnt/airgap"
        
    def connect_air_gap(self):
        """Physically connect air-gap storage"""
        print(f"[{datetime.now()}] Connecting air-gap device...")
        # Enable USB port temporarily
        subprocess.run(["usbguard", "allow-device", self.device])
        time.sleep(5)
        
        # Mount with read-only after write
        subprocess.run(["mount", self.device, self.mount_point])
        return True
        
    def perform_backup(self):
        """Perform backup to air-gap storage"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.mount_point}/backup_{timestamp}"
        
        # Create encrypted backup
        subprocess.run([
            "duplicity",
            "--encrypt-key", "backup@company.com",
            "--sign-key", "backup@company.com",
            "--full-if-older-than", "7D",
            self.source,
            f"file://{backup_path}"
        ])
        
        # Write protect immediately
        subprocess.run(["mount", "-o", "remount,ro", self.mount_point])
        
    def disconnect_air_gap(self):
        """Disconnect air-gap storage"""
        print(f"[{datetime.now()}] Disconnecting air-gap device...")
        subprocess.run(["umount", self.mount_point])
        # Disable USB port
        subprocess.run(["usbguard", "block-device", self.device])
        
    def verify_backup(self):
        """Verify backup integrity"""
        subprocess.run([
            "duplicity", "verify",
            "--encrypt-key", "backup@company.com",
            f"file://{self.mount_point}/backup_*",
            self.source
        ])

# Automated air-gap backup
if __name__ == "__main__":
    backup = AirGapBackup("/critical/data", "/dev/sdb1")
    
    try:
        backup.connect_air_gap()
        backup.perform_backup()
        backup.verify_backup()
    finally:
        backup.disconnect_air_gap()
```

---

## Backup Testing Automation

### Automated Recovery Testing
```powershell
# ML2/ML3 Automated backup testing script
function Test-BackupRecovery {
    param(
        [string]$BackupJob,
        [string]$TestVM = "TestRecovery-VM",
        [string]$IsolatedNetwork = "Test-Network"
    )
    
    Write-Host "Starting automated recovery test for $BackupJob"
    
    # Get latest backup
    $latestBackup = Get-VBRBackup -Name $BackupJob | 
        Get-VBRRestorePoint | 
        Sort-Object CreationTime -Descending | 
        Select-Object -First 1
    
    if (-not $latestBackup) {
        throw "No backup found for $BackupJob"
    }
    
    # Restore to isolated environment
    $startTime = Get-Date
    Start-VBRRestoreVM -RestorePoint $latestBackup `
        -VMName $TestVM `
        -NetworkMapping @{
            "Production Network" = $IsolatedNetwork
        } `
        -PowerOn `
        -Wait
    
    $restoreTime = (Get-Date) - $startTime
    
    # Verify restored VM
    $vm = Get-VM -Name $TestVM
    $testResults = @{
        BackupJob = $BackupJob
        BackupDate = $latestBackup.CreationTime
        RestoreTime = $restoreTime
        Status = "Unknown"
        Services = @()
        DataIntegrity = $false
    }
    
    # Test VM accessibility
    if (Test-Connection -ComputerName $vm.NetworkAdapters[0].IPAddresses[0] -Quiet) {
        $testResults.Status = "Accessible"
        
        # Test critical services
        $services = @("W32Time", "DNS", "MSSQLSERVER")
        foreach ($service in $services) {
            $svcStatus = Get-Service -ComputerName $TestVM -Name $service -ErrorAction SilentlyContinue
            $testResults.Services += @{
                Name = $service
                Status = $svcStatus.Status
            }
        }
        
        # Test data integrity
        $hashBefore = Get-FileHash "\\$TestVM\c$\critical\data.db" -Algorithm SHA256
        $hashAfter = Get-Content "\\backup\hashes\data.db.sha256"
        $testResults.DataIntegrity = ($hashBefore.Hash -eq $hashAfter)
    }
    
    # Cleanup test VM
    Remove-VM -Name $TestVM -Force
    
    # Generate report
    $testResults | ConvertTo-Json | Out-File "BackupTest_$(Get-Date -Format yyyyMMdd).json"
    
    # Alert if issues found
    if ($testResults.Status -ne "Accessible" -or -not $testResults.DataIntegrity) {
        Send-MailMessage -To "backup-admin@company.com" `
            -Subject "Backup Test Failed" `
            -Body ($testResults | ConvertTo-Json) `
            -SmtpServer "smtp.company.com"
    }
    
    return $testResults
}

# Schedule monthly testing for ML2
$trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 2am
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Test-BackupRecovery.ps1"
Register-ScheduledTask -TaskName "MonthlyBackupTest" `
    -Trigger $trigger -Action $action
```

---

## 3-2-1 Backup Rule Implementation

### Configuration Example
```yaml
# Docker Compose for 3-2-1 backup strategy
version: '3.8'

services:
  # Primary backup - Local NAS
  primary-backup:
    image: restic/restic
    volumes:
      - /data:/source:ro
      - nas-backup:/backup
    environment:
      - RESTIC_REPOSITORY=/backup
      - RESTIC_PASSWORD_FILE=/run/secrets/backup_password
    command: backup /source --tag primary --host production
    
  # Secondary backup - Different media type (Cloud)
  secondary-backup:
    image: restic/restic
    volumes:
      - /data:/source:ro
    environment:
      - RESTIC_REPOSITORY=s3:s3.amazonaws.com/backup-bucket
      - AWS_ACCESS_KEY_ID=${AWS_KEY}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET}
      - RESTIC_PASSWORD_FILE=/run/secrets/backup_password
    command: backup /source --tag secondary --host production
    
  # Tertiary backup - Offsite
  offsite-backup:
    image: restic/restic
    volumes:
      - /data:/source:ro
    environment:
      - RESTIC_REPOSITORY=b2:bucketname:/backup
      - B2_ACCOUNT_ID=${B2_ACCOUNT}
      - B2_ACCOUNT_KEY=${B2_KEY}
      - RESTIC_PASSWORD_FILE=/run/secrets/backup_password
    command: backup /source --tag offsite --host production

volumes:
  nas-backup:
    driver: local
    driver_opts:
      type: nfs
      o: addr=nas.company.com,rw,vers=4
      device: ":/backup"

secrets:
  backup_password:
    file: ./backup_password.txt
```

---

## Monitoring & Alerting

### Backup Monitoring Dashboard
```python
from prometheus_client import Gauge, Counter, Histogram
import time

# Prometheus metrics
backup_last_success = Gauge('backup_last_success_timestamp', 'Last successful backup', ['job'])
backup_duration = Histogram('backup_duration_seconds', 'Backup duration', ['job'])
backup_size = Gauge('backup_size_bytes', 'Backup size', ['job'])
backup_failures = Counter('backup_failures_total', 'Total backup failures', ['job'])

def monitor_backup_job(job_name, backup_func):
    """Monitor backup job execution"""
    start_time = time.time()
    
    try:
        result = backup_func()
        
        # Update metrics
        backup_last_success.labels(job=job_name).set(time.time())
        backup_duration.labels(job=job_name).observe(time.time() - start_time)
        backup_size.labels(job=job_name).set(result['size'])
        
        return result
        
    except Exception as e:
        backup_failures.labels(job=job_name).inc()
        raise e
```

---

## Resources
- [Veeam Best Practices](https://bp.veeam.com/)
- [Azure Backup Documentation](https://docs.microsoft.com/en-us/azure/backup/)
- [Restic Documentation](https://restic.readthedocs.io/)
- [NIST Contingency Planning Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-34r1.pdf)
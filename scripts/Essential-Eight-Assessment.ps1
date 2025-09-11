<#
.SYNOPSIS
    Essential Eight Maturity Assessment Script
.DESCRIPTION
    Automated assessment of Essential Eight implementation across Windows environments
.PARAMETER MaturityLevel
    Target maturity level to assess (ML1, ML2, ML3)
.PARAMETER OutputPath
    Path for assessment report output
.EXAMPLE
    .\Essential-Eight-Assessment.ps1 -MaturityLevel ML2 -OutputPath C:\Reports
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("ML1", "ML2", "ML3")]
    [string]$MaturityLevel,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PSScriptRoot\Reports"
)

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator. Exiting..."
    exit 1
}

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$assessmentDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$results = @{
    AssessmentDate = $assessmentDate
    MaturityLevel = $MaturityLevel
    ComputerName = $env:COMPUTERNAME
    Domain = $env:USERDOMAIN
    Controls = @{}
}

Write-Host "Starting Essential Eight Assessment for $MaturityLevel" -ForegroundColor Cyan
Write-Host "=" * 60

#region Application Control Assessment
Write-Host "`nAssessing Application Control..." -ForegroundColor Yellow

function Test-ApplicationControl {
    $appControlResults = @{
        AppLockerEnabled = $false
        WDACEnabled = $false
        Policies = @()
        BlockedPaths = @()
        Issues = @()
    }
    
    # Check AppLocker
    $appLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    if ($appLockerService -and $appLockerService.Status -eq "Running") {
        $appControlResults.AppLockerEnabled = $true
        
        # Get AppLocker policies
        try {
            $policies = Get-AppLockerPolicy -Effective -ErrorAction Stop
            if ($policies.RuleCollections) {
                $appControlResults.Policies = $policies.RuleCollections | ForEach-Object {
                    @{
                        Type = $_.RuleCollectionType
                        EnforcementMode = $_.EnforcementMode
                        RuleCount = $_.Count
                    }
                }
            }
        } catch {
            $appControlResults.Issues += "Failed to retrieve AppLocker policies: $_"
        }
    } else {
        $appControlResults.Issues += "AppLocker service not running"
    }
    
    # Check WDAC
    $wdacPolicies = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -ErrorAction SilentlyContinue
    if ($wdacPolicies) {
        $appControlResults.WDACEnabled = $true
    }
    
    # Check for common bypass paths
    $bypassPaths = @(
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "C:\Windows\Temp"
    )
    
    foreach ($path in $bypassPaths) {
        if (Test-Path $path) {
            $exeFiles = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue
            if ($exeFiles) {
                $appControlResults.BlockedPaths += $path
            }
        }
    }
    
    # ML-specific checks
    switch ($MaturityLevel) {
        "ML1" {
            if (!$appControlResults.AppLockerEnabled -and !$appControlResults.WDACEnabled) {
                $appControlResults.Issues += "No application control solution detected (ML1 requirement)"
            }
        }
        "ML2" {
            if ($appControlResults.Policies.Count -eq 0) {
                $appControlResults.Issues += "No application control policies configured (ML2 requirement)"
            }
            # Check for centralized logging
            $eventLog = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 1 -ErrorAction SilentlyContinue
            if (!$eventLog) {
                $appControlResults.Issues += "AppLocker logging not configured (ML2 requirement)"
            }
        }
        "ML3" {
            # Check for driver control
            $driverPolicies = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateCIPolicy -ErrorAction SilentlyContinue
            if (!$driverPolicies) {
                $appControlResults.Issues += "Driver control not implemented (ML3 requirement)"
            }
        }
    }
    
    $appControlResults.Compliant = ($appControlResults.Issues.Count -eq 0)
    return $appControlResults
}

$results.Controls["ApplicationControl"] = Test-ApplicationControl
#endregion

#region Patch Applications Assessment
Write-Host "Assessing Patch Applications..." -ForegroundColor Yellow

function Test-PatchApplications {
    $patchResults = @{
        LastUpdateCheck = $null
        PendingUpdates = @()
        InstalledUpdates = @()
        VulnerableApps = @()
        Issues = @()
    }
    
    # Check Windows Update
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        # Get pending updates
        $searchResult = $updateSearcher.Search("IsInstalled=0")
        $patchResults.PendingUpdates = $searchResult.Updates | ForEach-Object {
            @{
                Title = $_.Title
                Severity = $_.MsrcSeverity
                Categories = ($_.Categories | ForEach-Object { $_.Name }) -join ", "
                DatePublished = $_.LastDeploymentChangeTime
            }
        }
        
        # Get installed updates
        $installedResult = $updateSearcher.Search("IsInstalled=1")
        $recentUpdates = $installedResult.Updates | Where-Object { 
            $_.LastDeploymentChangeTime -gt (Get-Date).AddDays(-30) 
        }
        $patchResults.InstalledUpdates = $recentUpdates | Select-Object -First 10 | ForEach-Object {
            @{
                Title = $_.Title
                InstalledDate = $_.LastDeploymentChangeTime
            }
        }
    } catch {
        $patchResults.Issues += "Failed to query Windows Update: $_"
    }
    
    # Check for vulnerable applications
    $vulnerableApps = @{
        "Adobe Flash" = "Adobe Flash Player"
        "Java" = "Java*"
        "Adobe Reader" = "Adobe Acrobat Reader*"
    }
    
    foreach ($app in $vulnerableApps.GetEnumerator()) {
        $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object { $_.DisplayName -like $app.Value }
        
        if ($installed) {
            $patchResults.VulnerableApps += @{
                Name = $app.Key
                Version = $installed.DisplayVersion
                InstallDate = $installed.InstallDate
            }
        }
    }
    
    # ML-specific checks
    $criticalUpdates = $patchResults.PendingUpdates | Where-Object { $_.Severity -eq "Critical" }
    
    switch ($MaturityLevel) {
        "ML1" {
            if ($vulnerableApps.ContainsKey("Adobe Flash") -and 
                ($patchResults.VulnerableApps | Where-Object { $_.Name -eq "Adobe Flash" })) {
                $patchResults.Issues += "Adobe Flash installed (ML1 requires removal)"
            }
            if ($criticalUpdates.Count -gt 0) {
                $oldUpdates = $criticalUpdates | Where-Object { 
                    $_.DatePublished -lt (Get-Date).AddDays(-30) 
                }
                if ($oldUpdates) {
                    $patchResults.Issues += "Critical updates older than 30 days pending (ML1 requirement)"
                }
            }
        }
        "ML2" {
            if ($criticalUpdates.Count -gt 0) {
                $oldUpdates = $criticalUpdates | Where-Object { 
                    $_.DatePublished -lt (Get-Date).AddDays(-14) 
                }
                if ($oldUpdates) {
                    $patchResults.Issues += "Critical updates older than 14 days pending (ML2 requirement)"
                }
            }
        }
        "ML3" {
            if ($criticalUpdates.Count -gt 0) {
                $oldUpdates = $criticalUpdates | Where-Object { 
                    $_.DatePublished -lt (Get-Date).AddDays(-2) 
                }
                if ($oldUpdates) {
                    $patchResults.Issues += "Critical updates older than 48 hours pending (ML3 requirement)"
                }
            }
        }
    }
    
    $patchResults.Compliant = ($patchResults.Issues.Count -eq 0)
    return $patchResults
}

$results.Controls["PatchApplications"] = Test-PatchApplications
#endregion

#region Microsoft Office Macro Settings Assessment
Write-Host "Assessing Microsoft Office Macro Settings..." -ForegroundColor Yellow

function Test-OfficeMacroSettings {
    $macroResults = @{
        MacroSettings = @{}
        GPOConfigured = $false
        Issues = @()
    }
    
    # Check Office macro settings in registry
    $officeVersions = @("16.0", "15.0", "14.0")  # Office 2016+, 2013, 2010
    $officeApps = @("Excel", "Word", "PowerPoint", "Outlook", "Access")
    
    foreach ($version in $officeVersions) {
        foreach ($app in $officeApps) {
            $regPath = "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security"
            if (Test-Path $regPath) {
                $settings = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($settings) {
                    $macroResults.MacroSettings["$app $version"] = @{
                        VBAWarnings = $settings.VBAWarnings
                        BlockContentExecutionFromInternet = $settings.BlockContentExecutionFromInternet
                        DisableAllWithNotification = $settings.DisableAllWithNotification
                    }
                    $macroResults.GPOConfigured = $true
                }
            }
        }
    }
    
    # ML-specific checks
    switch ($MaturityLevel) {
        "ML1" {
            if (!$macroResults.GPOConfigured) {
                $macroResults.Issues += "Office macro settings not configured via GPO (ML1 requirement)"
            }
            foreach ($app in $macroResults.MacroSettings.GetEnumerator()) {
                if ($app.Value.BlockContentExecutionFromInternet -ne 1) {
                    $macroResults.Issues += "$($app.Key): Internet macros not blocked (ML1 requirement)"
                }
            }
        }
        "ML2" {
            foreach ($app in $macroResults.MacroSettings.GetEnumerator()) {
                if (!$app.Value.ContainsKey("MacroRuntimeScanScope") -or $app.Value.MacroRuntimeScanScope -ne 2) {
                    $macroResults.Issues += "$($app.Key): Macro antivirus scanning not enabled (ML2 requirement)"
                }
            }
        }
        "ML3" {
            foreach ($app in $macroResults.MacroSettings.GetEnumerator()) {
                if ($app.Value.VBAWarnings -ne 4) {
                    $macroResults.Issues += "$($app.Key): Not configured to only allow signed macros (ML3 requirement)"
                }
            }
        }
    }
    
    $macroResults.Compliant = ($macroResults.Issues.Count -eq 0)
    return $macroResults
}

$results.Controls["OfficeMacros"] = Test-OfficeMacroSettings
#endregion

#region User Application Hardening Assessment
Write-Host "Assessing User Application Hardening..." -ForegroundColor Yellow

function Test-UserApplicationHardening {
    $hardeningResults = @{
        BrowserSettings = @{}
        JavaStatus = $null
        FlashStatus = $null
        DotNetVersions = @()
        Issues = @()
    }
    
    # Check Java installation
    $java = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "Java*" }
    $hardeningResults.JavaStatus = if ($java) { "Installed" } else { "Not Installed" }
    
    # Check Flash
    $flash = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Where-Object { $_.DisplayName -like "*Flash*" }
    $hardeningResults.FlashStatus = if ($flash) { "Installed" } else { "Not Installed" }
    
    # Check .NET Framework versions
    $dotNetVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
        Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
        Where-Object { $_.Version -match '^[0-9]+\.' } |
        Select-Object @{Name="Version"; Expression={$_.Version}}, @{Name="Path"; Expression={$_.PSPath}}
    
    $hardeningResults.DotNetVersions = $dotNetVersions | ForEach-Object { $_.Version }
    
    # Check browser settings
    # Edge
    $edgeSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
    if ($edgeSettings) {
        $hardeningResults.BrowserSettings["Edge"] = @{
            FlashBlocked = $edgeSettings.DefaultPluginsSetting -eq 2
            JavaScriptBlocked = $edgeSettings.DefaultJavaScriptSetting -eq 2
        }
    }
    
    # Chrome
    $chromeSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue
    if ($chromeSettings) {
        $hardeningResults.BrowserSettings["Chrome"] = @{
            FlashBlocked = $chromeSettings.DefaultPluginsSetting -eq 2
            SafeBrowsingEnabled = $chromeSettings.SafeBrowsingEnabled -eq 1
        }
    }
    
    # ML-specific checks
    switch ($MaturityLevel) {
        "ML1" {
            if ($hardeningResults.JavaStatus -eq "Installed") {
                $hardeningResults.Issues += "Java is installed (ML1 requires blocking in browsers)"
            }
            if ($hardeningResults.FlashStatus -eq "Installed") {
                $hardeningResults.Issues += "Flash is installed (ML1 requires removal or blocking)"
            }
            $oldDotNet = $hardeningResults.DotNetVersions | Where-Object { $_ -match "^[1-3]\." }
            if ($oldDotNet) {
                $hardeningResults.Issues += ".NET Framework 3.5 or below detected (ML1 requires removal)"
            }
        }
        "ML2" {
            # Check for PowerShell constrained language mode
            if ($ExecutionContext.SessionState.LanguageMode -ne "ConstrainedLanguage") {
                $hardeningResults.Issues += "PowerShell not in Constrained Language Mode (ML2 requirement)"
            }
        }
        "ML3" {
            # Check for application sandboxing
            $sandboxing = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -ErrorAction SilentlyContinue
            if (!$sandboxing -or $sandboxing.EnableVirtualization -ne 1) {
                $hardeningResults.Issues += "Application sandboxing not enabled (ML3 requirement)"
            }
        }
    }
    
    $hardeningResults.Compliant = ($hardeningResults.Issues.Count -eq 0)
    return $hardeningResults
}

$results.Controls["UserApplicationHardening"] = Test-UserApplicationHardening
#endregion

#region Restrict Administrative Privileges Assessment
Write-Host "Assessing Administrative Privileges..." -ForegroundColor Yellow

function Test-AdminPrivileges {
    $adminResults = @{
        LocalAdmins = @()
        DomainAdmins = @()
        PrivilegedGroups = @()
        LAPSEnabled = $false
        Issues = @()
    }
    
    # Get local administrators
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminResults.LocalAdmins = $localAdmins | ForEach-Object {
            @{
                Name = $_.Name
                Type = $_.ObjectClass
                Source = $_.PrincipalSource
            }
        }
    } catch {
        $adminResults.Issues += "Failed to enumerate local administrators: $_"
    }
    
    # Check for LAPS
    $laps = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
    if ($laps -and $laps.AdmPwdEnabled -eq 1) {
        $adminResults.LAPSEnabled = $true
    }
    
    # Get domain admins (if domain joined)
    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        try {
            $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
            $adminResults.DomainAdmins = $domainAdmins | ForEach-Object {
                @{
                    Name = $_.Name
                    Type = $_.ObjectClass
                }
            }
        } catch {
            # Not domain admin or AD module not available
            $adminResults.Issues += "Unable to query domain admins (may require AD module or permissions)"
        }
    }
    
    # Check for privileged groups
    $privilegedGroups = @(
        "Backup Operators",
        "Server Operators",
        "Account Operators",
        "Print Operators"
    )
    
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            if ($members) {
                $adminResults.PrivilegedGroups += @{
                    Group = $group
                    MemberCount = $members.Count
                }
            }
        } catch {
            # Group doesn't exist or access denied
        }
    }
    
    # ML-specific checks
    switch ($MaturityLevel) {
        "ML1" {
            if ($adminResults.LocalAdmins.Count -gt 5) {
                $adminResults.Issues += "More than 5 local administrators detected (review for ML1)"
            }
            if (!$adminResults.LAPSEnabled) {
                $adminResults.Issues += "LAPS not enabled (recommended for ML1)"
            }
        }
        "ML2" {
            if (!$adminResults.LAPSEnabled) {
                $adminResults.Issues += "LAPS not enabled (ML2 requirement)"
            }
            # Check for separate admin accounts
            $standardUsers = $adminResults.LocalAdmins | Where-Object { $_.Name -notmatch "admin|adm" }
            if ($standardUsers) {
                $adminResults.Issues += "Standard user accounts with admin privileges detected (ML2 requires separate admin accounts)"
            }
        }
        "ML3" {
            # Check for PAW (Privileged Access Workstation) indicators
            $pawIndicator = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PAW" -ErrorAction SilentlyContinue
            if (!$pawIndicator) {
                $adminResults.Issues += "No PAW configuration detected (ML3 requirement)"
            }
        }
    }
    
    $adminResults.Compliant = ($adminResults.Issues.Count -eq 0)
    return $adminResults
}

$results.Controls["AdminPrivileges"] = Test-AdminPrivileges
#endregion

#region Patch Operating Systems Assessment
Write-Host "Assessing Operating System Patches..." -ForegroundColor Yellow

function Test-OSPatches {
    $osResults = @{
        OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
        OSBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
        LastBootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        LastPatchDate = $null
        PendingReboot = $false
        Issues = @()
    }
    
    # Get last installed patch
    $patches = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($patches) {
        $osResults.LastPatchDate = $patches.InstalledOn
    }
    
    # Check for pending reboot
    $pendingReboot = $false
    $rebootKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    
    foreach ($key in $rebootKeys) {
        if (Test-Path $key) {
            $pendingReboot = $true
            break
        }
    }
    $osResults.PendingReboot = $pendingReboot
    
    # Check OS support status
    $buildNumber = [int]$osResults.OSBuild
    $supportedBuilds = @{
        "19045" = "Windows 10 22H2"  # Supported until 2025
        "22621" = "Windows 11 22H2"  # Supported until 2024
        "22631" = "Windows 11 23H2"  # Current
    }
    
    if ($buildNumber -lt 19045) {
        $osResults.Issues += "Operating system version is out of support"
    }
    
    # ML-specific checks
    $daysSinceLastPatch = if ($osResults.LastPatchDate) { 
        (Get-Date) - $osResults.LastPatchDate 
    } else { 
        [TimeSpan]::MaxValue 
    }
    
    switch ($MaturityLevel) {
        "ML1" {
            if ($daysSinceLastPatch.Days -gt 30) {
                $osResults.Issues += "No OS patches installed in last 30 days (ML1 requirement)"
            }
        }
        "ML2" {
            if ($daysSinceLastPatch.Days -gt 14) {
                $osResults.Issues += "No OS patches installed in last 14 days (ML2 requirement)"
            }
        }
        "ML3" {
            if ($daysSinceLastPatch.Days -gt 2) {
                $osResults.Issues += "No OS patches installed in last 48 hours (ML3 requirement)"
            }
        }
    }
    
    $osResults.Compliant = ($osResults.Issues.Count -eq 0)
    return $osResults
}

$results.Controls["OSPatches"] = Test-OSPatches
#endregion

#region Multi-factor Authentication Assessment
Write-Host "Assessing Multi-factor Authentication..." -ForegroundColor Yellow

function Test-MFA {
    $mfaResults = @{
        AzureADJoined = $false
        ConditionalAccessPolicies = @()
        VPNMFARequired = $false
        Issues = @()
    }
    
    # Check Azure AD join status
    $dsregStatus = dsregcmd /status
    if ($dsregStatus -match "AzureAdJoined\s*:\s*YES") {
        $mfaResults.AzureADJoined = $true
        
        # Note: Actual CA policy check would require Graph API access
        $mfaResults.Issues += "Manual verification required: Check Azure AD Conditional Access policies"
    }
    
    # Check for VPN clients with MFA
    $vpnClients = @{
        "Cisco AnyConnect" = "HKLM:\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client"
        "FortiClient" = "HKLM:\SOFTWARE\Fortinet\FortiClient"
        "GlobalProtect" = "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect"
    }
    
    foreach ($client in $vpnClients.GetEnumerator()) {
        if (Test-Path $client.Value) {
            $mfaResults.VPNMFARequired = "Unknown - $($client.Key) detected"
        }
    }
    
    # Check for RADIUS/NPS with MFA extensions
    $npsRole = Get-WindowsFeature -Name NPAS -ErrorAction SilentlyContinue
    if ($npsRole -and $npsRole.InstallState -eq "Installed") {
        $mfaExtension = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AzureMFA" -ErrorAction SilentlyContinue
        if ($mfaExtension) {
            $mfaResults.VPNMFARequired = $true
        }
    }
    
    # ML-specific checks
    switch ($MaturityLevel) {
        "ML1" {
            if (!$mfaResults.VPNMFARequired -and !$mfaResults.AzureADJoined) {
                $mfaResults.Issues += "MFA not detected for remote access (ML1 requirement)"
            }
        }
        "ML2" {
            $mfaResults.Issues += "Manual verification required: Ensure MFA is phishing-resistant (no SMS)"
        }
        "ML3" {
            $mfaResults.Issues += "Manual verification required: Ensure passwordless authentication is implemented"
        }
    }
    
    $mfaResults.Compliant = ($mfaResults.Issues.Count -eq 0)
    return $mfaResults
}

$results.Controls["MFA"] = Test-MFA
#endregion

#region Regular Backups Assessment
Write-Host "Assessing Backup Configuration..." -ForegroundColor Yellow

function Test-Backups {
    $backupResults = @{
        WindowsBackupEnabled = $false
        LastBackupDate = $null
        BackupSchedule = $null
        VSS = $false
        ThirdPartyBackup = @()
        Issues = @()
    }
    
    # Check Windows Server Backup
    $wbPolicy = Get-WBPolicy -ErrorAction SilentlyContinue
    if ($wbPolicy) {
        $backupResults.WindowsBackupEnabled = $true
        $backupResults.BackupSchedule = $wbPolicy.Schedule
        
        $lastBackup = Get-WBJob -Previous 1 -ErrorAction SilentlyContinue
        if ($lastBackup) {
            $backupResults.LastBackupDate = $lastBackup.EndTime
        }
    }
    
    # Check Volume Shadow Copy
    $vss = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
    if ($vss) {
        $backupResults.VSS = $true
    }
    
    # Check for third-party backup solutions
    $backupSoftware = @{
        "Veeam" = "*Veeam*"
        "Acronis" = "*Acronis*"
        "Veritas" = "*Backup Exec*"
        "Commvault" = "*Commvault*"
    }
    
    foreach ($software in $backupSoftware.GetEnumerator()) {
        $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object { $_.DisplayName -like $software.Value }
        
        if ($installed) {
            $backupResults.ThirdPartyBackup += $software.Key
        }
    }
    
    # Check for backup to cloud
    $oneDrive = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive" -ErrorAction SilentlyContinue
    if ($oneDrive -and $oneDrive.UserFolder) {
        $backupResults.ThirdPartyBackup += "OneDrive"
    }
    
    # ML-specific checks
    $daysSinceLastBackup = if ($backupResults.LastBackupDate) { 
        (Get-Date) - $backupResults.LastBackupDate 
    } else { 
        [TimeSpan]::MaxValue 
    }
    
    switch ($MaturityLevel) {
        "ML1" {
            if (!$backupResults.WindowsBackupEnabled -and $backupResults.ThirdPartyBackup.Count -eq 0) {
                $backupResults.Issues += "No backup solution detected (ML1 requirement)"
            }
            if ($daysSinceLastBackup.Days -gt 1) {
                $backupResults.Issues += "No backup in last 24 hours (ML1 requires daily backups)"
            }
        }
        "ML2" {
            $backupResults.Issues += "Manual verification required: Ensure backups are encrypted"
            $backupResults.Issues += "Manual verification required: Ensure backup accounts have MFA"
        }
        "ML3" {
            $backupResults.Issues += "Manual verification required: Ensure continuous data protection is configured"
            $backupResults.Issues += "Manual verification required: Verify RTO < 1 hour"
        }
    }
    
    $backupResults.Compliant = ($backupResults.Issues.Count -eq 0)
    return $backupResults
}

$results.Controls["Backups"] = Test-Backups
#endregion

#region Generate Report
Write-Host "`nGenerating Assessment Report..." -ForegroundColor Green

$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Essential Eight Assessment Report - $MaturityLevel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .control { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .compliant { border-left: 5px solid #27ae60; }
        .non-compliant { border-left: 5px solid #e74c3c; }
        .issue { background-color: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        .score { font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Essential Eight Assessment Report</h1>
        <p>Maturity Level: $MaturityLevel | Date: $assessmentDate | System: $($results.ComputerName)</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
"@

$compliantControls = ($results.Controls.Values | Where-Object { $_.Compliant }).Count
$totalControls = $results.Controls.Count
$complianceScore = [math]::Round(($compliantControls / $totalControls) * 100, 2)

$htmlReport += @"
        <p class="score">Compliance Score: $complianceScore%</p>
        <p>Compliant Controls: $compliantControls / $totalControls</p>
        <table>
            <tr>
                <th>Control</th>
                <th>Status</th>
                <th>Issues</th>
            </tr>
"@

foreach ($control in $results.Controls.GetEnumerator()) {
    $status = if ($control.Value.Compliant) { "✅ Compliant" } else { "❌ Non-Compliant" }
    $issueCount = $control.Value.Issues.Count
    $htmlReport += @"
            <tr>
                <td>$($control.Key)</td>
                <td>$status</td>
                <td>$issueCount issue(s)</td>
            </tr>
"@
}

$htmlReport += @"
        </table>
    </div>
    
    <h2>Detailed Findings</h2>
"@

foreach ($control in $results.Controls.GetEnumerator()) {
    $cssClass = if ($control.Value.Compliant) { "control compliant" } else { "control non-compliant" }
    $htmlReport += @"
    <div class="$cssClass">
        <h3>$($control.Key)</h3>
"@
    
    if ($control.Value.Issues.Count -gt 0) {
        $htmlReport += "<h4>Issues Found:</h4>"
        foreach ($issue in $control.Value.Issues) {
            $htmlReport += "<div class='issue'>$issue</div>"
        }
    }
    
    # Add control-specific details
    $htmlReport += "<h4>Details:</h4><pre>"
    $htmlReport += ($control.Value | ConvertTo-Json -Depth 3 | Out-String)
    $htmlReport += "</pre>"
    
    $htmlReport += "</div>"
}

$htmlReport += @"
</body>
</html>
"@

# Save reports
$htmlPath = Join-Path $OutputPath "EssentialEight_Assessment_${MaturityLevel}_${assessmentDate}.html"
$jsonPath = Join-Path $OutputPath "EssentialEight_Assessment_${MaturityLevel}_${assessmentDate}.json"

$htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8

Write-Host "`nAssessment Complete!" -ForegroundColor Green
Write-Host "HTML Report: $htmlPath"
Write-Host "JSON Report: $jsonPath"
Write-Host "`nCompliance Score: $complianceScore%" -ForegroundColor Cyan

# Open HTML report
Start-Process $htmlPath
#endregion
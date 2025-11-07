<#
.SYNOPSIS
    Windows Fixer - Comprehensive System Health & Repair Utility
.DESCRIPTION
    One-click automation for SFC, DISM, disk checks, memory diagnostics, and safe registry repairs.
    Generates a detailed, stylish HTML report. Run with Administrator privileges.
.PARAMETER AutoMemoryTest
    Automatically schedule memory test and reboot after completion
.PARAMETER IncludeRegistryFixes
    Include safe, reversible registry repairs (creates restore point & backups first)
.EXAMPLE
    .\WindowsFixer.ps1
    .\WindowsFixer.ps1 -IncludeRegistryFixes
    .\WindowsFixer.ps1 -IncludeRegistryFixes -AutoMemoryTest:$true
.NOTES
    GitHub: https://github.com/pranjalchaubey
    Created by Pranjal Chaubey
#>
param(
    [switch]$AutoMemoryTest = $false,
    [switch]$IncludeRegistryFixes = $false
)

# ============================================================================
# INITIALIZATION & PREREQUISITE CHECKS
# ============================================================================
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Detect OneDrive Documents folder (falls back to local Documents if OneDrive not found)
$documentsPath = if (Test-Path "$env:USERPROFILE\OneDrive\Documents") {
    "$env:USERPROFILE\OneDrive\Documents"
} else {
    [Environment]::GetFolderPath("MyDocuments")
}

$logDir = "$documentsPath\WindowsFixer"
$logFile = "$logDir\WindowsFixer_Log_$timestamp.txt"
$htmlReport = "$logDir\WindowsFixer_Report_$timestamp.html"
$registryBackupDir = "$logDir\RegistryBackup_$timestamp"

# Create log directory
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# ============================================================================
# AUTOMATIC CLEANUP OF OLD FILES
# ============================================================================
function Remove-OldReports {
    param(
        [string]$Path,
        [int]$DaysToKeep = 7
    )
    
    if (Test-Path $Path) {
        $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
        $removedCount = 0
        
        # Clean old log files
        Get-ChildItem -Path $Path -Filter "WindowsFixer_Log_*.txt" -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate } | 
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $removedCount++ }
        
        # Clean old HTML reports
        Get-ChildItem -Path $Path -Filter "WindowsFixer_Report_*.html" -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate } | 
            ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $removedCount++ }
        
        # Clean old registry backups (these are large!)
        Get-ChildItem -Path $Path -Filter "RegistryBackup_*" -Directory -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate } | 
            ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; $removedCount++ }
        
        if ($removedCount -gt 0) {
            Write-Host "[Cleanup] Removed $removedCount old file(s) older than $DaysToKeep days" -ForegroundColor DarkGray
        }
    }
}

# Run cleanup (keeps last 7 days)
Remove-OldReports -Path $logDir -DaysToKeep 7

Start-Transcript -Path $logFile -Append | Out-Null

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (!(Test-IsAdmin)) {
    Write-Host "⚠️  Administrator rights required. Restarting elevated..." -ForegroundColor Yellow
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($AutoMemoryTest) { $arguments += " -AutoMemoryTest" }
    if ($IncludeRegistryFixes) { $arguments += " -IncludeRegistryFixes" }
    Start-Process PowerShell -ArgumentList $arguments -Verb RunAs
    exit
}

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host "  WINDOWS FIXER - SYSTEM REPAIR UTILITY" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Started: $timestamp" -ForegroundColor Gray
Write-Host "Report will be saved to: $htmlReport`n" -ForegroundColor Gray

function Write-Status {
    param($Message, $Type = "Info")
    $color = switch ($Type) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Task" { "Magenta" }
        "Registry" { "DarkCyan" }
    }
    Write-Host "[$Type] $Message" -ForegroundColor $color
}

function Start-CommandWithTimeout {
    param(
        [string]$Command,
        [string]$Arguments,
        [int]$TimeoutMinutes = 60
    )
    $job = Start-Job -ScriptBlock {
        param($cmd, $cmdArgs)
        & $cmd $cmdArgs.Split(' ') 2>&1
    } -ArgumentList $Command, $Arguments
    
    $result = Wait-Job $job -Timeout ($TimeoutMinutes * 60) | Receive-Job
    Remove-Job $job -Force
    return $result
}

$results = @{}

# ============================================================================
# PREFLIGHT CHECKS
# ============================================================================
Write-Status "Performing pre-flight checks..." "Task"
$preflight = @{}

$pendingReboot = (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or `
                 (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or `
                 ($null -ne (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue))
$preflight.PendingReboot = $pendingReboot

$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
$preflight.DiskSpaceGB = $freeSpaceGB

Write-Status "Pending reboot: $pendingReboot | Free space: $freeSpaceGB GB" $(if($pendingReboot -or $freeSpaceGB -lt 10){"Warning"}else{"Success"})

# ============================================================================
# STEP 1: SFC (FIRST PASS)
# ============================================================================
Write-Status "Running SFC Scan (First Pass)..." "Task"
$sfcResult = Start-CommandWithTimeout -Command "sfc.exe" -Arguments "/scannow"
$results.SFCFirstPass = @{
    Completed = $sfcResult -join "`n"
    IssuesFound = $sfcResult -match "corrupt|could not|errors"
}

# ============================================================================
# STEP 2: DISM IMAGE RESTORATION
# ============================================================================
Write-Status "Running DISM Image Restore..." "Task"
$dismResult = Start-CommandWithTimeout -Command "dism.exe" -Arguments "/Online /Cleanup-Image /RestoreHealth" -TimeoutMinutes 45
$results.DISM = @{
    Completed = $dismResult -join "`n"
    Success = $dismResult -match "The operation completed successfully"
}

# ============================================================================
# STEP 3: SFC (SECOND PASS)
# ============================================================================
Write-Status "Running SFC Scan (Second Pass)..." "Task"
$sfcResult2 = Start-CommandWithTimeout -Command "sfc.exe" -Arguments "/scannow"
$results.SFCSecondPass = @{
    Completed = $sfcResult2 -join "`n"
    IssuesFound = $sfcResult2 -match "corrupt|could not|errors"
}

# ============================================================================
# STEP 4: DISM COMPONENT CLEANUP
# ============================================================================
Write-Status "Cleaning up DISM Components..." "Task"
dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null

# ============================================================================
# STEP 5: DISK HEALTH CHECKS
# ============================================================================
Write-Status "Checking Disk Health..." "Task"
$wmicResult = wmic diskdrive get status, model, size /format:list
$results.WMICDisk = $wmicResult

try {
    $smartDisks = Get-CimInstance -Namespace "Root\WMI" -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    $results.SMART = foreach ($disk in $smartDisks) {
        [PSCustomObject]@{
            Model = (Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {$_.Index -eq $disk.InstanceName.Split('\')[-1]}).Model
            PredictFailure = $disk.PredictFailure
            Reason = $disk.Reason
        }
    }
} catch {
    Write-Status "SMART check not available" "Warning"
}

# ============================================================================
# STEP 6: TEMP FILE CLEANUP
# ============================================================================
Write-Status "Cleaning temporary files..." "Task"
$tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:SystemRoot\Logs\CBS")
$cleanedSize = 0
foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        $before = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        $after = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $cleanedSize += ($before - $after)
    }
}
$cleanedGB = [math]::Round($cleanedSize / 1GB, 2)

# ============================================================================
# STEP 7: EVENT LOG ANALYSIS
# ============================================================================
Write-Status "Analyzing recent critical events..." "Task"
$days = 7
$criticalEvents = Get-EventLog -LogName System -EntryType Error -After (Get-Date).AddDays(-$days) -ErrorAction SilentlyContinue |
                  Select-Object -First 20 TimeGenerated, Source, Message
$results.EventLog = @{
    Events = $criticalEvents
    Count = $criticalEvents.Count
}

# ============================================================================
# STEP 8: SAFE REGISTRY REPAIRS (OPT-IN)
# ============================================================================
if ($IncludeRegistryFixes) {
    Write-Host "`n==============================================" -ForegroundColor Red
    Write-Host "  REGISTRY REPAIR MODULE (OPT-IN ENABLED)" -ForegroundColor Red
    Write-Host "==============================================" -ForegroundColor Red
    
    Write-Warning "Registry fixes will create a restore point and backups first."
    Write-Host "This will take extra 5-10 minutes.`n" -ForegroundColor Yellow
    
    # Create System Restore Point
    try {
        Write-Status "Creating system restore point..." "Registry"
        Checkpoint-Computer -Description "Windows Fixer - Registry Repairs" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Status "Restore point created successfully" "Success"
    } catch {
        Write-Status "Could not create restore point: $($_.Exception.Message)" "Warning"
        Write-Status "Proceeding with registry backups only..." "Warning"
    }
    
    # Backup critical registry hives
    try {
        Write-Status "Backing up registry hives..." "Registry"
        New-Item -ItemType Directory -Path $registryBackupDir -Force | Out-Null
        reg export HKLM\SYSTEM "$registryBackupDir\HKLM_SYSTEM.reg" /y | Out-Null
        reg export HKLM\SOFTWARE "$registryBackupDir\HKLM_SOFTWARE.reg" /y | Out-Null
        reg export HKLM\COMPONENTS "$registryBackupDir\HKLM_COMPONENTS.reg" /y | Out-Null
        Write-Status "Registry backups saved to: $registryBackupDir" "Success"
    } catch {
        Write-Status "Registry backup failed: $($_.Exception.Message)" "Error"
        Write-Status "Skipping registry fixes due to backup failure" "Error"
        $IncludeRegistryFixes = $false
    }
    
    if ($IncludeRegistryFixes) {
        $registryResults = @{}
        
        # WMI Repository Reset
        Write-Status "Checking WMI health..." "Registry"
        try {
            Get-CimInstance -ClassName Win32_Process | Select-Object -First 1 | Out-Null
            Write-Status "WMI repository is healthy" "Success"
            $registryResults.WMI = "Healthy - No action taken"
        } catch {
            Write-Status "WMI repository corrupted, resetting..." "Warning"
            try {
                Stop-Service winmgmt -Force -ErrorAction Stop
                $resetResult = winmgmt /resetRepository
                Start-Service winmgmt -ErrorAction Stop
                Write-Status "WMI repository reset successful" "Success"
                $registryResults.WMI = "Reset completed - $resetResult"
            } catch {
                Write-Status "WMI reset failed: $($_.Exception.Message)" "Error"
                $registryResults.WMI = "Failed - $($_.Exception.Message)"
            }
        }
        
        # Windows Update Components Reset
        Write-Status "Resetting Windows Update components..." "Registry"
        $wuServices = @("wuauserv", "cryptSvc", "bits", "msiserver")
        try {
            foreach ($service in $wuServices) { Stop-Service -Name $service -Force -ErrorAction SilentlyContinue }
            
            # Remove old backups if they exist
            if (Test-Path "$env:SystemRoot\SoftwareDistribution.old") {
                Remove-Item -Path "$env:SystemRoot\SoftwareDistribution.old" -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path "$env:SystemRoot\System32\catroot2.old") {
                Remove-Item -Path "$env:SystemRoot\System32\catroot2.old" -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Now rename the current folders
            if (Test-Path "$env:SystemRoot\SoftwareDistribution") {
                Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force -ErrorAction Stop
            }
            if (Test-Path "$env:SystemRoot\System32\catroot2") {
                Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force -ErrorAction Stop
            }
            
            foreach ($service in $wuServices) { Start-Service -Name $service -ErrorAction SilentlyContinue }
            Write-Status "Windows Update components reset" "Success"
            $registryResults.WindowsUpdate = "Reset successful"
        } catch {
            Write-Status "Windows Update reset failed: $($_.Exception.Message)" "Error"
            $registryResults.WindowsUpdate = "Failed - $($_.Exception.Message)"
        }
        
        # Winsock/TCP-IP Stack Reset
        Write-Status "Resetting Winsock and TCP/IP stack..." "Registry"
        try {
            netsh winsock reset | Out-Null
            netsh int ip reset | Out-Null
            ipconfig /flushdns | Out-Null
            Write-Status "Network stack reset complete (reboot required)" "Success"
            $registryResults.NetworkStack = "Reset successful - Reboot needed"
        } catch {
            Write-Status "Network stack reset failed: $($_.Exception.Message)" "Error"
            $registryResults.NetworkStack = "Failed - $($_.Exception.Message)"
        }
        
        # Font Cache Rebuild
        Write-Status "Rebuilding font cache..." "Registry"
        try {
            Stop-Service -Name "FontCache" -Force -ErrorAction SilentlyContinue
            $fontCachePaths = @("$env:LocalAppData\Microsoft\Windows\Fonts", "$env:SystemRoot\System32\FNTCACHE.DAT")
            foreach ($path in $fontCachePaths) {
                if (Test-Path $path) { Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue }
            }
            Start-Service -Name "FontCache" -ErrorAction SilentlyContinue
            Write-Status "Font cache rebuilt" "Success"
            $registryResults.FontCache = "Rebuilt successfully"
        } catch {
            Write-Status "Font cache rebuild failed: $($_.Exception.Message)" "Warning"
            $registryResults.FontCache = "Partially failed - $($_.Exception.Message)"
        }
        
        # Registry Health Scan (READ-ONLY)
        Write-Status "Scanning registry for common issues..." "Registry"
        $readonlyScan = @{}
        
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        $orphanedApps = foreach ($path in $uninstallPaths) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Get-ItemProperty | 
            Where-Object { $_.DisplayName -eq $null -and $_.PSChildName -match '^[0-9a-fA-F\-]{36}$' } |
            Select-Object @{N="Path";E={$path}}, @{N="GUID";E={$_.PSChildName}}
        }
        $readonlyScan.OrphanedUninstallEntries = $orphanedApps
        
        $startupPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        $startupItems = foreach ($path in $startupPaths) {
            if (Test-Path $path) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -eq $null } | 
                Select-Object @{N="Path";E={$path}}, @{N="Name";E={$_.PSObject.Properties.Name}}, @{N="Command";E={$_.PSObject.Properties.Value}}
            }
        }
        $readonlyScan.StartupPrograms = $startupItems
        
        Write-Status "Found $($orphanedApps.Count) orphaned entries and $($startupItems.Count) startup items" "Info"
        $registryResults.ReadOnlyScan = $readonlyScan
    }
}

# ============================================================================
# STEP 9: GENERATE COMPREHENSIVE HTML REPORT
# ============================================================================
Write-Status "Generating detailed health report..." "Task"

$reportDate = Get-Date -Format "dd MMM yyyy HH:mm:ss"
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
$systemInfo = @{
    OS = $os.Caption
    Build = [System.Environment]::OSVersion.Version.ToString()
    Uptime = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    LastBoot = $os.LastBootUpTime
}

# Convert registry results to HTML sections
$registryHtml = if ($IncludeRegistryFixes -and $registryResults) {
    @"
        <h2>8. Registry Repair Operations</h2>
        <div class="section registry-section">
            <p><strong>Restore Point:</strong> Created before operations</p>
            <p><strong>Registry Backups:</strong> $registryBackupDir</p>
            <table>
                <tr><th>Operation</th><th>Status</th><th>Details</th></tr>
                <tr><td>WMI Repository</td><td class='$(if($registryResults.WMI -match "success"){"success"}else{"error"})'>$($registryResults.WMI)</td><td>Resets corrupted WMI that causes mystery issues</td></tr>
                <tr><td>Windows Update</td><td class='$(if($registryResults.WindowsUpdate -match "success"){"success"}else{"error"})'>$($registryResults.WindowsUpdate)</td><td>Resets WU components and cache</td></tr>
                <tr><td>Network Stack</td><td class='$(if($registryResults.NetworkStack -match "success"){"success"}else{"error"})'>$($registryResults.NetworkStack)</td><td>Resets Winsock and TCP/IP</td></tr>
                <tr><td>Font Cache</td><td class='$(if($registryResults.FontCache -match "success"){"success"}else{"warning"})'>$($registryResults.FontCache)</td><td>Fixes UI glitches and missing icons</td></tr>
            </table>
        </div>

        <h2>9. Registry Health Scan (Read-Only)</h2>
        <div class="section">
            <p>These issues were detected but NOT automatically fixed:</p>
            
            <h3>Orphaned Uninstall Entries: $($readonlyScan.OrphanedUninstallEntries.Count)</h3>
            $(if($readonlyScan.OrphanedUninstallEntries.Count -gt 0){
                "<table><tr><th>Registry Path</th><th>Application GUID</th></tr>"
                foreach($item in $readonlyScan.OrphanedUninstallEntries){
                    "<tr><td>$($item.Path)</td><td>$($item.GUID)</td></tr>"
                }
                "</table>"
            }else{
                "<p>✅ No orphaned entries found</p>"
            })
            
            <h3>Startup Programs: $($readonlyScan.StartupPrograms.Count)</h3>
            $(if($readonlyScan.StartupPrograms.Count -gt 0){
                "<table><tr><th>Registry Path</th><th>Program Name</th><th>Command</th></tr>"
                foreach($item in $readonlyScan.StartupPrograms){
                    "<tr><td>$($item.Path)</td><td>$($item.Name)</td><td>$($item.Command)</td></tr>"
                }
                "</table>"
            }else{
                "<p>✅ No startup items detected</p>"
            })
            <p class="tip">
                <strong>💡 Tip:</strong> Review these entries manually. Only delete if you're certain they're unwanted.
            </p>
        </div>
"@
} else {
    "<h2>8. Registry Repair Operations</h2><div class='section'><p>⚠️ Not performed (use -IncludeRegistryFixes to enable)</p></div>"
}

# Final HTML Report Generation
$reportHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Fixer Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=IBM+Plex+Mono:wght@400&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-bright: #f0f6fc;
            --accent-glow: #00cfff;
            --success-glow: #00f0b0;
            --warning-glow: #ffdd00;
            --error-glow: #ff3366;
            --font-body: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: 'IBM Plex Mono', monospace;
        }

        * { box-sizing: border-box; }

        body {
            font-family: var(--font-body);
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: #484f58; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #58a6ff; }

        .container {
            max-width: 1100px;
            margin: 20px auto;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            padding: 40px;
        }

        h1, h2, h3 {
            font-family: var(--font-body);
            color: var(--text-bright);
            letter-spacing: -0.5px;
            font-weight: 700;
        }

        h1 {
            font-size: 2.5em;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-top: 0;
            margin-bottom: 25px;
            font-weight: 700;
        }

        h2 {
            font-size: 1.75em;
            margin-top: 50px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            font-weight: 600;
        }

        h3 {
            font-size: 1.25em;
            margin-top: 25px;
            color: var(--text-bright);
            font-weight: 600;
        }

        p { margin-bottom: 15px; font-size: 1em; }

        .summary {
            font-size: 1.1em;
            padding: 25px;
            background: rgba(0, 207, 255, 0.05);
            border: 1px solid var(--accent-glow);
            border-radius: 12px;
        }
        .summary h3 {
            margin-top: 0;
            color: var(--accent-glow);
        }
        .summary ul {
            list-style: none;
            padding-left: 0;
            margin: 0;
        }
        .summary li {
            padding: 5px 0;
            position: relative;
            font-size: 1.05em;
        }

        .section {
            margin: 20px 0;
            padding: 20px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            transition: all 0.3s ease;
            border-left-width: 4px;
        }
        
        .section.success { border-left-color: var(--success-glow); }
        .section.warning { border-left-color: var(--warning-glow); }
        .section.error { border-left-color: var(--error-glow); }
        .registry-section { border-left-color: #8e24aa; }

        pre {
            background: #010409;
            color: var(--success-glow);
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.95em;
            border: 1px solid var(--border-color);
        }

        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 20px 0;
            font-size: 0.95em;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: rgba(255, 255, 255, 0.03);
            color: var(--accent-glow);
            font-family: var(--font-body);
            font-weight: 600;
            font-size: 1.05em;
        }
        tr { background-color: var(--card-bg); }
        tbody tr:hover { background-color: rgba(255, 255, 255, 0.02); }
        tr:last-child td { border-bottom: none; }

        .tip {
            background: rgba(255, 221, 0, 0.05);
            padding: 12px 18px;
            border: 1px solid var(--warning-glow);
            border-radius: 8px;
            color: var(--warning-glow);
        }
        
        .footer-text {
            margin-top: 40px;
            text-align: center;
            color: #484f58;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Windows Fixer Report</h1>
        <p><strong>Generated:</strong> $reportDate</p>
        <p><strong>System:</strong> $($systemInfo.OS) | Build: $($systemInfo.Build) | Uptime: $($systemInfo.Uptime)</p>
        
        <div class="summary">
            <h3>Executive Summary</h3>
            <ul>
                <li>✅ Free Disk Space: $($preflight.DiskSpaceGB) GB</li>
                <li>$(if($preflight.PendingReboot){"⚠️"}else{"✅"}) Pending Reboot: $($preflight.PendingReboot)</li>
                <li>$(if($results.SFCFirstPass.IssuesFound){"⚠️"}else{"✅"}) SFC First Pass: $(if($results.SFCFirstPass.IssuesFound){"Issues Detected"}else{"Clean"})</li>
                <li>$(if($results.SFCSecondPass.IssuesFound){"⚠️"}else{"✅"}) SFC Second Pass: $(if($results.SFCSecondPass.IssuesFound){"Issues Detected"}else{"Clean"})</li>
                <li>$(if($results.DISM.Success){"✅"}else{"⚠️"}) DISM Restore: $(if($results.DISM.Success){"Successful"}else{"Review Required"})</li>
                <li>$(if($IncludeRegistryFixes){"✅"}else{"⚠️"}) Registry Fixes: $(if($IncludeRegistryFixes){"Enabled & Completed"}else{"Not Run"})</li>
                <li>⚠️ Critical Events (7 days): $($results.EventLog.Count)</li>
            </ul>
        </div>

        <h2>1. Preflight Checks</h2>
        <div class="section $(if($preflight.PendingReboot -or $preflight.DiskSpaceGB -lt 10){'warning'}else{'success'})">
            <p><strong>Pending Reboot:</strong> $($preflight.PendingReboot)</p>
            <p><strong>Free Space:</strong> $($preflight.DiskSpaceGB) GB</p>
        </div>

        <h2>2. SFC Scans</h2>
        <div class="section">
            <h3>First Pass Results:</h3>
            <pre>$($results.SFCFirstPass.Completed)</pre>
            <h3>Second Pass Results:</h3>
            <pre>$($results.SFCSecondPass.Completed)</pre>
        </div>

        <h2>3. DISM Restore Health</h2>
        <div class="section $(if($results.DISM.Success){'success'}else{'warning'})">
            <pre>$($results.DISM.Completed)</pre>
        </div>

        <h2>4. Disk Health Analysis</h2>
        <div class="section">
            <h3>WMIC Status:</h3>
            <pre>$($results.WMICDisk)</pre>
            $(if($results.SMART){
            "<h3>SMART Details:</h3>
            <table>
                <thead>
                    <tr><th>Disk Model</th><th>Predict Failure</th><th>Reason</th></tr>
                </thead>
                <tbody>
                $($results.SMART | ForEach-Object {
                    "<tr><td>$($_.Model)</td><td>$($_.PredictFailure)</td><td>$($_.Reason)</td></tr>"
                } | Out-String)
                </tbody>
            </table>"
            })
        </div>

        <h2>5. Recent Critical Events (Last 7 Days)</h2>
        <div class="section $(if($results.EventLog.Count -gt 10){'warning'}else{'success'})">
            <p>Total Critical Events: $($results.EventLog.Count)</p>
            $(if($results.EventLog.Count -gt 0){
            "<table>
                <thead>
                    <tr><th>Time</th><th>Source</th><th>Message</th></tr>
                </thead>
                <tbody>
                $($results.EventLog.Events | ForEach-Object {
                    "<tr><td>$($_.TimeGenerated)</td><td>$($_.Source)</td><td>$($_.Message)</td></tr>"
                } | Out-String)
                </tbody>
            </table>"
            })
        </div>

        <h2>6. Cleanup Summary</h2>
        <div class="section success">
            <p>Temporary files cleaned: $cleanedGB GB</p>
            <p>DISM component store cleaned</p>
        </div>

        $registryHtml

        <p class="footer-text">
            Log file: $logFile<br>
            <em>Windows Fixer v1.0</em><br>
            Created by <a href="https://github.com/pranjalchaubey" target="_blank" style="color: var(--accent-glow); text-decoration: none;">Pranjal Chaubey</a>
        </p>
    </div>
</body>
</html>
"@

$reportHtml | Out-File -FilePath $htmlReport -Encoding utf8
Write-Status "Report saved to: $htmlReport" "Success"

# ============================================================================
# STEP 10: MEMORY DIAGNOSTIC HANDLING
# ============================================================================
Write-Status "Memory Diagnostic" "Task"

if ($AutoMemoryTest) {
    Write-Status "Scheduling memory test and rebooting in 30 seconds..." "Warning"
    Write-Host "Press CTRL+C to abort!" -ForegroundColor Red
    Start-Sleep -Seconds 30
    & $env:SystemRoot\System32\mdsched.exe /s
    Restart-Computer -Force
} else {
    Write-Status "Launching Windows Memory Diagnostic tool..." "Info"
    Write-Host "Please select 'Restart now and check for problems' when prompted." -ForegroundColor Yellow
    Write-Host "Report has been saved to: $htmlReport" -ForegroundColor Cyan
    Start-Process mdsched.exe
    
    $shortcutPath = "$env:USERPROFILE\Desktop\Windows Fixer - Memory Test.lnk"
    if (!(Test-Path $shortcutPath)) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:SystemRoot\System32\mdsched.exe"
        $shortcut.Save()
        Write-Status "Created desktop shortcut: 'Windows Fixer - Memory Test'" "Success"
    }
}

Stop-Transcript | Out-Null
Start-Process $htmlReport
Write-Status "Windows Fixer completed successfully!" "Success"
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
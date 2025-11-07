<#
.SYNOPSIS
    Comprehensive Windows System Health & Repair Script
.DESCRIPTION
    Automates SFC, DISM, disk checks, memory diagnostics and generates a detailed report.
    Run with Administrator privileges.
.PARAMETER AutoMemoryTest
    Automatically schedule memory test and reboot after completion
.EXAMPLE
    .\Repair-WindowsSystem.ps1
    .\Repair-WindowsSystem.ps1 -AutoMemoryTest:$true
#>
param(
    [switch]$AutoMemoryTest = $false
)

# ============================================================================
# INITIALIZATION & PREREQUISITE CHECKS
# ============================================================================
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logDir = "$env:USERPROFILE\Documents\WindowsSystemHealth"
$logFile = "$logDir\RepairLog_$timestamp.txt"
$htmlReport = "$logDir\HealthReport_$timestamp.html"

# Create log directory if it doesn't exist
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Start transcript logging
Start-Transcript -Path $logFile -Append | Out-Null

# Check for Administrator rights
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (!(Test-IsAdmin)) {
    Write-Host "⚠️  Administrator rights required. Restarting elevated..." -ForegroundColor Yellow
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($AutoMemoryTest) { $arguments += " -AutoMemoryTest" }
    Start-Process PowerShell -ArgumentList $arguments -Verb RunAs
    exit
}

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host "  WINDOWS SYSTEM HEALTH & REPAIR UTILITY" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Started: $timestamp" -ForegroundColor Gray
Write-Host "Report will be saved to: $htmlReport`n" -ForegroundColor Gray

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
function Write-Status {
    param($Message, $Type = "Info")
    $color = switch ($Type) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Task" { "Magenta" }
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

# Results collection
$results = @{}

# ============================================================================
# STEP 1: PREFLIGHT CHECKS
# ============================================================================
Write-Status "Performing pre-flight checks..." "Task"
$preflight = @{}

# Check pending reboot
$pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -or
                 Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -or
                 (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue)
$preflight.PendingReboot = $pendingReboot
Write-Status "Pending reboot detected: $pendingReboot" $(if($pendingReboot){"Warning"}else{"Success"})

# Check disk space
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
$preflight.DiskSpaceGB = $freeSpaceGB
Write-Status "Free space on C:\: $freeSpaceGB GB" $(if($freeSpaceGB -lt 10){"Warning"}else{"Success"})

# ============================================================================
# STEP 2: SYSTEM FILE CHECKER (FIRST PASS)
# ============================================================================
Write-Status "Running SFC Scan (First Pass)..." "Task"
Write-Host "This may take 15-30 minutes..." -ForegroundColor Gray
$sfcResult = Start-CommandWithTimeout -Command "sfc.exe" -Arguments "/scannow"
$results.SFCFirstPass = @{
    Completed = $sfcResult -join "`n"
    IssuesFound = $sfcResult -match "corrupt|could not|errors"
}
Write-Status "SFC First Pass Complete" $(if($results.SFCFirstPass.IssuesFound){"Warning"}else{"Success"})

# ============================================================================
# STEP 3: DISM IMAGE RESTORATION
# ============================================================================
Write-Status "Running DISM Image Restore..." "Task"
Write-Host "This may take 20-40 minutes. Internet connection recommended..." -ForegroundColor Gray
$dismResult = Start-CommandWithTimeout -Command "dism.exe" -Arguments "/Online /Cleanup-Image /RestoreHealth" -TimeoutMinutes 45
$results.DISM = @{
    Completed = $dismResult -join "`n"
    IssuesFound = $dismResult -match "Error|failed|corruption"
    Success = $dismResult -match "The operation completed successfully"
}
Write-Status "DISM Restore Complete" $(if($results.DISM.Success){"Success"}else{"Warning"})

# ============================================================================
# STEP 4: SYSTEM FILE CHECKER (SECOND PASS)
# ============================================================================
Write-Status "Running SFC Scan (Second Pass)..." "Task"
$sfcResult2 = Start-CommandWithTimeout -Command "sfc.exe" -Arguments "/scannow"
$results.SFCSecondPass = @{
    Completed = $sfcResult2 -join "`n"
    IssuesFound = $sfcResult2 -match "corrupt|could not|errors"
}
Write-Status "SFC Second Pass Complete" $(if($results.SFCSecondPass.IssuesFound){"Warning"}else{"Success"})

# ============================================================================
# STEP 5: DISM COMPONENT CLEANUP (ADDED VALUE)
# ============================================================================
Write-Status "Cleaning up DISM Components..." "Task"
dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
Write-Status "Component Cleanup Completed" "Success"

# ============================================================================
# STEP 6: DISK HEALTH CHECKS
# ============================================================================
Write-Status "Checking Disk Health..." "Task"

# WMIC check (your original)
$wmicResult = wmic diskdrive get status, model, size /format:list
$results.WMICDisk = $wmicResult

# SMART check for more detail (added value)
try {
    $smartDisks = Get-CimInstance -Namespace "Root\WMI" -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    $smartStatus = foreach ($disk in $smartDisks) {
        [PSCustomObject]@{
            Model = (Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {$_.Index -eq $disk.InstanceName.Split('\')[-1]}).Model
            PredictFailure = $disk.PredictFailure
            Reason = $disk.Reason
        }
    }
    $results.SMART = $smartStatus
    Write-Status "SMART Status Retrieved" "Success"
} catch {
    Write-Status "SMART check not available on this system" "Warning"
}

# ============================================================================
# STEP 7: TEMP FILE CLEANUP (ADDED VALUE)
# ============================================================================
Write-Status "Cleaning temporary files..." "Task"
$tempPaths = @(
    $env:TEMP,
    "$env:SystemRoot\Temp",
    "$env:SystemRoot\Logs\CBS"
)
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
Write-Status "Cleaned $cleanedGB GB of temporary files" "Success"

# ============================================================================
# STEP 8: EVENT LOG ANALYSIS (ADDED VALUE)
# ============================================================================
Write-Status "Analyzing recent critical events..." "Task"
$days = 7
$criticalEvents = Get-EventLog -LogName System -EntryType Error -After (Get-Date).AddDays(-$days) -ErrorAction SilentlyContinue |
                  Select-Object -First 20 TimeGenerated, Source, Message
$results.EventLog = @{
    Events = $criticalEvents
    Count = $criticalEvents.Count
}
Write-Status "Found $($criticalEvents.Count) critical events in last $days days" $(if($criticalEvents.Count -gt 10){"Warning"}else{"Success"})

# ============================================================================
# STEP 9: GENERATE COMPREHENSIVE HTML REPORT
# ============================================================================
Write-Status "Generating detailed health report..." "Task"

$reportDate = Get-Date -Format "dd MMM yyyy HH:mm:ss"
$systemInfo = @{
    OS = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    Build = [System.Environment]::OSVersion.Version.ToString()
    Uptime = (Get-Uptime).ToString("d\d\ h\h\ m\m")
    LastBoot = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
}

$reportData = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows System Health Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #0078d4; background: #f9f9f9; }
        .success { border-left-color: #0f0; background: #e8f5e9; }
        .warning { border-left-color: #ff9800; background: #fff3e0; }
        .error { border-left-color: #f44336; background: #ffebee; }
        pre { background: #263238; color: #aed581; padding: 15px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0078d4; color: white; }
        .summary { font-size: 1.1em; padding: 15px; background: #e3f2fd; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Windows System Health Report</h1>
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
                <tr><th>Disk Model</th><th>Predict Failure</th><th>Reason</th></tr>
                $(foreach($disk in $results.SMART){
                    `"<tr><td>$($disk.Model)</td><td>$($disk.PredictFailure)</td><td>$($disk.Reason)</td></tr>`"
                })
            </table>"
            })
        </div>

        <h2>5. Recent Critical Events (Last 7 Days)</h2>
        <div class="section $(if($results.EventLog.Count -gt 10){'warning'}else{'success'})">
            <p>Total Critical Events: $($results.EventLog.Count)</p>
            $(if($results.EventLog.Count -gt 0){
            "<table>
                <tr><th>Time</th><th>Source</th><th>Message</th></tr>
                $(foreach($evt in $results.EventLog.Events){
                    `"<tr><td>$($evt.TimeGenerated)</td><td>$($evt.Source)</td><td>$($evt.Message)</td></tr>`"
                })
            </table>"
            })
        </div>

        <h2>6. Cleanup Summary</h2>
        <div class="section success">
            <p>Temporary files cleaned: $cleanedGB GB</p>
            <p>DISM component store cleaned</p>
        </div>

        <p style="margin-top: 40px; text-align: center; color: #666;">
            Log file: $logFile<br>
            <em>Report generated by Windows System Health Utility</em>
        </p>
    </div>
</body>
</html>
"@

$reportData | Out-File -FilePath $htmlReport -Encoding utf8
Write-Status "Report saved to: $htmlReport" "Success"

# ============================================================================
# STEP 10: MEMORY DIAGNOSTIC HANDLING
# ============================================================================
Write-Status "Memory Diagnostic" "Task"

if ($AutoMemoryTest) {
    Write-Status "Scheduling memory test and rebooting in 30 seconds..." "Warning"
    Write-Host "Press CTRL+C to abort!" -ForegroundColor Red
    Start-Sleep -Seconds 30
    
    # Schedule memory test on next boot
    & $env:SystemRoot\System32\mdsched.exe /s
    
    # Force reboot
    Restart-Computer -Force
} else {
    Write-Status "Launching Windows Memory Diagnostic tool..." "Info"
    Write-Host "Please select 'Restart now and check for problems' when prompted." -ForegroundColor Yellow
    Write-Host "Report has been saved to: $htmlReport" -ForegroundColor Cyan
    Write-Host "You can run the memory test later if needed." -ForegroundColor Gray
    
    # Just open the GUI
    Start-Process mdsched.exe
    
    # Also create a desktop shortcut for easy access
    $shortcutPath = "$env:USERPROFILE\Desktop\Run Memory Test.lnk"
    if (!(Test-Path $shortcutPath)) {
        $WScriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$env:SystemRoot\System32\mdsched.exe"
        $shortcut.Save()
        Write-Status "Created desktop shortcut: 'Run Memory Test'" "Success"
    }
}

Stop-Transcript | Out-Null

# Open the report
Start-Process $htmlReport

Write-Status "All operations complete! Review the report for details." "Success"
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
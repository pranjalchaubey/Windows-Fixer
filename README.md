# Windows Fixer 🔧

**One-Click Windows System Repair & Health Check Utility**

Windows Fixer is a powerful yet safe PowerShell script that automates common Windows troubleshooting tasks. It fixes system corruption, cleans junk files, checks your disk health, and generates a beautiful, easy-to-read report—all with a single click. No technical knowledge required!

![Windows Fixer Demo](https://via.placeholder.com/800x450?text=Windows+Fixer+Demo)

---

## What Does Windows Fixer Do?

Windows Fixer performs these operations automatically:

| Feature | What It Fixes | Time Required |
|---------|---------------|---------------|
| **SFC Scan** | Corrupt system files | 15-30 minutes |
| **DISM Repair** | Broken Windows image | 20-40 minutes |
| **Disk Health Check** | Failing hard drive/SSD | 1 minute |
| **Temp File Cleanup** | Junk files taking up space | 2-5 minutes |
| **Memory Test** | Detect bad RAM modules | Requires reboot |
| **Registry Fixes** | WMI, Windows Update, Network issues | 5-10 minutes (optional) |

**Total Time:** ~10 minutes (plus optional memory test)

---

## 🛡️ Safety First

Windows Fixer is designed to be **safer than manual repairs**:

- ✅ **Creates restore points** before making changes
- ✅ **Backs up registry** automatically  
- ✅ **Read-only scans** detect but don't delete suspicious items
- ✅ **Uses only Microsoft-approved commands**
- ✅ **Opt-in for registry changes**—won't touch registry unless you ask

---

## Prerequisites

**What you need:**
- Windows 10 or Windows 11 (64-bit)
- Administrator access to your computer
- At least 5 GB of free space on C: drive
- Internet connection (recommended for DISM repair)

**How to check your Windows version:**
1. Press `Win + R`
2. Type `winver`
3. Press Enter
4. You should see "Windows 10" or "Windows 11"

---

## Installation (3 Steps)

### Step 1: Download the Script

Download **`WindowsFixer.ps1`** from the GitHub repository:
- Click the green "Code" button → "Download ZIP"
- Extract the ZIP file to your **Desktop**

**Result:** You should see `WindowsFixer.ps1` on your Desktop.

---

### Step 2: Allow PowerShell Scripts (One-Time Setup)

Windows blocks scripts by default for security. Let's allow this one:

1. **Right-click the Start button** → Select **"Windows PowerShell (Admin)"** or **"Windows Terminal (Admin)"**
2. Copy this command (select it, then press `Ctrl+C`):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
   ```
3. Right-click in the PowerShell window to paste, then press Enter

**What this does:** Allows you to run local scripts like Windows Fixer while still blocking malicious ones from the internet.

---

### Step 3: Create Your 1-Click Shortcut

This lets you run Windows Fixer by double-clicking an icon:

1. Right-click on your Desktop → New → Shortcut
2. **Location:** Paste this exact text:
   ```
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\Desktop\WindowsFixer.ps1"
   ```
3. **Name:** Type `Windows Fixer` and click Finish
4. Right-click your new Windows Fixer shortcut → Properties
5. Click "Advanced..." → ✓ Run as administrator → OK → OK

**You're done!** A "Windows Fixer" icon now lives on your Desktop.

---

## How to Use Windows Fixer

### Method 1: Simple Repair (Recommended for First-Time Users)

1. Double-click the **Windows Fixer** desktop shortcut
2. Click "Yes" when User Account Control asks for permission
3. The script will run automatically—don't close the window!
4. When finished, a beautiful dark-mode report opens in your browser
5. Review the report, then restart your computer to apply all fixes

---

### Method 2: Full Repair (Includes Registry Fixes)

Use this if your system has persistent weird issues:

1. Right-click the Start button → Windows PowerShell (Admin)
2. Type this command and press Enter:
   ```powershell
   & "$env:USERPROFILE\Desktop\WindowsFixer.ps1" -IncludeRegistryFixes
   ```
3. Wait for completion and review the report
4. Restart your computer when prompted

**What this adds:** Fixes Windows Update, network stack, font cache, and WMI issues.

---

### Method 3: Unattended Mode (Full + Auto Memory Test)

⚠️ **Only use this when you're ready to reboot!**

1. Right-click the Start button → Windows PowerShell (Admin)
2. Type this command:
   ```powershell
   & "$env:USERPROFILE\Desktop\WindowsFixer.ps1" -IncludeRegistryFixes -AutoMemoryTest:$true
   ```
3. The script will automatically reboot after 30 seconds to run memory test
4. After reboot, memory test runs (takes 10-30 minutes)
5. Windows starts normally and shows the results

---

## Understanding Your Report

After running Windows Fixer, you'll see an HTML report like this:

### Executive Summary

At the top, you'll see a quick checklist:

- ✅ **Green** = Good/Was Fixed
- ⚠️ **Yellow** = Warning/Attention Needed
- ❌ **Red** = Error/Requires Manual Action

### Key Sections Explained

#### 1. Preflight Checks
- **Pending Reboot:** If "True," restart needed before fixes work properly
- **Free Space:** Should be >10 GB. Low space causes wonky behavior

#### 2. SFC Scans (System File Checker)
Shows if corrupt Windows files were found and repaired. Run twice for thoroughness.

#### 3. DISM Restore Health
Repairs the Windows image itself. If this fails, you may need installation media.

#### 4. Disk Health Analysis
- **WMIC Status:** Should say "OK" for all drives
- **SMART Details:** If "Predict Failure" is True, backup immediately—drive is dying

#### 5. Critical Events
Lists recent system errors. More than 10 in 7 days indicates deeper issues.

#### 6. Cleanup Summary
Shows how many GB of junk files were removed.

#### 7. Registry Repairs (If Enabled)
Shows what registry fixes were applied. Always creates restore point first.

#### 8. Registry Health Scan (Read-Only)
Lists orphaned apps and startup programs. Review before manually deleting.

---

## Troubleshooting

### Problem: "Script cannot be loaded because running scripts is disabled"
**Solution:** Run the Step 2 command again.

### Problem: "Access denied" or "Administrator rights required"
**Solution:** Make sure your shortcut has "Run as administrator" checked (see Installation Step 3).

### Problem: DISM fails with "Error: 0x800f081f"
**Solution:** You need a Windows installation media for repair. This is rare—usually means deep system damage.

### Problem: Report doesn't open automatically
**Solution:** Find it manually at:
```
Documents\WindowsFixer\WindowsFixer_Report_[date]_[time].html
```

### Problem: System seems slower after running
**Solution:** This is normal for the first few minutes. Windows is rebuilding indexes and caches. Restart if it persists.

---

## Frequently Asked Questions

### Q: Is this safe? Will I lose my files?
**A:** Yes, it's safe! Windows Fixer only repairs system components and cleans temporary files. Your documents, photos, and programs are never touched.

### Q: How often should I run this?
**A:** Run it when your system feels "wonky"—slowdowns, glitches, or weird errors. As preventive maintenance, once per month is fine.

### Q: Can I use my computer while it runs?
**A:** Light use (web browsing) is okay, but avoid heavy tasks like gaming or video editing. The script needs full system access.

### Q: The memory test didn't run. What happened?
**A:** By default, it only opens the memory tool. Use `-AutoMemoryTest:$true` for automatic reboot, or click "Restart now" when prompted.

### Q: What if something goes wrong?
**A:** Windows Fixer creates a system restore point before changes. To undo:
1. Press `Win + R` → Type `rstrui` → Press Enter
2. Select the restore point named "Windows Fixer - Registry Repairs"
3. Follow the wizard to restore

### Q: Do I need to pay for this?
**A:** No! Windows Fixer is completely free and open-source.

### Q: Will this work on Windows 7/8?
**A:** No. Windows Fixer is designed for Windows 10 and 11 only.

---

## Uninstalling / Cleanup

Windows Fixer doesn't install anything, so removal is simple:

1. Delete the `WindowsFixer.ps1` file from your Desktop
2. Delete the Windows Fixer desktop shortcut
3. Delete the `Documents\WindowsFixer` folder (contains old reports)

---

## Support & Contributing

- **Found a bug?** Open an issue on GitHub:  
  https://github.com/pranjalchaubey/Windows-Fixer/issues
- **Want to improve?** Submit a pull request!
- **Questions?** Discussions are open on GitHub.

---

## License

This project is licensed under the MIT License. See LICENSE file for details.

**Disclaimer:** This tool is provided as-is. While thoroughly tested, use at your own risk. Always maintain backups of important data.

---

<div align="center">

⭐ **If Windows Fixer helped you, please star the repository!** ⭐

</div>

---

## Repository Structure

```
Windows-Fixer/
├── src/
│   └── WindowsFixer.ps1      # Main script
├── README.md                 # This file
├── LICENSE                   # MIT License
```

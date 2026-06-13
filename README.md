# Security Research Tool Protection Suite

PowerShell scripts for managing Windows Defender exclusions, file integrity
monitoring, and out-of-band alerting for known-signature security research tools.

Built for a Windows 11 home lab running OSCP / CPTS study and penetration
testing research. Designed to apply the principle of least privilege at the
Defender exclusion layer and integrate file integrity monitoring into a
notification pipeline via the WiFi Pineapple Pager.

---

## Architecture

```
Add-TrustedFileExclusion.ps1
    If file already has a Defender exclusion:
        SHA256 displayed - prompt to keep or remove exclusion
        Y: exclusion kept, registry updated
        N: exclusion removed
    Otherwise:
        File-specific Defender exclusion added before download
        SHA256 computed, file deleted, exclusion removed
        Hash displayed with source cross-reference link - user verifies against official release
        Y/N prompt - N exits cleanly, nothing left on disk
        Y: re-adds exclusion, re-downloads, verifies hash matches approved value
            Read-only flag set (TOCTOU mitigation)
            Hash registered in trusted_hashes.json

Watch-FileIntegrity.ps1 (persistent, runs at startup)
    Polls trusted_hashes.json every 60 seconds
    Computes SHA256 of each registered file
        Hash changed  -> INTEGRITY VIOLATION (urgent)
        File deleted  -> FILE DELETED (urgent)
            Pager TCP alert via soar_listener.sh
            ntfy push notification to phone

Confirm-FileProtection.ps1
    6-point spot-check of all protection components
```

---

## Prerequisites

- **Windows 11, PowerShell 5.1+, elevated session** (`#Requires -RunAsAdministrator`)
- **WiFi Pineapple Pager** with `soar_listener.sh` running (for Pager alerts)
- **ntfy** self-hosted on Mac Mini via Tailscale (for phone push notifications)
- **Tailscale** enrolled on both Aurora and Pager for stable IP addressing

---

## Scripts

### `Add-TrustedFileExclusion.ps1`

Downloads or locates a file, computes its hash for source verification,
then applies a file-specific Defender exclusion and integrity monitoring.

**Parameters:**
| Parameter | Required | Description |
|---|---|---|
| `-FilePath` | Yes | Full path to the file. Used as download destination if -URL provided. Accepts a directory for direct file URLs — filename derived from URL. ZIP URLs require a full file path including the target filename to extract. |
| `-URL` | No | Download URL. GitHub blob/tree URLs converted to raw automatically. ZIP archives supported — script extracts the target filename from inside the archive. |
| `-ExpectedHash` | No | Optional safety check. Verifies hash matches a previously known value before prompting. |
| `-PagerIP` | No | Tailscale IP of the Pager - omit to skip notification |
| `-PagerPort` | No | Pager netcat listener port (default: 9999) |

**What it does:**

If the file already has a Defender exclusion (previously trusted):
1. Computes SHA256 and displays it
2. Prompts: "File already has a Defender exclusion. Y to continue trusting, N to remove"
   - **Y**: exclusion kept, registry and read-only updated
   - **N**: exclusion removed

Otherwise (new file or URL download):
1. If `-URL` provided: adds exclusions, downloads file
   - **ZIP URL**: exclusions added for temp path, destination directory, and target file before download. ZIP extracted to temp, target filename located inside archive, copied to `-FilePath`, temp files cleaned up
   - **Direct URL**: exclusion added for target path before download
2. Computes SHA256 hash
3. Deletes file and removes exclusion pending confirmation
4. Displays hash with link to cross-reference against known values
5. Prompts: "Does this hash match the official release? (Y/N)"
   - **N**: exits cleanly - no file on disk, no exclusion
   - **Y**: re-adds exclusion, re-downloads, verifies hash matches approved value, sets read-only, writes to hash registry, optionally notifies Pager

**Usage:**
```powershell
# File already on disk
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

# Download from URL to specific path (GitHub blob or raw URLs accepted)
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"

# Download from ZIP - script finds the target filename inside the archive
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\mimikatz.exe" -URL "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"

# Download to directory - filename derived from URL
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"

# With Pager notification
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -PagerIP "100.x.x.x"

# Re-download with safety check against previously known hash
.\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -ExpectedHash "AD9E4D..."
```

**Source verification:**

Search by hash, not URL — URL analysis caches results and may reflect a file
from months or years ago. Security research tools will show detections; this is
expected and not disqualifying. What matters is hash consistency: does this hash
match the known value from the official repository or release page? If it does,
the binary is authentic. Answer Y only after confirming against the official source.

Raw GitHub URL format (blob URL to raw URL):
```
github.com/{user}/{repo}/blob/{branch}/{path}
                 to
raw.githubusercontent.com/{user}/{repo}/{branch}/{path}
```

GitHub blob URLs are converted automatically — you can paste either format.

**Note on directory exclusions:**
This script adds a file-path exclusion, not a directory exclusion. A directory
exclusion creates a trusted execution zone any file benefits from - including
files an attacker places there. A file-path exclusion trusts exactly one artifact.

---

### `Watch-FileIntegrity.ps1`

Polls registered file paths every 60 seconds and fires Pager and ntfy alerts
when a file's SHA256 no longer matches its registered value.

Detection is hash-based, not event-based. File replacement removes any SACL on
the original object, making Event 4663 detection unreliable. Hash polling detects
changes regardless of how the file was modified or replaced.

**Parameters:**
| Parameter | Required | Description |
|---|---|---|
| `-PagerIP` | Yes | Tailscale IP of the Pager |
| `-PagerPort` | No | Pager netcat listener port (default: 9999) |
| `-NtfyURL` | Yes | URL of the self-hosted ntfy instance |
| `-RegistryPath` | No | Path to trusted_hashes.json (default: ProgramData\SecurityBaseline) |
| `-IntervalSeconds` | No | Poll interval in seconds (default: 60) |

**Usage:**
```powershell
.\Watch-FileIntegrity.ps1 `
    -PagerIP "100.x.x.x" `
    -NtfyURL "http://100.x.x.x:80/security-alerts"
```

**Run at startup (recommended):**
```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -File C:\Scripts\Watch-FileIntegrity.ps1 -PagerIP 100.x.x.x -NtfyURL http://100.x.x.x:80/security-alerts"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "FileIntegrityWatcher" `
    -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

**Alert format:**
```
INTEGRITY VIOLATION
File:     nanodump.x64.exe
Path:     F:\nanodump.x64.exe
Expected: AD9E4D...
Actual:   B7F2A1...
Time:     2026-06-07 14:32:15
```

---

### `Confirm-FileProtection.ps1`

Six-point verification of all protection components on a registered file.
Run after `Add-TrustedFileExclusion.ps1` to confirm everything is in place.

**Usage:**
```powershell
.\Confirm-FileProtection.ps1 -FilePath "F:\nanodump.x64.exe"
```

**Checks:**
1. File exists on disk
2. Drive is NTFS
3. Read-only flag is set
4. Defender exclusion is present for this exact path
5. DACL restricts Users group to Read — no Write path for standard users
6. Hash registry entry exists
7. Current hash matches registry value

---

### `soar_listener.sh` (Pager side)

Runs on the WiFi Pineapple Pager. Listens on TCP port 9999 for messages from
the Aurora notification pipeline and triggers DuckyScript ALERT + VIBRATE.

**Installation:**
```sh
scp soar_listener.sh root@<pager-ip>:/root/scripts/
ssh root@<pager-ip> "chmod +x /root/scripts/soar_listener.sh"
```

Add to `/etc/rc.local` to run at boot:
```sh
/root/scripts/soar_listener.sh &
```

**Message routing:**
- `EXCLUSION_ADDED:` prefix uses the dedicated exclusion alert payload
- All other messages use the generic alert handler

---

## LSASS Dump Test Scripts

Three batch files for testing credential access detection against a live LSASS process.
These illustrate the distinction between signature detection and behavioral detection.

### `lsass_nanodump.bat`

**Works** when `Add-TrustedFileExclusion.ps1` has been run against the nanodump binary.
nanodump carries a known malicious signature — Defender quarantines it on sight without
the exclusion. With the file-specific exclusion in place, signature detection is bypassed
and nanodump executes cleanly because its technique does not trigger behavioral detection.
The exclusion is the only thing standing between nanodump and a successful LSASS dump.

```cmd
# Default output - saves to script directory
.\lsass_nanodump.bat

# Custom output path
.\lsass_nanodump.bat "F:\dumps\"
.\lsass_nanodump.bat "F:\dumps\lsass.dmp"
```

### `lsass_procdump.bat`

**Does not work** regardless of any file exclusion. Procdump is a legitimate Sysinternals
tool — it has no malicious signature and Defender will never quarantine it. The block comes
from behavioral detection, which fires the moment procdump opens a handle to the LSASS PID.
A file-specific exclusion has no effect on behavioral detection — the two systems are
independent. The exclusion prevents quarantine; behavioral detection operates at runtime
and cannot be bypassed by an exclusion.

```cmd
# Default output - procdump names the file automatically
.\lsass_procdump.bat

# Custom output path
.\lsass_procdump.bat "F:\dumps\"
.\lsass_procdump.bat "F:\dumps\lsass.dmp"
```

### `lsass_comsvcs.bat`

**Does not work** for the same reason as procdump. Uses `rundll32.exe` to call `MiniDump`
via `comsvcs.dll` — a Windows system file. There is no standalone executable to quarantine,
so signature detection never fires. The block is behavioral: Defender detects the MiniDump
call targeting the LSASS PID and denies it at the handle acquisition stage, identical to
the procdump block.

```cmd
.\lsass_comsvcs.bat
.\lsass_comsvcs.bat "F:\dumps\"
.\lsass_comsvcs.bat "F:\dumps\lsass.dmp"
```

### Summary

| Script | Signature blocked | Behavioral blocked | Works with exclusion |
|---|---|---|---|
| nanodump | Yes — quarantined without exclusion | No | Yes |
| procdump | No — legitimate tool | Yes — LSASS PID access denied | No |
| comsvcs | No — Windows system file | Yes — MiniDump on LSASS denied | No |

---

## End-to-End Test

```powershell
# 1. Confirm baseline state
.\Confirm-FileProtection.ps1 -FilePath "F:\nanodump.x64.exe"

# 2. Start the watcher in a separate terminal
.\Watch-FileIntegrity.ps1 -PagerIP "100.x.x.x" -NtfyURL "http://100.x.x.x:80/security-alerts"

# 3. Trigger an integrity violation
Set-ItemProperty "F:\nanodump.x64.exe" -Name IsReadOnly -Value $false
copy C:\Windows\System32\cmd.exe "F:\nanodump.x64.exe"

# Within 60 seconds the Pager should buzz and phone receive:
# INTEGRITY VIOLATION - hash changed

# 4. Restore by re-running Add-TrustedFileExclusion.ps1
```

---

## Security Design Notes

**Least privilege at the exclusion layer**
Defender path exclusions are scoped to a single file, not a directory. An attacker
with an admin shell who knows the exclusion exists cannot use it as a trusted
execution zone for other tools.

**Delete before trust**
The file does not exist on disk while waiting for user confirmation. If the user
answers N, nothing is left behind. If Y, the file is re-downloaded and verified
against the hash that was confirmed to match the official release, closing the gap
between verification and final trust.

**NTFS DACL write restriction**
After trust, the DACL is modified to grant Administrators full control and restrict the Users group to Read only. This removes the write path for standard users, breaking the first element of a binary overwrite privilege escalation chain. A writable privileged binary requires both a writable file and a privileged execution context — removing write access for non-admins eliminates the attack regardless of whether the attacker later escalates privileges.

**TOCTOU mitigation**
Files are set read-only immediately after the final verified download. Replacing
the file requires clearing the read-only attribute first - an additional privileged
step.

**Hash polling over event detection**
File integrity is monitored by polling SHA256 every 60 seconds rather than relying
on SACLs and Event 4663. File replacement removes any SACL on the original object,
making event-driven detection unreliable. Hash polling detects changes regardless
of how the file was modified.

**Out-of-band notification**
Alerts route through the Pager and phone via TCP to the Pager's netcat listener,
operating independently of the Aurora's security state. An attacker who disables
Sysmon or Defender on the Aurora cannot suppress these notifications.

---

## File Layout

```
C:\ProgramData\SecurityBaseline\
    trusted_hashes.json          Hash registry for Watch-FileIntegrity.ps1

/root/scripts/soar_listener.sh   Pager - TCP listener and alert trigger
/root/payloads/alerts/exclusion/
    payload.ds                   DuckyScript for exclusion-added alerts
```

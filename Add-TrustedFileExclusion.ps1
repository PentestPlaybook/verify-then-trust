#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds a file-specific Defender exclusion then verifies the hash.

.DESCRIPTION
    Two-step workflow:

    Step 1 - Get the hash (run without -ExpectedHash):
        The script adds a temporary exclusion, computes the SHA256, removes
        the exclusion, and displays the hash. Paste that hash into VirusTotal
        and search by hash (not URL - URL results are cached and may be stale).

    Step 2 - Trust the file (run with -ExpectedHash):
        The script adds the exclusion, recomputes the hash, and compares it
        against the expected value. On match: sets read-only, applies SACL,
        writes to hash registry, optionally notifies Pager. On mismatch:
        removes exclusion immediately.

.PARAMETER FilePath
    Full path to the file. Must exist on disk.

.PARAMETER ExpectedHash
    SHA256 verified on VirusTotal by hash search. Omit on first run to
    compute and display the hash.

.PARAMETER PagerIP
    Tailscale IP of the Pager. Optional - omit to skip notification.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.EXAMPLE
    # Step 1 - compute hash and verify on VirusTotal
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

    # Step 2 - trust the file after verification
    .\Add-TrustedFileExclusion.ps1 `
        -FilePath     "F:\nanodump.x64.exe" `
        -ExpectedHash "AD9E4DDCE68A34F0BA3010E66286BC3AA056043C7DCA7A22C3222A279614025A"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [string]$ExpectedHash = "",
    [string]$PagerIP      = "",
    [int]$PagerPort       = 9999,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$ErrorActionPreference = "Stop"
$fileName = Split-Path $FilePath -Leaf

Write-Host ""
Write-Host "File: $FilePath"
Write-Host ""

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

# Add exclusion so Defender does not block the file read
Add-MpPreference -ExclusionPath $FilePath
Start-Sleep -Seconds 3

# Compute hash
$actualHash = $null
try {
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
} catch {
    Write-Host "[-] Hash computation failed: $_" -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

# Step 1 mode - no ExpectedHash provided
# Display hash, remove exclusion, direct user to VirusTotal
if ($ExpectedHash -eq "") {
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    Write-Host "SHA256: $actualHash" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Search this hash on VirusTotal:" -ForegroundColor Yellow
    Write-Host "  https://www.virustotal.com/gui/search/$actualHash" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Do not use the URL analysis - search by hash to get results" -ForegroundColor Yellow
    Write-Host "for the exact file you have, not a cached version." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Once verified, re-run with -ExpectedHash to trust the file:" -ForegroundColor Gray
    Write-Host "  .\Add-TrustedFileExclusion.ps1 -FilePath `"$FilePath`" -ExpectedHash `"$actualHash`"" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# Step 2 mode - ExpectedHash provided, compare and proceed
$expectedNorm = $ExpectedHash.ToUpper().Trim()
Write-Host "Expected: $expectedNorm"
Write-Host "Actual:   $actualHash"
Write-Host ""

if ($actualHash -ne $expectedNorm) {
    Write-Host "FAIL  Hash mismatch." -ForegroundColor Red
    Write-Host "      Removing exclusion - file is not trusted." -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "PASS  Hash verified." -ForegroundColor Green
Write-Host "[+] Exclusion confirmed." -ForegroundColor Green

# Set read-only (TOCTOU mitigation)
Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $true
Write-Host "[+] File set to read-only." -ForegroundColor Cyan

# Apply SACL - requires SeSecurityPrivilege enabled explicitly
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class SACLHelper2 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, bool DisableAll,
        ref TOKEN_PRIVILEGES2 NewState, uint Len,
        IntPtr Prev, IntPtr RetLen);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(
        string System, string Name, ref LUID2 Luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(
        IntPtr Process, uint Access, out IntPtr Token);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID2 { public uint Lo; public int Hi; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES2 {
        public uint Count; public LUID2 Luid; public uint Attributes; }
    public static bool Enable(string priv) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) return false;
        LUID2 luid = new LUID2();
        if (!LookupPrivilegeValue(null, priv, ref luid)) return false;
        TOKEN_PRIVILEGES2 tp = new TOKEN_PRIVILEGES2();
        tp.Count = 1; tp.Luid = luid; tp.Attributes = 0x2;
        return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@
$null = [SACLHelper2]::Enable("SeSecurityPrivilege")

try {
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        [System.Security.AccessControl.FileSystemRights]"Modify,Delete",
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    $acl = [System.IO.File]::GetAccessControl(
        $FilePath,
        [System.Security.AccessControl.AccessControlSections]::Audit
    )
    $acl.AddAuditRule($rule)
    [System.IO.File]::SetAccessControl($FilePath, $acl)
    $null = & auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1
    Write-Host "[+] SACL applied. Event 4663 will fire on write or delete." -ForegroundColor Cyan
} catch {
    Write-Warning "SACL could not be applied: $_"
}

# Write to hash registry
try {
    $dir = Split-Path $RegistryPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $reg = if (Test-Path $RegistryPath) {
        Get-Content $RegistryPath -Raw | ConvertFrom-Json
    } else { [PSCustomObject]@{} }
    $reg | Add-Member -NotePropertyName $FilePath -NotePropertyValue ([PSCustomObject]@{
        expectedHash = $expectedNorm
        fileName     = $fileName
        registeredAt = (Get-Date -Format "o")
    }) -Force
    $reg | ConvertTo-Json -Depth 5 | Set-Content $RegistryPath -Force
    Write-Host "[+] Registered in hash registry." -ForegroundColor Cyan
} catch {
    Write-Warning "Hash registry write failed: $_"
}

# Notify Pager if IP provided
if ($PagerIP -ne "") {
    try {
        $msg    = "EXCLUSION_ADDED: " + $fileName + " Hash verified"
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ConnectAsync($PagerIP, $PagerPort).Wait(3000) | Out-Null
        if ($client.Connected) {
            $stream = $client.GetStream()
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes($msg + "`n")
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $client.Close()
            Write-Host "[+] Pager notified." -ForegroundColor Cyan
        } else {
            Write-Warning "Pager connection timed out."
        }
    } catch {
        Write-Warning "Pager notification failed: $_"
    }
}

Write-Host ""
Write-Host "Done. $fileName is trusted at: $FilePath" -ForegroundColor Green
Write-Host "Exclusion scope: this file path only." -ForegroundColor Gray

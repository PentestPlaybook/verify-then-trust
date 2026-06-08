#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Adds a file-specific Defender exclusion then verifies the hash.

.DESCRIPTION
    Two-step workflow:

    Step 1 - Get the hash (run without -ExpectedHash):
        Adds a temporary exclusion, computes the SHA256, removes the exclusion,
        and outputs the hash with a direct VirusTotal search link.
        Search by hash on VirusTotal - not URL, URL results are cached and stale.

    Step 2 - Trust the file (run with -ExpectedHash):
        Recomputes the hash and compares against the expected value.
        On match: keeps exclusion, sets read-only, applies SACL, writes to
        hash registry, optionally notifies Pager.
        On mismatch: removes exclusion immediately.

    Accepts either a local file path (-FilePath) or a URL (-URL).
    GitHub blob URLs are converted to raw URLs automatically.

.PARAMETER FilePath
    Full path to a file already on disk.

.PARAMETER URL
    Download URL for the file. GitHub blob URLs are accepted and converted
    to raw URLs automatically.

.PARAMETER Destination
    Folder to save downloaded files. Defaults to F:\.

.PARAMETER ExpectedHash
    SHA256 verified on VirusTotal by hash search. Omit on first run to
    compute and display the hash.

.PARAMETER PagerIP
    Tailscale IP of the Pager. Optional - omit to skip notification.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.EXAMPLE
    # File already on disk - Step 1
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

    # File already on disk - Step 2
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -ExpectedHash "AD9E4D..."

    # Download from URL - Step 1 (GitHub blob or raw URL)
    .\Add-TrustedFileExclusion.ps1 -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"

    # Download from URL - Step 2
    .\Add-TrustedFileExclusion.ps1 -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe" -ExpectedHash "AD9E4D..."

    # Download from URL - Step 2 with Pager notification
    .\Add-TrustedFileExclusion.ps1 -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe" -ExpectedHash "AD9E4D..." -PagerIP "100.x.x.x"
#>

param(
    [Parameter(ParameterSetName="ByFile", Mandatory=$true)]
    [string]$FilePath,

    [Parameter(ParameterSetName="ByURL", Mandatory=$true)]
    [string]$URL,

    [Parameter(ParameterSetName="ByURL")]
    [string]$Destination = "F:\",

    [Parameter(Mandatory=$false)]
    [string]$ExpectedHash = "",

    [string]$PagerIP  = "",
    [int]$PagerPort   = 9999,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$ErrorActionPreference = "Stop"

# ── URL mode: normalize and download ─────────────────────────────────────────
if ($PSCmdlet.ParameterSetName -eq "ByURL") {

    # Convert GitHub blob URL to raw URL
    if ($URL -match '^https://github\.com/(.+)/blob/(.+)$') {
        $URL = "https://raw.githubusercontent.com/" + $Matches[1] + "/" + $Matches[2]
        Write-Host "[+] GitHub blob URL detected. Using raw URL:" -ForegroundColor Cyan
        Write-Host "    $URL" -ForegroundColor Cyan
        Write-Host ""
    }

    $fileName = Split-Path -Path ([System.Uri]$URL).LocalPath -Leaf
    if (-not $fileName) {
        Write-Error "Cannot determine filename from URL. Specify a direct download link."
        exit 1
    }

    if (-not (Test-Path $Destination)) {
        Write-Error "Destination path does not exist: $Destination"
        exit 1
    }

    $FilePath = Join-Path (Resolve-Path $Destination) $fileName

    # Clear read-only if the file already exists from a previous run
    if (Test-Path $FilePath) {
        Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Write-Host "[+] Existing file found - cleared read-only for overwrite." -ForegroundColor Cyan
    }

    Write-Host "[+] Downloading $fileName..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Download complete." -ForegroundColor Cyan
    } catch {
        Write-Error "Download failed: $_"
        exit 1
    }
}

$fileName = Split-Path $FilePath -Leaf

Write-Host ""
Write-Host "File: $FilePath"
Write-Host ""

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

# ── Add exclusion so Defender does not block the file read ────────────────────
Add-MpPreference -ExclusionPath $FilePath
Start-Sleep -Seconds 3

# ── Compute hash ──────────────────────────────────────────────────────────────
$actualHash = $null
try {
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
} catch {
    Write-Host "[-] Hash computation failed: $_" -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

# ── Step 1: no ExpectedHash - display hash and VirusTotal link ────────────────
if ($ExpectedHash -eq "") {
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    Write-Host "SHA256: $actualHash" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Search this hash on VirusTotal:" -ForegroundColor Yellow
    Write-Host "  https://www.virustotal.com/gui/search/$actualHash" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Do not use URL analysis - search by hash for results" -ForegroundColor Yellow
    Write-Host "matching the exact file you have, not a cached version." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Once verified, re-run with -ExpectedHash to trust the file:" -ForegroundColor Gray
    if ($URL) {
        Write-Host "  .\Add-TrustedFileExclusion.ps1 -URL `"$URL`" -ExpectedHash `"$actualHash`"" -ForegroundColor Gray
    } else {
        Write-Host "  .\Add-TrustedFileExclusion.ps1 -FilePath `"$FilePath`" -ExpectedHash `"$actualHash`"" -ForegroundColor Gray
    }
    Write-Host ""
    exit 0
}

# ── Step 2: ExpectedHash provided - compare and apply protection ──────────────
$expectedNorm = $ExpectedHash.ToUpper().Trim()
Write-Host "Expected: $expectedNorm"
Write-Host "Actual:   $actualHash"
Write-Host ""

if ($actualHash -ne $expectedNorm) {
    Write-Host "FAIL  Hash mismatch." -ForegroundColor Red
    Write-Host "      Removing exclusion - file is not trusted." -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    if ($PSCmdlet.ParameterSetName -eq "ByURL") {
        Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        Write-Host "      Downloaded file deleted." -ForegroundColor Red
    }
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

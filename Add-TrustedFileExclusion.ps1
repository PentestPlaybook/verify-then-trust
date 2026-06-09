#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads or locates a file, computes its hash, then deletes it and
    waits for VirusTotal confirmation before re-downloading and trusting.

.DESCRIPTION
    Workflow:
      1. Download the file (exclusion added first to prevent quarantine)
         OR locate an existing file.
      2. Compute SHA256 hash.
      3. If -ExpectedHash is provided, verify the hash matches before proceeding.
      4. Delete the file and remove the exclusion.
      5. Display the hash with a direct VirusTotal search link.
      6. Prompt: "Have you verified this hash on VirusTotal? (Y/N)"
         - N: exits cleanly. No file on disk, no exclusion, nothing trusted.
         - Y: re-adds exclusion, re-downloads the file, verifies the hash
              matches what was approved, then applies full protection.
              If the re-download hash does not match, the file is deleted
              and the exclusion is removed.

    For files already on disk without a URL, the file is not deleted.
    The exclusion is removed on N and re-applied on Y.

    GitHub blob URLs are converted to raw URLs automatically.

.PARAMETER FilePath
    Full path to the file. Used as the download destination if -URL is
    provided. Accepts a directory - filename derived from URL.

.PARAMETER URL
    Optional download URL. GitHub blob URLs accepted and converted
    to raw URLs automatically.

.PARAMETER ExpectedHash
    Optional safety check. Verifies hash matches a previously known value.
    Use when re-trusting a file to confirm it has not changed.

.PARAMETER PagerIP
    Tailscale IP of the Pager. Optional - omit to skip notification.

.PARAMETER PagerPort
    TCP port of the Pager netcat listener. Defaults to 9999.

.EXAMPLE
    # Download and trust
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://github.com/fortra/nanodump/blob/main/dist/nanodump.x64.exe"

    # Trust a file already on disk
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe"

    # Re-download and verify hash has not changed
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -ExpectedHash "AD9E4D..."

    # With Pager notification
    .\Add-TrustedFileExclusion.ps1 -FilePath "F:\nanodump.x64.exe" -URL "https://..." -PagerIP "100.x.x.x"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$false)]
    [string]$URL = "",

    [Parameter(Mandatory=$false)]
    [string]$ExpectedHash = "",

    [string]$PagerIP  = "",
    [int]$PagerPort   = 9999,
    [string]$RegistryPath = "$env:ProgramData\SecurityBaseline\trusted_hashes.json"
)

$ErrorActionPreference = "Stop"
$urlMode = $URL -ne ""

# ── If FilePath is a directory and URL provided, derive filename from URL ─────
if ($urlMode -and (Test-Path $FilePath -PathType Container)) {
    $urlFileName = Split-Path -Path ([System.Uri]$URL).LocalPath -Leaf
    $FilePath    = Join-Path (Resolve-Path $FilePath) $urlFileName
    Write-Host "[+] Directory provided - saving as: $FilePath" -ForegroundColor Cyan
}

$fileName = Split-Path $FilePath -Leaf
Write-Host ""

# ── Convert GitHub blob URL to raw URL ───────────────────────────────────────
if ($urlMode -and ($URL -match '^https://github\.com/(.+)/blob/(.+)$')) {
    $URL = "https://raw.githubusercontent.com/" + $Matches[1] + "/" + $Matches[2]
    Write-Host "[+] GitHub blob URL detected. Using raw URL:" -ForegroundColor Cyan
    Write-Host "    $URL" -ForegroundColor Cyan
    Write-Host ""
}

# ── Download (URL mode) ───────────────────────────────────────────────────────
if ($urlMode) {
    # Add exclusion BEFORE download so Defender does not quarantine on write
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
    Write-Host "[+] Exclusion added for: $FilePath" -ForegroundColor Cyan

    if (Test-Path $FilePath) {
        Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Write-Host "[+] Overwriting existing file..." -ForegroundColor Cyan
    } else {
        Write-Host "[+] Downloading to $FilePath..." -ForegroundColor Cyan
    }

    try {
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Download complete." -ForegroundColor Cyan
    } catch {
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        Write-Error "Download failed: $_"
        exit 1
    }

} elseif (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath. Provide -URL to download it."
    exit 1
} else {
    # FilePath mode - add exclusion before reading
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
}

Write-Host "File: $FilePath"
Write-Host ""

# ── Compute hash ──────────────────────────────────────────────────────────────
$approvedHash = $null
try {
    $approvedHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
} catch {
    Write-Host "[-] Hash computation failed: $_" -ForegroundColor Red
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    exit 1
}

# ── Optional: verify against expected hash ────────────────────────────────────
if ($ExpectedHash -ne "") {
    $expectedNorm = $ExpectedHash.ToUpper().Trim()
    if ($approvedHash -ne $expectedNorm) {
        Write-Host "FAIL  Hash does not match expected value." -ForegroundColor Red
        Write-Host "      Expected: $expectedNorm" -ForegroundColor Red
        Write-Host "      Actual:   $approvedHash" -ForegroundColor Red
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        if ($urlMode) {
            Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
        exit 1
    }
    Write-Host "[+] Hash matches expected value." -ForegroundColor Green
}

# ── Delete file and remove exclusion before prompting (URL mode) ──────────────
# The file should not exist on disk while waiting for user confirmation.
# If the user says N, nothing is left behind. If Y, the file is re-downloaded
# and verified against the hash the user reviewed on VirusTotal.
if ($urlMode) {
    Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    Write-Host "[+] File deleted and exclusion removed pending confirmation." -ForegroundColor Cyan
} else {
    # FilePath mode - remove exclusion while prompting but keep the file
    Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
    Write-Host "[+] Exclusion removed pending confirmation." -ForegroundColor Cyan
}

# ── Display hash and VirusTotal link ──────────────────────────────────────────
Write-Host ""
Write-Host "SHA256: $approvedHash" -ForegroundColor Cyan
Write-Host ""
Write-Host "Search this hash on VirusTotal:" -ForegroundColor Yellow
Write-Host "  https://www.virustotal.com/gui/search/$approvedHash" -ForegroundColor Yellow
Write-Host ""
Write-Host "Do not use URL analysis - search by hash for the exact file you have." -ForegroundColor Yellow
Write-Host ""

# ── Prompt for confirmation ───────────────────────────────────────────────────
$confirm = Read-Host "Have you verified this hash on VirusTotal? (Y/N)"

if ($confirm -notmatch '^[Yy]$') {
    Write-Host ""
    if ($urlMode) {
        Write-Host "[-] Cancelled. File deleted, no exclusion added." -ForegroundColor Yellow
    } else {
        Write-Host "[-] Cancelled. Exclusion not applied." -ForegroundColor Yellow
    }
    exit 0
}

Write-Host ""
Write-Host "[+] Confirmed. Applying protection..." -ForegroundColor Green

# ── URL mode: re-download and verify hash matches what was approved ───────────
if ($urlMode) {
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
    Write-Host "[+] Re-adding exclusion for final download..." -ForegroundColor Cyan

    try {
        Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Download complete." -ForegroundColor Cyan
    } catch {
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        Write-Error "Re-download failed: $_"
        exit 1
    }

    $finalHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    if ($finalHash -ne $approvedHash) {
        Write-Host "FAIL  Re-downloaded file does not match approved hash." -ForegroundColor Red
        Write-Host "      Approved: $approvedHash" -ForegroundColor Red
        Write-Host "      Actual:   $finalHash" -ForegroundColor Red
        Write-Host "      The file may have changed between your review and this download." -ForegroundColor Red
        Remove-MpPreference -ExclusionPath $FilePath -ErrorAction SilentlyContinue
        Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Host "[+] Re-download verified. Hash matches approved value." -ForegroundColor Green

} else {
    # FilePath mode - re-add exclusion
    Add-MpPreference -ExclusionPath $FilePath
    Start-Sleep -Seconds 3
}

# ── Set read-only (TOCTOU mitigation) ─────────────────────────────────────────
Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $true
Write-Host "[+] File set to read-only." -ForegroundColor Cyan

# ── Write to hash registry ─────────────────────────────────────────────────────
try {
    $dir = Split-Path $RegistryPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $reg = if (Test-Path $RegistryPath) {
        Get-Content $RegistryPath -Raw | ConvertFrom-Json
    } else { [PSCustomObject]@{} }
    $reg | Add-Member -NotePropertyName $FilePath -NotePropertyValue ([PSCustomObject]@{
        expectedHash = $approvedHash
        fileName     = $fileName
        registeredAt = (Get-Date -Format "o")
    }) -Force
    $reg | ConvertTo-Json -Depth 5 | Set-Content $RegistryPath -Force
    Write-Host "[+] Registered in hash registry." -ForegroundColor Cyan
} catch {
    Write-Warning "Hash registry write failed: $_"
}

# ── Notify Pager if IP provided ───────────────────────────────────────────────
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

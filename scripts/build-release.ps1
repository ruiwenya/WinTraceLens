param(
    [string]$Version = "2.0.0-preview",
    [string]$OutputDirectory = "dist",
    [string]$SignToolPath = "",
    [string]$CertificateThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.acs.microsoft.com"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $repoRoot $OutputDirectory
$guiPath = Join-Path $outputPath "WinTraceLens.exe"
$cliPath = Join-Path $outputPath "WinTraceLens-cli.exe"

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
Push-Location $repoRoot
try {
    & go build -trimpath -ldflags "-H windowsgui -s -w -X main.version=$Version-gui" -o $guiPath .\cmd\wintracelensgui
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

    & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $cliPath .\cmd\wintracelens
    if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

    if ($CertificateThumbprint) {
        if (-not $SignToolPath) {
            throw "CertificateThumbprint requires SignToolPath"
        }
        foreach ($file in @($guiPath, $cliPath)) {
            & $SignToolPath sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d "WinTraceLens" $file
            if ($LASTEXITCODE -ne 0) { throw "Signing failed: $file" }
            & $SignToolPath verify /pa /v $file
            if ($LASTEXITCODE -ne 0) { throw "Signature verification failed: $file" }
        }
    } else {
        Write-Warning "Unsigned build: Smart App Control may block these executables. Use a trusted code-signing certificate for release artifacts."
    }

    $hashLines = foreach ($file in @($guiPath, $cliPath)) {
        $hash = Get-FileHash -LiteralPath $file -Algorithm SHA256
        "{0}  {1}" -f $hash.Hash, (Split-Path -Leaf $file)
    }
    Set-Content -LiteralPath (Join-Path $outputPath "SHA256SUMS.txt") -Value $hashLines -Encoding ascii
} finally {
    Pop-Location
}

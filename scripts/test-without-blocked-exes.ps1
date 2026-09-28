$ErrorActionPreference = "Stop"

$module = (& go list -m).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to resolve Go module" }

$excluded = @(
    "$module/internal/server",
    "$module/internal/investigation",
    "$module/cmd/wintracelensgui"
)
$packages = @(& go list ./... | Where-Object { $excluded -notcontains $_ })
if ($LASTEXITCODE -ne 0) { throw "Unable to enumerate Go packages" }

Write-Host "Skipping test executables blocked by endpoint security:"
$excluded | ForEach-Object { Write-Host "  $_" }

& go test @packages
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

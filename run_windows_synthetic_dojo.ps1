# Candidate-only native Windows synthetic test runner. No MIDAS, network or production changes.
# The only filesystem writes are temporary synthetic unittest fixtures and Python stdout.
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    throw 'WINDOWS_RUNTIME_REQUIRED'
}
$folder = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONDONTWRITEBYTECODE = '1'
Push-Location -LiteralPath $folder
try {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & py -3 -B offline_windows_dojo_gate.py
    } else {
        $python = Get-Command python -ErrorAction Stop
        & python -B offline_windows_dojo_gate.py
    }
    if ($LASTEXITCODE -ne 0) { throw "NATIVE_SYNTHETIC_DOJO_BLOCKED:$LASTEXITCODE" }
} finally {
    Pop-Location
}

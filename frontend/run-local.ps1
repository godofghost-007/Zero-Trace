# ZeroTrace local demo — Windows host runner
#
# Serves the built React UI and the Flask API from a single origin:
#   http://127.0.0.1:3000/
#
# First run installs Python dependencies and builds the frontend when missing.

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Creating Python virtual environment..."
    py -m venv .venv
    & $python -m pip install --disable-pip-version-check -q -r requirements.txt
}

if (-not (Test-Path "dist\public\index.html")) {
    Write-Host "Installing frontend dependencies and building..."
    pnpm install
    pnpm build
}

Write-Host "ZeroTrace demo: http://127.0.0.1:3000/"
& $python -m flask --app backend:create_app run --host=127.0.0.1 --port=3000 --no-reload

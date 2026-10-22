# ZeroTrace local live demo (Windows)
#
# Serves the built React UI and the Flask BFF from http://127.0.0.1:3000 and
# starts the loopback-only live engine on http://127.0.0.1:8765.
#
# The engine is optional for the fixture pages. The Targets & Scope console
# uses it; without it those pages show an offline state.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location -LiteralPath $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $fallback = Join-Path $root "frontend\.venv\Scripts\python.exe"
    if (Test-Path $fallback) {
        $python = $fallback
    } else {
        Write-Host "Creating the local Python virtual environment..."
        py -m venv .venv
        $python = Join-Path $root ".venv\Scripts\python.exe"
        & $python -m pip install --disable-pip-version-check -q -e . -r frontend\requirements.txt
    }
}

if (-not (Test-Path "frontend\dist\public\index.html")) {
    Write-Host "Building the React dashboard..."
    Push-Location frontend
    try {
        pnpm install
        pnpm build
    } finally {
        Pop-Location
    }
}

Write-Host "Preparing the local sign-in account..."
Push-Location frontend
try {
    & $python -m flask --app backend:create_app demo-credentials
} finally {
    Pop-Location
}

$engine = $null
try {
    $running = $false
    try {
        $probe = Invoke-WebRequest -Uri "http://127.0.0.1:8765/ready" `
            -UseBasicParsing -TimeoutSec 1
        $running = $probe.StatusCode -eq 200
    } catch {
        $running = $false
    }

    if (-not $running) {
        Write-Host "Starting the loopback live engine..."
        $engine = Start-Process -FilePath $python `
            -ArgumentList "-m", "scripts.live_engine" `
            -WorkingDirectory $root -PassThru -WindowStyle Hidden

        $ready = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            Start-Sleep -Milliseconds 250
            try {
                $probe = Invoke-WebRequest -Uri "http://127.0.0.1:8765/ready" `
                    -UseBasicParsing -TimeoutSec 1
                if ($probe.StatusCode -eq 200) {
                    $ready = $true
                    break
                }
            } catch {
                # The engine is still starting.
            }
        }
        if (-not $ready) {
            throw "The live engine did not become ready on 127.0.0.1:8765."
        }
    }

    Write-Host ""
    Write-Host "ZeroTrace demo: http://127.0.0.1:3000/"
    Write-Host "Live engine:    http://127.0.0.1:8765/ready"
    Write-Host "Press Ctrl+C to stop the demo."
    Write-Host ""

    Push-Location frontend
    try {
        & $python -m flask --app backend:create_app run `
            --host=127.0.0.1 --port=3000 --no-reload
    } finally {
        Pop-Location
    }
} finally {
    if ($engine -ne $null -and -not $engine.HasExited) {
        Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
  Measure local inference throughput against the LM Studio server.

.DESCRIPTION
  Phase 0 evidence tool. Produces reproducible numbers instead of feelings.
  Sends the same fixed prompt twice (thinking on / thinking off), measures
  wall-clock time and token counts, reports effective tokens per second, and
  appends a JSON record.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\bench-lmstudio.ps1
  powershell -ExecutionPolicy Bypass -File scripts\bench-lmstudio.ps1 -Model qwen/qwen3.5-9b -MaxTokens 128
#>
[CmdletBinding()]
param(
    [string]$BaseUrl   = "http://localhost:1235/v1",
    [string]$Model,
    [int]   $MaxTokens = 192,
    [string]$OutFile   = "scripts\bench-results.json"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

function Get-ApiBase { $BaseUrl.TrimEnd('/') }
function Get-ScratchDir {
    $d = Join-Path $env:LOCALAPPDATA "Temp\opencode"
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    return $d
}

function Invoke-Chat {
    param(
        [string]$ApiBase,
        [string]$ModelId,
        [hashtable]$ExtraBody,
        [int]$MaxTokens,
        [string]$Prompt,
        [string]$Scratch
    )

    $payload = @{
        model       = $ModelId
        messages    = @(@{ role = "user"; content = $Prompt })
        max_tokens  = $MaxTokens
        temperature = 0
        stream      = $false
    }
    if ($ExtraBody) { foreach ($k in $ExtraBody.Keys) { $payload[$k] = $ExtraBody[$k] } }

    $bodyPath = Join-Path $Scratch "bench-body.json"
    ($payload | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $bodyPath -Encoding UTF8

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $raw = & curl.exe -s -S --max-time 600 -X POST "$ApiBase/chat/completions" `
        -H "Content-Type: application/json" `
        --data-binary "@$bodyPath" 2>&1
    $sw.Stop()

    $elapsedMs = $sw.Elapsed.TotalMilliseconds
    $obj = $null
    try { $obj = $raw | ConvertFrom-Json } catch { }

    if (-not $obj) {
        return [pscustomobject]@{ ok = $false; error = ($raw | Out-String).Trim(); elapsed_ms = [math]::Round($elapsedMs,0) }
    }
    if ($obj.error) {
        return [pscustomobject]@{ ok = $false; error = ($obj.error | ConvertTo-Json -Compress); elapsed_ms = [math]::Round($elapsedMs,0) }
    }

    $msg      = $obj.choices[0].message
    $content  = if ($msg.content) { [string]$msg.content } else { "" }
    $reason   = if ($msg.reasoning_content) { [string]$msg.reasoning_content } elseif ($msg.reasoning) { [string]$msg.reasoning } else { "" }
    $ct       = 0; $pt = 0
    if ($obj.usage) {
        if ($obj.usage.completion_tokens) { $ct = [int]$obj.usage.completion_tokens }
        if ($obj.usage.prompt_tokens)     { $pt = [int]$obj.usage.prompt_tokens }
    }
    $tps = if ($ct -gt 0 -and $elapsedMs -gt 0) { [math]::Round($ct / ($elapsedMs / 1000), 2) } else { 0 }

    return [pscustomobject]@{
        ok                 = $true
        elapsed_ms         = [math]::Round($elapsedMs, 0)
        prompt_tokens      = $pt
        completion_tokens  = $ct
        effective_tok_s    = $tps
        reasoning_chars    = $reason.Length
        content_chars      = $content.Length
        content_preview    = if ($content.Length -gt 120) { $content.Substring(0,120) } else { $content }
        finish_reason      = $obj.choices[0].finish_reason
    }
}

# --- resolve model -------------------------------------------------------
$api = Get-ApiBase
$scratch = Get-ScratchDir

$nativeBase = $api -replace '/v1$', ''
$server = (Invoke-WebRequest -Uri "$nativeBase/api/v0/models" -TimeoutSec 15 -UseBasicParsing).Content | ConvertFrom-Json

if (-not $Model) {
    $loaded = $server.data | Where-Object { $_.state -eq 'loaded' -and $_.type -ne 'embeddings' } | Select-Object -First 1
    if (-not $loaded) { throw "No model is loaded in LM Studio. Load one, then re-run." }
    $Model = $loaded.id
}
$meta = $server.data | Where-Object { $_.id -eq $Model } | Select-Object -First 1

Write-Host ""
Write-Host "LM Studio benchmark" -ForegroundColor Cyan
Write-Host ("  model            : {0}" -f $Model)
if ($meta) {
    Write-Host ("  architecture     : {0}   quant: {1}" -f $meta.arch, $meta.quantization)
    Write-Host ("  context          : {0} / {1}" -f $meta.loaded_context_length, $meta.max_context_length)
    Write-Host ("  type             : {0}" -f $meta.type)
}
Write-Host ("  max_tokens       : {0}" -f $MaxTokens)
Write-Host ""

$prompt = "Write a Python function fib(n) that returns the n-th Fibonacci number iteratively. Include a docstring and 3 pytest test functions. Output only code."

$results = [ordered]@{}
$results["thinking_on"]  = Invoke-Chat -ApiBase $api -ModelId $Model -MaxTokens $MaxTokens -Prompt $prompt -Scratch $scratch
$results["thinking_off"] = Invoke-Chat -ApiBase $api -ModelId $Model -MaxTokens $MaxTokens -Prompt $prompt -Scratch $scratch `
    -ExtraBody @{ chat_template_kwargs = @{ enable_thinking = $false } }

foreach ($k in $results.Keys) {
    $r = $results[$k]
    Write-Host ("[{0}]" -f $k) -ForegroundColor Yellow
    if (-not $r.ok) {
        Write-Host ("   FAILED: {0}" -f $r.error) -ForegroundColor Red
    } else {
        Write-Host ("   elapsed          : {0} ms" -f $r.elapsed_ms)
        Write-Host ("   tokens           : {0} prompt + {1} completion" -f $r.prompt_tokens, $r.completion_tokens)
        Write-Host ("   effective tok/s  : {0}" -f $r.effective_tok_s)
        Write-Host ("   reasoning chars  : {0}" -f $r.reasoning_chars)
        Write-Host ("   content chars    : {0}" -f $r.content_chars)
        Write-Host ("   finish_reason    : {0}" -f $r.finish_reason)
        Write-Host ("   preview          : {0}" -f $r.content_preview)
    }
    Write-Host ""
}

$record = [pscustomobject]@{
    recorded_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    base_url        = $api
    model           = $Model
    meta            = $meta
    max_tokens      = $MaxTokens
    results         = $results
}
$outPath = Join-Path (Get-Location) $OutFile
$dir = Split-Path $outPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$existing = @()
if (Test-Path $outPath) {
    try { $existing = @(Get-Content -LiteralPath $outPath -Raw | ConvertFrom-Json) } catch { $existing = @() }
}
($existing + $record) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outPath -Encoding UTF8
Write-Host ("appended record -> {0}" -f $outPath) -ForegroundColor Green

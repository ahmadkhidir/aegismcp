#Requires -Version 5.1
<#
.SYNOPSIS
    Build the packaged gateway, boot it on an ephemeral port, and assert /health.

.DESCRIPTION
    The script builds the gateway distribution with the Gradle wrapper, starts the installed
    launcher with AEGIS_GATEWAY_PORT=0 so the operating system assigns a free port, waits for the
    server to announce the bound port, and requires GET /health to answer 200 with "status":"UP".
    The process is stopped and its temporary files are removed on exit, success or failure.

    This is the PowerShell counterpart of scripts/verify-artifact.

.EXAMPLE
    scripts/verify-artifact.ps1

    Exit status is 0 when the packaged artifact boots and answers the health check, 1 otherwise.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$workDir = Join-Path ([IO.Path]::GetTempPath()) ('aegis-boot-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir | Out-Null
$log = Join-Path $workDir 'gateway.log'
$errorLog = Join-Path $workDir 'gateway.err'
$body = Join-Path $workDir 'health.json'

$script:serverProcess = $null

function Show-Log {
    if (Test-Path -LiteralPath $log) {
        $lines = Get-Content -LiteralPath $log -ErrorAction SilentlyContinue
        if ($lines) {
            [Console]::Error.WriteLine('--- gateway log (tail) ---')
            $lines | Select-Object -Last 40 | ForEach-Object { [Console]::Error.WriteLine($_) }
            [Console]::Error.WriteLine('--------------------------')
        }
    }
    if ((Test-Path -LiteralPath $errorLog) -and (Get-Item -LiteralPath $errorLog).Length -gt 0) {
        [Console]::Error.WriteLine('--- gateway stderr ---')
        Get-Content -LiteralPath $errorLog | Select-Object -Last 40 | ForEach-Object { [Console]::Error.WriteLine($_) }
        [Console]::Error.WriteLine('----------------------')
    }
}

function Stop-Server {
    if ($null -ne $script:serverProcess -and -not $script:serverProcess.HasExited) {
        if ($env:OS -eq 'Windows_NT') {
            & taskkill /PID $script:serverProcess.Id /T /F *> $null
        }
        else {
            & kill -TERM $script:serverProcess.Id 2> $null
            if (-not $script:serverProcess.WaitForExit(5000)) {
                & kill -KILL $script:serverProcess.Id 2> $null
            }
        }
        $script:serverProcess.WaitForExit(5000) | Out-Null
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

try {
    $gradlew = Join-Path $repoRoot 'gradlew.bat'
    if (-not (Test-Path -LiteralPath $gradlew -PathType Leaf)) {
        $gradlew = Join-Path $repoRoot 'gradlew'
    }

    Write-Output 'verify-artifact: building the gateway distribution'
    & $gradlew ':services:gateway:installDist' '--console=plain'
    if ($LASTEXITCODE -ne 0) {
        [Console]::Error.WriteLine('verify-artifact: the gateway distribution failed to build')
        exit 1
    }

    $installDir = Join-Path $repoRoot 'services/gateway/build/install/gateway'
    if ($env:OS -eq 'Windows_NT') {
        $launcher = Join-Path $installDir 'bin/gateway.bat'
        $fileName = $env:ComSpec
        $arguments = @('/c', "`"$launcher`"")
    }
    else {
        $launcher = Join-Path $installDir 'bin/gateway'
        $fileName = 'bash'
        $arguments = @($launcher)
    }
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        [Console]::Error.WriteLine("verify-artifact: the installed launcher $launcher is missing")
        exit 1
    }

    Write-Output 'verify-artifact: booting the packaged gateway on an ephemeral port'
    $previousHost = $env:AEGIS_GATEWAY_HOST
    $previousPort = $env:AEGIS_GATEWAY_PORT
    $env:AEGIS_GATEWAY_HOST = '127.0.0.1'
    $env:AEGIS_GATEWAY_PORT = '0'
    try {
        $script:serverProcess = Start-Process -FilePath $fileName -ArgumentList $arguments `
            -NoNewWindow -PassThru -RedirectStandardOutput $log -RedirectStandardError $errorLog
    }
    finally {
        $env:AEGIS_GATEWAY_HOST = $previousHost
        $env:AEGIS_GATEWAY_PORT = $previousPort
    }

    $port = $null
    $deadline = (Get-Date).AddSeconds(30)
    while (-not $port -and (Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $log) {
            $content = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
            if ($content -match 'started successfully on .*:(\d+)') {
                $port = $Matches[1]
                break
            }
        }
        if ($script:serverProcess.HasExited) {
            [Console]::Error.WriteLine('verify-artifact: the gateway exited before reporting a bound port')
            Show-Log
            exit 1
        }
        Start-Sleep -Milliseconds 100
    }

    if (-not $port) {
        [Console]::Error.WriteLine('verify-artifact: the gateway did not report a bound port within 30 seconds')
        Show-Log
        exit 1
    }

    $healthUrl = "http://127.0.0.1:$port/health"
    $healthy = $false
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                Set-Content -LiteralPath $body -Value $response.Content
                $healthy = $true
                break
            }
        }
        catch {
            # The server may still be starting; retry until the deadline.
        }
        if ($script:serverProcess.HasExited) {
            [Console]::Error.WriteLine("verify-artifact: the gateway exited before answering $healthUrl")
            Show-Log
            exit 1
        }
        Start-Sleep -Milliseconds 200
    }

    if (-not $healthy) {
        [Console]::Error.WriteLine("verify-artifact: $healthUrl did not answer HTTP 200 within 30 seconds")
        Show-Log
        exit 1
    }

    $healthBody = Get-Content -LiteralPath $body -Raw
    if ($healthBody -notmatch '"status"\s*:\s*"UP"') {
        [Console]::Error.WriteLine("verify-artifact: $healthUrl did not report status UP")
        [Console]::Error.WriteLine("verify-artifact: response body: $healthBody")
        Show-Log
        exit 1
    }

    Write-Output "verify-artifact: packaged gateway booted on 127.0.0.1:$port and /health reported status UP"
}
finally {
    Stop-Server
}

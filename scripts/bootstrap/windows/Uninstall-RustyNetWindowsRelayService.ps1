param(
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$RelayRoot = 'C:\ProgramData\RustyNet\relay',
    [string]$ServiceName = 'RustyNetRelay',
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
$script:UninstallFailureStep = 'startup'

function Test-ReviewedRelayServiceName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -ne 'RustyNetRelay') {
        throw "unsupported relay service name: $Name"
    }
}

function Test-ReviewedInstallRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -ne 'C:\Program Files\RustyNet') {
        throw "unsupported install root: $Path"
    }
}

function Test-ReviewedRelayRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -ne 'C:\ProgramData\RustyNet\relay') {
        throw "unsupported relay root: $Path"
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = (& sc.exe @Arguments 2>&1 | Out-String)
    return [ordered]@{
        exit_code = $LASTEXITCODE
        output = $output.Trim()
    }
}

function Remove-ReviewedFileIfPresent {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer) {
            throw "refusing to remove directory through file removal path: $Path"
        }
        Remove-Item -LiteralPath $Path -Force
    }
}

function New-RelayUninstallReport {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        schema_version = 1
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        platform = 'windows'
        service_name = $ServiceName
        install_root = $InstallRoot
        relay_root = $RelayRoot
        status = $Status
        reason = $Reason
        failure_step = $script:UninstallFailureStep
        preserved_artifacts = @(
            (Join-Path $RelayRoot 'relay-verifier.key'),
            (Join-Path $RelayRoot 'relay-replay.nonces')
        )
    }
}

function Write-RelayUninstallReportIfRequested {
    param([Parameter(Mandatory = $true)][object]$Report)
    if (-not $OutputPath -or $OutputPath.Trim().Length -eq 0) {
        return
    }
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        Ensure-Directory -Path $outputDirectory
    }
    ($Report | ConvertTo-Json -Depth 8) | Set-Content -Encoding utf8 -LiteralPath $OutputPath
}

trap {
    $failureReason = if ($_.Exception -and $_.Exception.Message) {
        $_.Exception.Message.Trim()
    }
    else {
        ($_ | Out-String).Trim()
    }
    if (-not $failureReason) {
        $failureReason = 'windows-relay-service-uninstall-exception'
    }
    Write-RelayUninstallReportIfRequested -Report (New-RelayUninstallReport -Status 'fail' -Reason $failureReason)
    Write-Error $_
    exit 1
}

Test-ReviewedRelayServiceName -Name $ServiceName
Test-ReviewedInstallRoot -Path $InstallRoot
Test-ReviewedRelayRoot -Path $RelayRoot

$relayDest = Join-Path $InstallRoot 'rustynet-relay.exe'
$envFile = Join-Path $RelayRoot 'relay.env'

$script:UninstallFailureStep = 'stop-existing-relay-service'
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(20)
    while ($true) {
        $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ((-not $current) -or $current.Status -eq 'Stopped') {
            break
        }
        if ((Get-Date) -ge $deadline) {
            throw "service did not stop before uninstall deadline: $ServiceName"
        }
        Start-Sleep -Milliseconds 250
    }
}

$script:UninstallFailureStep = 'delete-service-registration'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $deleteResult = Invoke-Sc -Arguments @('delete', $ServiceName)
    if ($deleteResult.exit_code -ne 0) {
        throw "sc.exe delete failed: $($deleteResult.output)"
    }
    $deadline = (Get-Date).AddSeconds(20)
    while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        if ((Get-Date) -ge $deadline) {
            throw "service registration still present after delete: $ServiceName"
        }
        Start-Sleep -Milliseconds 250
    }
}

$script:UninstallFailureStep = 'remove-reviewed-runtime-files'
Remove-ReviewedFileIfPresent -Path $relayDest
Remove-ReviewedFileIfPresent -Path $envFile

$script:UninstallFailureStep = 'verify-removed'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "service registration remains after uninstall: $ServiceName"
}
if (Test-Path -LiteralPath $relayDest) {
    throw "relay binary remains after uninstall: $relayDest"
}
if (Test-Path -LiteralPath $envFile) {
    throw "relay env file remains after uninstall: $envFile"
}

Write-RelayUninstallReportIfRequested -Report (New-RelayUninstallReport -Status 'pass' -Reason 'relay-service-uninstalled')
Write-Output "RustyNetRelay service uninstalled; verifier key and replay store preserved under $RelayRoot"

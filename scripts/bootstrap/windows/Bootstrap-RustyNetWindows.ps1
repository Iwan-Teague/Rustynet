param(
    [ValidateSet('prepare-transport','sync-source','build-release','install-release','restart-runtime','verify-runtime','collect-diagnostics','all')]
    [string]$Phase = 'all',
    [ValidateSet('git','archive')]
    [string]$SourceMode = 'git',
    [string]$RepoUrl = '',
    [string]$Branch = 'main',
    [string]$RustyNetRoot = 'C:\Rustynet',
    [string]$ArchiveZipPath = '',
    [string]$InstallRoot = 'C:\Program Files\RustyNet',
    [string]$StateRoot = 'C:\ProgramData\RustyNet',
    [string]$ServiceName = 'RustyNet',
    [string]$AutomationPublicKey = '',
    [string]$WingetConfigPath = '',
    [string]$VsConfigPath = '',
    [string]$ResultPath = '',
    [switch]$InstallPowerShell7,
    [switch]$SetDefaultShellToPowerShell,
    [switch]$SetDefaultShellToPowerShell7,
    [switch]$InteractiveBuildBootstrapChild,
    # Opt-in fallback to Register-ScheduledTask -LogonType Interactive when
    # the SYSTEM-context build-release path cannot resolve a usable
    # toolchain.  Off by default: lab images install Rust + VS Build Tools
    # machine-scoped (see WindowsLabVmStabilityAndSessionModel_2026-04-30.md)
    # so the SYSTEM short-circuit succeeds without an Active interactive
    # Windows session.  When this switch is off and the SYSTEM path cannot
    # resolve the toolchain, build-release fails fast with a precise error
    # naming which canonical paths were missing.  Only set this for ad-hoc
    # runs against a Windows host where Rust lives only in a user profile.
    [switch]$AllowInteractiveTaskFallback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    $failureReason = Format-TopLevelFailureReason -PhaseName $Phase -ErrorRecord $_
    Write-FailClosedPhaseResultIfRequested -FailureReason $failureReason
    Write-Error $_
    exit 1
}

if ($SetDefaultShellToPowerShell -and $SetDefaultShellToPowerShell7) {
    throw 'Specify only one of -SetDefaultShellToPowerShell or -SetDefaultShellToPowerShell7'
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function New-PrepareTransportFailureReport {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [ordered]@{
        openssh_installed = $false
        service_running = $false
        firewall_rule_enabled = $false
        authorized_keys_applied = $false
        host_key_present = $false
        listener_ready = $false
        default_shell_configured = $false
        status = 'fail'
        reason = $Reason
        host_key = ''
    }
}

function Format-TopLevelFailureReason {
    param(
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)]$ErrorRecord
    )

    $detail = ''
    if ($null -ne $ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $detail = $ErrorRecord.Exception.Message.Trim()
    }
    if (-not $detail) {
        $detail = ($ErrorRecord | Out-String).Trim()
    }
    if (-not $detail) {
        $detail = 'unhandled-exception'
    }
    if ($PhaseName -eq 'prepare-transport') {
        return [string]::Concat('prepare-transport-exception: ', $detail)
    }
    return [string]::Concat($PhaseName, '-exception: ', $detail)
}

function Write-FailClosedPhaseResultIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)

    $trimmedResultPath = $ResultPath.Trim()
    if ($trimmedResultPath.Length -eq 0) {
        return
    }

    if ($Phase -eq 'prepare-transport') {
        try {
            $report = New-PrepareTransportFailureReport -Reason $FailureReason
            $parent = Split-Path -Path $trimmedResultPath -Parent
            if ($parent -and $parent.Trim().Length -gt 0) {
                Ensure-Directory -Path $parent
            }
            $report | ConvertTo-Json -Compress | Set-Content -LiteralPath $trimmedResultPath -Encoding utf8
        }
        catch {
            # Preserve the original failure as the dominant root cause.
        }
        return
    }

    if ($Phase -eq 'build-release') {
        Write-FailClosedBuildReleaseReportIfRequested -FailureReason $FailureReason
    }
}

function Write-JsonPhaseResult {
    param([Parameter(Mandatory = $true)]$Value)

    $json = $Value | ConvertTo-Json -Compress
    $trimmedResultPath = $ResultPath.Trim()
    if ($trimmedResultPath.Length -gt 0) {
        $parent = Split-Path -Path $trimmedResultPath -Parent
        if ($parent -and $parent.Trim().Length -gt 0) {
            Ensure-Directory -Path $parent
        }
        Set-Content -LiteralPath $trimmedResultPath -Value $json -Encoding utf8
    }
    Write-Output $json
}

function Write-TextFileAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [ValidateSet('utf8', 'ascii')]
        [string]$Encoding = 'utf8'
    )

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and $parent.Trim().Length -gt 0) {
        Ensure-Directory -Path $parent
    }
    $leaf = Split-Path -Path $Path -Leaf
    $tempPath = Join-Path $parent ([string]::Concat($leaf, '.tmp.', [guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $tempPath -Value $Content -Encoding $Encoding
    Move-Item -LiteralPath $tempPath -Destination $Path -Force
}

function Get-FileTailOrEmpty {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$LineCount = 20
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    try {
        return ((Get-Content -LiteralPath $Path -Tail $LineCount -ErrorAction Stop) -join "`n").Trim()
    }
    catch {
        return ''
    }
}

function Get-BuildReleaseReportLayout {
    param([string]$ManifestPath = '')

    $trimmedManifestPath = $ManifestPath.Trim()
    if ($trimmedManifestPath.Length -eq 0) {
        return $null
    }

    $reportRoot = Split-Path -Path $trimmedManifestPath -Parent
    if (-not $reportRoot -or $reportRoot.Trim().Length -eq 0) {
        throw "build-release result path must have a parent directory: $trimmedManifestPath"
    }

    return [ordered]@{
        report_root = $reportRoot
        manifest_path = $trimmedManifestPath
        stdout_path = (Join-Path $reportRoot 'stdout.txt')
        stderr_path = (Join-Path $reportRoot 'stderr.txt')
        exit_code_path = (Join-Path $reportRoot 'exit_code.txt')
        toolchain_path = (Join-Path $reportRoot 'toolchain.txt')
        complete_marker_path = (Join-Path $reportRoot 'complete.marker')
    }
}

# Classify a resolved cargo/rustc/rustup exe path as "machine"-scope
# (lab-image install under C:\CargoHome\bin or $env:CARGO_HOME\bin) or
# "user"-scope (USERPROFILE\.cargo\bin or scoop/chocolatey).  Returns
# "unknown" for any other location and "" for empty input.  Used in
# the build-release manifest so the orchestrator can confirm at the
# host end that the bootstrap took the SYSTEM short-circuit and did
# not silently fall back to the Interactive Scheduled Task.
function Get-ToolchainScope {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$ResolvedExePath)
    if ([string]::IsNullOrWhiteSpace($ResolvedExePath)) { return '' }
    $normalized = $ResolvedExePath.Replace('/', '\').ToLowerInvariant()
    $machinePrefixes = @('c:\cargohome\bin\')
    if ($env:CARGO_HOME -and $env:CARGO_HOME.Trim().Length -gt 0) {
        $machinePrefixes += ((Join-Path $env:CARGO_HOME 'bin') + '\').ToLowerInvariant()
    }
    foreach ($prefix in $machinePrefixes) {
        if ($normalized.StartsWith($prefix)) { return 'machine' }
    }
    $userMarkers = @('\.cargo\bin\', '\scoop\apps\rustup\', '\chocolatey\lib\rust\')
    foreach ($marker in $userMarkers) {
        if ($normalized.Contains($marker)) { return 'user' }
    }
    return 'unknown'
}

function New-BuildReleaseReport {
    param(
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [AllowEmptyString()][string]$StderrTail = ''
    )

    $cargoPathForScope = ''
    try { $cargoPathForScope = [string](Resolve-CargoExePath) } catch { $cargoPathForScope = '' }
    $toolchainScope = Get-ToolchainScope -ResolvedExePath $cargoPathForScope

    return [ordered]@{
        schema_version = 2
        phase = 'build-release'
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        status = $Status
        reason = $Reason
        rustynet_root = $RustyNetRoot
        report_root = $Layout.report_root
        stdout_path = $Layout.stdout_path
        stderr_path = $Layout.stderr_path
        exit_code_path = $Layout.exit_code_path
        toolchain_path = $Layout.toolchain_path
        toolchain_scope = $toolchainScope
        manifest_path = $Layout.manifest_path
        complete_marker_path = $Layout.complete_marker_path
        exit_code = $ExitCode
        stderr_tail = $StderrTail
        notes = @('guest-authored-build-report')
    }
}

function Write-BuildReleaseReport {
    param(
        [Parameter(Mandatory = $true)]$Layout,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [AllowEmptyString()][string]$StderrTail = ''
    )

    Ensure-Directory -Path $Layout.report_root
    if (-not (Test-Path -LiteralPath $Layout.stdout_path)) {
        Write-TextFileAtomically -Path $Layout.stdout_path -Content ''
    }
    if (-not (Test-Path -LiteralPath $Layout.stderr_path)) {
        Write-TextFileAtomically -Path $Layout.stderr_path -Content ''
    }
    if (-not (Test-Path -LiteralPath $Layout.toolchain_path)) {
        Write-TextFileAtomically -Path $Layout.toolchain_path -Content ''
    }
    Write-TextFileAtomically -Path $Layout.exit_code_path -Content ([string]$ExitCode) -Encoding ascii
    $manifest = New-BuildReleaseReport -Layout $Layout -Status $Status -Reason $Reason -ExitCode $ExitCode -StderrTail $StderrTail
    if (Test-Path -LiteralPath $Layout.complete_marker_path) {
        Remove-Item -LiteralPath $Layout.complete_marker_path -Force -ErrorAction SilentlyContinue
    }
    Write-TextFileAtomically -Path $Layout.manifest_path -Content ($manifest | ConvertTo-Json -Depth 6)
    Write-TextFileAtomically -Path $Layout.complete_marker_path -Content 'complete' -Encoding ascii
}

function Write-BuildReleaseToolchainReport {
    param([Parameter(Mandatory = $true)]$Layout)

    $toolingState = Get-WindowsBootstrapToolingState
    $content = Format-WindowsBootstrapToolingStateReport -State $toolingState
    Write-TextFileAtomically -Path $Layout.toolchain_path -Content $content
}

function Invoke-CargoBuildForReport {
    param(
        [Parameter(Mandatory = $true)][string]$CargoCommand,
        [Parameter(Mandatory = $true)][string[]]$CargoArgs,
        [Parameter(Mandatory = $true)]$Layout,
        [switch]$Append
    )

    Ensure-Directory -Path $Layout.report_root
    # PS5.1: $ErrorActionPreference='Stop' treats native-command stderr as a
    # terminating NativeCommandError even when stderr is redirected to a file.
    # Lower to Continue for the cargo invocation so build output is captured
    # and $LASTEXITCODE is used for success/failure instead of an exception.
    $ErrorActionPreference = 'Continue'
    if ($Append) {
        & $CargoCommand @CargoArgs 1>> $Layout.stdout_path 2>> $Layout.stderr_path
    }
    else {
        & $CargoCommand @CargoArgs 1> $Layout.stdout_path 2> $Layout.stderr_path
    }
    return [int]$LASTEXITCODE
}

function Write-FailClosedBuildReleaseReportIfRequested {
    param([Parameter(Mandatory = $true)][string]$FailureReason)

    try {
        $layout = Get-BuildReleaseReportLayout -ManifestPath $ResultPath
        if ($null -eq $layout) {
            return
        }
        if ((Test-Path -LiteralPath $layout.manifest_path) -and (Test-Path -LiteralPath $layout.complete_marker_path)) {
            return
        }
        Ensure-Directory -Path $layout.report_root
        if (-not (Test-Path -LiteralPath $layout.stdout_path)) {
            Write-TextFileAtomically -Path $layout.stdout_path -Content ''
        }
        if (-not (Test-Path -LiteralPath $layout.stderr_path)) {
            Write-TextFileAtomically -Path $layout.stderr_path -Content $FailureReason
        }
        if (-not (Test-Path -LiteralPath $layout.toolchain_path)) {
            Write-BuildReleaseToolchainReport -Layout $layout
        }
        $stderrTail = Get-FileTailOrEmpty -Path $layout.stderr_path
        Write-BuildReleaseReport -Layout $layout -Status 'fail' -Reason $FailureReason -ExitCode 1 -StderrTail $stderrTail
    }
    catch {
        # Preserve the original failure as the dominant root cause.
    }
}

function Get-LocalizedAccountNameFromSid {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        throw "failed to translate Windows SID $Sid to a localized account name: $($_.Exception.Message)"
    }
}

function Get-CurrentInteractiveUserName {
    try {
        return [string]((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName)
    }
    catch {
        return ''
    }
}

# Verify that an interactive Windows session is available (Active or Disconnected).
# Returns the resolved user name, or empty string if no session exists.
#
# Background: Win32_ComputerSystem.UserName is non-empty even when the
# interactive session has been disconnected or the lock screen is up.
# For RDP/remote, Scheduled Task with LogonType=Interactive may not run on
# disconnected sessions. But for console (e.g., UTM), Disconnected sessions
# are still active console sessions and can run interactive tasks.
#
# This function accepts both 'Active' and 'Disconnected' states to support
# console-based VM environments (UTM, KVM) where the session is legitimately
# accessible via console even if not in 'Active' state.
function Get-ActiveInteractiveUserSessionName {
    try {
        $quserOutput = (& quser.exe 2>$null | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($quserOutput)) {
            return ''
        }
        $lines = $quserOutput -split "`r?`n"
        # Skip header line; columns vary by locale, so match on STATE token
        # Accept 'Active' or 'Disconnected' (for console sessions).
        foreach ($line in $lines | Select-Object -Skip 1) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                continue
            }
            $tokens = $trimmed -split '\s+'
            # Accept Active or Disconnected session states
            if ($tokens -contains 'Active' -or $tokens -contains 'Disconnected') {
                $userToken = $tokens[0]
                if ($userToken.StartsWith('>')) {
                    $userToken = $userToken.Substring(1)
                }
                if (-not [string]::IsNullOrWhiteSpace($userToken)) {
                    return $userToken.Trim()
                }
            }
        }
        return ''
    }
    catch {
        return ''
    }
}

function Test-SystemExecutionContext {
    return [string]::Equals($env:USERNAME, 'SYSTEM', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-SystemProfileExecutionContext {
    if (-not $env:USERPROFILE) {
        return $false
    }
    return $env:USERPROFILE.IndexOf('\systemprofile', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Resolve-BootstrapScriptSelfPath {
    if ($PSCommandPath -and $PSCommandPath.Trim().Length -gt 0) {
        return $PSCommandPath
    }
    if ($MyInvocation.MyCommand.Path -and $MyInvocation.MyCommand.Path.Trim().Length -gt 0) {
        return $MyInvocation.MyCommand.Path
    }
    throw 'failed to resolve Bootstrap-RustyNetWindows.ps1 self path'
}

function ConvertTo-PowerShellSingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    return ([string]::Concat("'", $Value.Replace("'", "''"), "'"))
}

function Get-WindowsBootstrapToolingState {
    $wingetCommand = Get-Command winget.exe -ErrorAction SilentlyContinue
    $cargoCommand = Get-Command cargo.exe -ErrorAction SilentlyContinue
    $rustcCommand = Get-Command rustc.exe -ErrorAction SilentlyContinue
    $rustupCommand = Get-Command rustup.exe -ErrorAction SilentlyContinue
    $vsDevCmdPath = Resolve-VsDevCmdPath
    $pwshPath = 'C:\Program Files\PowerShell\7\pwsh.exe'
    $interactiveUser = Get-CurrentInteractiveUserName
    $appInstallerPackages = @(
        Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
    )
    $windowsAppsMatches = @()
    if (Test-Path -LiteralPath 'C:\Program Files\WindowsApps') {
        $windowsAppsMatches = @(
            Get-ChildItem -LiteralPath 'C:\Program Files\WindowsApps' -Filter 'Microsoft.DesktopAppInstaller*' -ErrorAction SilentlyContinue |
                Select-Object -First 10 -ExpandProperty FullName
        )
    }
    return [ordered]@{
        os_caption = (Get-CimInstance Win32_OperatingSystem).Caption
        os_version = (Get-CimInstance Win32_OperatingSystem).Version
        ps_version = $PSVersionTable.PSVersion.ToString()
        current_username = $env:USERNAME
        current_userdomain = $env:USERDOMAIN
        current_userprofile = $env:USERPROFILE
        interactive_user = $interactiveUser
        interactive_user_present = ($interactiveUser.Trim().Length -gt 0)
        system_execution_context = (Test-SystemExecutionContext)
        systemprofile_execution_context = (Test-SystemProfileExecutionContext)
        interactive_build_bootstrap_child = [bool]$InteractiveBuildBootstrapChild
        path = $env:PATH
        winget_command_present = [bool]$wingetCommand
        winget_command_source = if ($wingetCommand) { $wingetCommand.Source } else { '' }
        appinstaller_present = ($appInstallerPackages.Count -gt 0)
        appinstaller_packages = @(
            $appInstallerPackages | ForEach-Object {
                [ordered]@{
                    Name = $_.Name
                    PackageFullName = $_.PackageFullName
                    PackageFamilyName = $_.PackageFamilyName
                    Version = $_.Version.ToString()
                    Status = $_.Status.ToString()
                }
            }
        )
        windowsapps_matches = @($windowsAppsMatches)
        cargo_present = [bool]$cargoCommand
        cargo_source = if ($cargoCommand) { $cargoCommand.Source } else { '' }
        rustc_present = [bool]$rustcCommand
        rustc_source = if ($rustcCommand) { $rustcCommand.Source } else { '' }
        rustup_present = [bool]$rustupCommand
        rustup_source = if ($rustupCommand) { $rustupCommand.Source } else { '' }
        powershell7_present = (Test-Path -LiteralPath $pwshPath)
        powershell7_path = if (Test-Path -LiteralPath $pwshPath) { $pwshPath } else { '' }
        vsdevcmd_present = [bool]$vsDevCmdPath
        vsdevcmd_path = if ($vsDevCmdPath) { $vsDevCmdPath } else { '' }
    }
}

function Try-Register-WingetFromAppInstaller {
    $registration = [ordered]@{
        attempted = $false
        succeeded = $false
        reason = ''
    }
    $appInstallerPackages = @(
        Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
    )
    if ($appInstallerPackages.Count -eq 0) {
        $registration.reason = 'appinstaller-package-missing'
        return $registration
    }

    $registration.attempted = $true
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe' -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
    }
    catch {
        $registration.reason = $_.Exception.Message.Trim()
        return $registration
    }

    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
        $registration.succeeded = $true
        return $registration
    }

    $registration.reason = 'winget-command-still-missing-after-registration'
    return $registration
}

function Require-Winget {
    $state = Get-WindowsBootstrapToolingState
    if ($state.winget_command_present) {
        return $state
    }

    $registration = Try-Register-WingetFromAppInstaller
    $state = Get-WindowsBootstrapToolingState
    if ($state.winget_command_present) {
        return $state
    }

    $reasons = @()
    if (-not $state.appinstaller_present) {
        $reasons += 'App Installer package is not installed on this Windows image'
    }
    else {
        $reasons += 'App Installer package is present but winget.exe is not registered for this user or session'
    }
    if ($registration.attempted -and $registration.reason) {
        $reasons += ('registration_attempt=' + $registration.reason)
    }
    throw ('winget.exe is not available; ' + ($reasons -join '; ') + '; install App Installer or use a pre-baked Windows lab template')
}

function Format-WindowsBootstrapToolingStateReport {
    param([Parameter(Mandatory = $true)]$State)

    $lines = @(
        '## bootstrap-tooling-state',
        ($State | ConvertTo-Json -Depth 6),
        ''
    )
    foreach ($commandText in @(
        'where.exe winget',
        'where.exe cargo',
        'where.exe rustc',
        'where.exe cl',
        'cargo.exe --version',
        'rustc.exe --version',
        'rustup.exe show active-toolchain'
    )) {
        $lines += "## $commandText"
        try {
            $lines += (cmd.exe /c $commandText 2>&1 | Out-String).TrimEnd()
        }
        catch {
            $lines += ($_ | Out-String).TrimEnd()
        }
        $lines += ''
    }
    return ($lines -join "`r`n")
}

function Invoke-BuildReleaseViaInteractiveUserTask {
    param([Parameter(Mandatory = $true)]$Layout)

    $interactiveUser = (Get-CurrentInteractiveUserName).Trim()
    if ($interactiveUser.Length -eq 0) {
        throw 'interactive Windows user session is not available; log into the guest as an administrator or use a pre-baked Windows lab template'
    }

    # Fail fast when the OS reports a "logged on" user (Win32_ComputerSystem.UserName)
    # but no session is in 'Active' state per quser. In that case the
    # Scheduled Task we are about to register cannot actually run, and the
    # poll loop below would block for 4 hours waiting on a complete.marker
    # that will never appear. Detect now and surface a precise error so the
    # operator can sign into the desktop and re-run.
    $activeSessionUser = (Get-ActiveInteractiveUserSessionName).Trim()
    if ($activeSessionUser.Length -eq 0) {
        throw ([string]::Concat(
            'no Active interactive Windows session detected (Win32_ComputerSystem.UserName=',
            $interactiveUser,
            ' but quser reports no Active session); ',
            'Bootstrap-RustyNetWindows.ps1 -Phase build-release requires an interactive desktop ',
            'session to run cargo via Scheduled Task with LogonType=Interactive. ',
            'Sign into the Windows VM console (UTM) as ', $interactiveUser,
            ' and re-run the orchestrator.'
        ))
    }

    $taskName = [string]::Concat('RustyNet-BuildRelease-', [guid]::NewGuid().ToString('N'))
    $taskScriptPath = Join-Path $Layout.report_root 'build-release-interactive-task.ps1'
    $bootstrapScriptPath = Resolve-BootstrapScriptSelfPath
    $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $psExe)) {
        $psExe = 'powershell.exe'
    }

    $taskLines = @(
        'Set-StrictMode -Version Latest'
        "$ErrorActionPreference = 'Stop'"
        "$ProgressPreference = 'SilentlyContinue'"
    )
    $invocation = @(
        '&',
        (ConvertTo-PowerShellSingleQuotedLiteral $bootstrapScriptPath),
        '-Phase', "'build-release'",
        '-RustyNetRoot', (ConvertTo-PowerShellSingleQuotedLiteral $RustyNetRoot),
        '-InstallRoot', (ConvertTo-PowerShellSingleQuotedLiteral $InstallRoot),
        '-StateRoot', (ConvertTo-PowerShellSingleQuotedLiteral $StateRoot),
        '-ServiceName', (ConvertTo-PowerShellSingleQuotedLiteral $ServiceName),
        '-ResultPath', (ConvertTo-PowerShellSingleQuotedLiteral $Layout.manifest_path),
        '-InteractiveBuildBootstrapChild'
    )
    if ($WingetConfigPath -and $WingetConfigPath.Trim().Length -gt 0) {
        $invocation += @('-WingetConfigPath', (ConvertTo-PowerShellSingleQuotedLiteral $WingetConfigPath))
    }
    if ($VsConfigPath -and $VsConfigPath.Trim().Length -gt 0) {
        $invocation += @('-VsConfigPath', (ConvertTo-PowerShellSingleQuotedLiteral $VsConfigPath))
    }
    if ($InstallPowerShell7) {
        $invocation += '-InstallPowerShell7'
    }
    $taskLines += ($invocation -join ' ')
    $taskLines += 'exit $LASTEXITCODE'
    Write-TextFileAtomically -Path $taskScriptPath -Content ($taskLines -join "`r`n")

    $quotedTaskScriptPath = [string]::Concat('"', $taskScriptPath.Replace('"', '""'), '"')
    $action = New-ScheduledTaskAction `
        -Execute $psExe `
        -Argument ([string]::Concat('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ', $quotedTaskScriptPath))
    $principal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4)

    $finishedWithoutReportCount = 0
    $lastTaskResult = $null
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $deadline = (Get-Date).AddHours(4)
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path -LiteralPath $Layout.manifest_path) -and (Test-Path -LiteralPath $Layout.complete_marker_path)) {
                return
            }

            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            if ($taskInfo) {
                $lastTaskResult = [int]$taskInfo.LastTaskResult
            }
            if ($task -and $task.State -ne 'Running' -and $taskInfo -and $taskInfo.LastRunTime -gt [datetime]::MinValue) {
                $finishedWithoutReportCount += 1
                if ($finishedWithoutReportCount -ge 3) {
                    break
                }
            }
            else {
                $finishedWithoutReportCount = 0
            }

            Start-Sleep -Seconds 2
        }

        $lastTaskResultSuffix = if ($null -ne $lastTaskResult) {
            [string]::Concat(' last_task_result=', [string]$lastTaskResult)
        }
        else {
            ''
        }
        throw ([string]::Concat(
            'interactive build bootstrap task did not write a complete build report for ',
            $interactiveUser,
            ': ',
            $Layout.manifest_path,
            $lastTaskResultSuffix
        ))
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -LiteralPath $taskScriptPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [string]$Override = ''
    )
    Require-Winget | Out-Null
    $args = @(
        'install',
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--disable-interactivity',
        '-e',
        '--id',
        $Id
    )
    if ($Override -and $Override.Trim().Length -gt 0) {
        $args += @('--override', $Override)
    }
    & winget @args
    if ($LASTEXITCODE -ne 0) {
        throw "winget install failed for package id: $Id"
    }
}

function Ensure-PowerShell7 {
    $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (Test-Path -LiteralPath $pwsh) {
        return
    }
    if (-not $InstallPowerShell7) {
        throw 'PowerShell 7 is not installed and -InstallPowerShell7 was not supplied'
    }
    Invoke-WingetInstall -Id 'Microsoft.PowerShell'
    if (-not (Test-Path -LiteralPath $pwsh)) {
        throw 'PowerShell 7 is still unavailable after winget installation attempt'
    }
}

function Resolve-SshdExecutablePath {
    $command = Get-Command sshd.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $candidates = @(
        'C:\Windows\System32\OpenSSH\sshd.exe',
        'C:\Program Files\OpenSSH-Win64\sshd.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Resolve-DefaultShellPath {
    if ($SetDefaultShellToPowerShell7) {
        Ensure-PowerShell7
        return 'C:\Program Files\PowerShell\7\pwsh.exe'
    }
    if ($SetDefaultShellToPowerShell) {
        return 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    return $null
}

function Ensure-OpenSshDefaultShell {
    $expectedShell = Resolve-DefaultShellPath
    if (-not $expectedShell) {
        return $true
    }
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -PropertyType String -Value $expectedShell -Force | Out-Null
    $configured = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name 'DefaultShell' -ErrorAction Stop).DefaultShell
    return ([string]$configured -eq $expectedShell)
}

function Repair-SshProtectedFileAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    # icacls /setowner needs SeRestorePrivilege which a UAC-filtered
    # Administrator token doesn't have. Best-effort: try to flip ownership
    # to BUILTIN\Administrators (so admins can manage the file later) but
    # keep going on failure — sshd validates the DACL, not the owner, so
    # leaving ownership as the current user is acceptable.
    # 2>$null (discard stderr) — see comment in Ensure-AuthorizedKeys for
    # why merging stderr into the pipeline would mask our $LASTEXITCODE
    # gates.
    & icacls $Path /setowner $AdministratorsName 2>$null | Out-Null
    & icacls $Path /inheritance:r 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "[E6-repair-inheritance] icacls /inheritance:r failed for $Path (LASTEXITCODE=$LASTEXITCODE)"
    }
    & icacls $Path /grant:r "$AdministratorsName`:F" "$LocalSystemName`:F" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "[E7-repair-grant] icacls /grant:r failed for $Path (LASTEXITCODE=$LASTEXITCODE)"
    }
}

function Ensure-AuthorizedKeys {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKey,
        [Parameter(Mandatory = $true)][string]$AdministratorsName,
        [Parameter(Mandatory = $true)][string]$LocalSystemName
    )

    $trimmedKey = $PublicKey.Trim()
    if (-not $trimmedKey) {
        return $false
    }
    $adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    $sshDir = Split-Path -Parent $adminKeys
    if (-not (Test-Path -LiteralPath $sshDir)) {
        New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
    }
    # 1. Release any sshd-held file lock on administrators_authorized_keys.
    #    sshd can keep the file open in shared mode after a previous run; a
    #    truncate-write from this script then trips "Access is denied". The
    #    later sshd restart (Set-Service / Start-Service) re-reads the new
    #    contents on its next accept().
    try {
        $existingService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
        if ($null -ne $existingService -and $existingService.Status -eq 'Running') {
            Stop-Service -Name 'sshd' -Force -ErrorAction Stop
        }
    } catch {
        throw "[E1-stop-sshd] stop pre-existing sshd before authorized_keys write failed: $($_.Exception.Message)"
    }
    # 2. Make sure Administrators has Modify on the parent dir. /grant only
    #    needs WRITE_DAC on the target — Administrators already has that on
    #    the OpenSSH-installed dir — so no SeRestorePrivilege required and
    #    this works from a UAC-filtered Administrator token. We deliberately
    #    skip icacls /setowner because that DOES need SeRestorePrivilege
    #    which the filtered token lacks; the existing
    #    Repair-SshProtectedFileAcl below re-tightens the DACL to the
    #    OpenSSH-default once we're done writing.
    # Discard stderr instead of `2>&1`. With $ErrorActionPreference='Stop',
    # merging stderr into the pipeline lets PowerShell raise a terminating
    # error from native-command stderr text BEFORE the $LASTEXITCODE check
    # below runs — masking our own throw with bare icacls output. 2>$null
    # discards stderr entirely so the gate is just the exit code.
    & icacls $sshDir /grant "${AdministratorsName}:(OI)(CI)M" /C 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "[E2-grant-dir] icacls /grant Administrators:M on ${sshDir} failed (LASTEXITCODE=${LASTEXITCODE})"
    }
    # 3. Remove any pre-existing file. We've now got Modify on the dir, so
    #    delete works. This also drops a sticky restrictive ACL the file
    #    might have inherited from a prior failed bootstrap.
    if (Test-Path -LiteralPath $adminKeys) {
        try {
            Remove-Item -LiteralPath $adminKeys -Force -ErrorAction Stop
        } catch {
            throw "[E3-remove-file] remove pre-existing ${adminKeys} failed: $($_.Exception.Message)"
        }
    }
    # 4. Write the new content fresh.
    try {
        Set-Content -LiteralPath $adminKeys -Encoding ascii -Value ($trimmedKey + "`r`n") -ErrorAction Stop
    } catch {
        throw "[E4-set-content] Set-Content ${adminKeys} failed: $($_.Exception.Message)"
    }
    # 5. Read back BEFORE tightening the DACL. With a UAC-filtered
    #    Administrator token, Administrators is a deny-only SID — the
    #    post-Repair DACL of "SYSTEM:F + Administrators:F" then locks the
    #    current process out of its own freshly-written file. Verify content
    #    here while we still own the file and Modify is granted.
    $actual = ''
    try {
        $actual = (Get-Content -LiteralPath $adminKeys -Raw -ErrorAction Stop).Trim()
    } catch {
        throw "[E5-readback] readback of ${adminKeys} failed: $($_.Exception.Message)"
    }
    if ($actual -ne $trimmedKey) {
        return $false
    }
    # 6. Now tighten the file DACL to the hardened
    #    SYSTEM+Administrators-only profile expected by sshd. The /setowner
    #    inside Repair-SshProtectedFileAcl is best-effort; the /grant:r
    #    DACL update is what sshd actually validates.
    Repair-SshProtectedFileAcl -Path $adminKeys -AdministratorsName $AdministratorsName -LocalSystemName $LocalSystemName
    return $true
}

function Ensure-OpenSshFirewallRule {
    $ruleName = 'OpenSSH-Server-In-TCP'
    $displayName = 'OpenSSH Server (RustyNet vm-lab)'

    $testRule = {
        param($Rule)
        if (-not $Rule) {
            return $false
        }
        $matchingPortFilter = $Rule |
            Get-NetFirewallPortFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Protocol -eq 'TCP' -and [string]$_.LocalPort -eq '22' } |
            Select-Object -First 1
        return ($Rule.Enabled -eq 'True' -and $Rule.Direction -eq 'Inbound' -and $Rule.Action -eq 'Allow' -and $null -ne $matchingPortFilter)
    }

    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($rule -and -not (& $testRule $rule)) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop | Out-Null
        $rule = $null
    }
    if (-not $rule) {
        New-NetFirewallRule -Name $ruleName -DisplayName $displayName -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    } else {
        Set-NetFirewallRule -Name $ruleName -Enabled True -Direction Inbound -Action Allow | Out-Null
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    }
    return (& $testRule $rule)
}

function Test-SshdConfiguration {
    param([Parameter(Mandatory = $true)][string]$SshdPath)

    $validationOutput = & $SshdPath -t 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return @{
            Valid = $false
            Reason = 'invalid-sshd-config'
            Details = $validationOutput.Trim()
        }
    }
    return @{
        Valid = $true
        Reason = 'ok'
        Details = ''
    }
}

function Test-SshListenerReady {
    $listeners = @(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)
    return ($listeners.Count -gt 0)
}

function Get-TransportHostKeyLine {
    $hostKeyPath = 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub'
    if (Test-Path -LiteralPath $hostKeyPath) {
        return ((Get-Content -LiteralPath $hostKeyPath -Raw -ErrorAction Stop).Trim())
    }
    return ''
}

function Get-PrepareTransportReport {
    param([string]$PublicKey = '')

    $administratorsName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-32-544'
    $localSystemName = Get-LocalizedAccountNameFromSid -Sid 'S-1-5-18'
    $authorizedKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
    $report = New-PrepareTransportFailureReport -Reason 'prepare-transport-not-run'
    try {
        Ensure-Directory -Path 'C:\ProgramData\ssh'

        $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
        if (-not $sshCapability -or $sshCapability.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
            $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
        }
        $report.openssh_installed = [bool]($sshCapability -and $sshCapability.State -eq 'Installed')
        if (-not $report.openssh_installed) {
            $report.reason = 'openssh-server-not-installed'
            return $report
        }

        $report.default_shell_configured = Ensure-OpenSshDefaultShell
        if (-not $report.default_shell_configured) {
            $report.reason = 'default-shell-not-configured'
            return $report
        }

        $trimmedPublicKey = $PublicKey.Trim()
        if ($trimmedPublicKey.Length -gt 0) {
            $report.authorized_keys_applied = Ensure-AuthorizedKeys -PublicKey $trimmedPublicKey -AdministratorsName $administratorsName -LocalSystemName $localSystemName
            if (-not $report.authorized_keys_applied) {
                $report.reason = 'authorized-keys-not-applied'
                return $report
            }
        } elseif (Test-Path -LiteralPath $authorizedKeysPath) {
            Repair-SshProtectedFileAcl -Path $authorizedKeysPath -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }

        foreach ($path in @('C:\ProgramData\ssh\sshd_config')) {
            Repair-SshProtectedFileAcl -Path $path -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }
        foreach ($path in @(Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)) {
            Repair-SshProtectedFileAcl -Path $path -AdministratorsName $administratorsName -LocalSystemName $localSystemName
        }

        $report.firewall_rule_enabled = Ensure-OpenSshFirewallRule
        if (-not $report.firewall_rule_enabled) {
            $report.reason = 'firewall-rule-not-enabled'
            return $report
        }

        $sshdPath = Resolve-SshdExecutablePath
        if (-not $sshdPath) {
            $report.reason = 'sshd-command-unavailable'
            return $report
        }

        $configValidation = Test-SshdConfiguration -SshdPath $sshdPath
        if (-not $configValidation.Valid) {
            $report.reason = [string]$configValidation.Reason
            return $report
        }

        Set-Service -Name sshd -StartupType Automatic
        $service = Get-Service -Name sshd -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            Restart-Service -Name sshd -ErrorAction Stop
        } else {
            Start-Service -Name sshd -ErrorAction Stop
        }
        Start-Sleep -Seconds 2

        $service = Get-Service -Name sshd -ErrorAction Stop
        $report.service_running = ($service.Status -eq 'Running')
        if (-not $report.service_running) {
            $report.reason = 'sshd-service-not-running'
            return $report
        }

        $report.listener_ready = Test-SshListenerReady
        if (-not $report.listener_ready) {
            $report.reason = 'ssh-listener-not-ready'
            return $report
        }

        $report.host_key = Get-TransportHostKeyLine
        $report.host_key_present = ($report.host_key.Length -gt 0)
        if (-not $report.host_key_present) {
            $report.reason = 'host-key-unavailable'
            return $report
        }

        $report.status = 'pass'
        $report.reason = 'ok'
        return $report
    }
    catch {
        $report.reason = [string]::Concat('prepare-transport-exception: ', $_.Exception.Message)
        return $report
    }
}

function Resolve-WingetConfigurationPath {
    param([string]$ConfigPath = '')
    if ($ConfigPath -and $ConfigPath.Trim().Length -gt 0) {
        return $ConfigPath
    }
    return (Join-Path $PSScriptRoot 'RustyNetBootstrap.winget.yml')
}

function Resolve-VsConfigPath {
    param([string]$ConfigPath = '')
    if ($ConfigPath -and $ConfigPath.Trim().Length -gt 0) {
        return $ConfigPath
    }
    return (Join-Path $PSScriptRoot 'RustyNetBuildTools.vsconfig')
}

function Resolve-InstallHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Install-RustyNetWindowsService.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows install helper not found: $candidate"
    }
    return $candidate
}

function Resolve-VerifyHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Verify-RustyNetWindowsBootstrap.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows verify helper not found: $candidate"
    }
    return $candidate
}

function Resolve-DiagnosticsHelperPath {
    $candidate = Join-Path $PSScriptRoot 'Collect-RustyNetWindowsDiagnostics.ps1'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Windows diagnostics helper not found: $candidate"
    }
    return $candidate
}

function Ensure-WingetConfigurationDependencies {
    param([string]$ConfigPath = '')
    $candidate = Resolve-WingetConfigurationPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "WinGet configuration file not found: $candidate"
    }
    Require-Winget | Out-Null
    & winget configure --file $candidate --accept-configuration-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) {
        throw 'winget configure failed for RustyNet bootstrap configuration'
    }
    Assert-RustyNetWingetDependenciesInstalled
}

# After winget configure reports success, double-check that every
# package the RustyNet bootstrap depends on actually landed at the
# canonical path the install helper + daemon expect. winget can
# return success when an individual package install is "best-effort"
# OR when a previous run's cached state masks a partial failure;
# explicit post-install verification means a degraded bootstrap
# fails loud here rather than silently producing an install where
# the daemon falls back to `windows-unsupported` (because WireGuard
# wasn't actually installed).
function Assert-RustyNetWingetDependenciesInstalled {
    $missing = @()

    # WireGuard for Windows — the daemon's `windows-wireguard-nt`
    # backend shells out to wireguard.exe / wg.exe. Use multi-path
    # resolvers so an installer that picks the (x86) tree, or a
    # pre-baked image with a non-default location, still validates.
    if (-not (Resolve-WireGuardExePath)) {
        $missing += 'WireGuard.WireGuard (wireguard.exe not found at any known canonical path)'
    }
    if (-not (Resolve-WireGuardCliPath)) {
        $missing += 'WireGuard.WireGuard cli (wg.exe not found at any known canonical path)'
    }

    # Rustup — Resolve-RustupExePath checks PATH plus the canonical
    # rustup install (USERPROFILE\.cargo\bin) plus scoop / chocolatey
    # alternates.
    if (-not (Resolve-RustupExePath)) {
        $missing += 'Rustlang.Rustup (rustup.exe not found at any known canonical path)'
    }

    # Git — the source-sync flow uses git directly. Resolve via PATH
    # plus Program Files\Git\{cmd,bin}.
    if (-not (Resolve-GitExePath)) {
        $missing += 'Git.Git (git.exe not found at any known canonical path)'
    }

    if ($missing.Count -gt 0) {
        $list = $missing -join '; '
        throw ("RustyNet winget bootstrap reported success but the following packages did NOT install at their reviewed canonical paths: $list. Re-run the bootstrap; if the failure persists, install the package manually from its vendor's official source per documents/operations/WindowsWorkingNodeBringUpRunbook.md before continuing.")
    }
}

# Resolve the toolchain bin directory on disk in priority order:
#   1. machine-scope CARGO_HOME\bin if CARGO_HOME is set in the env
#   2. canonical lab-image path C:\CargoHome\bin
#   3. user-profile fallback %USERPROFILE%\.cargo\bin
# Returns the first existing dir, or empty string if none exist.
# Used by both Ensure-CargoOnPath and the Resolve-* helpers so the
# decision is made in one place.
function Resolve-MachineScopedCargoBinDir {
    $candidates = @()
    if ($env:CARGO_HOME -and $env:CARGO_HOME.Trim().Length -gt 0) {
        $candidates += (Join-Path $env:CARGO_HOME 'bin')
    }
    $candidates += 'C:\CargoHome\bin'
    if ($env:USERPROFILE -and $env:USERPROFILE.Trim().Length -gt 0) {
        $candidates += (Join-Path $env:USERPROFILE '.cargo\bin')
    }
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Ensure-CargoOnPath {
    # Machine-scoped tools (lab image standard) win over user-profile
    # installs because the machine path is visible to SYSTEM-context
    # bootstrap runs.  When CARGO_HOME is set in machine env, honor it;
    # otherwise probe the canonical lab-image path C:\CargoHome\bin
    # before falling back to %USERPROFILE%\.cargo\bin.
    $cargoBin = Resolve-MachineScopedCargoBinDir
    if ($cargoBin -and (-not ($env:PATH -split ';' | Where-Object { $_ -ieq $cargoBin }))) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is not available after bootstrap"
    }
}

function Test-CommandPresent {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-VsDevCmdPath {
    # Lab-image canonical install at C:\BuildTools wins.  Falls through
    # to the standard Visual Studio 2022 install paths so this resolver
    # also works on developer machines and pre-existing Windows hosts
    # that have a normal Visual Studio installation.
    $candidates = @(
        'C:\BuildTools\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat'
    )
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

# Build the candidate list for a Rust toolchain binary in the same
# priority order Resolve-MachineScopedCargoBinDir uses, with fallbacks
# for non-image hosts (scoop, chocolatey, alternate users).
function Get-RustToolchainBinaryCandidates {
    param([Parameter(Mandatory = $true)][string]$ExeName)
    $candidates = @()
    if ($env:CARGO_HOME -and $env:CARGO_HOME.Trim().Length -gt 0) {
        $candidates += (Join-Path (Join-Path $env:CARGO_HOME 'bin') $ExeName)
    }
    $candidates += (Join-Path 'C:\CargoHome\bin' $ExeName)
    if ($env:USERPROFILE -and $env:USERPROFILE.Trim().Length -gt 0) {
        $candidates += (Join-Path (Join-Path $env:USERPROFILE '.cargo\bin') $ExeName)
    }
    $candidates += (Join-Path 'C:\Users\Administrator\.cargo\bin' $ExeName)
    $candidates += (Join-Path 'C:\.cargo\bin' $ExeName)
    if ($env:LOCALAPPDATA -and $env:LOCALAPPDATA.Trim().Length -gt 0) {
        $candidates += (Join-Path (Join-Path $env:LOCALAPPDATA 'scoop\apps\rustup\current\.cargo\bin') $ExeName)
    }
    $candidates += (Join-Path 'C:\ProgramData\chocolatey\lib\rust\tools\bin' $ExeName)
    return $candidates
}

# Multi-path lookup for cargo.exe. Checks PATH first (fastest), then the
# canonical rustup install path under USERPROFILE, then a couple of common
# alternates that surface when Rust is installed via scoop / chocolatey /
# pre-baked images. Returns the resolved file path, or empty string if
# absent. Use this in preference to Test-CommandPresent for tools the
# orchestrator depends on, because Test-CommandPresent only checks PATH —
# whereas a fresh OpenSSH login session may not have ~\.cargo\bin on PATH
# even when the binary is present at its canonical location.
function Resolve-CargoExePath {
    $cmd = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return (Get-RustToolchainBinaryCandidates -ExeName 'cargo.exe' |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Resolve-RustcExePath {
    $cmd = Get-Command rustc.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return (Get-RustToolchainBinaryCandidates -ExeName 'rustc.exe' |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Resolve-RustupExePath {
    $cmd = Get-Command rustup.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return (Get-RustToolchainBinaryCandidates -ExeName 'rustup.exe' |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Resolve-WireGuardExePath {
    $cmd = Get-Command wireguard.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        'C:\Program Files\WireGuard\wireguard.exe',
        'C:\Program Files (x86)\WireGuard\wireguard.exe'
    )
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Resolve-WireGuardCliPath {
    $cmd = Get-Command wg.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        'C:\Program Files\WireGuard\wg.exe',
        'C:\Program Files (x86)\WireGuard\wg.exe'
    )
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Resolve-GitExePath {
    $cmd = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files (x86)\Git\cmd\git.exe',
        'C:\Program Files\Git\bin\git.exe'
    )
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

# Add Windows Defender real-time-scan exclusions for the build paths the
# RustyNet bootstrap touches. Defender scanning every cargo intermediate
# (.rmeta / .rlib / .d / .obj / link.exe outputs) under real-time monitoring
# can stretch a 2-minute incremental build into a 30-minute hang. Idempotent:
# Add-MpPreference -ExclusionPath silently no-ops if the path is already
# excluded.
#
# Best-effort: a non-elevated SSH session running cargo cannot modify
# Defender preferences; in that case Set-MpPreference fails and the bootstrap
# continues without exclusions, surfacing a warning so the operator sees
# why subsequent runs may be slow. Setup-RustyNetWindowsHost.ps1 handles the
# elevated first-time install.
function Ensure-DefenderExclusionsForBuildPaths {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Output '[bootstrap] Add-MpPreference unavailable; skipping Defender exclusions.'
        return
    }
    $paths = @(
        $RustyNetRoot,
        (Join-Path $env:USERPROFILE '.cargo'),
        'C:\Windows\Temp\rustynet-stage',
        $StateRoot,
        $InstallRoot
    )
    foreach ($path in $paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        }
        catch {
            $msg = $_.Exception.Message
            # 'Access is denied' = non-elevated session; expected when the
            # orchestrator drives bootstrap as a regular user.
            if ($msg -match 'denied' -or $msg -match 'requires.*elevation') {
                Write-Output ('[bootstrap] Defender exclusion for ' + $path + ' skipped (not elevated).')
                return
            }
            if ($msg -notmatch 'already' -and $msg -notmatch 'duplicate') {
                Write-Output ('[bootstrap] WARNING: Add-MpPreference ' + $path + ' failed: ' + $msg)
            }
        }
    }
}

function Ensure-BuildTools {
    param([string]$ConfigPath = '')
    if (Resolve-VsDevCmdPath) {
        return
    }
    $effectiveConfig = Resolve-VsConfigPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $effectiveConfig)) {
        throw "Visual Studio build tools config not found: $effectiveConfig"
    }
    Invoke-WingetInstall -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override "--passive --wait --config `"$effectiveConfig`""
    if (-not (Resolve-VsDevCmdPath)) {
        throw 'VsDevCmd.bat not found after Build Tools installation attempt'
    }
}

function Enter-VsBuildEnvironment {
    $devCmd = Resolve-VsDevCmdPath
    if (-not $devCmd) {
        throw 'VsDevCmd.bat not found; Build Tools do not appear to be installed correctly'
    }
    foreach ($line in (cmd.exe /s /c "`"$devCmd`" -arch=x64 -host_arch=x64 >nul && set")) {
        if ($line -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

function Sync-SourceGit {
    if (-not $RepoUrl -or $RepoUrl.Trim().Length -eq 0) {
        throw 'Git source mode requires -RepoUrl'
    }
    Ensure-WingetConfigurationDependencies -ConfigPath $WingetConfigPath
    Ensure-CargoOnPath
    Require-Command -Name git.exe

    $parent = Split-Path -Parent $RustyNetRoot
    if ($parent -and $parent.Trim().Length -gt 0) {
        Ensure-Directory -Path $parent
    }
    if (-not (Test-Path -LiteralPath $RustyNetRoot)) {
        New-Item -ItemType Directory -Force -Path $RustyNetRoot | Out-Null
    }

    if (-not (Test-Path -LiteralPath (Join-Path $RustyNetRoot '.git'))) {
        if ((Get-ChildItem -LiteralPath $RustyNetRoot -Force | Measure-Object).Count -gt 0) {
            throw "RustyNet root exists but is not empty and not a git repository: $RustyNetRoot"
        }
        git clone --origin origin --branch $Branch --single-branch $RepoUrl $RustyNetRoot
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed for $RepoUrl"
        }
    }
    else {
        git -C $RustyNetRoot remote set-url origin $RepoUrl
        if ($LASTEXITCODE -ne 0) {
            throw "git remote set-url failed for $RepoUrl"
        }
        git -C $RustyNetRoot fetch origin $Branch --prune
        if ($LASTEXITCODE -ne 0) {
            throw "git fetch failed for branch $Branch"
        }
        git -C $RustyNetRoot checkout -B $Branch FETCH_HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "git checkout failed for branch $Branch"
        }
        git -C $RustyNetRoot reset --hard FETCH_HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "git reset failed for branch $Branch"
        }
        git -C $RustyNetRoot clean -fdx
        if ($LASTEXITCODE -ne 0) {
            throw "git clean failed for $RustyNetRoot"
        }
    }
}

function Sync-SourceArchive {
    if (-not $ArchiveZipPath -or $ArchiveZipPath.Trim().Length -eq 0) {
        throw 'Archive source mode requires -ArchiveZipPath'
    }
    if (-not (Test-Path -LiteralPath $ArchiveZipPath)) {
        throw "Archive ZIP not found: $ArchiveZipPath"
    }
    $parent = Split-Path -Parent $RustyNetRoot
    if ($parent -and $parent.Trim().Length -gt 0) {
        Ensure-Directory -Path $parent
    }
    if (Test-Path -LiteralPath $RustyNetRoot) {
        Remove-Item -LiteralPath $RustyNetRoot -Recurse -Force
    }
    Expand-Archive -LiteralPath $ArchiveZipPath -DestinationPath $RustyNetRoot -Force
}

function Build-RustyNet {
    $buildReportLayout = Get-BuildReleaseReportLayout -ManifestPath $ResultPath
    if ($null -ne $buildReportLayout) {
        Ensure-Directory -Path $buildReportLayout.report_root
        foreach ($path in @(
            $buildReportLayout.manifest_path,
            $buildReportLayout.complete_marker_path,
            $buildReportLayout.stdout_path,
            $buildReportLayout.stderr_path,
            $buildReportLayout.exit_code_path,
            $buildReportLayout.toolchain_path
        )) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Ensure-CargoOnPath
    # Add Defender exclusions for $RustyNetRoot, ~\.cargo, the orchestrator
    # staging dir, and the daemon state/install roots. Best-effort; non-
    # elevated sessions log and continue. The first-time-user setup script
    # (Setup-RustyNetWindowsHost.ps1) sets these once at install and is the
    # supported path; this idempotent call covers re-runs and lab images
    # where the setup script was not used.
    Ensure-DefenderExclusionsForBuildPaths
    if ($null -ne $buildReportLayout) {
        Write-BuildReleaseToolchainReport -Layout $buildReportLayout
    }
    # Multi-path tool resolution: an SSH session may have a stripped-down
    # PATH that hides ~\.cargo\bin even when cargo is installed there. The
    # resolver functions consult PATH first, then known canonical install
    # locations, so the bootstrap path keeps working under both cargo-on-
    # PATH and cargo-only-at-canonical-location conditions.
    $cargoPath = Resolve-CargoExePath
    $rustcPath = Resolve-RustcExePath
    $cargoPresent = [bool]$cargoPath
    $rustcPresent = [bool]$rustcPath
    $buildToolsPresent = [bool](Resolve-VsDevCmdPath)
    $systemScopedContext = (Test-SystemExecutionContext) -or (Test-SystemProfileExecutionContext)
    if (-not $InteractiveBuildBootstrapChild -and $null -ne $buildReportLayout -and $systemScopedContext -and (-not ($cargoPresent -and $rustcPresent -and $buildToolsPresent))) {
        if (-not $AllowInteractiveTaskFallback) {
            $missing = @()
            if (-not $cargoPresent)      { $missing += 'cargo.exe'      }
            if (-not $rustcPresent)      { $missing += 'rustc.exe'      }
            if (-not $buildToolsPresent) { $missing += 'VsDevCmd.bat'   }
            $missingDisplay = ($missing -join ', ')
            $cargoHint = if ($env:CARGO_HOME) { "CARGO_HOME=$($env:CARGO_HOME)" } else { 'CARGO_HOME unset' }
            throw ([string]::Concat(
                'Windows bootstrap build-release: SYSTEM-context build cannot resolve toolchain (',
                $missingDisplay, '). Install Rust + VS Build Tools machine-scoped on the lab image ',
                '(see Provision-RustyNetWindowsLabImage.ps1; canonical paths: C:\CargoHome\bin, ',
                'C:\BuildTools\Common7\Tools\VsDevCmd.bat). Current resolver context: ',
                $cargoHint, ', cargo=', [string]$cargoPath, ', rustc=', [string]$rustcPath, '. ',
                'Pass -AllowInteractiveTaskFallback to opt back into the legacy Scheduled Task ',
                'fallback for ad-hoc developer hosts where Rust lives in a user profile.'
            ))
        }
        Invoke-BuildReleaseViaInteractiveUserTask -Layout $buildReportLayout
        return
    }
    if (-not ($cargoPresent -and $rustcPresent -and $buildToolsPresent)) {
        Ensure-WingetConfigurationDependencies -ConfigPath $WingetConfigPath
    }
    Ensure-CargoOnPath
    Ensure-BuildTools -ConfigPath $VsConfigPath
    Ensure-CargoOnPath
    # Re-resolve via the multi-path lookup (Ensure-CargoOnPath only adds
    # USERPROFILE\.cargo\bin to PATH; the resolver also handles scoop /
    # chocolatey / Administrator-profile installs).
    $cargoPath = Resolve-CargoExePath
    $rustcPath = Resolve-RustcExePath
    if (-not $cargoPath) {
        throw 'cargo.exe is not available after bootstrap (checked PATH and known canonical install locations)'
    }
    if (-not $rustcPath) {
        throw 'rustc.exe is not available after bootstrap (checked PATH and known canonical install locations)'
    }
    Enter-VsBuildEnvironment
    if ($null -ne $buildReportLayout) {
        Write-BuildReleaseToolchainReport -Layout $buildReportLayout
    }

    if (-not (Test-Path -LiteralPath (Join-Path $RustyNetRoot 'Cargo.toml'))) {
        throw "RustyNet source tree is missing Cargo.toml: $RustyNetRoot"
    }

    $cargoCommand = $cargoPath
    # Build rustynetd (the Windows service host) and the minimal Windows
    # trust CLI used by Install-RustyNetWindowsService.ps1 to rotate
    # per-host trust evidence under SYSTEM at install-release time.  The
    # full ops CLI remains Unix-oriented; this Windows bin intentionally
    # exposes only `rustynet trust keygen/export-verifier-key/issue`.
    $daemonBuildArgs = @('build', '--locked', '--release', '-p', 'rustynetd')
    $trustCliBuildArgs = @('build', '--locked', '--release', '-p', 'rustynet-cli', '--bin', 'rustynet-windows-trust-cli')
    Push-Location $RustyNetRoot
    try {
        if ($null -eq $buildReportLayout) {
            & $cargoCommand $daemonBuildArgs
            if ($LASTEXITCODE -ne 0) {
                throw 'cargo build failed for Windows daemon build-release'
            }
            & $cargoCommand $trustCliBuildArgs
            if ($LASTEXITCODE -ne 0) {
                throw 'cargo build failed for Windows trust CLI build-release'
            }
            return
        }

        $exitCode = Invoke-CargoBuildForReport `
            -CargoCommand $cargoCommand `
            -CargoArgs $daemonBuildArgs `
            -Layout $buildReportLayout
        if ($exitCode -eq 0) {
            $exitCode = Invoke-CargoBuildForReport `
                -CargoCommand $cargoCommand `
                -CargoArgs $trustCliBuildArgs `
                -Layout $buildReportLayout `
                -Append
        }
        $stderrTail = Get-FileTailOrEmpty -Path $buildReportLayout.stderr_path
        if ($exitCode -eq 0) {
            Write-BuildReleaseReport -Layout $buildReportLayout -Status 'pass' -Reason 'ok' -ExitCode $exitCode -StderrTail $stderrTail
            return
        }
        $failureReason = ('cargo build failed for Windows build-release (exit_code={0})' -f $exitCode)
        Write-BuildReleaseReport -Layout $buildReportLayout -Status 'fail' -Reason $failureReason -ExitCode $exitCode -StderrTail $stderrTail
        throw $failureReason
    }
    finally {
        Pop-Location
    }
}

function Install-RustyNetRuntime {
    $helper = Resolve-InstallHelperPath
    $output = & $helper -RustyNetRoot $RustyNetRoot -InstallRoot $InstallRoot -StateRoot $StateRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows install helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if (-not $trimmed) {
        throw "Windows install helper produced no output for service: $ServiceName"
    }
    try {
        $parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Windows install helper emitted invalid JSON for service ${ServiceName}: $($_.Exception.Message)"
    }
    if ($parsed.status -ne 'pass') {
        $reason = if ($parsed.reason) { [string]$parsed.reason } else { 'install-failed' }
        throw "Windows install helper reported blocked status for service ${ServiceName}: $reason"
    }
    Write-Output $trimmed
}

function Restart-RustyNetRuntime {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "Windows runtime service is not installed: $ServiceName"
    }
    try {
        if ($service.Status -eq 'Running') {
            Restart-Service -Name $ServiceName -ErrorAction Stop
        }
        else {
            Start-Service -Name $ServiceName -ErrorAction Stop
        }
    }
    catch {
        Write-Output ("service-control-error=" + $_.Exception.Message)
    }
    Start-Sleep -Seconds 3
    Invoke-VerifyRuntime | Out-Null
}

function Invoke-VerifyRuntime {
    $helper = Resolve-VerifyHelperPath
    $output = & $helper -RustyNetRoot $RustyNetRoot -InstallRoot $InstallRoot -StateRoot $StateRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows verify helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if (-not $trimmed) {
        throw "Windows verify helper produced no output for service: $ServiceName"
    }
    try {
        $parsed = $trimmed | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Windows verify helper emitted invalid JSON for service ${ServiceName}: $($_.Exception.Message)"
    }
    if ($parsed.status -ne 'pass') {
        $reason = if ($parsed.reason) { [string]$parsed.reason } else { 'verification-failed' }
        throw "Windows verify helper reported blocked status for service ${ServiceName}: $reason"
    }
    Write-Output $trimmed
}

function Invoke-CollectDiagnostics {
    $helper = Resolve-DiagnosticsHelperPath
    $outputRoot = Join-Path $StateRoot 'vm-lab\diagnostics'
    $output = & $helper -OutputRoot $outputRoot -InstallRoot $InstallRoot -ServiceName $ServiceName | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "Windows diagnostics helper failed for service: $ServiceName"
    }
    $trimmed = $output.Trim()
    if ($trimmed.Length -gt 0) {
        Write-Output $trimmed
    }
}

function Invoke-BootstrapAll {
    if ($SourceMode -eq 'git') {
        Sync-SourceGit
    }
    else {
        Sync-SourceArchive
    }
    Build-RustyNet
    Install-RustyNetRuntime
    Restart-RustyNetRuntime
    Invoke-VerifyRuntime
}

switch ($Phase) {
    'prepare-transport' {
        $report = Get-PrepareTransportReport -PublicKey $AutomationPublicKey
        Write-JsonPhaseResult -Value $report
    }
    'sync-source' {
        if ($SourceMode -eq 'git') {
            Sync-SourceGit
        }
        else {
            Sync-SourceArchive
        }
    }
    'build-release' {
        Build-RustyNet
    }
    'install-release' {
        Install-RustyNetRuntime
    }
    'restart-runtime' {
        Restart-RustyNetRuntime
    }
    'verify-runtime' {
        Invoke-VerifyRuntime
    }
    'collect-diagnostics' {
        Invoke-CollectDiagnostics
    }
    'all' {
        Invoke-BootstrapAll
    }
}

@echo off
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "RG_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== PowerShell below: run RansomGuard automatically at sign-in =====
$ErrorActionPreference = 'Continue'
$Script   = Join-Path $env:RG_DIR 'ransom_guard.py'  # in the same folder as this .bat
$TaskName = 'RansomGuard'
$LogFile  = Join-Path $env:LOCALAPPDATA 'RansomGuard\guard.log'

function Done($code) { Write-Host ''; Read-Host 'Press Enter to close' | Out-Null; exit $code }
function Fail($msg)  { Write-Host ''; Write-Host "[Failed] $msg" -ForegroundColor Red; Done 1 }

try {
    Write-Host '=== RansomGuard: start automatically at sign-in ===' -ForegroundColor Cyan
    if (-not (Test-Path $Script)) { Fail "Not found: $Script" }

    Write-Host '[1/4] Looking for Python...'
    $py = $null
    $cands = @()
    $cands += Get-ChildItem "$env:LOCALAPPDATA\Python\pythoncore-*\python.exe" -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch '\d+t-' } | Sort-Object FullName -Descending | ForEach-Object { $_.FullName }
    $cands += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object { $_.FullName }
    $cands += @((Join-Path $env:RG_DIR '.venv\Scripts\python.exe'), 'py', 'python')
    foreach ($c in $cands) {
        try {
            $out = @(& $c -c 'import sys; print(sys.executable)' 2>$null)
            if ($LASTEXITCODE -eq 0 -and $out.Count -gt 0) {
                $p = "$($out[0])".Trim()
                if ($p -and (Test-Path $p)) { $py = $p; break }
            }
        } catch { }
    }
    if (-not $py) { Fail 'Python not found. Install Python (check "Add python.exe to PATH" during setup), then run this again.' }
    $pyw = Join-Path (Split-Path $py) 'pythonw.exe'
    if (-not (Test-Path $pyw)) { Fail "Not found: $pyw" }
    Write-Host "      Using $py"

    Write-Host '[2/4] Installing the watchdog package...'
    & $py -m pip install --upgrade --quiet --disable-pip-version-check watchdog
    & $py -c 'import watchdog'
    if ($LASTEXITCODE -ne 0) { Fail 'Failed to install watchdog. Run manually: pip install watchdog' }

    Write-Host '[3/4] Creating a scheduled task that runs at sign-in...'
    $user = "$env:USERDOMAIN\$env:USERNAME"
    # -E ignores PYTHON* environment variables; -P (Python 3.11+) doesn't load modules from the script's
    # folder, so a planted fake json.py there can't run with administrator rights
    $hasP = "$(& $py -c 'import sys; print(int(sys.version_info >= (3, 11)))')".Trim() -eq '1'
    $pyArgs = if ($hasP) { '-E -P ' } else { '-E ' }
    $action = New-ScheduledTaskAction -Execute $pyw -Argument ($pyArgs + '"' + $Script + '"') -WorkingDirectory (Split-Path $Script)
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $setArgs = @{
        AllowStartIfOnBatteries    = $true
        DontStopIfGoingOnBatteries = $true
        ExecutionTimeLimit         = [TimeSpan]::Zero
        MultipleInstances          = 'IgnoreNew'
        RestartCount               = 3
        RestartInterval            = (New-TimeSpan -Minutes 1)
    }
    $settings = New-ScheduledTaskSettingsSet @setArgs
    $regArgs = @{
        TaskName    = $TaskName
        Action      = $action
        Trigger     = $trigger
        Principal   = $principal
        Settings    = $settings
        Description = "Detects ransomware behavior and cuts off the network automatically ($Script)"
        Force       = $true
        ErrorAction = 'Stop'
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue  # stop the old version so the new one loads
    }
    Register-ScheduledTask @regArgs | Out-Null

    Write-Host '[4/4] Starting monitoring...'
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Start-Sleep -Seconds 5
    $state = (Get-ScheduledTask -TaskName $TaskName).State

    Write-Host ''
    if ($state -eq 'Running') {
        Write-Host 'Done! Monitoring is running in the background and starts every time you sign in to Windows.' -ForegroundColor Green
    } else {
        Write-Host "The scheduled task was created, but it is $state (not running)." -ForegroundColor Yellow
        Write-Host 'Last lines of the log:'
        if (Test-Path $LogFile) { Get-Content $LogFile -Tail 8 -Encoding UTF8 }
    }
    Write-Host ''
    Write-Host "Log file: $LogFile"
    Write-Host "To stop starting automatically, run as administrator:  schtasks /delete /tn $TaskName /f"
} catch {
    Fail $_.Exception.Message
}
Done 0

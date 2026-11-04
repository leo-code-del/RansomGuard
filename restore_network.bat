@echo off
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== PowerShell below: restore a network that RansomGuard cut off =====
$ErrorActionPreference = 'Continue'
$TaskName  = 'RansomGuard'
# State lives where only administrators can change it (since 1.7.5); older versions kept it in the user folder
$StateDir  = Join-Path $env:ProgramData 'RansomGuard'
$StateFile = Join-Path $StateDir 'state.json'
$OldState  = Join-Path $env:LOCALAPPDATA 'RansomGuard\state.json'
if (-not (Test-Path $StateFile) -and (Test-Path $OldState)) { $StateFile = $OldState }
# Canary files RansomGuard recorded (since 1.7.5), plus the visible names older versions used
$Record    = Join-Path $StateDir 'canaries.json'
$OldCanaries = @('!!!_canary_do_not_delete.docx', '!!!_canary_do_not_delete.xlsx', 'zzz_canary_do_not_delete.docx',
                 ('!!!_canary_' + [char]0x52FF + [char]0x522A + '.docx'),
                 ('!!!_canary_' + [char]0x52FF + [char]0x522A + '.xlsx'),
                 ('zzz_canary_' + [char]0x52FF + [char]0x522A + '.docx'))
# The only firewall values put back, whatever the state file says
$FirewallOk = @{ Name = @('Domain', 'Private', 'Public'); Enabled = @('True', 'False');
                 In = @('Block', 'Allow', 'NotConfigured'); Out = @('Block', 'Allow', 'NotConfigured') }

function Done($code) { Write-Host ''; Read-Host 'Press Enter to close' | Out-Null; exit $code }

try {
    Write-Host '=== Restore network ===' -ForegroundColor Cyan
    $st = $null
    if (Test-Path $StateFile) {
        try { $st = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
    if ($st -and $st.triggered_at) {
        Write-Host "RansomGuard cut off the network at $($st.triggered_at)." -ForegroundColor Yellow
    }
    if ($st -and $st.paused) {
        $list = (@($st.paused) | ForEach-Object { "$($_.name) (PID $($_.pid))" }) -join ', '
        Write-Host "RansomGuard paused these programs when it triggered: $list" -ForegroundColor Yellow
        Write-Host 'This script does not resume them; restarting the computer ends them. The control panel''s'
        Write-Host '"Restore network and restart monitoring" button resumes the ones Microsoft Defender finds clean.'
    }
    Write-Host 'First make sure this was a test or a false alarm, not a real ransomware infection.'
    $ans = Read-Host 'Restore the network? (Y/N)'
    if ($ans -notmatch '^[Yy]') { Write-Host 'Cancelled. The network stays cut off.'; Done 0 }

    # Stop monitoring first, so resetting the canary files doesn't trigger it again
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName }

    Write-Host '[1/3] Re-enabling network adapters...'
    $names = @()
    if ($st -and $st.disabled_adapters) { $names = @($st.disabled_adapters) }
    if ($names.Count -gt 0) {
        $targets = @(Get-NetAdapter -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Disabled' })
    } else {
        $targets = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Disabled' })
    }
    if ($targets.Count -eq 0) { Write-Host '      No disabled network adapters' }
    foreach ($a in $targets) {
        try {
            Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
            Write-Host "      Enabled $($a.Name)"
        } catch {
            Write-Host "      Could not enable $($a.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    # If the firewall was used to block the network, put its original settings back
    if ($st -and $st.firewall) {
        foreach ($p in @($st.firewall)) {
            $bad = @($FirewallOk.Keys | Where-Object { $FirewallOk[$_] -notcontains "$($p.$_)" })
            if ($bad.Count -gt 0) { Write-Host "      Skipped firewall settings with unexpected values" -ForegroundColor Yellow; continue }
            try {
                Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.In -DefaultOutboundAction $p.Out -ErrorAction Stop
                Write-Host "      Restored firewall settings for $($p.Name)"
            } catch {
                Write-Host "      Could not restore firewall settings for $($p.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    Start-Sleep -Seconds 3
    & "$env:SystemRoot\System32\ipconfig.exe" /renew | Out-Null

    Write-Host '[2/3] Clearing the trigger record and resetting canary files...'
    foreach ($f in @($StateFile, $OldState)) { if (Test-Path $f) { Remove-Item $f -Force } }
    if (Test-Path $Record) {
        $names = @('0000 Scan index.docx', 'Household budget.xlsx', 'ZZ Archive notes.docx')  # CANARY_NAMES
        try { foreach ($p in @(Get-Content $Record -Raw -Encoding UTF8 | ConvertFrom-Json)) {
            # only files with a canary's name, whatever the record says; -Force: they are hidden
            if ($p -and ($names -contains (Split-Path $p -Leaf)) -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Force }
        } } catch { }
        Remove-Item $Record -Force
    }
    foreach ($d in @([Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('MyPictures'))) {
        foreach ($n in $OldCanaries) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
        }
    }

    Write-Host '[3/3] Restarting monitoring...'
    if ($task) {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 5
        $state = (Get-ScheduledTask -TaskName $TaskName).State
        if ($state -eq 'Running') { Write-Host '      Monitoring restarted' }
        else { Write-Host "      Monitoring is $state. Please run install_ransom_guard.bat again" -ForegroundColor Yellow }
    } else {
        Write-Host '      Scheduled task not found. Please run install_ransom_guard.bat' -ForegroundColor Yellow
    }

    Write-Host ''
    $up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
    if ($up.Count -gt 0) {
        Write-Host "Done! Connected network adapters: $(($up | ForEach-Object { $_.Name }) -join ', ')" -ForegroundColor Green
    } else {
        Write-Host 'Network adapters are enabled but not connected yet. Wi-Fi may take a few seconds to reconnect, or connect to Wi-Fi manually.' -ForegroundColor Yellow
    }
} catch {
    Write-Host "[Failed] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'To restore manually: press Win+R, type ncpa.cpl, then right-click each network adapter and choose "Enable"'
}
Done 0

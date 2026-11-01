@echo off
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== 以下為 PowerShell：設定 RansomGuard 開機自動執行 =====
$ErrorActionPreference = 'Continue'
$Script   = 'D:\python\ransom_guard.py'
$TaskName = 'RansomGuard'
$LogFile  = Join-Path $env:LOCALAPPDATA 'RansomGuard\guard.log'

function Done($code) { Write-Host ''; Read-Host '按 Enter 關閉視窗' | Out-Null; exit $code }
function Fail($msg)  { Write-Host ''; Write-Host "[失敗] $msg" -ForegroundColor Red; Done 1 }

try {
    Write-Host '=== RansomGuard 開機自動啟動設定 ===' -ForegroundColor Cyan
    if (-not (Test-Path $Script)) { Fail "找不到 $Script" }

    Write-Host '[1/4] 尋找 Python...'
    $py = $null
    $cands = @()
    $cands += Get-ChildItem "$env:LOCALAPPDATA\Python\pythoncore-*\python.exe" -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch '\d+t-' } | Sort-Object FullName -Descending | ForEach-Object { $_.FullName }
    $cands += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object { $_.FullName }
    $cands += @('D:\python\.venv\Scripts\python.exe', 'py', 'python')
    foreach ($c in $cands) {
        try {
            $out = @(& $c -c 'import sys; print(sys.executable)' 2>$null)
            if ($LASTEXITCODE -eq 0 -and $out.Count -gt 0) {
                $p = "$($out[0])".Trim()
                if ($p -and (Test-Path $p)) { $py = $p; break }
            }
        } catch { }
    }
    if (-not $py) { Fail '找不到 Python。請先安裝 Python（安裝時勾選 Add python.exe to PATH），再執行一次。' }
    $pyw = Join-Path (Split-Path $py) 'pythonw.exe'
    if (-not (Test-Path $pyw)) { Fail "找不到 $pyw" }
    Write-Host "      使用 $py"

    Write-Host '[2/4] 安裝 watchdog 套件...'
    & $py -m pip install --upgrade --quiet --disable-pip-version-check watchdog
    & $py -c 'import watchdog'
    if ($LASTEXITCODE -ne 0) { Fail 'watchdog 安裝失敗，請手動執行：pip install watchdog' }

    Write-Host '[3/4] 建立登入時自動執行的排程工作...'
    $user = "$env:USERDOMAIN\$env:USERNAME"
    # -E 忽略 PYTHON* 環境變數、-P 不從程式所在資料夾載入模組（Python 3.11+），
    # 避免有人在 D:\python 放假的 json.py 之類的檔案，被以系統管理員權限執行
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
        Description = "偵測勒索病毒行為並自動切斷網路（$Script）"
        Force       = $true
        ErrorAction = 'Stop'
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue  # 停掉舊版，才會載入新程式
    }
    Register-ScheduledTask @regArgs | Out-Null

    Write-Host '[4/4] 啟動監控...'
    Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    Start-Sleep -Seconds 5
    $state = (Get-ScheduledTask -TaskName $TaskName).State

    Write-Host ''
    if ($state -eq 'Running') {
        Write-Host '設定完成！監控已在背景執行，之後每次登入 Windows 都會自動啟動。' -ForegroundColor Green
    } else {
        Write-Host "排程工作已建立，但目前狀態是 $state（不是執行中）。" -ForegroundColor Yellow
        Write-Host '最後幾行紀錄：'
        if (Test-Path $LogFile) { Get-Content $LogFile -Tail 8 -Encoding UTF8 }
    }
    Write-Host ''
    Write-Host "紀錄檔：$LogFile"
    Write-Host "取消自動啟動：以系統管理員執行  schtasks /delete /tn $TaskName /f"
} catch {
    Fail $_.Exception.Message
}
Done 0

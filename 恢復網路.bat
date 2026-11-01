@echo off
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== 以下為 PowerShell：恢復被 RansomGuard 切斷的網路 =====
$ErrorActionPreference = 'Continue'
$TaskName  = 'RansomGuard'
$StateFile = Join-Path $env:LOCALAPPDATA 'RansomGuard\state.json'
$Canaries  = @('!!!_canary_勿刪.docx', '!!!_canary_勿刪.xlsx', 'zzz_canary_勿刪.docx')

function Done($code) { Write-Host ''; Read-Host '按 Enter 關閉視窗' | Out-Null; exit $code }

try {
    Write-Host '=== 恢復網路 ===' -ForegroundColor Cyan
    $st = $null
    if (Test-Path $StateFile) {
        try { $st = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
    }
    if ($st -and $st.triggered_at) {
        Write-Host "RansomGuard 在 $($st.triggered_at) 切斷了網路。" -ForegroundColor Yellow
    }
    Write-Host '請先確認這次是測試或誤判，而不是真的中了勒索病毒。'
    $ans = Read-Host '確定要恢復網路嗎？(Y/N)'
    if ($ans -notmatch '^[Yy]') { Write-Host '已取消，網路維持切斷。'; Done 0 }

    # 先停止監控，避免重設誘餌檔時又觸發
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName }

    Write-Host '[1/3] 重新啟用網路卡...'
    $names = @()
    if ($st -and $st.disabled_adapters) { $names = @($st.disabled_adapters) }
    if ($names.Count -gt 0) {
        $targets = @(Get-NetAdapter -Name $names -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Disabled' })
    } else {
        $targets = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Disabled' })
    }
    if ($targets.Count -eq 0) { Write-Host '      沒有被停用的網路卡' }
    foreach ($a in $targets) {
        try {
            Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
            Write-Host "      已啟用 $($a.Name)"
        } catch {
            Write-Host "      無法啟用 $($a.Name)：$($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Start-Sleep -Seconds 3
    ipconfig /renew | Out-Null

    Write-Host '[2/3] 清除觸發紀錄、重設誘餌檔...'
    if (Test-Path $StateFile) { Remove-Item $StateFile -Force }
    foreach ($d in @([Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('MyPictures'))) {
        foreach ($n in $Canaries) {
            $p = Join-Path $d $n
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
        }
    }

    Write-Host '[3/3] 重新啟動監控...'
    if ($task) {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 5
        $state = (Get-ScheduledTask -TaskName $TaskName).State
        if ($state -eq 'Running') { Write-Host '      監控已重新啟動' }
        else { Write-Host "      監控狀態：$state，請重新執行 install_ransom_guard.bat" -ForegroundColor Yellow }
    } else {
        Write-Host '      找不到排程工作，請執行 install_ransom_guard.bat' -ForegroundColor Yellow
    }

    Write-Host ''
    $up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
    if ($up.Count -gt 0) {
        Write-Host "完成！目前連線中的網路卡：$(($up | ForEach-Object { $_.Name }) -join '、')" -ForegroundColor Green
    } else {
        Write-Host '網路卡已啟用，但還沒連上。Wi-Fi 可能需要幾秒鐘重新連線，或請手動點選 Wi-Fi 連線。' -ForegroundColor Yellow
    }
} catch {
    Write-Host "[失敗] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '手動恢復：按 Win+R 輸入 ncpa.cpl，對每張網路卡按右鍵 →「啟用」'
}
Done 0

@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== 預覽 RansomGuard 的全螢幕警告（不偵測、不斷網）=====
$Script = 'D:\python\ransom_guard.py'
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
if (-not $py) { Write-Host '找不到 Python' -ForegroundColor Red; Read-Host '按 Enter 關閉'; exit 1 }
Write-Host '正在開啟警告預覽，按「我知道了」即可關閉...'
& $py $Script --test-alert

@echo off
set "RG_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0',[Text.Encoding]::UTF8); Invoke-Expression ($s.Substring($s.IndexOf('#PS'+'START')+8))"
exit /b
#PSSTART
# ===== Preview RansomGuard's full-screen warning (no detection, no network cut) =====
$Script = Join-Path $env:RG_DIR 'ransom_guard.py'  # in the same folder as this .bat
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
if (-not $py) { Write-Host 'Python not found' -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }
Write-Host 'Opening the warning preview. Click "I understand" to close it...'
& $py $Script --test-alert

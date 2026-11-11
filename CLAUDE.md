# RansomGuard

Windows 勒索軟體防護工具（Python 3.14 + tkinter，PyInstaller 打包成單一 exe）。
GitHub：`leo-code-del/RansomGuard`（**公開**），主分支 `main`。

詳細說明在 `DEVELOPMENT.zh-TW.md`，改程式前先讀它；這裡只列最容易出錯的地方。

## 常用指令

```
python -m unittest discover -s tests -v                      # 全部測試
python -m unittest discover -s tests -p test_backup.py       # 單一檔案
python -m pyflakes ransom_guard.py ransomguard make_icon.py make_version_info.py check_build.py tests .github/scripts
```

提交前這兩項都要通過，CI（`.github/workflows/ci.yml`）跑的是同一組。

## 程式慣例

- `ransom_guard.py` 只負責啟動，程式碼都在 `ransomguard/` 套件，每個模組對應 `tests/test_<模組>.py`。
- 模組之間一律用 `模組.名稱` 呼叫（例如 `network.disconnect_network()`），不要 `from 模組 import 名稱`（只有 `tr`、`log`、`norm` 例外），否則測試替換不到。
- 新增測試檔時開頭要有 `setUpModule, tearDownModule = support.setUpModule, support.tearDownModule`，否則 `test_suite.py` 會失敗。
- 介面文字有中英兩種語言，新增字串時兩邊都要補。文件也是成對的（`*.md` 與 `*.zh-TW.md`），改一份就要改另一份。

## 這台電腦上的限制

- 這台電腦本身裝著正式版 RansomGuard（`C:\Program Files\RansomGuard`），以系統管理員權限在背景監控。
- **不要**從原始碼執行會改動系統的指令：`--install`、解除安裝、`install_ransom_guard.bat`、`restore_network.bat`。要驗證行為就寫測試；真的需要實機操作時先問使用者。
- 程式和測試裡有危險指令的字串（刪還原點、關 Defender 之類）。這些字串只能出現在檔案裡，不要打在 Bash / PowerShell 命令列、heredoc 或 commit 訊息上，否則正式版會把它當攻擊並切斷網路。需要時用 Write 工具寫進檔案，再用 `git commit -F <檔案>`。
- 臨時檔和實驗只放在 `%TEMP%`。
- 本機 `build.bat` 產生的 `dist\RansomGuard.exe` 可能被 Defender 隔離，而且不需要：發布版本由 GitHub Actions 打包。除非使用者要求，不要在本機打包。

## 發布

- 流程：改 `ransomguard/config.py` 的 `VERSION` → 寫 `release-notes/v<版本>.md` → 測試 → 提交推送 → 打 tag。
- Release 是**不可變更**的，tag 推出去就收不回來。打 tag、推 tag 之前一定要先得到使用者明確同意。
- 打包固定用 Python 3.14.6（較新的版本搭配目前的 PyInstaller 會做出無法啟動的 exe），不要自行升級 workflow 裡的 Python 版本。
- commit 訊息用英文；版本 commit 的格式是 `v1.15.1: <一句話說明>`。

## 隱私

這是公開專案。commit 作者一律用 GitHub noreply 地址；程式碼、文件、發布說明裡不能出現個人 email、Windows 使用者名稱或含使用者名稱的路徑。`.git/hooks` 裝有 pre-commit / commit-msg 隱私檢查，被擋下時要修正內容，不要跳過 hook。

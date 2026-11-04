# 開發

[English](DEVELOPMENT.md) | **中文(繁體)** · [回到 README](README.zh-TW.md)

## 從原始碼執行

```
pip install -r requirements-build.txt
python ransom_guard.py --gui
```

`requirements.txt` 列出從原始碼執行需要的套件；`requirements-build.txt` 再加上發布版本使用的固定 PyInstaller 版本。

不想用 exe、直接用 Python 執行的話，專案裡有幾個輔助檔案（要和 `ransom_guard.py` 放在同一個資料夾）：

| 檔案 | 作用 |
| --- | --- |
| `install_ransom_guard.bat` | 用 Python 版安裝背景監控（自動找 Python、安裝 watchdog） |
| `restore_network.bat` | 不需要 Python 也能恢復被切斷的網路 |
| `preview_warning.bat` | 預覽全螢幕警告 |

> [!WARNING]
> 這樣安裝的排程工作，會以系統管理員權限執行原本資料夾裡的 `ransom_guard.py` 和 `ransomguard` 套件。請把專案放在只有系統管理員能修改的資料夾；詳見[已知的安全問題](README.zh-TW.md#已知的安全問題)。

## 程式結構

`ransom_guard.py` 只負責啟動程式，程式碼都在 `ransomguard` 套件裡：

| 模組 | 作用 |
| --- | --- |
| `config` | 版本、可調整的設定、介面語言、使用者設定 |
| `winapi` | Windows 底層功能：PowerShell 與系統程式、kernel32、程序資訊、訊息框、使用者資料夾 |
| `storage` | 紀錄檔，以及放在 `C:\ProgramData\RansomGuard`、只有系統管理員能修改的狀態資料 |
| `folders` | 監控哪些資料夾 |
| `canary` | 隱藏的誘餌檔 |
| `detection` | 分辨加密和日常操作；檔案事件處理 |
| `processes` | 危險指令與程序監控 |
| `response` | 觸發時的處理：暫停程式、全螢幕警告 |
| `defender` | Microsoft Defender 掃描與下載掃描 |
| `network` | 切斷與恢復網路 |
| `install` | 排程工作、安裝、解除安裝、防護狀態檢查 |
| `updates` | 從 GitHub 取得新版本 |
| `backup` | 檔案有沒有備份（檔案歷程記錄、OneDrive）與備份提醒 |
| `gui` | 控制台 |
| `app` | 監控主迴圈與命令列 |

模組之間一律用 `模組.名稱` 互相呼叫（例如 `network.disconnect_network()`），不使用 `from 模組 import 名稱`（只有 `tr`、`log`、`norm` 例外）。這樣測試替換某個模組裡的名稱時，所有地方都會用到替換後的版本。測試透過一個 `rg` 物件存取整個程式，它會自動找到每個名稱所在的模組。

## 打包

```
build.bat
```

打包好的檔案在 `dist\RansomGuard.exe`。要用不在 PATH 裡的 Python，先設定 `PYTHON`，例如 `set PYTHON=C:\Python314\python.exe`。

- `build.bat` 會把 `icon.ico` 打包進 exe。少了它，視窗、工作列和桌面捷徑都會顯示 PyInstaller 的預設圖示。
- 打包前它會先執行 `make_version_info.py`，把產品名稱和 `ransomguard/config.py` 裡的 `VERSION` 寫進 exe 的版本資訊（內容 > 詳細資料）。程式碼簽章需要這些資訊。
- 接著它會執行 `check_build.py`：如果 exe 裡缺少 `ransomguard` 套件的任何模組，或缺少控制台需要的 Tcl/Tk 檔案，打包就算失敗。PyInstaller 對這種情況只會發出警告，但這樣的 exe 完全無法啟動。v1.7.1 就是這樣：它用 Python 3.14.9 打包，PyInstaller 6.21 無法打包它的 Tcl/Tk 9 檔案；發布版本固定使用 Python 3.14.6。

圖示 `icon.ico` / `icon.png` 由 `make_icon.py` 產生（需要 `pip install pillow`），要改圖示就改這個檔案再執行一次。

## 測試

使用 Python 內建的 `unittest`，也可以用 `pytest` 執行：

```
python -m unittest discover -s tests -v
```

測試只使用暫存資料夾，不會動到你的檔案、網路設定、網際網路或已安裝的程式。整套測試都強制遵守這一點：

- 使用者資料夾、程式資料夾和安裝資料夾都會被導向暫存的沙盒；
- 測試如果沒有先換掉操作網路卡、防火牆或排程工作的 PowerShell 指令、`ipconfig` / `netsh` / 關機、網際網路或全螢幕警告就碰到它們，會直接失敗；
- 測試只能暫停自己開出來的程序。

有些測試會實際使用唯讀的 Windows 功能：透過 WMI 監看新程序、用 Defender 掃描暫存檔，以及讀取排程工作。

## 套件更新

[Dependabot](.github/dependabot.yml) 每週會檢查一次，鎖定版本的 GitHub Action 或 Python 套件有新版時就開 PR。CI 會在 Windows 上打包和測試，通過了才合併。Python 本身在 workflow 裡維持固定版本，等確認新版能搭配 PyInstaller 使用才更新。

## 發布新版

發布版本由 GitHub Actions 打包和發布，不再手動上傳：

1. 修改 `ransomguard/config.py` 裡的 `VERSION`，例如 `"1.7.6"`，並在 `release-notes/v1.7.6.md` 寫好發布說明。
2. 執行測試、提交並推送。每次推送分支和每個 pull request，[CI workflow](.github/workflows/ci.yml) 都會執行檢查、測試和打包。
3. 為這個 commit 加上 tag 並推送：

   ```
   git tag v1.7.6
   git push origin v1.7.6
   ```

4. [發布 workflow](.github/workflows/release.yml) 會確認 tag 和 `VERSION` 一致、執行測試、打包 exe、簽署 attestation、發布 Release，說明取自 `release-notes/<tag>.md` 並在最後自動加上 Code signing policy 連結（先建立草稿，讓 exe 在版本變成不可變更之前附上去），並在上一版的說明加上建議更新的提示。

v1.7.0 起的 Release 是不可變更的：發布後檔案和 tag 都不能修改，所以出錯時只能發新的版本號，它們的 exe 也會一直可以下載。README 的下載按鈕永遠指向最新版本，不需要修改。

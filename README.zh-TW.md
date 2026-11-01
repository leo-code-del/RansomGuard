<img src="icon.png" width="96" alt="">

# RansomGuard

[English](README.md) | **中文(繁體)**

偵測勒索病毒的加密行為，一發現異常就**自動切斷網路**並跳出全螢幕警告，避免檔案繼續被加密、資料被傳出去。

[![下載 RansomGuard.exe](https://img.shields.io/badge/下載-RansomGuard.exe-2563eb?style=for-the-badge&logo=windows)](https://github.com/leo-code-del/RansomGuard/releases/latest/download/RansomGuard.exe)

[所有版本與更新紀錄](https://github.com/leo-code-del/RansomGuard/releases)

> 介面支援英文與中文(繁體)：第一次開啟時會讓你選擇語言（English 或 中文(繁體)），之後可以用控制台右上角的 **English / 中文(繁體)** 按鈕隨時切換，背景監控跳出的警告也會用同一種語言。

## 安裝

1. 按上方按鈕下載 `RansomGuard.exe`（只支援 Windows 10 / 11）。
2. 雙擊執行，出現「使用者帳戶控制」時按「是」（切斷網路需要系統管理員權限）。
   - 若出現「Windows 已保護您的電腦」，按「其他資訊」→「仍要執行」。這是因為程式沒有數位簽章。
3. 在控制台按 **安裝／更新並開始監控**。

安裝後程式會複製到 `C:\Program Files\RansomGuard`，每次登入 Windows 都會在背景自動啟動，桌面也會出現「RansomGuard」捷徑可以開啟控制台。

### 如果被 Windows Defender 刪除

Defender 有時會把 RansomGuard.exe 判定為威脅（例如 `Trojan:Win32/Bearfoos!ml`）。`!ml` 代表機器學習的推測，不是已知病毒：用 PyInstaller 打包、需要系統管理員權限、會終止程序和停用網路卡的程式，在它看來很可疑。這時 Defender 會連同已安裝的程式和排程工作一起刪除，**防護會在沒有任何提示下停止**，請偶爾確認控制台顯示「執行中」。

1. 先比對檔案的 SHA-256 和[版本頁面](https://github.com/leo-code-del/RansomGuard/releases) Assets 底下顯示的是否相同（PowerShell：`Get-FileHash RansomGuard.exe`），相同才繼續。
2. Windows 安全性 → 病毒與威脅防護 → 保護歷程記錄 → 選擇該項目 → **還原**（或 **允許在裝置上**）。
3. 再執行一次 RansomGuard.exe，按 **安裝／更新並開始監控**。
4. 請到 <https://www.microsoft.com/wdsi/filesubmission> 回報誤判（選「Incorrectly detected」），Microsoft 確認後所有人都不會再被誤判。

## 偵測方式

以下任一情況成立就會觸發：

| 偵測 | 說明 |
| --- | --- |
| 誘餌檔 | 在「文件」與「圖片」放幾個 `!!!_canary_do_not_delete.docx` 之類的檔案，被修改、移動或刪除就觸發 |
| 檔案壞掉 | 短時間內多個 .docx / .pdf / .jpg / .mp4 等檔頭被破壞，或文字檔變成像加密過的亂碼 |
| 陌生副檔名 | 短時間內大量檔案被改名，例如 `報告.docx` → `報告.docx.locked` |
| 勒索訊息 | 短時間內多個資料夾出現 `HOW_TO_DECRYPT.txt` 之類的檔案 |
| 危險指令 | 有程式刪除系統還原點、關閉開機修復、刪除備份、清除事件紀錄或關閉 Defender（會立刻終止該程式） |

監控範圍：桌面、文件、圖片、下載、影片、音樂。

「下載」資料夾和桌面上新出現的程式、腳本和壓縮檔（`.exe`、`.msi`、`.js`、`.zip` 等）下載完成後，也會用 Microsoft Defender 掃描。Defender 發現威脅時會跳出訊息通知你。這種情況不會斷網，因為 Defender 會把檔案移除。

> 請不要開啟、移動或刪除誘餌檔（檔名含 `canary_do_not_delete`），那樣會觸發斷網。

## 觸發之後

1. 寫入最多資料的程式會被暫停，讓加密停下來，再交給 Microsoft Defender 掃描。Windows 系統程序、Defender 和桌面不會被暫停。接著所有網路卡會被停用（失敗時改用防火牆封鎖），所有螢幕顯示紅色警告，警告上會列出被暫停的程式。
2. **不要恢復網路**，也不要插上備份硬碟或隨身碟。
3. 如果檔案還在一個一個被改名或打不開，立刻按住電源鍵強制關機。
4. 用手機拍下勒索訊息，並用手機更改 Email、銀行等重要帳號的密碼。

**如果確認是誤判**（例如自己動到誘餌檔）：開啟桌面上的「RansomGuard」，按 **恢復網路並重新開啟監控**。被暫停的程式會先讓 Defender 再掃描一次，沒有問題就恢復執行。維持暫停的程式，重新開機後就會結束。

## 更新

有新版本時 RansomGuard 會主動通知：背景監控在登入 2 分鐘後檢查一次，之後每 6 小時檢查一次；開啟控制台時也會檢查。按 **是** 就會自動更新（同一個版本在每次登入期間只會詢問一次）。

要手動更新，開啟桌面上的「RansomGuard」，按 **安裝／更新並開始監控**。程式會到 GitHub 檢查有沒有新版本，有的話自動下載、用 GitHub 公布的 SHA-256 確認檔案沒被竄改、安裝，再用新版本重新開啟控制台。沒有網路時則重新安裝目前的版本。控制台左上角會顯示目前的版本號。

> 1.4.0 以前的版本還不會自動更新：請到 [Releases](https://github.com/leo-code-del/RansomGuard/releases) 下載新版 `RansomGuard.exe`，執行後按 **安裝／更新並開始監控**，之後就能用按鈕更新。

## 控制台功能

| 按鈕 | 作用 |
| --- | --- |
| 安裝／更新並開始監控 | 從 GitHub 更新到最新版本、安裝背景監控並立即啟動 |
| 恢復網路並重新開啟監控 | 誤判後恢復網路 |
| 停止監控 | 暫時停止，下次登入會自動再啟動 |
| 預覽警告畫面 | 看看觸發時的警告長什麼樣子，不會斷網 |
| 開啟紀錄檔 | 紀錄檔位置：`%LOCALAPPDATA%\RansomGuard\guard.log` |
| 解除安裝 | 移除背景監控、桌面捷徑與誘餌檔 |
| English / 中文(繁體)（右上角） | 切換介面語言 |

## 命令列參數

```
RansomGuard.exe              開啟控制台
RansomGuard.exe --install    安裝／更新背景監控
RansomGuard.exe --update     開啟控制台並更新到最新版本
RansomGuard.exe --restore    恢復網路，並重新開啟背景監控
RansomGuard.exe --dry-run    測試模式：只記錄與跳窗，不會真的斷網
RansomGuard.exe --test-alert 預覽全螢幕警告
RansomGuard.exe --watch D:\資料 --watch E:\備份   自訂監控資料夾
RansomGuard.exe --version    顯示版本
RansomGuard.exe --lang en    這次用英文介面（zh＝中文(繁體)）
```

## 從原始碼執行與打包

```
pip install watchdog pyinstaller
python ransom_guard.py --gui
python -m PyInstaller --onefile --windowed --uac-admin --name RansomGuard --icon ..\icon.ico ^
       --add-data "..\icon.ico;." --distpath dist --workpath build --specpath build ransom_guard.py
```

執行測試（只使用暫存資料夾，不會動到網路或已安裝的程式）：

```
python -m unittest discover -s tests -v
```

圖標 `icon.ico` / `icon.png` 由 `make_icon.py` 產生（需要 `pip install pillow`），要改圖標就改這個檔案再執行一次。

不想用 exe、直接用 Python 執行的話，專案裡有幾個輔助檔案（要和 `ransom_guard.py` 放在同一個資料夾）：

| 檔案 | 作用 |
| --- | --- |
| `install_ransom_guard.bat` | 用 Python 版安裝背景監控（自動找 Python、安裝 watchdog） |
| `restore_network.bat` | 不需要 Python 也能恢復被切斷的網路 |
| `preview_warning.bat` | 預覽全螢幕警告 |

打包好的檔案在 `dist\RansomGuard.exe`。

### 發布新版

1. 修改 `ransom_guard.py` 裡的 `VERSION`，例如 `"1.4.3"`。
2. 執行測試、重新打包，提交並推送。
3. 建立 Release 並附上 exe：

   ```
   gh release create v1.4.3 dist\RansomGuard.exe --title "RansomGuard 1.4.3" --notes-file notes.md
   ```

4. 只提供最新版本下載：移除上一版附的 exe，並在它的說明最上方加上停止提供下載的提示（說明仍可閱讀）：

   ```
   gh release delete-asset v1.4.2 RansomGuard.exe --yes
   ```

README 的下載按鈕永遠指向最新版本，不需要修改。

## 注意

RansomGuard 是額外的防線，不能取代防毒軟體與**離線備份**。重要檔案請定期備份到平常不接在電腦上的硬碟。

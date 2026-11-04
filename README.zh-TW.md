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
3. 在控制台按 **安裝並開始監控**。

安裝後程式會複製到 `C:\Program Files\RansomGuard`，每次登入 Windows 都會在背景自動啟動，桌面也會出現「RansomGuard」捷徑可以開啟控制台。

### 驗證下載的檔案

從 v1.7.1 起，每個 `RansomGuard.exe` 都由 [GitHub Actions](.github/workflows/release.yml) 依照標記的原始碼打包，而不是在任何人自己的電腦上打包；GitHub 也會為它簽署一份 *build provenance attestation*：記錄是哪個 repo、哪個 workflow、哪個 commit 產生了這個檔案。執行 exe 之前可以先驗證：

1. 安裝 [GitHub CLI](https://cli.github.com/)，並執行一次 `gh auth login` 登入。
2. 在下載檔案所在的資料夾執行：

   ```
   gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard
   ```

   如果還要確認它來自發布用的 workflow（而不是 repo 裡其他的 workflow）：

   ```
   gh attestation verify RansomGuard.exe --repo leo-code-del/RansomGuard --signer-workflow leo-code-del/RansomGuard/.github/workflows/release.yml
   ```

3. 出現「Verification succeeded」代表這個檔案和 workflow 打包出來的完全一樣。如果驗證失敗，請不要執行這個檔案。

發布的版本也是不可變更的：發布後檔案就不能被替換。要確認檔案就是某個版本附上的那一個，執行 `gh release verify-asset v1.7.1 RansomGuard.exe --repo leo-code-del/RansomGuard`（換成你下載的版本）。

沒有 GitHub CLI 的話，可以比對[版本頁面](https://github.com/leo-code-del/RansomGuard/releases) Assets 底下顯示的 SHA-256 和 PowerShell 的 `Get-FileHash RansomGuard.exe`。

1.7.1 以前的版本是在開發者自己的電腦上打包的，沒有 attestation。

### 如果被 Windows Defender 刪除

Defender 有時會把 RansomGuard.exe 判定為威脅（例如 `Trojan:Win32/Bearfoos!ml`）。`!ml` 代表機器學習的推測，不是已知病毒：用 PyInstaller 打包、需要系統管理員權限、會終止程序和停用網路卡的程式，在它看來很可疑。這時 Defender 會連同已安裝的程式和排程工作一起刪除，防護就停止了。1.7.0 起有另外的「防護狀態檢查」會發現這種情況：登入 5 分鐘後和每天中午，如果防護不見了或監控沒在執行，會跳出訊息，並提供開啟下載頁面或控制台。它執行時不會開啟任何視窗，也不需要 RansomGuard.exe。1.7.0 以前的版本不會提示，請偶爾確認控制台顯示「執行中」。

1. 先比對檔案的 SHA-256 和[版本頁面](https://github.com/leo-code-del/RansomGuard/releases) Assets 底下顯示的是否相同（PowerShell：`Get-FileHash RansomGuard.exe`），相同才繼續。
2. Windows 安全性 → 病毒與威脅防護 → 保護歷程記錄 → 選擇該項目 → **還原**（或 **允許在裝置上**）。
3. 再執行一次 RansomGuard.exe，按 **安裝並開始監控**。
4. 請到 <https://www.microsoft.com/wdsi/filesubmission> 回報誤判（選「Incorrectly detected」），Microsoft 確認後所有人都不會再被誤判。

## 偵測方式

以下任一情況成立就會觸發：

| 偵測 | 說明 |
| --- | --- |
| 誘餌檔 | 在「文件」與「圖片」放幾個 `!!!_canary_do_not_delete.docx` 之類的檔案，被修改、移動或刪除就觸發 |
| 檔案壞掉 | 短時間內多個 .docx / .pdf / .jpg / .mp4 等檔頭被破壞，或文字檔變成像加密過的亂碼 |
| 陌生副檔名 | 短時間內大量檔案被改名，例如 `報告.docx` → `報告.docx.locked` |
| 勒索訊息 | 短時間內多個資料夾出現 `HOW_TO_DECRYPT.txt` 之類的檔案 |
| 危險指令 | 有程式刪除系統還原點、關閉開機修復、刪除備份、清除事件紀錄或關閉 Defender。會立刻終止這個指令，並暫停下達指令的程式，因為勒索病毒通常是做完這些之後才開始加密 |

監控範圍：桌面、文件、圖片、下載、影片、音樂。

「下載」資料夾和桌面上新出現的程式、腳本和壓縮檔（`.exe`、`.msi`、`.js`、`.zip` 等）下載完成後，也會用 Microsoft Defender 掃描。Defender 發現威脅時會跳出訊息通知你。這種情況不會斷網，因為 Defender 會把檔案移除。

> 請不要修改、移動或刪除誘餌檔（檔名含 `canary_do_not_delete`），那樣會觸發斷網。用 Word 或 Excel 打開會看到說明文字，請直接關閉、不要儲存；Word 和 Excel 也會建議以唯讀方式開啟。

## 觸發之後

1. 寫入最多資料的程式（以及下達危險指令的程式）會被暫停，讓加密停下來，再交給 Microsoft Defender 掃描。Windows 系統程序、Defender 和桌面不會被暫停。接著所有網路卡會被停用（失敗時改用防火牆封鎖），所有螢幕顯示紅色警告，警告上會列出被暫停的程式。
2. **不要恢復網路**，也不要插上備份硬碟或隨身碟。
3. 如果檔案還在一個一個被改名或打不開，立刻按住電源鍵強制關機。
4. 用手機拍下勒索訊息，並用手機更改 Email、銀行等重要帳號的密碼。

**如果確認是誤判**（例如自己動到誘餌檔）：開啟桌面上的「RansomGuard」，按 **恢復網路並重新開啟監控**。被暫停的程式會先讓 Defender 再掃描一次，沒有問題就恢復執行。維持暫停的程式，重新開機後就會結束。

## 它會對電腦做什麼

這一段列出 RansomGuard 會對電腦做的所有事，方便你判斷要不要信任它。它會記錄哪些關於你的資料、保存多久、怎麼刪除，請看[隱私權說明](PRIVACY.zh-TW.md)。

**權限。** 啟動 RansomGuard.exe 時會要求系統管理員權限（使用者帳戶控制）。背景監控透過每次登入都會啟動的排程工作，以系統管理員權限執行。防護狀態檢查則用一般使用者權限執行。

**讀取的檔案。** 會讀取桌面、文件、圖片、下載、影片、音樂裡有變動的檔案。常見格式（Office 檔、PDF、圖片、影片、文字檔）只讀前 16 KB，用來判斷是不是像被加密過。OneDrive 還沒下載到電腦上的檔案不會讀。不會讀其他磁碟或網路磁碟，除非你用 `--watch` 加進來。

**監看的程式。** 會讀取每個啟動的程式的命令列，用來找出上面列的危險指令，只有這些會寫進紀錄檔。觸發時，也會讀取每個執行中的程式寫入了多少資料。

**建立或修改的檔案與設定。**

| 位置 | 內容 |
| --- | --- |
| 文件、圖片（或用 `--watch` 指定的資料夾） | 各 3 個誘餌檔（`!!!_canary_do_not_delete.docx` 等） |
| `%LOCALAPPDATA%\RansomGuard\` | `guard.log`（最多 4 個、每個 1 MB，超過 30 天的紀錄會被刪除）、`state.json`（切斷或暫停了什麼）、`settings.json`（語言、是否自動檢查新版本） |
| `C:\Program Files\RansomGuard\` | `RansomGuard.exe`、`icon.ico`、`health_check.js` |
| 桌面 | 「RansomGuard」捷徑 |
| 工作排程器 | 「RansomGuard」和「RansomGuard Health Check」兩個排程工作 |
| `%TEMP%` | exe 執行時會把自己解壓縮到一個 `_MEI…` 資料夾，結束時刪除。`MpCmdRun.log` 是 Microsoft Defender 的掃描程式為 RansomGuard 要求的掃描所留的紀錄 |
| Windows 的圖示快取 | 安裝時重新整理，讓捷徑顯示目前的圖示 |

**會刪除什麼。** 不會刪除你自己的檔案，只有兩個例外，列在[可能出錯的情況](#已知限制與風險)：和誘餌檔同名的檔案，以及你放進 `C:\Program Files\RansomGuard` 的東西。除此之外只會刪除它自己建立的東西：誘餌檔（恢復網路和解除安裝時）、舊版留下的檔案、超過 30 天的紀錄、你按 **清除紀錄檔** 時的紀錄檔；解除安裝時還會刪除桌面捷徑、兩個排程工作、`C:\Program Files\RansomGuard` 資料夾，以及 `%LOCALAPPDATA%\RansomGuard` 裡它自己的紀錄檔和設定。

**程式與網路。**

| 時機 | 動作 |
| --- | --- |
| 有程式執行危險指令（刪除還原點、關閉 Defender 等） | 結束那個程式，並暫停下達指令的程式（往上最多三層） |
| 偵測到疑似勒索病毒 | 暫停寫入最多資料的程式（最多五個）、請 Microsoft Defender 掃描被暫停的程式並執行快速掃描、停用所有網路卡（失敗時改用防火牆封鎖所有連線、釋放 IP 位址並中斷 Wi-Fi）、顯示全螢幕警告 |
| 「下載」資料夾或桌面出現新的程式、腳本或壓縮檔 | 檔案完成後請 Microsoft Defender 掃描，發現威脅時通知你 |
| 警告畫面開著的時候 | 網路卡被重新啟用會再停用一次 |
| 你恢復網路時 | 重新啟用網路卡、還原防火牆設定，並恢復 Defender 確認沒問題的程式 |
| 你按警告畫面的「立即強制關機」 | 確認後強制關機 |

**網路連線。** 預設情況下，RansomGuard 不會自己連上網路。只有 exe 版會連網，而且只連 GitHub：你按 **更新到最新版本**（或用 `--update`、`--install` 執行）時；或是你開啟 **自動檢查新版本** 後（預設關閉，因為每次檢查都會讓 GitHub 看到你的 IP 位址），每 6 小時以及開啟控制台時。你同意更新後才從 `github.com` 下載新版，安裝前會核對 SHA-256。不會傳送任何關於你或你的檔案的資訊。Python 版完全不連網。Microsoft Defender 的掃描在你的電腦上執行；Defender 本身是否連線到 Microsoft，取決於你的 Defender 設定。

## 更新

想在有新版本時收到通知，請勾選控制台左下角的 **自動檢查新版本**。勾選後，背景監控會在登入 2 分鐘後和之後每 6 小時檢查 GitHub，開啟控制台時也會檢查。按 **是** 就會自動更新（同一個版本在每次登入期間只會詢問一次）。這個選項預設關閉，因為每次檢查都會讓 GitHub 看到你的 IP 位址（見[隱私權說明](PRIVACY.zh-TW.md)）；1.7.3 以前的版本一律會檢查。

要手動更新，開啟桌面上的「RansomGuard」，按 **更新到最新版本**（開啟自動檢查新版本時，控制台發現有新版，按鈕會顯示 **更新到 v…** 並變成藍色）。程式會到 GitHub 檢查有沒有新版本，有的話自動下載、用 GitHub 公布的 SHA-256 確認檔案沒被竄改、安裝，再用新版本重新開啟控制台。沒有網路時則重新安裝目前的版本。控制台左上角會顯示目前的版本號。

**不一定要更新。** 詢問時按 **否**，就會繼續用目前的版本監控。**安裝並開始監控** 不會連到 GitHub：它安裝正在執行的這個版本，並用它開始監控。想更新時隨時都可以更新。

> 1.4.0 以前的版本還不會自動更新：請到 [Releases](https://github.com/leo-code-del/RansomGuard/releases) 下載新版 `RansomGuard.exe`，執行後按 **安裝並開始監控**，之後就能用按鈕更新。

## 控制台功能

| 按鈕 | 作用 |
| --- | --- |
| 安裝並開始監控 | 用正在執行的版本安裝背景監控並立即啟動，不連到 GitHub |
| 更新到最新版本 | 從 GitHub 更新到最新版本、安裝並開始監控 |
| 恢復網路並重新開啟監控 | 誤判後恢復網路 |
| 停止監控 | 暫時停止，下次登入會自動再啟動 |
| 預覽警告畫面 | 看看觸發時的警告長什麼樣子，不會斷網 |
| 開啟紀錄檔 | 紀錄檔位置：`%LOCALAPPDATA%\RansomGuard\guard.log`（超過 30 天的紀錄會被刪除） |
| 自動檢查新版本（左下角） | 預設關閉。開啟後，RansomGuard 會每 6 小時以及開啟控制台時向 GitHub 查詢新版本 |
| 清除紀錄檔 | 清空記錄了偵測到的檔案與程式的紀錄檔 |
| 解除安裝 | 移除背景監控、防護狀態檢查、桌面捷徑、誘餌檔、`C:\Program Files\RansomGuard` 資料夾，以及紀錄檔和設定 |
| English / 中文(繁體)（右上角） | 切換介面語言 |

## 命令列參數

```
RansomGuard.exe              開啟控制台
RansomGuard.exe --install    安裝背景監控（有新版會先更新）
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
pip install -r requirements-build.txt
python ransom_guard.py --gui
build.bat
```

`requirements.txt` 列出從原始碼執行需要的套件；`requirements-build.txt` 再加上發布版本使用的固定 PyInstaller 版本。

`build.bat` 會把 `icon.ico` 打包進 exe。少了它，視窗、工作列和桌面捷徑都會顯示 PyInstaller 的預設圖示。接著它會執行 `check_build.py`：如果 exe 裡缺少控制台需要的 Tcl/Tk 檔案，打包就算失敗。PyInstaller 對這種情況只會發出警告，但這樣的 exe 完全無法啟動（v1.7.1 就是這樣：它用 Python 3.14.9 打包，PyInstaller 6.21 無法打包它的 Tcl/Tk 9 檔案；發布版本固定使用 Python 3.14.6）。要用不在 PATH 裡的 Python，先設定 `PYTHON`，例如 `set PYTHON=C:\Python314\python.exe`。

執行測試（使用 Python 內建的 `unittest`，也可以用 `pytest` 執行）：

```
python -m unittest discover -s tests -v
```

測試只使用暫存資料夾，不會動到你的檔案、網路設定、網際網路或已安裝的程式。整套測試都強制遵守這一點：使用者資料夾、程式資料夾和安裝資料夾都會被導向暫存的沙盒；測試如果沒有先換掉操作網路卡、防火牆或排程工作的 PowerShell 指令、`ipconfig` / `netsh` / 關機、網際網路或全螢幕警告就碰到它們，會直接失敗。測試只能暫停自己開出來的程序。有些測試會實際使用唯讀的 Windows 功能：透過 WMI 監看新程序、用 Defender 掃描暫存檔，以及讀取排程工作。

圖標 `icon.ico` / `icon.png` 由 `make_icon.py` 產生（需要 `pip install pillow`），要改圖標就改這個檔案再執行一次。

不想用 exe、直接用 Python 執行的話，專案裡有幾個輔助檔案（要和 `ransom_guard.py` 放在同一個資料夾）：

| 檔案 | 作用 |
| --- | --- |
| `install_ransom_guard.bat` | 用 Python 版安裝背景監控（自動找 Python、安裝 watchdog） |
| `restore_network.bat` | 不需要 Python 也能恢復被切斷的網路 |
| `preview_warning.bat` | 預覽全螢幕警告 |

打包好的檔案在 `dist\RansomGuard.exe`。

### 發布新版

發布版本由 GitHub Actions 打包和發布，不再手動上傳：

1. 修改 `ransom_guard.py` 裡的 `VERSION`，例如 `"1.7.2"`，並在 `release-notes/v1.7.2.md` 寫好發布說明。
2. 執行測試、提交並推送。每次推送分支和每個 pull request，[CI workflow](.github/workflows/ci.yml) 都會執行檢查、測試和打包。
3. 為這個 commit 加上 tag 並推送：

   ```
   git tag v1.7.2
   git push origin v1.7.2
   ```

4. [發布 workflow](.github/workflows/release.yml) 會確認 tag 和 `VERSION` 一致、執行測試、打包 exe、簽署 attestation、發布 Release（先建立草稿，讓 exe 在版本變成不可變更之前附上去），並在上一版的說明加上建議更新的提示。

v1.7.0 起的 Release 是不可變更的：發布後檔案和 tag 都不能修改，所以出錯時只能發新的版本號，它們的 exe 也會一直可以下載。README 的下載按鈕永遠指向最新版本，不需要修改。

## 開發方式

RansomGuard 主要使用 Anthropic 的 AI 程式開發助理 [Claude Code](https://claude.com/claude-code) 開發。repo 擁有者負責審閱修改內容、決定每個版本要放進什麼，並在自己的電腦上試用新版本。每次修改都會經過 `tests/` 裡的自動測試。AI 輔助寫出的程式仍可能有錯，發現任何問題請到 [Issues](https://github.com/leo-code-del/RansomGuard/issues) 回報。

## 已知限制與風險

RansomGuard 是額外的一道防線，不是唯一的防護。請繼續使用防毒軟體（例如 Microsoft Defender）、安裝 Windows 更新，並定期把重要檔案備份到**平常不接在電腦上**的硬碟。一直接著的備份硬碟也可能一起被加密。

**做不到的事**

- 它不是防毒軟體，不認得惡意程式，只會對「看起來像在加密」的行為做出反應。
- 只監控桌面、文件、圖片、下載、影片、音樂。其他磁碟、網路磁碟，以及不在這些資料夾裡的雲端資料夾都不受保護，除非用 `--watch` 加進來。
- 反應之前會有一些檔案已經被加密：30 秒內約 8 到 10 個檔案看起來被加密才會觸發（或誘餌檔被動到），而且 Windows 回報檔案變動本身就有約 1 秒的延遲。
- 加密速度慢到低於這些門檻的勒索病毒，只有碰到誘餌檔才會被抓到。保留檔名、又不動檔案開頭的勒索病毒也一樣。
- 透過 Windows 程式介面刪除還原點、而不是執行 `vssadmin` 這類指令的勒索病毒，危險指令檢查抓不到。
- 透過記憶體映射檔案寫入的程式不會出現在寫入量統計中，可能找不到它來暫停。
- 已經取得系統管理員權限的勒索病毒可以停止 RansomGuard 或刪除它的排程工作。防護狀態檢查會在一天內提醒你。
- 觸發後、關閉警告畫面之後，監控會停止，直到你恢復網路或再次登入 Windows 為止。如果在恢復網路之前再次登入，它會提醒你網路已被切斷，並重新開始監控。
- 只用自動測試和模擬的勒索病毒（由測試腳本加密並改名檔案）測試過，沒有用真正的勒索病毒測試過。
- 只支援 Windows 10 和 11，而且需要系統管理員權限。

**可能出錯的情況**

- **誤判會切斷網路。** 例如你自己動到誘餌檔、有程式在 30 秒內把 10 個以上的檔案改成不常見的副檔名，或三個資料夾出現名稱像勒索訊息的檔案（例如 `how to recover files.txt`）。
- **正當的系統維護會被中止。** 備份軟體或系統管理員執行 `wbadmin delete backup`、`vssadmin delete shadows` 或 `wevtutil cl` 時會被當成勒索病毒：指令會被結束，網路會被切斷。
- **誤判時正常程式可能被暫停。** 編輯器、瀏覽器和 OneDrive 這類一直在寫檔的程式可能被暫停（畫面卡住），直到你從控制台恢復網路。如果改用 `restore_network.bat` 恢復，它們會一直暫停到重新開機。
- **不主動查詢就不會知道有新版本。** 為了保護隱私，自動檢查新版本預設關閉，所以改進和修正只有在你偶爾按 **更新到最新版本**，或開啟 **自動檢查新版本** 時才會送到你手上。
- **解除安裝會刪除整個 `C:\Program Files\RansomGuard` 資料夾**，包括你自己放進去的檔案。
- 文件或圖片資料夾裡如果有你自己的檔案剛好和誘餌檔同名（例如 `!!!_canary_do_not_delete.docx`），會被誘餌檔取代。

**已知的安全問題**（修好後會從這裡移除）

- **從 Python 原始碼執行，可能讓惡意程式取得系統管理員權限。** `install_ransom_guard.bat` 和 `ransom_guard.py --install` 建立的排程工作，會以系統管理員權限執行原本資料夾裡的 `ransom_guard.py`。如果那個資料夾不需要系統管理員權限就能修改（例如 D: 上的資料夾或你的使用者資料夾），任何以你的身分執行的程式都可以改這支腳本，在你下次登入時取得系統管理員權限。exe 版沒有這個問題：它會把自己複製到只有系統管理員能修改的 `C:\Program Files\RansomGuard`。如果要從原始碼執行，請把專案放在只有系統管理員能修改的資料夾。
- **使用者資料夾裡的設定會影響以系統管理員權限執行的動作。** `state.json` 放在 `%LOCALAPPDATA%\RansomGuard`，任何以你的身分執行的程式都能修改。恢復網路時，裡面記錄的防火牆設定會以系統管理員權限還原，所以惡意程式可以利用它在那一刻把防火牆關掉。它也可以讓防護狀態檢查不提示監控已停止。
- **更新只對照 GitHub 檢查。** 用來核對更新的 SHA-256 同樣來自 GitHub，所以能防止下載損毀，但防不了 GitHub 帳號被入侵。程式內建的更新也不會檢查 attestation，不過你可以自己驗證（見[驗證下載的檔案](#驗證下載的檔案)）。exe 也沒有數位簽章，這也是 SmartScreen 和 Defender 有時不信任它的原因。

# 隱私權說明

[English](PRIVACY.md) | **中文(繁體)**

這份說明描述 RansomGuard 會處理哪些個人資料。撰寫時依循歐盟《一般資料保護規則》（GDPR）的原則：盡量少收集、不保存超過需要的時間、公開透明，並讓你可以刪除。這是程式行為的說明，不是法律意見。

## 重點

- **開發者不收集任何資料。** RansomGuard 沒有遙測、使用統計、當機回報、帳號或廣告，也絕對不會把你的檔案、檔名、紀錄檔或設定傳送到任何地方。
- RansomGuard 記錄的所有東西都只存在你的電腦上，紀錄檔最多保留 30 天，你隨時都可以刪除。
- 預設情況下，RansomGuard **不會自己連上網路**。只有在你按 **檢查版本更新**，或你開啟 **自動檢查新版本** 後每 6 小時，才會連到 GitHub。

## 留在你電腦上的資料

| 資料 | 位置 | 內容 | 保存多久 |
| --- | --- | --- | --- |
| 紀錄檔 | `%LOCALAPPDATA%\RansomGuard\guard.log`（以及 `.1` 到 `.3`） | 時間、看起來被加密的檔案名稱、被結束或暫停的程式（含命令列）、RansomGuard 做了什麼。檔案和資料夾名稱可能包含你的 Windows 使用者名稱或其他個人資訊 | RansomGuard 啟動時，以及監控期間每天，會刪除超過 30 天的紀錄；全部加起來最多 4 MB |
| 狀態 | `C:\ProgramData\RansomGuard\state.json` | 什麼時候切斷了網路、要還原哪些網路卡和防火牆設定、暫停了哪些程式、為什麼觸發，以及最多 50 個被判定像被加密的檔名 | 恢復網路為止 |
| 誘餌檔紀錄、監控的資料夾、停止記號 | `C:\ProgramData\RansomGuard\`（`canaries.json`、`watch.json`、`monitor_stopped`） | 它建立的誘餌檔和你加入的資料夾的路徑；你什麼時候停止了監控 | 解除安裝為止 |
| 設定 | `%LOCALAPPDATA%\RansomGuard\settings.json` | 介面語言、是否開啟自動檢查新版本 | 解除安裝為止 |
| 誘餌檔 | 每個監控的資料夾（隱藏） | 說明這是什麼檔案的固定文字，沒有任何關於你的資料 | 解除安裝為止 |

`C:\ProgramData\RansomGuard` 只有系統管理員能修改，所以任何以你的身分執行的程式，都無法竄改 RansomGuard 以系統管理員權限執行的動作。你自己的帳號可以讀取。

**刪除方式：** 控制台的 **清除紀錄檔** 按鈕會清空紀錄檔。**解除安裝** 會刪除 `%LOCALAPPDATA%\RansomGuard`、`C:\ProgramData\RansomGuard`、誘餌檔，以及 RansomGuard 安裝的所有東西。你也可以自己刪除這些檔案（`C:\ProgramData\RansomGuard` 需要系統管理員權限），RansomGuard 會重新建立需要的部分。

RansomGuard 會讀取監控資料夾中有變動的檔案的前 16 KB，用來判斷是否像被加密過。讀到的內容只在記憶體中比對，不會保存；只有在檔案看起來被加密時，紀錄檔才會記下它的檔名。

## 網路連線

RansomGuard 唯一會連線的地方是 **GitHub**（`api.github.com`、`github.com`），而且只在以下情況：

- 你按 **檢查版本更新** 時，以及下載你同意安裝的新版本時（或執行 `RansomGuard.exe --update` / `--install` 時）；
- **只有在你開啟了「自動檢查新版本」時**，每 6 小時一次以及開啟控制台時（預設關閉；開啟前控制台會先說明這代表什麼）；
- 防護狀態檢查發現防護不見了，而你選擇用瀏覽器開啟下載頁面時。

GitHub 會收到：你的 IP 位址、時間，以及請求本身（只是查詢最新版本或下載 exe）。RansomGuard 只以 `RansomGuard` 表明身分，不包含版本號或任何關於你的資訊。GitHub 依照 [GitHub 一般隱私權聲明](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement) 處理這些資料，開發者收不到這些資料。

**連線時，你的 IP 位址無法對伺服器隱藏**，任何程式都做不到。如果不想讓 GitHub 知道你的 IP，請保持自動檢查新版本關閉、不要按更新按鈕，或透過 VPN 更新（RansomGuard 會使用 Windows 的代理伺服器設定）。改用 VPN 時，看得到你 IP 位址的會變成 VPN 業者。

**用「安裝並開始監控」安裝時，完全不會連上網路。**

## Microsoft Defender

RansomGuard 會請 Windows 內建的 Microsoft Defender 掃描「下載」資料夾和桌面上新出現的程式、腳本和壓縮檔，以及觸發時被暫停的程式。掃描在你的電腦上執行。Defender 是否把檔案資訊（或檔案本身）傳送給 Microsoft，取決於你的 Defender 設定，而不是 RansomGuard：Windows 安全性 → 病毒與威脅防護 → 管理設定 → **雲端提供的保護** 和 **自動提交範例**。Defender 本來就會自己掃描下載的檔案，所以 RansomGuard 的掃描不會改變 Defender 可能傳送的內容。請參考 [Microsoft 隱私權聲明](https://privacy.microsoft.com/privacystatement)。

Defender 的掃描程式（`MpCmdRun.exe`）會自己留一份紀錄 `%TEMP%\MpCmdRun.log`，裡面列出被要求掃描的檔案。這份紀錄屬於 Defender，所以 RansomGuard 不會清除或刪除它；你可以自己刪除。

## 你在 GDPR 下的權利

開發者不收集、不接收也不保存 RansomGuard 使用者的任何個人資料，所以沒有任何資料可以讓開發者為你查閱、更正、匯出或刪除。上面描述的資料都留在你自己的電腦上、由你掌控：你可以閱讀它（都是純文字）、刪除它（清除紀錄檔、解除安裝），也可以停止產生它（解除安裝）。

## 問題

請到 [Issues](https://github.com/leo-code-del/RansomGuard/issues) 提問。Issues 是公開的：請不要在那裡貼出你的紀錄檔或任何個人資訊。

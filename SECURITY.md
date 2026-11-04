# Security policy

**English** | [中文(繁體)](#安全政策)

RansomGuard runs with administrator rights, so a security problem in it can be serious. Thank you for reporting one privately.

## Supported versions

Only the [latest release](https://github.com/leo-code-del/RansomGuard/releases/latest) gets security fixes. Older versions are not patched; update with **Check for updates** in the control panel or download the latest `RansomGuard.exe`.

## Reporting a vulnerability

**Please don't report security problems in public Issues or Discussions**, because that tells everyone how to attack RansomGuard's users before a fix exists.

Report it privately through GitHub instead: [**Report a vulnerability**](https://github.com/leo-code-del/RansomGuard/security/advisories/new) (Security tab → Advisories → Report a vulnerability). Only the maintainer can see the report.

Please include:

- the RansomGuard version (control panel, or the exe's Properties → Details) and the Windows version;
- what an attacker could do, and what they would need first (for example, a program already running as the user);
- steps to reproduce, or a proof of concept that doesn't harm anyone else's computer.

## What to expect

RansomGuard is maintained by one person in their spare time, so these are aims, not guarantees:

- a first reply within **7 days**;
- a fix released as soon as practical, depending on how serious the problem is;
- credit in the release notes and the GitHub advisory, unless you'd rather stay anonymous.

Please give the fix time to be released before you publish details.

## Already known

Problems that are already known and not yet fixed are listed under [Known security issues](README.md#known-security-issues) in the README; there is no need to report those again.

## Out of scope

- Ransomware that RansomGuard doesn't detect. RansomGuard is an extra line of defense and can't catch everything (see [Known limitations and risks](README.md#known-limitations-and-risks)); a missed detection is welcome as a normal Issue, as long as it contains no malware samples or personal data.
- Attacks that already need administrator rights. A program with administrator rights can already disable or remove RansomGuard.

---

# 安全政策

[English](#security-policy) | **中文(繁體)**

RansomGuard 以系統管理員權限執行，所以它的安全問題可能很嚴重。感謝你私下回報。

## 支援的版本

只有[最新版本](https://github.com/leo-code-del/RansomGuard/releases/latest)會收到安全修正，舊版本不會另外修補。請用控制台的**檢查更新**更新，或下載最新的 `RansomGuard.exe`。

## 回報漏洞

**請不要在公開的 Issues 或 Discussions 回報安全問題**，否則在修正推出前，等於先告訴所有人怎麼攻擊 RansomGuard 的使用者。

請改用 GitHub 私下回報：[**Report a vulnerability**](https://github.com/leo-code-del/RansomGuard/security/advisories/new)（Security 分頁 → Advisories → Report a vulnerability）。只有維護者看得到回報內容。

請附上：

- RansomGuard 的版本（控制台，或 exe 的「內容 → 詳細資料」）和 Windows 版本；
- 攻擊者能做到什麼，以及事先需要什麼條件（例如已經有一個以使用者身分執行的程式）；
- 重現步驟，或不會傷害他人電腦的概念驗證。

## 回報之後

RansomGuard 由一個人利用空閒時間維護，以下是目標，不是保證：

- **7 天內**第一次回覆；
- 依問題的嚴重程度，盡快發布修正版本；
- 在版本說明和 GitHub advisory 中致謝，除非你希望匿名。

在修正版本發布前，請先不要公開細節。

## 已知的問題

已知但還沒修正的問題列在 README 的[已知的安全問題](README.zh-TW.md#已知的安全問題)，不需要再回報。

## 不在範圍內

- RansomGuard 沒偵測到的勒索軟體。RansomGuard 是額外的防線，無法攔下所有攻擊（見[已知限制與風險](README.zh-TW.md#已知限制與風險)）。漏偵測歡迎用一般 Issue 回報，但請不要附上惡意程式樣本或個人資料。
- 本來就需要系統管理員權限的攻擊。已經有系統管理員權限的程式，本來就能停用或移除 RansomGuard。

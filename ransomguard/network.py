"""Cutting the network off (adapters, firewall fallback), keeping it off, and restoring it."""
import json
import time

from . import canary, config, defender, install, storage, winapi
from .config import log, tr


def disconnect_network() -> bool:
    if not config.IS_WINDOWS:
        log.error(tr("目前只支援 Windows 斷網", "Cutting the network is only supported on Windows"))
        return False
    st = storage.load_state()
    try:
        _, out, _ = winapi._ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                               "| ForEach-Object {$_.Name}")
        names = [line.strip() for line in out.splitlines() if line.strip()]
        st["disabled_adapters"] = sorted(set(st.get("disabled_adapters", []) + names))
        st["triggered_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        storage.save_state(st)
        rc, _, err = winapi._ps("Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'} "
                                "| Disable-NetAdapter -Confirm:$false")
        if rc != 0:
            log.error(tr("停用網路卡時出現錯誤：%s", "Error while disabling network adapters: %s"), err)
    except Exception:
        log.exception(tr("停用網路卡失敗", "Failed to disable network adapters"))

    up = adapters_up()
    if up == "0":
        log.critical(tr("已停用所有網路卡：%s", "All network adapters disabled: %s"),
                     ", ".join(st.get("disabled_adapters", [])))
        return True
    log.error(tr("仍有網路卡在線上（%s），改用防火牆封鎖與備援方式斷線",
                 "Network adapters still up (%s); falling back to firewall block and disconnect"), up)
    block_firewall()
    winapi._run([winapi.sys_exe("ipconfig.exe"), "/release"])
    winapi._run([winapi.sys_exe("netsh.exe"), "wlan", "disconnect"])
    return False


def adapters_up() -> str:
    """Number of connected network adapters (as a string); "?" if the query fails."""
    try:
        return winapi._ps("@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}).Count")[1]
    except Exception:
        return "?"


def block_firewall():
    """Fallback when disabling adapters fails: block all traffic in every firewall profile (the original
    settings are saved in state.json)."""
    st = storage.load_state()
    try:
        if "firewall" not in st:
            _, out, _ = winapi._ps(
                "@(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{"
                "Name=$_.Name; Enabled=\"$($_.Enabled)\"; "
                "In=\"$($_.DefaultInboundAction)\"; Out=\"$($_.DefaultOutboundAction)\"} })"
                " | ConvertTo-Json -Compress")
            saved = json.loads(out)
            st["firewall"] = saved if isinstance(saved, list) else [saved]
            storage.save_state(st)
        rc, _, err = winapi._ps("Set-NetFirewallProfile -All -Enabled True "
                                "-DefaultInboundAction Block -DefaultOutboundAction Block")
        if rc == 0:
            log.critical(tr("已用防火牆封鎖所有進出連線", "Firewall now blocks all inbound and outbound connections"))
        else:
            log.error(tr("防火牆封鎖失敗：%s", "Firewall block failed: %s"), err)
    except Exception:
        log.exception(tr("防火牆封鎖失敗", "Firewall block failed"))


def keep_offline(proc):
    """While the warning is open, disable any network adapter that gets re-enabled (e.g. by malware)."""
    while proc.poll() is None:
        time.sleep(10)
        if proc.poll() is None and adapters_up() not in ("0", "?"):
            log.warning(tr("偵測到網路卡被重新啟用，再次切斷網路",
                           "A network adapter was re-enabled; cutting the network again"))
            disconnect_network()


def restore_network(report=print) -> bool:
    """Restore network adapters and firewall settings, reset canary files, then restart background monitoring."""
    if config.IS_WINDOWS and not winapi.is_admin():
        report(tr("需要以系統管理員身分執行才能恢復網路。",
                  "Administrator rights are needed to restore the network."))
        return False
    storage.secure_state_dir()
    st = storage.load_state()
    if st.get("triggered_at"):
        report(tr(f"RansomGuard 在 {st['triggered_at']} 切斷了網路。",
                  f"RansomGuard cut off the network at {st['triggered_at']}."))
        for line in storage.incident_lines(st, limit=5):
            report(line)
    installed = bool(install.task_state())
    report(tr("停止監控（避免重設誘餌檔時又觸發）...",
              "Stopping monitoring (so resetting canary files doesn't trigger it again)..."))
    install.stop_monitor()

    ok = True
    names = st.get("disabled_adapters") or []
    if names:
        report(tr("重新啟用網路卡...", "Re-enabling network adapters..."))
        # enable them one by one, so a missing adapter (e.g. an unplugged USB one) doesn't stop the others
        _, out, err = winapi._ps(
            f"$t = @(Get-NetAdapter -Name @({','.join(winapi._ps_quote(n) for n in names)}) "
            "-ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Disabled'}); "
            "foreach ($a in $t) { try { Enable-NetAdapter -Name $a.Name -Confirm:$false "
            "-ErrorAction Stop; \"OK`t$($a.Name)\" } "
            "catch { \"FAIL`t$($a.Name)`t$($_.Exception.Message)\" } }")
        lines = [line.split("\t") for line in out.splitlines() if line.strip()]
        for r in lines:
            if r[0] == "OK":
                log.info(tr("已重新啟用網路卡：%s", "Network adapter re-enabled: %s"), r[1])
                report(tr(f"  已啟用 {r[1]}", f"  Enabled {r[1]}"))
            else:
                ok = False
                log.error(tr("無法啟用網路卡 %s：%s", "Could not enable network adapter %s: %s"), r[1], r[-1])
                report(tr(f"  無法啟用 {r[1]}：{r[-1]}", f"  Could not enable {r[1]}: {r[-1]}"))
        if not lines:
            report(tr("  網路卡都已經是啟用狀態", "  All network adapters are already enabled")
                   + (f" ({err})" if err else ""))
    else:
        report(tr("沒有被本程式停用的網路卡。", "No network adapters were disabled by this program."))
    for p in st.get("firewall") or []:
        r = winapi._ps(f"Set-NetFirewallProfile -Name {winapi._ps_quote(p['Name'])} "
                       f"-Enabled {winapi._ps_quote(p['Enabled'])} -DefaultInboundAction {winapi._ps_quote(p['In'])} "
                       f"-DefaultOutboundAction {winapi._ps_quote(p['Out'])}")
        if r[0] == 0:
            log.info(tr("已還原防火牆設定：%s", "Firewall settings restored: %s"), p["Name"])
            report(tr(f"  已還原防火牆設定 {p['Name']}", f"  Restored firewall settings for {p['Name']}"))
        else:
            ok = False
            log.error(tr("還原防火牆設定失敗（%s）：%s", "Failed to restore firewall settings (%s): %s"),
                      p["Name"], r[2])
            report(tr(f"  還原防火牆設定失敗（{p['Name']}）：{r[2]}",
                      f"  Failed to restore firewall settings ({p['Name']}): {r[2]}"))
    if storage.network_cut(st):
        time.sleep(3)
        winapi._run([winapi.sys_exe("ipconfig.exe"), "/renew"])
    if st.get("paused"):
        defender.resume_paused(st["paused"], report)
    if ok:
        storage.save_state({})
    else:
        report(tr("部分設定沒有還原成功，請按 Win+R 輸入 ncpa.cpl 手動啟用網路卡。",
                  "Some settings were not restored. Press Win+R, type ncpa.cpl and enable "
                  "the network adapters manually."))

    report(tr("重設誘餌檔...", "Resetting canary files..."))
    canary.remove_canaries()
    if installed:
        report(tr("重新開啟監控...", "Restarting monitoring..."))
        report(tr("  監控已重新啟動", "  Monitoring restarted") if install.start_monitor() else
               tr("  監控沒有正常啟動，請按「安裝並開始監控」，或查看紀錄檔",
                  "  Monitoring did not start. Click \"Install and start monitoring\" "
                  "or check the log"))
    else:
        report(tr("尚未安裝背景監控（排程工作），所以沒有重新開啟監控。",
                  "Background monitoring (scheduled task) is not installed, so it was not restarted."))
    up = adapters_up()
    report(tr(f"完成。目前連線中的網路卡：{up} 張", f"Done. Network adapters connected now: {up}") + (
        tr("（Wi-Fi 可能需要幾秒鐘重新連線）", " (Wi-Fi may take a few seconds to reconnect)")
        if up == "0" else ""))
    return ok

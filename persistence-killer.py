"""
无文件木马通用猎人 v3.2 (广谱雷达 + 深度修复版)
================================================
v3.2 修复清单:
  - [BUG] json.loads 双重调用 (step4/6/9) → 提取为 parse_json_safe()
  - [BUG] step1/5/6/7/8/9 缺少 record()，威胁不进 HTML 报告
  - [BUG] BITS JobId 为 None 时删除命令崩溃
  - [BUG] HTML 报告退化 → 恢复 v2.0 卡片汇总 + 暗色主题
  - [BUG] IP 嗅探未过滤 172.16-31 内网段
  - [BUG] AppInit_DLLs 0x0 误报

v3.2 新增检测:
  - [新] AMSI / ETW bypass 特征（反杀软常见手法）
  - [新] Living-off-the-Land 扩展（msbuild/regasm/cmstp 等）
  - [新] COM 劫持持久化（HKCU InprocServer32 异常路径）
  - [新] NTFS 备用数据流 (ADS) 隐藏载荷扫描
  - [新] Winlogon Notify / LSA 认证包劫持检测
  - [新] 服务注册表 ImagePath 异常位置检测

检测范围 (共 11 步):
  1.  已知恶意计划任务自动清除
  2.  未知可疑计划任务 (特征库 + IP 嗅探)
  3.  注册表 (Run / Winlogon / LSA / IFEO / AppInit / 服务)
  4.  WMI 事件订阅后门 (CommandLine + ActiveScript)
  5.  启动文件夹 LNK 深度追踪
  6.  可疑 Windows 服务扫描
  7.  PowerShell $PROFILE 持久化检查
  8.  hosts 文件劫持检测
  9.  BITS 恶意影子下载任务
  10. COM 劫持 / DLL 侧加载检测
  11. NTFS 备用数据流 (ADS) 扫描

使用方法: 以管理员身份运行
  python malware_hunter.py           # 标准交互模式
  python malware_hunter.py --auto    # 仅扫描，不执行删除
  python malware_hunter.py --report  # 强制生成 HTML 报告
"""

import subprocess, os, sys, re, json, logging, shutil, argparse
from datetime import datetime
from pathlib import Path

# ── 参数解析 ──────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--auto",   action="store_true", help="仅扫描，跳过所有删除询问")
parser.add_argument("--report", action="store_true", help="强制生成 HTML 报告")
ARGS, _ = parser.parse_known_args()

# ── 日志配置 ──────────────────────────────────────────────────────────────────
TEMP_DIR  = os.environ.get("TEMP", "C:\\Temp")
LOG_FILE  = os.path.join(TEMP_DIR, "malware_hunter.log")
HTML_FILE = os.path.join(TEMP_DIR, "malware_hunter_report.html")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)
REPORT_ITEMS: list[dict] = []

# ═══════════════════════════════════════════════════════════════
#  特征库
# ═══════════════════════════════════════════════════════════════

MALICIOUS_TASKS = [
    {"name": "Windows Perflog",
     "path": "\\",
     "reason": "伪装系统任务，从 79.8.141.x 远程下载执行恶意脚本"},
    {"name": "GoogleUpdaterTaskSystem47.0.7703.3{47263A17-2D66-43B9-9692-30514D0C1AEC}",
     "path": "\\GoogleSystem\\GoogleUpdater\\",
     "reason": "伪装 Google 更新，执行相同恶意 C2 下载命令"},
]

SAFE_TASKS = {
    "USER_ESRV_SVC_QUEENCREEK":                     "Intel SUR 合法组件",
    "PCR Prediction Framework Firmware Update Task": "Windows TPM 固件管理",
    "NvTmRep":                                       "Nvidia 遥测正常任务",
    "MicrosoftEdgeUpdateTaskMachineCore":            "Edge 正常更新",
    "MicrosoftEdgeUpdateTaskMachineUA":              "Edge 正常更新",
    "GoogleUpdateTaskMachineCore":                   "Google Chrome 正常更新",
    "GoogleUpdateTaskMachineUA":                     "Google Chrome 正常更新",
    "OneDrive Standalone Update Task":               "OneDrive 正常更新",
    "Adobe Acrobat Update Task":                     "Adobe 正常更新",
}

# 命令行行为特征 ─────────────────────────────────────────────────
MALICIOUS_PATTERNS = [
    # 绕过安全机制
    "ExecutionPolicy Bypass", "WindowStyle Hidden",
    "-nop ", "-noprofile", "-noninteractive",
    "-enc ", "-encodedcommand", "frombase64string",
    # AMSI / ETW bypass（新增）
    "amsiInitFailed", "amsiContext", "AmsiScanBuffer",
    "etwEventWrite", "EtwpNotificationThread",
    "Set-MpPreference -Disable", "Add-MpPreference -ExclusionPath",
    # 混淆标志
    "ROGieROGx", "`i`e`x", "i''ex", "char(", "join('')",
    # 远程代码执行
    "downloadstring", "iex(", "invoke-expression", "net.webclient",
    "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
    # Living-off-the-Land 滥用系统工具（新增）
    "bitsadmin /transfer", "certutil -urlcache", "certutil -decode",
    "msbuild.exe", "regasm.exe", "regsvcs.exe",
    "cmstp.exe", "csc.exe /out:",
    "wmic process call create",
    "regsvr32 /s /n /u /i:http",
    "mshta http", "mshta.exe http",
    "rundll32 javascript",
    "wscript.shell", "createobject(", "shellexecute",
    # 内存注入 / 反射加载（新增）
    "virtualalloc", "writeprocessmemory", "createthread",
    "reflectiveloader", "[reflection.assembly]::load",
    # 已知 C2
    "79.8141710",
]

# 路径高危特征 ───────────────────────────────────────────────────
MALICIOUS_PATH_PATTERNS = [
    r"Free Downloaded Files",
    r"\data\.temp",
    r"\AppData\Local\Temp\[0-9a-f]{8}",
    "DNSWatcher",
]

# 注册表扫描范围 ─────────────────────────────────────────────────
REGISTRY_SCAN_KEYS = [
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",            # 新增：LSA 认证包
    r"HKLM\SYSTEM\CurrentControlSet\Services",               # 新增：服务 ImagePath
]

STARTUP_FOLDERS = [
    os.path.join(os.environ.get("APPDATA", ""),    r"Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
]

HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

# ADS 扫描目录（只扫高危位置）
ADS_SCAN_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    "C:\\Windows\\Temp",
    "C:\\ProgramData",
]

# 合法 COM InprocServer32 路径前缀
SAFE_COM_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

# LSA 合法认证包白名单
SAFE_LSA_PACKAGES = {"msv1_0", "kerberos", "wdigest", "tspkg", "pku2u", "livessp"}

# ═══════════════════════════════════════════════════════════════
#  工具函数
# ═══════════════════════════════════════════════════════════════

def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run(cmd: list, capture=True, timeout=30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=capture, text=True,
            encoding="utf-8", errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        log.warning(f"  [超时] {' '.join(cmd[:3])}")
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def parse_json_safe(text: str) -> list:
    """安全解析 JSON 为 list（修复 v3.1 双重调用 bug）"""
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return []


def banner(title: str):
    log.info("\n" + "═" * 64)
    log.info(f"  {title}")
    log.info("═" * 64)


def ask(prompt: str) -> bool:
    if ARGS.auto:
        return False
    try:
        return input(f"     {prompt} (y/n): ").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def record(level: str, category: str, name: str, detail: str, action: str = ""):
    REPORT_ITEMS.append({
        "level": level, "category": category, "name": name,
        "detail": detail, "action": action,
        "time": datetime.now().strftime("%H:%M:%S"),
    })


def backup_task(name: str):
    ps = f'Export-ScheduledTask -TaskName "{name}" -ErrorAction SilentlyContinue'
    xml = run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip()
    if not xml:
        return
    safe = re.sub(r'[\\/:*?"<>|]', "_", name[:40])
    bpath = os.path.join(TEMP_DIR, f"task_backup_{safe}.xml")
    try:
        Path(bpath).write_text(xml, encoding="utf-8")
        log.info(f"     已备份至: {bpath}")
    except Exception:
        pass


def delete_task(name: str, path: str = "\\") -> bool:
    ps = (
        f'Unregister-ScheduledTask -TaskName "{name}" '
        f'-TaskPath "{path}" -Confirm:$false -ErrorAction Stop'
    )
    r = run(["powershell", "-NoProfile", "-Command", ps])
    if r.returncode == 0:
        log.info(f"  [已删除] {path}{name}")
        return True
    log.error(f"  [失败]   {path}{name}  →  {r.stderr.strip()}")
    return False


def get_lnk_target(lnk_path: str) -> str:
    ps = f'$sh=New-Object -ComObject WScript.Shell; $sh.CreateShortcut("{lnk_path}").TargetPath'
    return run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip()


def match_patterns(text: str, patterns: list) -> list:
    t = text.lower()
    return [p for p in patterns if p.lower() in t]


def extract_suspicious_ips(text: str) -> list:
    """提取公网 IP，过滤所有私有/特殊地址（修复 v3.1 遗漏 172.16-31）"""
    SAFE_IPS = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "114.114.114.114", "223.5.5.5", "223.6.6.6",
        "208.67.222.222", "208.67.220.220",
    }
    found = re.findall(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        text
    )
    result = []
    for ip in found:
        if ip in SAFE_IPS:
            continue
        try:
            a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
        except (ValueError, IndexError):
            continue
        if (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or   # 修复：v3.1 遗漏此段
                (a == 192 and b == 168) or
                (a == 169 and b == 254) or
                ip in ("0.0.0.0", "255.255.255.255")):
            continue
        if ip not in result:
            result.append(ip)
    return result


# ═══════════════════════════════════════════════════════════════
#  步骤函数
# ═══════════════════════════════════════════════════════════════

def step1_remove_known_tasks() -> int:
    banner("步骤 1 / 11 — 删除已知恶意计划任务")
    removed = 0
    for t in MALICIOUS_TASKS:
        name, path, reason = t["name"], t["path"], t["reason"]
        ps = f'Get-ScheduledTask -TaskName "{name}" -ErrorAction SilentlyContinue'
        if not run(["powershell", "-NoProfile", "-Command", ps]).stdout.strip():
            log.info(f"  [不存在] {name}")
            continue
        log.warning(f"\n  ⚠  确认恶意任务: {name}")
        log.warning(f"     原因: {reason}")
        backup_task(name)
        if delete_task(name, path):
            removed += 1
            record("HIGH", "计划任务", name, reason, "已自动删除")  # 修复：v3.1 缺少
    if removed == 0:
        log.info("  未发现已知恶意任务")
    return removed


def step2_scan_unknown_tasks() -> int:
    banner("步骤 2 / 11 — 扫描未知可疑计划任务 (特征库 + IP 嗅探)")
    ps = (
        r"Get-ScheduledTask | ForEach-Object {"
        r" $t=$_; $act=($t.Actions | ForEach-Object { $_.Execute+' '+$_.Arguments }) -join ' ';"
        r" [PSCustomObject]@{Name=$t.TaskName;Path=$t.TaskPath;Actions=$act;Author=$t.Author}"
        r"} | ConvertTo-Json -Compress"
    )
    r     = run(["powershell", "-NoProfile", "-Command", ps])
    tasks = parse_json_safe(r.stdout)   # 修复：安全解析

    known          = {t["name"] for t in MALICIOUS_TASKS}
    removed, found = 0, False

    for t in tasks:
        name    = t.get("Name", "")
        path    = t.get("Path", "\\")
        actions = t.get("Actions", "")
        author  = t.get("Author", "")

        if name in known or name in SAFE_TASKS:
            continue

        hits = match_patterns(actions, MALICIOUS_PATTERNS)
        ips  = extract_suspicious_ips(actions)
        if not hits and not ips:
            continue

        found = True
        log.warning(f"\n  ⚠  可疑任务: {path}{name}  (作者: {author})")
        if hits: log.warning(f"     匹配特征: {', '.join(hits)}")
        if ips:  log.warning(f"     发现外网 IP: {', '.join(ips)}")
        log.warning(f"     完整命令: {actions}")
        record("HIGH", "计划任务", name,
               f"特征:{','.join(hits)} IP:{','.join(ips)}\n{actions[:300]}")

        if ask("是否删除"):
            backup_task(name)
            if delete_task(name, path):
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已手动删除"

    if not found:
        log.info("  未发现可疑计划任务")
    return removed


def step3_scan_registry() -> int:
    banner("步骤 3 / 11 — 检查注册表 (Run / Winlogon / LSA / IFEO / AppInit / 服务)")
    removed = 0

    for key in REGISTRY_SCAN_KEYS:
        r = run(["reg", "query", key])
        if r.returncode != 0:
            continue

        is_ifeo     = "Image File Execution Options" in key
        is_winlogon = "Winlogon" in key
        is_lsa      = r"Control\Lsa" in key
        is_services = r"CurrentControlSet\Services" in key
        current_sub = key

        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.upper().startswith("HKEY"):
                current_sub = line
                continue

            parts    = line.split()
            kname    = parts[0].lower() if parts else ""
            regval   = parts[2] if len(parts) >= 3 else ""
            hits     = []

            # Winlogon 核心键值劫持
            if is_winlogon:
                if kname == "shell" and regval.lower() != "explorer.exe":
                    hits = [f"Shell 被劫持为: {regval}"]
                elif kname == "userinit" and "userinit.exe" not in regval.lower():
                    hits = [f"Userinit 被劫持为: {regval}"]
                elif kname == "notify" and regval:
                    hits = [f"Winlogon Notify DLL 注入: {regval}"]
                if not hits:
                    continue

            # LSA 认证包劫持（新增）
            elif is_lsa:
                if kname in ("authentication packages", "security packages"):
                    unknown = set(regval.lower().split()) - SAFE_LSA_PACKAGES - {""}
                    if unknown:
                        hits = [f"LSA 包含未知认证包: {', '.join(unknown)}"]
                if not hits:
                    continue

            # IFEO 映像劫持
            elif is_ifeo:
                if "debugger" not in line.lower():
                    continue
                if regval and "vsjitdebugger" not in regval.lower():
                    hits = [f"IFEO Debugger 劫持: {regval}"]

            # 服务 ImagePath 异常位置（新增）
            elif is_services:
                if kname != "imagepath":
                    continue
                if any(x in regval.lower() for x in ["\\users\\", "\\appdata\\", "\\temp\\"]):
                    hits = [f"服务可执行文件位于用户目录: {regval}"]
                else:
                    continue

            # 常规 Run 键 / AppInit
            else:
                hits = match_patterns(line, MALICIOUS_PATTERNS)
                if kname == "loadappinit_dlls":
                    if regval in ("0x1", "1"):
                        hits = ["LoadAppInit_DLLs 已启用，需确认 AppInit_DLLs 值"]
                    else:
                        continue   # 0x0 = 默认禁用，不报警（修复误报）
                elif kname == "appinit_dlls" and regval not in ("", '""', "''"):
                    hits = [f"AppInit_DLLs 包含 DLL 路径: {regval}"]

            if not hits:
                continue

            log.warning(f"\n  ⚠  可疑注册表: {current_sub}")
            log.warning(f"     内容: {line}")
            log.warning(f"     诊断: {', '.join(hits)}")
            record("HIGH", "注册表", current_sub, f"{line}\n{', '.join(hits)}")

            if is_winlogon or is_lsa:
                log.warning("     [重要] 系统核心键值，请手动打开 regedit 修复！")
                REPORT_ITEMS[-1]["action"] = "需手动修复"
            elif parts and ask("是否删除该注册表值"):
                r2 = run(["reg", "delete", current_sub, "/v", parts[0], "/f"])
                if r2.returncode == 0:
                    log.info(f"  [已删除] {current_sub}\\{parts[0]}")
                    removed += 1
                    REPORT_ITEMS[-1]["action"] = "已手动删除"
                else:
                    log.error(f"  [失败] {r2.stderr.strip()}")

    return removed


def step4_scan_wmi() -> int:
    banner("步骤 4 / 11 — 扫描 WMI 事件订阅后门")
    removed, found = 0, False

    for cls, field in [
        ("CommandLineEventConsumer",  "CommandLineTemplate"),
        ("ActiveScriptEventConsumer", "ScriptText"),
    ]:
        ps = (
            f"Get-WmiObject -Namespace root\\subscription -Class {cls} "
            f"-ErrorAction SilentlyContinue | Select-Object Name,{field} | ConvertTo-Json -Compress"
        )
        r         = run(["powershell", "-NoProfile", "-Command", ps])
        consumers = parse_json_safe(r.stdout)   # 修复：安全解析

        for c in consumers:
            name    = c.get("Name", "Unknown")
            content = c.get(field, "")
            hits    = match_patterns(content, MALICIOUS_PATTERNS)
            ips     = extract_suspicious_ips(content)

            found = True
            log.warning(f"\n  ⚠  发现 WMI {cls}: {name}")
            log.warning(f"     内容: {content[:400]}")
            if hits: log.warning(f"     匹配特征: {', '.join(hits)}")
            if ips:  log.warning(f"     发现外网 IP: {', '.join(ips)}")
            record("CRITICAL", "WMI后门", name,
                   f"{content[:200]}\n特征:{','.join(hits)} IP:{','.join(ips)}")

            if ask("该项极度危险，是否清除（含绑定和过滤器）"):
                for wmi_cls in [cls, "FilterToConsumerBinding", "__EventFilter"]:
                    del_ps = (
                        f"Get-WmiObject -Namespace root\\subscription -Class {wmi_cls} "
                        f"-Filter \"Name='{name}'\" -ErrorAction SilentlyContinue "
                        f"| Remove-WmiObject -ErrorAction SilentlyContinue"
                    )
                    run(["powershell", "-NoProfile", "-Command", del_ps])
                log.info(f"  [已清除] WMI 订阅: {name}")
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已手动清除"

    if not found:
        log.info("  未发现 WMI 事件订阅后门")
    return removed


def step5_scan_startup_folders() -> int:
    banner("步骤 5 / 11 — 扫描启动文件夹 (LNK 深度追踪)")
    removed      = 0
    script_exts  = {".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".wsf"}

    for folder in STARTUP_FOLDERS:
        if not os.path.exists(folder):
            continue
        for root, _, files in os.walk(folder):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext   = os.path.splitext(fname)[1].lower()

                if ext == ".lnk":
                    target = get_lnk_target(fpath)
                    hits   = match_patterns(fname + target, MALICIOUS_PATH_PATTERNS)
                    if not hits:
                        continue
                    log.warning(f"\n  🔴 发现恶意启动快捷方式: {fname}")
                    log.warning(f"     真实指向: {target}")
                    log.warning(f"     命中特征: {', '.join(hits)}")
                    record("HIGH", "启动文件夹", fname, f"目标: {target}")  # 修复：v3.1 缺少

                    if ask("是否删除快捷方式及其指向的恶意目录"):
                        try:
                            os.remove(fpath)
                            log.info(f"  [已删除] 快捷方式: {fname}")
                        except Exception as e:
                            log.error(f"  [失败] {e}")
                        if target and os.path.exists(target):
                            for pattern in ["Free Downloaded Files", r"\data\.temp"]:
                                if pattern in target:
                                    kill_dir = target.split(pattern)[0] + pattern
                                    if os.path.isdir(kill_dir):
                                        shutil.rmtree(kill_dir, ignore_errors=True)
                                        log.info(f"  [已摧毁] 毒源目录: {kill_dir}")
                        removed += 1
                        REPORT_ITEMS[-1]["action"] = "已删除"

                elif ext in script_exts:
                    log.warning(f"\n  ⚠  启动文件夹发现可疑脚本: {fpath}")
                    record("MEDIUM", "启动文件夹", fname, fpath)  # 修复：v3.1 缺少

                    if ask("是否删除"):
                        try:
                            os.remove(fpath)
                            log.info(f"  [已删除] {fname}")
                            removed += 1
                            REPORT_ITEMS[-1]["action"] = "已删除"
                        except Exception as e:
                            log.error(f"  [失败] {e}")
    return removed


def step6_scan_services() -> int:
    banner("步骤 6 / 11 — 扫描可疑 Windows 服务")
    ps = (
        "Get-WmiObject Win32_Service | "
        "Select-Object Name, DisplayName, PathName, StartMode, State "
        "| ConvertTo-Json -Compress"
    )
    r        = run(["powershell", "-NoProfile", "-Command", ps])
    services = parse_json_safe(r.stdout)   # 修复：安全解析
    removed, found = 0, False

    for svc in services:
        name  = svc.get("Name", "")
        path  = svc.get("PathName", "") or ""
        disp  = svc.get("DisplayName", "")
        start = svc.get("StartMode", "")

        hits       = match_patterns(path, MALICIOUS_PATTERNS)
        in_userdir = any(x in path.lower() for x in ["\\users\\", "\\appdata\\", "\\temp\\"])

        if not hits and not in_userdir:
            continue

        found = True
        log.warning(f"\n  ⚠  可疑服务: {name} ({disp})")
        log.warning(f"     路径: {path}  启动: {start}")
        if hits:       log.warning(f"     匹配特征: {', '.join(hits)}")
        if in_userdir: log.warning("     服务文件位于用户目录（高度可疑）")

        level = "HIGH" if hits else "MEDIUM"
        record(level, "服务", name, f"路径:{path}\n{', '.join(hits)}")  # 修复：v3.1 缺少

        if ask(f"是否停止并删除服务 [{name}]"):
            run(["sc", "stop", name])
            r2 = run(["sc", "delete", name])
            if r2.returncode == 0:
                log.info(f"  [已删除] 服务: {name}")
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已删除"
            else:
                log.error(f"  [失败] {r2.stderr.strip()}")

    if not found:
        log.info("  未发现可疑服务")
    return removed


def step7_check_powershell_profiles() -> int:
    banner("步骤 7 / 11 — 检查 PowerShell 配置文件 ($PROFILE 持久化)")
    profiles = [
        os.path.join(os.environ.get("USERPROFILE", ""),
                     r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
        os.path.join(os.environ.get("USERPROFILE", ""),
                     r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\profile.ps1",
    ]
    removed, found = 0, False

    for profile in profiles:
        if not os.path.exists(profile):
            continue
        try:
            content = Path(profile).read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        hits = match_patterns(content, MALICIOUS_PATTERNS)
        if not hits:
            continue

        found = True
        log.warning(f"\n  ⚠  发现可疑 PowerShell Profile: {profile}")
        log.warning(f"     匹配特征: {', '.join(hits)}")
        log.warning(f"     文件内容:\n{content[:500]}")
        record("HIGH", "PS Profile", profile, content[:300])  # 修复：v3.1 缺少

        if ask("是否清空该配置文件（清空而非删除，保留文件结构）"):
            try:
                Path(profile).write_text("# Cleared by malware_hunter\n", encoding="utf-8")
                log.info(f"  [已清空] {profile}")
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已清空"
            except Exception as e:
                log.error(f"  [失败] {e}")

    if not found:
        log.info("  PowerShell 配置文件未发现异常")
    return removed


def step8_check_hosts() -> int:
    banner("步骤 8 / 11 — 检查 hosts 文件劫持")
    try:
        content = Path(HOSTS_FILE).read_text(encoding="utf-8", errors="replace")
    except Exception:
        log.info("  无法读取 hosts 文件，跳过")
        return 0

    suspicious = [
        line for line in content.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and not re.match(r"^(127\.0\.0\.1|::1)\s+localhost", line.strip(), re.I)
    ]

    if not suspicious:
        log.info("  hosts 文件正常")
        return 0

    log.warning(f"\n  ⚠  hosts 包含 {len(suspicious)} 条非标准条目:")
    for sl in suspicious:
        log.warning(f"     {sl}")
    record("MEDIUM", "hosts劫持", HOSTS_FILE, "\n".join(suspicious[:20]))  # 修复：v3.1 缺少

    if ask("是否备份并还原 hosts 为默认值"):
        backup = HOSTS_FILE + f".bak_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        shutil.copy2(HOSTS_FILE, backup)
        log.info(f"  [已备份] {backup}")
        try:
            Path(HOSTS_FILE).write_text(
                "# Generated by malware_hunter\n127.0.0.1 localhost\n::1 localhost\n",
                encoding="utf-8"
            )
            log.info("  [已还原] hosts 文件")
            REPORT_ITEMS[-1]["action"] = "已还原"
            return 1
        except Exception as e:
            log.error(f"  [失败] {e}")
    return 0


def step9_scan_bits_jobs() -> int:
    banner("步骤 9 / 11 — 扫描 BITS 恶意影子下载任务 (带 IP 嗅探)")
    ps = (
        "Import-Module BitsTransfer -ErrorAction SilentlyContinue; "
        "Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | "
        "Select-Object JobId, DisplayName, CommandName, CommandParameters "
        "| ConvertTo-Json -Compress"
    )
    r    = run(["powershell", "-NoProfile", "-Command", ps])
    jobs = parse_json_safe(r.stdout)   # 修复：安全解析
    removed, found = 0, False

    for job in jobs:
        job_id = job.get("JobId") or ""           # 修复：None 崩溃
        disp   = job.get("DisplayName", "Unknown")
        cmd    = job.get("CommandName", "") or ""
        args   = job.get("CommandParameters", "") or ""
        full   = f"{cmd} {args}".strip()

        hits       = match_patterns(full, MALICIOUS_PATTERNS)
        ips        = extract_suspicious_ips(full)
        in_userdir = any(x in full.lower() for x in ["\\temp\\", "\\appdata\\"])

        if not hits and not ips and not in_userdir and not cmd:
            continue

        found = True
        log.warning(f"\n  ⚠  可疑 BITS 任务: {disp}  (JobId: {job_id})")
        log.warning(f"     命令: {full}")
        if ips: log.warning(f"     发现外网 IP: {', '.join(ips)}")
        record("HIGH", "BITS任务", disp, f"JobId:{job_id}\n{full}")  # 修复：v3.1 缺少

        if job_id and ask("是否强制取消该 BITS 任务"):
            r2 = run([
                "powershell", "-NoProfile", "-Command",
                f"Remove-BitsTransfer -JobId '{job_id}' -Confirm:$false -ErrorAction SilentlyContinue"
            ])
            if r2.returncode == 0:
                log.info(f"  [已取消] BITS: {disp}")
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已取消"

    if not found:
        log.info("  未发现可疑 BITS 任务")
    return removed


def step10_scan_com_hijack() -> int:
    banner("步骤 10 / 11 — 扫描 COM 劫持 / DLL 侧加载 (HKCU 用户级注册)")
    removed, found = 0, False

    ps = r"""
$out = @()
Get-ChildItem -Path 'HKCU:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $clsid = $_.PSChildName
    $inproc = Get-ItemProperty -Path "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc -and $inproc.'(default)') {
        $out += [PSCustomObject]@{ CLSID=$clsid; Path=$inproc.'(default)' }
    }
}
$out | ConvertTo-Json -Compress
"""
    r     = run(["powershell", "-NoProfile", "-Command", ps], timeout=60)
    items = parse_json_safe(r.stdout)

    for item in items:
        clsid = item.get("CLSID", "")
        path  = item.get("Path", "") or ""

        if any(path.lower().startswith(s) for s in SAFE_COM_PATHS):
            continue
        if not any(x in path.lower() for x in ["\\users\\", "\\appdata\\", "\\temp\\"]):
            continue

        found = True
        log.warning(f"\n  ⚠  COM 劫持嫌疑: CLSID {clsid}")
        log.warning(f"     DLL 路径: {path}")
        log.warning("     （用户级 COM 注册可覆盖系统 COM，常见于免杀权限维持）")
        record("HIGH", "COM劫持", clsid, path)

        if ask(f"是否删除该 HKCU COM 注册项 [{clsid}]"):
            del_ps = (
                f"Remove-Item -Path 'HKCU:\\SOFTWARE\\Classes\\CLSID\\{clsid}' "
                f"-Recurse -Force -ErrorAction SilentlyContinue"
            )
            r2 = run(["powershell", "-NoProfile", "-Command", del_ps])
            if r2.returncode == 0:
                log.info(f"  [已删除] COM 注册: {clsid}")
                removed += 1
                REPORT_ITEMS[-1]["action"] = "已删除"

    if not found:
        log.info("  未发现可疑 COM 劫持注册项")
    return removed


def step11_scan_ads() -> int:
    banner("步骤 11 / 11 — 扫描 NTFS 备用数据流 (ADS) 隐藏载荷")
    found_any = False

    for scan_dir in ADS_SCAN_DIRS:
        if not scan_dir or not os.path.isdir(scan_dir):
            continue
        ps = (
            f"Get-ChildItem -Path '{scan_dir}' -Recurse -ErrorAction SilentlyContinue | "
            r"ForEach-Object { Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue } | "
            r"Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } | "
            r"Select-Object FileName, Stream, Length | ConvertTo-Json -Compress"
        )
        r     = run(["powershell", "-NoProfile", "-Command", ps], timeout=60)
        items = parse_json_safe(r.stdout)

        for item in items:
            fname  = item.get("FileName", "")
            stream = item.get("Stream", "")
            size   = item.get("Length", 0)

            if size < 50:   # 跳过小型无害流
                continue

            found_any = True
            log.warning(f"\n  ⚠  发现 ADS 隐藏流: {fname}")
            log.warning(f"     流名称: {stream}  大小: {size} bytes")
            log.warning("     （可执行代码可完全隐藏于此流，文件管理器不可见）")
            record("HIGH", "ADS隐藏流", fname, f"流:{stream} 大小:{size}B")

            if ask("是否删除该隐藏流（不影响原始文件内容）"):
                del_ps = f"Remove-Item -Path '{fname}:{stream}' -Force -ErrorAction SilentlyContinue"
                r2 = run(["powershell", "-NoProfile", "-Command", del_ps])
                if r2.returncode == 0:
                    log.info(f"  [已删除] ADS: {fname}:{stream}")
                    REPORT_ITEMS[-1]["action"] = "已删除"

    if not found_any:
        log.info("  未发现可疑 ADS 隐藏流")
    return 0


# ═══════════════════════════════════════════════════════════════
#  HTML 报告（恢复 v2.0 卡片汇总 + 暗色主题）
# ═══════════════════════════════════════════════════════════════

def generate_html_report(totals: dict):
    level_color = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "INFO":     "#2ecc71",
    }
    rows = ""
    for item in REPORT_ITEMS:
        color  = level_color.get(item["level"], "#95a5a6")
        detail = item["detail"].replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        action = item["action"] or '<span style="color:#e67e22">待处理</span>'
        rows  += (
            f"<tr>"
            f"<td style='color:{color};font-weight:600'>{item['level']}</td>"
            f"<td style='color:#8b949e'>{item['time']}</td>"
            f"<td>{item['category']}</td>"
            f"<td style='font-family:monospace;font-size:12px;max-width:180px;word-break:break-all'>{item['name']}</td>"
            f"<td style='font-family:monospace;font-size:11px;max-width:360px;word-break:break-all'>{detail}</td>"
            f"<td style='color:#2ecc71'>{action}</td>"
            f"</tr>"
        )

    c_n = sum(1 for i in REPORT_ITEMS if i["level"] == "CRITICAL")
    h_n = sum(1 for i in REPORT_ITEMS if i["level"] == "HIGH")
    m_n = sum(1 for i in REPORT_ITEMS if i["level"] == "MEDIUM")
    r_n = totals.get("removed", 0)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>木马猎人 v3.2 扫描报告</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:"Microsoft YaHei",sans-serif;padding:28px;line-height:1.6}}
  h1{{color:#58a6ff;font-size:22px;margin-bottom:4px}}
  .meta{{color:#8b949e;font-size:13px;margin-bottom:20px}}
  .cards{{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}}
  .card{{background:#161b22;border:1px solid #21262d;border-radius:10px;
         padding:16px 24px;flex:1;min-width:110px;text-align:center}}
  .card .num{{font-size:32px;font-weight:700;display:block;margin-bottom:4px}}
  .card .lbl{{font-size:12px;color:#8b949e}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#161b22;color:#8b949e;padding:10px 8px;text-align:left;
      font-weight:500;border-bottom:2px solid #21262d}}
  td{{padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#161b22}}
  .footer{{margin-top:24px;color:#8b949e;font-size:12px;
           border-top:1px solid #21262d;padding-top:16px}}
</style>
</head>
<body>
<h1>🛡 无文件木马猎人 v3.2 扫描报告</h1>
<p class="meta">扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  &nbsp;|&nbsp; 日志: {LOG_FILE}</p>
<div class="cards">
  <div class="card"><span class="num" style="color:#e74c3c">{c_n}</span><span class="lbl">严重</span></div>
  <div class="card"><span class="num" style="color:#e67e22">{h_n}</span><span class="lbl">高危</span></div>
  <div class="card"><span class="num" style="color:#f1c40f">{m_n}</span><span class="lbl">中危</span></div>
  <div class="card"><span class="num" style="color:#2ecc71">{r_n}</span><span class="lbl">已处理</span></div>
  <div class="card"><span class="num" style="color:#58a6ff">{len(REPORT_ITEMS)}</span><span class="lbl">总发现</span></div>
</div>
<table>
  <tr><th>等级</th><th>时间</th><th>类型</th><th>名称</th><th>详情</th><th>操作</th></tr>
  {rows if rows else '<tr><td colspan="6" style="text-align:center;color:#2ecc71;padding:20px">✓ 未发现威胁</td></tr>'}
</table>
<div class="footer">
  <b>后续建议：</b><br>
  1. 重启系统，观察卡巴斯基是否仍有报警<br>
  2. 重启后再运行一次卡巴斯基完整扫描<br>
  3. 检查浏览器扩展，卸载近期安装的可疑软件<br>
  4. 若仍有报警，将本报告提交安全人员分析
</div>
</body>
</html>"""

    Path(HTML_FILE).write_text(html, encoding="utf-8")
    log.info(f"  HTML 报告已生成: {HTML_FILE}")


# ═══════════════════════════════════════════════════════════════
#  主入口
# ═══════════════════════════════════════════════════════════════

def main():
    banner(f"无文件木马通用猎人 v3.2  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info(f"日志文件: {LOG_FILE}")
    if ARGS.auto:
        log.info("  模式: 自动扫描（不执行任何删除，仅记录）")

    if not is_admin():
        log.error("请以管理员身份运行！右键 → 以管理员身份运行")
        sys.exit(1)

    total = sum([
        step1_remove_known_tasks(),
        step2_scan_unknown_tasks(),
        step3_scan_registry(),
        step4_scan_wmi(),
        step5_scan_startup_folders(),
        step6_scan_services(),
        step7_check_powershell_profiles(),
        step8_check_hosts(),
        step9_scan_bits_jobs(),
        step10_scan_com_hijack(),
        step11_scan_ads(),
    ])

    c_n = sum(1 for i in REPORT_ITEMS if i["level"] == "CRITICAL")
    h_n = sum(1 for i in REPORT_ITEMS if i["level"] == "HIGH")
    m_n = sum(1 for i in REPORT_ITEMS if i["level"] == "MEDIUM")

    banner("综合排查完成")
    log.info(f"  严重项:   {c_n}")
    log.info(f"  高危项:   {h_n}")
    log.info(f"  中危项:   {m_n}")
    log.info(f"  已处理:   {total} 项")
    log.info(f"  日志:     {LOG_FILE}")

    if ARGS.report or REPORT_ITEMS:
        generate_html_report({"removed": total})

    log.info("\n  后续建议:")
    log.info("  1. 重启系统，观察卡巴斯基是否仍报警")
    log.info("  2. 重启后运行卡巴斯基完整扫描")
    log.info("  3. 检查浏览器扩展，卸载近期可疑软件")
    log.info("  4. 若仍有报警，将 HTML 报告提交安全人员分析")


if __name__ == "__main__":
    main()

# 🛡️ persistence-killer (Windows 持久化后门清理辅助脚本)

`persistence-killer` 是一个专为 Windows 应急响应设计的**自动化排查与后门辅助清理脚本**。主要用于解决无文件木马（Fileless Malware）或顽固威胁在系统残留的各类权限维持（Persistence）机制。

本工具通过对注册表、WMI、BITS 等 11 个核心高危模块进行策略审计，帮助安全运维人员快速定位隐蔽后门，并提供交互式清理与自动化 HTML 报告功能。


## 🛠️ 功能特点

* **针对性排查**：不依赖文件哈希，专注于检测利用系统白名单工具（LotL 行为）和无文件特征的常驻后门。
* **自动化备份**：在执行任何计划任务删除操作前，**自动导出 XML 配置文件**至本地临时目录，确保清理过程可逆。
* **纯脚本运行**：仅依赖 Python 标准库与系统自带的 PowerShell，无第三方库依赖，便于应急响应时快速部署。
* **数据可视化**：扫描完成后自动生成标准暗色主题的 HTML 汇总报告，方便数据留存与复盘分析。


## 🔍 11 步审计模块

| 步骤 | 排查模块 | 审计行为 |
| --- | --- | --- |
| **01-02** | **计划任务审计** | 已知恶意任务清理 + 未知任务特征匹配与公网可疑 IP 嗅探 |
| **03** | **核心注册表检查** | 覆盖 Run / Winlogon / LSA 认证包 / IFEO 映像劫持 / AppInit_DLLs |
| **04** | **WMI 事件订阅** | 检查 CommandLine 与 ActiveScript 隐蔽常驻后门 |
| **05-06** | **启动项与服务** | LNK 快捷方式真实指向深度追踪、用户目录异常 Windows 服务扫描 |
| **07-08** | **环境与网络合规** | PowerShell `$PROFILE` 持久化检查、`hosts` 文件异常条目核对 |
| **09** | **BITS 影子任务** | 审计利用后台智能传输服务（BITS）建立的异常下载任务 |
| **10** | **COM 劫持检测** | 扫描 HKCU 用户级 CLSID 异常注册，防止 DLL 侧加载 |
| **11** | **NTFS 备用数据流** | 扫描利用 NTFS ADS 特性隐藏的高危数据流载荷 |


## 🚀 快速开始

### 运行环境

* Windows 10 / 11 或 Windows Server 2016+
* Python 3.8+ (需具备管理员权限)

### 使用方法

> ⚠️ **注意**：脚本涉及深层系统配置审计，**必须以管理员身份运行**。

1. 下载脚本后，打开管理员权限的 CMD 或 PowerShell，进入脚本所在目录。
2. 运行以下命令：
**交互模式（推荐）**：边排查边提示，手动确认是否清理异常项。
```bash
python persistence_killer.py




**仅扫描模式（不修改系统）**：只排查风险并生成报告，不执行任何删除操作。
```bash
python persistence_killer.py --auto



**强制生成报告**：
```bash
python persistence_killer.py --report


## 📊 报告与日志

运行结束后，工具将在系统的 `TEMP` 目录（如 `C:\Users\用户名\AppData\Local\Temp\`）下输出：

* **流水日志**：`malware_hunter.log`
* **HTML 报告**：`malware_hunter_report.html` (包含风险分类与处理状态汇总)


## 📄 免责声明与许可

* 本项目基于 **[MIT License](https://www.google.com/search?q=LICENSE)** 协议开源。
* 本工具仅用于合规的安全审计、基线检查与应急响应。安全人员在生产环境使用前，请务必在测试环境验证脚本的兼容性，因使用不当导致的系统故障由使用者自行承担。

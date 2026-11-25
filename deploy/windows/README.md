# Windows 部署（无驱动）

Windows 被防护端不安装内核驱动，依靠系统自带的访问控制与自愈机制：

| 层 | 做什么 | 部署代价 |
|---|---|---|
| ACL 锁定 | 受保护目录只允许 SYSTEM 写，Everyone 只读 | 无 |
| 完整性级别（MIC） | 路径标 System + `NO_WRITE_UP`，提权管理员（High）写入被内核拒绝 | 无 |
| 自愈（self-heal） | 每 30s 对照内容基线，被绕过修改的文件回滚并记 `tamper.restored` | 无 |
| 服务加固 | Agent 以 LocalSystem 运行、失败自动重启、服务 ACL 只允许 SYSTEM 停止 | 无 |

## 安装步骤

```powershell
# 1. 以管理员身份运行 PowerShell，把二进制放到程序目录
New-Item -ItemType Directory -Force 'C:\Program Files\TamperGuard'
Copy-Item .\tg-agent.exe 'C:\Program Files\TamperGuard\'

# 2. 安装加固服务
Set-ExecutionPolicy -Scope Process Bypass -Force
.\deploy\windows\install-service.ps1

# 3. 注册（一次性）
& 'C:\Program Files\TamperGuard\tg-agent.exe' enroll `
    --server https://<控制面>:8443 --bootstrap <protect token> `
    --ca <ca.crt> --state-dir 'C:\ProgramData\TamperGuard' `
    --role protect --publisher-sids '<发布账号，如 CONTOSO\svc-publisher>'
```

策略里的路径使用 Windows 形式，例如 `C:\inetpub\wwwroot`（内部统一为 `C:/inetpub/wwwroot`）。

## 运维

- 日志：`Get-Content C:\ProgramData\TamperGuard\agent.log -Wait`（若配置了日志文件）
- 停止服务需要先取得服务所有权（服务 ACL 已限制管理员停止），这会让"随手停防护"变成显式操作
- 退出防护并恢复权限：`& 'C:\Program Files\TamperGuard\tg-agent.exe' unlock --state-dir 'C:\ProgramData\TamperGuard'`
- 自愈扫描间隔：环境变量 `TG_WIN_SCAN_SECONDS`（默认 30；最小 2，仅用于测试）

## 局限（已写入威胁模型）

- 管理员可通过取得文件所有权、修改 SACL、重写 DACL 绕过 ACL/MIC；自愈会在下一个扫描周期回滚并记录 `tamper.restored`，但无法阻止"先改后读"的短窗口。
- 管理员取得服务所有权后仍可停止 Agent；服务加固只是提高门槛。
- 不做内核驱动：驱动需要 WDK、测试签名/重启与微软签名，真实客户现场落地成本过高（见 `docs/advanced-techniques.md`）。

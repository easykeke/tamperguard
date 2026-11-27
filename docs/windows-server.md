# Windows 部署管理端

控制面 `tg-server` 可以作为 Windows 服务运行，适合没有 Linux 服务器、但需要统一管理 Windows/Linux Agent 的环境。

## 前置条件

- Windows 10 / Windows Server 2019 及以上；
- 管理员 PowerShell；
- 入站 TCP 8443（可在安装时自动加防火墙规则）。

## 安装

下载 `tamperguard_<版本>_windows_amd64_server.zip`，解压后管理员运行：

```powershell
.\install-server-service.ps1
```

默认参数：

| 项 | 默认值 |
|---|---|
| 程序目录 | `C:\Program Files\TamperGuardServer` |
| 数据目录 | `C:\ProgramData\TamperGuardServer` |
| 监听 | `:8443` |
| 服务名 | `TamperGuardServer` |

脚本会：

1. 复制 `tg-server.exe`；
2. 首次运行时执行 `tg-server init`，生成 CA、服务端证书、管理员密码和一次性注册令牌；
3. 把数据目录权限收紧为 SYSTEM/Administrators；
4. 注册并启动 `TamperGuardServer` 服务（LocalSystem，自动启动、失败重启）；
5. 添加入站防火墙规则。

初始化输出会打印一次，同时保存到：

```
C:\ProgramData\TamperGuardServer\init-output.txt
```

请立即保存管理员密码和注册令牌。

## 访问

```text
https://<服务器IP或主机名>:8443
```

CA 证书：

```
C:\ProgramData\TamperGuardServer\keys\ca.crt
```

管理页「节点 → Agent 下载与安装」可直接下载 Agent；在 Agent 主机注册时把 `--server` 指向本机地址即可（证书 SAN 已包含本机主机名和所有本地 IP）。

## 服务管理

```powershell
Get-Service TamperGuardServer
Restart-Service TamperGuardServer
sc.exe qc TamperGuardServer
```

重置管理员密码（管理员 PowerShell）：

```powershell
& 'C:\Program Files\TamperGuardServer\tg-server.exe' reset-admin-password `
  --data-dir 'C:\ProgramData\TamperGuardServer'
```

## 数据与备份

- 数据库：`C:\ProgramData\TamperGuardServer\tamperguard.db`
- 密钥：`C:\ProgramData\TamperGuardServer\keys\`
- 日志：`C:\ProgramData\TamperGuardServer\server.log`
- 备份时**同时备份数据库和 keys 目录**；只备份数据库会导致 Agent 证书/令牌无法验证。

## 升级

1. 停止服务：`Stop-Service TamperGuardServer`；
2. 替换 `C:\Program Files\TamperGuardServer\tg-server.exe`；
3. 启动服务。

数据目录与 `server.json` 不需要重建。

## 限制

- 控制面一次只能监听一个地址/端口（`server.json` 中的 `listen`）；
- Windows 防火墙需放行 Agent 访问的端口；
- 没有 systemd 的 journald，日志在 `server.log`；
- 与 Linux 控制面功能一致，但 Docker/Kubernetes 部署示例不适用。

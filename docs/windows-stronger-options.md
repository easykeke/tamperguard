# Windows 更强方案评估（无驱动前提）

目标：在"不安装自制内核驱动"的前提下，尽量接近"只有发布端能写、管理员也改不了"的效果。本文比较了 6 条路线，并给出本产品的选择。

## 0. 结论

1. **能从根本上解决问题的不是"更硬的写保护"，而是"内容交付校验"**。只要用户拿到的页面是校验过的可信内容，磁盘上文件是否被改就不再是攻击成功条件。这层不需要驱动、不需要管理员权限，且对所有 Web Server 通用——推荐作为下一个主能力（P5.7）。
2. **借用 Defender 的受控文件夹访问（CFA）** 理论上可用微软自带 minifilter 实现内核级写入拦截，但要求 Defender 是活动主杀毒；**本机实测 Defender 未运行**，且中国客户常见 360/奇安信/火绒等第三方杀毒会把 Defender 置为关闭，因此只能作为"环境恰好满足时"的可选增强，不能作为产品基线。
3. **自愈的短板是窗口**（默认 30 s）。用系统自带的目录变更通知（`ReadDirectoryChangesW`，无需驱动）可以把窗口压到亚秒级——本轮已实现。
4. VSS 卷影副本可做高效基线，但管理员能删快照；不可变磁盘/Windows 容器是架构级最强解，适合新建系统，不适合存量。

## 1. 候选方案对比

| 方案 | 依赖 | 能挡管理员吗 | 阻断/恢复 | 部署成本 | 适用场景 |
|---|---|---|---|---|---|
| ACL 严格模式 + MIC（已实现） | 无 | 普通写入被拒；主动绕过可 | 阻断（open 时） | 低（Agent 管理员运行） | 所有 Windows 文件系统 |
| 内容基线自愈（已实现） | 无 | 绕过后的修改被回滚 | 恢复（默认 30 s） | 低 | 同上 |
| **事件驱动自愈（本轮）** | 无 | 同上，窗口 → 亚秒级 | 恢复 | 低 | 同上 |
| Defender 受控文件夹访问（CFA） | Defender 为活动主 AV + 实时保护开 | 内核级阻断"不可信应用"；管理员可关（除非托管 tamper protection） | 阻断（微软签名 minifilter） | 低，但**环境受限** | 恰好用 Defender 的客户 |
| **Web 层内容校验（推荐新增）** | 无反驱动；需在前面加校验代理或 IIS 模块 | **是**：即使磁盘被改，用户也拿不到坏内容 | 交付侧校验 | 中（改流量路径/装模块） | 所有 Windows Web 场景 |
| VSS 快照 + 恢复 | 卷影副本服务 | 快照被删后失效 | 恢复（大文件高效） | 中 | 大站点、需保留历史版本 |
| 只读镜像 / Windows 容器 / 差量 VHD | Hyper-V 或容器运行时 | 是（架构层无写路径） | 结构性只读 | 高 | 新建系统、云原生 |

## 2. 本机实测（2026-11-25）

```
Get-MpComputerStatus:
  AMRunningMode             : Not running
  RealTimeProtectionEnabled : False
  AntivirusEnabled          : False
  IsTamperProtected         : False
Get-MpPreference -> 0x800106ba（Defender 服务未运行）
```

结论：这台机器上 CFA 不可用；说明"依赖 Defender"的方案在真实环境里覆盖不全。

同一台机器还实测了完整性标签（MIC）：`SetNamedSecurityInfo`/`SetFileSecurity` 均返回成功但 SACL 留空（SDDL `S:PAI`），`icacls` 仅支持 Low/Medium/High，System 直接报错。因此产品把 MIC 做成**启动自检、失败即降级**的可选层；管理员普通写入由严格 DACL 拦截（已实测），绕过行为由自愈回滚（已实测）。官方文档也明确：CFA 要求 Defender Antivirus 处于 Active 模式且实时保护开启，Windows 10+/Server 2019+。

来源：[Controlled folder access overview](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview)、[Configure CFA](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure)

## 3. Web 层内容校验（推荐新增，P5.7）

思路：在 Web Server 前面放一个校验代理（`tg-proxy`），或做成 IIS 原生模块：

1. 静态文件响应发出前，用发布清单里的 SHA-256 校验磁盘内容；
2. 校验失败（被篡改）时，返回基线存储里的可信副本，并记 `tamper.restored`；
3. 响应加 `X-TG-Integrity: verified`，便于上游/监控识别；
4. 动态请求原样转发，不改变业务；
5. 代理以普通服务账号运行，**不需要管理员、不需要驱动**。

为什么它更"厉害"：攻击者即使通过管理员权限改了磁盘文件，用户访问到的仍是签名清单里的原始内容；同时审计链记录"某文件被改、已回退"。它把防篡改从"保护文件"提升到"保证交付"。

落地形态：

- 独立反向代理（Go 实现，Windows/Linux 通用，跨平台复用现有 baseline/manifest 代码）；
- 或 IIS 原生模块（仅 IIS，需注册模块并回收应用池，但无驱动签名）。

## 4. 事件驱动自愈（本轮实现）

`ReadDirectoryChangesW` 是 Windows 自带的目录变更通知（无需管理员、无需驱动）。把它接入自愈扫描：

- 受保护目录发生任何 create/write/rename/delete → 立即触发一次一致性扫描（带 300 ms 去抖）；
- 自愈窗口从"一个定时器周期（默认 30 s）"降到"事件 + 扫描耗时"，实测通常在百毫秒级；
- 定时扫描保留兜底（事件丢失、网络盘等场景）。

## 5. 演进优先级

| 优先级 | 能力 | 状态 |
|---|---|---|
| P5.5' | ACL 严格模式 + MIC + 自愈 + 服务加固 | 已实现（0.2.1 开发中） |
| P5.7 | 事件驱动自愈（ReadDirectoryChangesW） | **本轮实现** |
| P5.8 | Web 层内容校验（校验代理 / IIS 模块） | 建议下一个做 |
| P5.9 | CFA 协同（检测到 Defender 活动时自动注册受保护目录与允许应用） | 可选，环境受限 |
| P5.10 | VSS 快照基线 / 不可变镜像 | 按客户场景 |

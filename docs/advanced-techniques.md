# 先进防篡改技术实现调研

本文调研"网页防篡改"在 Windows 与 Linux 上的先进实现路线，用于指导 TamperGuard 的架构演进。所有关键机制均标注了官方文档来源，不引用厂商宣传材料。

## 0. 结论

1. **Windows 没有"用户态即可同步阻断"的机制。** 真正的阻断只有两条路：内核文件系统过滤驱动（minifilter），或利用系统既有的强制访问控制（ACL / 完整性级别）。前者能力最强，但需要 EV 证书并通过微软 Dev Portal 签名，交付成本高；后者无驱动，但挡不住管理员，且只覆盖 open 时刻。
2. **Linux 侧现有 eBPF LSM 已是最强的同步阻断层**，进一步加固的方向不是"再拦一层写"，而是：进程自保护（Landlock）、发布后固化（fs-verity / IMA）、部署侧只读视图（systemd 硬化、只读挂载）。这三者不依赖 root 或几乎零代码。
3. **先进度最高、长期成本最低的是"不可变基础设施"**：只读镜像层 + 发布即新镜像/新 Pod。产品应主动支持这种模式，而不是要求客户关闭它来使用"文件防篡改"。
4. 对 TamperGuard：短期补 **Landlock（Linux 进程自保护）** 与 **Windows 完整性级别加固**，中期做 **fs-verity 发布固化** 与 **Windows USN/ETW 审计恢复**，长期再评估 minifilter 自研或采购。

## 1. Windows 侧可选方案

### 1.1 文件系统过滤驱动（minifilter）——正统阻断方案

Filter Manager（`FltMgr.sys`）是 Windows 自带的内核组件，minifilter 注册后按 altitude 挂到卷的文件系统栈上，对选定 I/O 操作注册 pre/postoperation 回调：pre 回调返回失败即可**在 I/O 到达文件系统前拒绝**。

可实现的能力：

- 拦截 `IRP_MJ_CREATE`（带写/删除意图的打开请求）→ 阻断写入的最早时机；
- 拦截 `IRP_MJ_WRITE`、`IRP_MJ_SET_INFORMATION`（rename/delete/setattr）→ 覆盖内存映射写、重命名、删除、属性修改；
- 回调中能拿到发起进程的 PID/SID 与文件路径 → **具备精确策略与审计能力**，这是 ACL 方案拿不到的；
- 可以用名称/路径过滤表实现"路径级保护 + 发布窗口放行"，与 TamperGuard 的策略模型天然对应。

代价与限制（决定它不能是第一步）：

- 从 Windows 10 1607 起，**新内核驱动必须由微软 Dev Portal 签名**；注册 Hardware Dev Center 需要 **EV 代码签名证书**，生产驱动还要 HLK 测试（或用 attestation 签名，仅限客户端系统）。
- 驱动缺陷导致**蓝屏**，测试矩阵（大量杀软、备份、加密、同步软件共存）成本高；altitude 冲突是常见兼容问题。
- 开源项目分发"用户自行签名"的驱动不现实：用户要么开测试签名模式（不安全），要么拿不到可用于生产的签名。

**建议**：作为独立工作包评估。先做"最小 minifilter 原型"（仅 CREATE 写拒绝 + 事件上报，不拦截写 IRP），在两个 Windows 版本 + 主流 IIS 环境上验证兼容性与性能，再决定自研或采购。

来源：[Filter Manager Concepts（Microsoft Learn）](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)、[Driver Signing Policy（Microsoft Learn）](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)

### 1.2 强制完整性控制（MIC）——无驱动的第二道锁

Windows 的 Mandatory Integrity Control 在 DACL 检查**之前**生效：每个对象在 SACL 里存一个完整性标签（`SYSTEM_MANDATORY_LABEL_ACE`），默认策略是 `NO_WRITE_UP`——低完整性级别的进程**即使 DACL 允许写，也不能写更高完整性级别的对象**。

对防篡改的意义：

- 把站点根目录标为 High 完整性，把 IIS 应用池改成 Medium 或更低完整性运行（专用低权账户），则**即使文件 ACL 被改坏、甚至写入了允许 Everyone 写的 ACE，Web 进程依然写不进去**——这是 ACL 方案做不到的"第二道锁"。
- 需要管理员改 SACL 才能解除（管理员作弊仍在威胁模型之外）。
- 局限：IIS 应用池若以 SYSTEM 身份运行，其进程完整性是 System，会绕过高完整性标签；必须先把应用池降到专用账户/Medium IL，这与安全基线本来一致。

**建议**：作为 Windows ACL 后端的增强项实现——ACL 管"谁能写"，MIC 管"什么完整性级别的进程能写"。

**本产品默认组合**：DACL 不授予 Administrators 写 + 标签 **System**（`NO_WRITE_UP`）。提权管理员是 High 完整性，因此普通写入被内核拒绝；发布窗口内临时降为 Medium 放行授权账号。管理员仍可通过取得所有权/改 SACL/停 Agent 绕过（普通写入不再是绕过方式）。

来源：[Mandatory Integrity Control（Microsoft Learn）](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

### 1.3 USN Journal + ETW/Sysmon——无驱动的审计与秒级恢复

- **USN Journal** 是 NTFS 卷级的变更日志，记录文件创建/写入/删除/重命名及原因；可按 USN 增量读取，适合做"变更后恢复"。
- **ETW Threat Intelligence / Sysmon** 的 `FileCreate`、`FileWrite` 事件能给出进程路径、PID、命令行摘要，可弥补"没有驱动就拿不到写者身份"的缺口。
- 两者组合可以实现"发现 → 定位写者 → 回滚"，但**不能阻断**。

**建议**：作为 Windows 降级执行层（对应 Linux 的 fanotify 检测+恢复），用于不满足 ACL 条件（如站点目录与业务写入共享）的场景。

### 1.4 其他相关但互补的技术

- **IIS 原生模块 / 反向代理内容校验**：防的是"数据库被注入导致页面内容被篡改"（内容级篡改），与文件防篡改是两条线，可组合但不能替代。
- **AppContainer / 受限令牌**：把 Web 工作进程关进 AppContainer 后无法写用户目录，但改造成本高、兼容性差，适合新建系统而非存量。

## 2. Linux 侧先进方案

### 2.1 Landlock——进程自保护（最高性价比增强）

Landlock 是内核 LSM，**任何进程（包括非特权进程）都可以给自己和子进程叠加不可撤销的文件访问限制**。应用方式：web 进程启动时声明"对站点目录只允许读"，此后即使被 RCE，写文件系统调用直接返回 `EACCES`。

关键事实（来自内核文档）：

- 纯限制性：只能收紧，不能放权；规则一旦设置无法移除，只会在进程生命周期内持续；
- 支持 `LANDLOCK_ACCESS_FS_WRITE_FILE`、`TRUNCATE`、`REMOVE_FILE/DIR`、`MAKE_REG` 等写类权限的精细控制；
- 限制对**已打开的 fd 不生效**（限制前打开的 fd 保持原有能力），因此必须在应用启动早期施加；
- 与 bind mount 配合良好（权限沿 bind mount 传播），但与 OverlayFS 的 merged 目录是两套层级，规则需按实际路径施加；
- ABI 版本演进，需按运行的 ABI 做 best-effort 降级（官方示例即此模式）。

对 TamperGuard 的集成方式：

- 新增 `tg-agent landlock run --read-only /var/www -- <web 进程>`：无需 root、无需 eBPF，给 PHP-FPM/Node/Java 子进程加自保护；
- 或生成 systemd drop-in（`ExecStart` 包一层），把对手从"防文件被写"变成"Web 进程根本没有写权限"；
- 这层与现有 eBPF 内核阻断**互补**：eBPF 管"所有写者"，Landlock 管"Web 进程自身被 RCE 后的横向写"。

来源：[Landlock: unprivileged access control（Linux 内核文档）](https://docs.kernel.org/userspace-api/landlock.html)

### 2.2 fs-verity + IMA——发布后固化（内核级只读 + 读取校验）

fs-verity 为单个文件建立 Merkle 树并持久化，启用后文件变为**只读**：任何写入/截断返回 `EPERM`；每次读页（含 mmap）都按 Merkle 树校验，读坏数据返回 `EIO`/`SIGBUS`。这把防护从"阻止写"推进到"即使写进去了也读不出来"，可对抗磁盘/固件级篡改。

与发布流程的天然契合：

1. 发布端写到临时文件；
2. 校验后对临时文件执行 `FS_IOC_ENABLE_VERITY`（或 `fsverity enable`）；
3. rename 到正式路径（rename 保留 verity 属性）；
4. 发布窗口结束时不需要额外操作——文件已不可写。

限制：启用后不可更新（要更新需重建文件）；目录不支持；ext4/f2fs/btrfs 需开启 verity 特性；不适用于频繁变动的上传目录。

配套 **IMA appraisal**（内核文档同源）可做系统级签名策略，**IPE** 可按 fs-verity digest 授权执行，属于"可信计算"路线，适合高安全等级场景。

来源：[fs-verity（Linux 内核文档）](https://docs.kernel.org/filesystems/fsverity.html)

### 2.3 部署侧只读视图（零代码）

- systemd 硬化：`ProtectSystem=strict`、`ReadOnlyPaths=/var/www`、`PrivateTmp=`、`ProtectHome=`——服务进程看到的是只读视图，内核层直接拒绝写；
- 独立 mount namespace 内 `mount --bind` + `remount,ro` 站点目录；
- 与 TamperGuard 的发布窗口天然冲突，需要用"发布时切换视图"的方式解决（发布端在另一个 namespace 写数据，或用 overlay 切换）。

**建议**：写进部署文档作为推荐基线，产品本身不需要改代码；对存量环境，Landlock 版 `tg-agent landlock run` 是该思路的产品化形态。

## 3. 架构层：不可变基础设施

现代 Web 部署的先进做法是把"防篡改"变成"没有可写文件"：

- 容器镜像分层：站点内容打进只读镜像层，容器 `readOnlyRootFilesystem: true`，运行时没有任何可写目录；
- 发布 = 构建新镜像 → 滚动替换 Pod；回滚 = 切回旧镜像；
- 攻击者即使拿到 RCE，也无法修改运行中容器的站点文件（文件系统只读），改镜像需要仓库权限（可审计）。

这与"文件防篡改产品"不是替代关系：存量环境（IIS + 传统 VM、无法容器化的系统）仍需 TamperGuard 补偿；在不可变环境里，TamperGuard 的价值转向**发布编排、跨机分发、审计留痕**。

## 4. 与 TamperGuard 的演进路线

| 优先级 | 能力 | 平台 | 依赖 | 预期收益 | 成本/风险 |
|---|---|---|---|---|---|
| P5.1 | Landlock 进程自保护（`tg-agent landlock run`） | Linux | 内核 Landlock（主流发行版默认启用） | 高：Web 进程被 RCE 后写不了站点 | 低 |
| P5.2 | MIC 完整性级别加固（ACL 后端增强） | Windows | 管理员权限 | 中高：ACL 被改坏仍能挡 | 低（**已实现，0.2.0**） |
| P5.3 | fs-verity 发布固化（发布完成后自动 enable） | Linux | 文件系统支持 verity | 高：内核级只读 + 读取校验 | 中（**已实现，0.2.0**；运行时验证待支持 verity 的内核） |
| P5.4 | USN/ETW 审计 + 恢复（Windows 降级层） | Windows | 无 | 中：无驱动场景可用 | 中 |
| P5.5 | minifilter 驱动（自研或采购） | Windows | EV 证书 + 微软签名 + HLK | 高：真正同步阻断 + 精确审计 | 高 |
| P5.6 | 不可变发布模式（只读镜像 + 滚动发布） | 通用 | 容器平台 | 高：攻击面消失 | 低（**已落地文档与示例，0.2.0**：`docs/immutable.md`、`deploy/k8s/immutable/`） |

## 5. 现状对照

| 平台 | 当前实现 | 能力边界 |
|---|---|---|
| Linux | eBPF LSM（14 hook，同步阻断）→ fanotify（检测+回滚）→ observe | 主路径已验证；5.10–6.2 降级 |
| Windows | ACL 锁定（SYSTEM/Administrators 全权，Everyone 只读；发布窗口临时授权发布账号） | 挡得住非管理员；挡不住管理员；无法审计每次写 |
| 两者 | 令牌 + 审计链 + 自升级 + 控制面 | 身份/授权/证据层与平台无关 |

## 6. 参考来源

1. [Filter Manager Concepts — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts)
2. [Driver Signing Policy — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
3. [Mandatory Integrity Control — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
4. [Landlock: unprivileged access control — Linux 内核文档](https://docs.kernel.org/userspace-api/landlock.html)
5. [fs-verity: read-only file-based authenticity protection — Linux 内核文档](https://docs.kernel.org/filesystems/fsverity.html)

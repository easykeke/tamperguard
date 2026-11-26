# 兼容性与能力探测

## 0. TLS 证书

控制面与 Agent 之间的 TLS 使用 **ECDSA P-256** 的 CA 与服务端证书；令牌、策略、发布清单等签名仍用 **Ed25519**。早期版本使用 Ed25519 证书，Windows Schannel（curl/PowerShell）和部分客户端会直接拒绝握手（`ERR_SSL_VERSION_OR_CIPHER_MISMATCH`），因此改为 ECDSA。自签名证书在浏览器里会提示不受信任，内网部署可把 CA 导入受信任根，或前面加一层正式证书的反向代理。

## 1. 如何自查

```bash
sudo tg-agent probe --state-dir /var/lib/tamperguard-agent
```

输出示例（Linux 6.6 + bpf LSM 已启用）：

```
kernel        : 6.6.87
cmdline       : ... lsm=lockdown,capability,landlock,yama,apparmor,bpf
lsm active    : capability,landlock,yama,apparmor,bpf (bpf=true)
kernel BTF    : true
eBPF LSM      : available
fanotify      : available
selected      : ebpf-lsm (degraded=false)
```

探测会真的加载并挂载 eBPF 程序、初始化 fanotify，因此结论就是这台机器实际会使用的执行层。

## 2. 执行层矩阵

| 内核条件 | 执行层 | 能力 | 状态 |
|---|---|---|---|
| ≥ 6.3，`CONFIG_BPF_LSM=y`，`lsm=` 含 `bpf`，有 BTF | eBPF LSM | 写入前同步阻断，14 个 hook | **已在 6.6 验证** |
| 5.10 – 6.2（上述条件中的 BTF/LSM 满足） | 大概率回退 fanotify | 检测+回滚 | 未验证；LSM hook 签名在 6.3 前后有差异，加载失败即自动降级 |
| 无 bpf LSM / 无 BTF / 无 BPF 权限 | fanotify | 检测+回滚（覆盖写毫秒级回滚、新建/删除巡检恢复） | 已在 6.6 验证 |
| 无 bpf LSM（Ubuntu 24.04 默认，内核 6.8，KVM） | fanotify | 检测+回滚 | **已在 6.8 云主机验证**：e2e-fanotify/sim/uninstall/proxy/proxy-signed/pull/upgrade 通过；eBPF 层需在 `lsm=` 中加入 `bpf` 并重启 |
| 无 fanotify 或无 CAP_SYS_ADMIN | observe | 只记录不阻断，节点标记 degraded | 已验证（显式降级，不伪装） |
| 内核启用 `CONFIG_FS_VERITY`，且文件系统带 `verity` 特性（ext4/f2fs/btrfs） | fs-verity 发布固化（`--verity`） | 发布安装的文件变为只读（写入 `EPERM`），每次读页（含 mmap）按 Merkle 树校验，坏数据 `EIO`/`SIGBUS`；与发布窗口天然兼容（下次发布 rename 覆盖即可） | `tg-agent probe` 报告可用性；本机 WSL2 内核未启用该选项，**未做运行时验证** |
| 任意 Linux（内核启用 Landlock，`lsm=` 含 `landlock`） | landlock（进程自保护） | 把 Web 进程及其子进程限制为只读视图：站点目录的写/删/改名返回 EACCES，无需 root、无需 eBPF | 已在 6.6 验证（ABI 3）；`tg-agent landlock --check` 查看 ABI，无 Landlock 时该层跳过 |

关键约束：

- eBPF 对象按 6.6 的 LSM hook 签名编译（例如 `inode_create(dir, dentry, mode)`、`inode_setxattr(idmap, ...)`）。6.3 之前部分 hook 没有 `mnt_idmap` 参数，整对象加载会失败，此时自动降级到 fanotify，不会出现“挂了一半”的防护。
- 未启用 `lsm=...,bpf` 时，`CONFIG_BPF_LSM=y` 也不生效；启动参数必须显式包含 `bpf`。
- WSL2 的默认内核 `CONFIG_LSM` 不含 `bpf`，需要在 `%UserProfile%\.wslconfig` 增加 `kernelCommandLine=lsm=...,bpf` 后 `wsl --shutdown`。
- 普通容器内不能运行 Agent（需要宿主内核与宿主文件系统）；K8s 用 privileged + hostPID DaemonSet，见 `deploy/k8s/`。

## 3. 文件系统矩阵

| 场景 | 结果 | 说明 |
|---|---|---|
| ext4 / xfs / tmpfs | 已验证 | inode 索引直接匹配 |
| OverlayFS（容器可写层） | 已验证 | 钩子作用在 overlay inode，与 merged 路径索引一致；`TestOverlayEnforcement` |
| NFS / CIFS | 不承诺 | 内核钩子与 fanotify 在网络文件系统上行为不同 |
| 直接写 upperdir/lowerdir | 不覆盖 | 需要宿主 root，超出威胁模型 |

## 4. RASP 运行时兼容性

| 运行时 | 接入方式 | 要求 | 状态 |
|---|---|---|---|
| Node.js | `NODE_OPTIONS="--require .../tamperguard.js"` | 无额外依赖；代理走 `fs` 包装 | 已验证（e2e-rasp） |
| Java | `-javaagent:tg-rasp.jar=socket=...` | **JDK 16–21**（Unix domain socket + SecurityManager）；需 `-Djava.security.manager=allow` | 已验证（e2e-rasp-java） |
| PHP / 其它 | 未提供 | — | 不可用 |

Java 说明：探针通过 SecurityManager 拦截 `FilePermission` 的 write/delete 检查，覆盖 `java.io.FileOutputStream`、`File#delete`、`Files.write/newOutputStream/delete/move` 等；SecurityManager 在新 JDK 中被标记移除，装不上时探针只打警告、不会假装在防护。

## 5. Windows 被防护端（实验性）

Windows 没有 eBPF LSM，也没有 fanotify 等价物；用户态可用的同步阻断只有系统自带的访问控制。当前实现选择 **NTFS ACL 锁定**：

| 项 | 要求 / 行为 |
|---|---|
| 权限 | Agent 必须以管理员或 SYSTEM 运行（否则 `windows-acl` 不可用，自动降级 observe 并上报 degraded） |
| 文件系统 | NTFS（ACL 与继承语义依赖）；ReFS 未验证 |
| 保护方式 | 显式 DACL：SYSTEM 完全控制、Everyone 只读+执行；**默认不授予 Administrators 写权限**（`--windows-allow-admins` 可恢复兼容模式），子对象继承 |
| 发布窗口 | 令牌有效期内给 `--publisher-sids` 配置的账号追加写+删除 ACE，到期/吊销后重新应用 DACL 收回 |
| 阻断边界 | 默认阻断所有 System 完整性以下进程的写入/删除/重命名，**包括提权管理员**；管理员仅能通过取得所有权/重写 ACL/改 SACL/停 Agent 绕过（心跳会重新施加，窗口默认约 15 s）；以 SYSTEM 运行的进程（如 SYSTEM 应用池、备份服务）不受限 |
| 审计 | 无内核事件：只有策略应用/错误与 RASP 事件进审计链，**不产生每次写操作记录** |
| 自愈（无驱动替代） | 受保护目录有内容基线（内容寻址存储），由 `ReadDirectoryChangesW` 事件立即触发（亚秒级），并以 `TG_WIN_SCAN_SECONDS`（默认 30s）兜底：被修改/删除的文件回滚、基线中不存在的新文件删除，事件记 `tamper.restored`；发布窗口内的变更视为可信，窗口结束后成为新基线 | 需 state 目录可写；基线在安装/策略首次应用时生成 |
| 服务加固 | 以 LocalSystem 运行、失败自动重启、服务 ACL 只允许 SYSTEM 停止/配置（管理员只能查询/启动） | `deploy/windows/install-service.ps1` |
| 卸载/回滚 | `tg-agent unlock --state-dir ...` 恢复继承权限；Agent 退出或崩溃**不会**自动解锁（防止防护静默消失） |
| 完整性级别（MIC，默认 `--integrity-level system`） | 受保护路径再打 **System** + `NO_WRITE_UP` 完整性标签（继承子对象）：System 完整性以下的进程（含**提权管理员**）即使 DACL 允许也写不进去；发布窗口内临时降为 Medium。**启动时会对 state 目录做一次写读自检**，宿主不支持则自动禁用并写入 capability 原因 | 需要 agent 以 SYSTEM 运行且宿主能正常保存完整性标签；本机（Win11 26100）实测写入不生效，已自动降级；`--integrity-level off` 关闭 |

实测限制与后续路线：

- IIS 应用池若以 SYSTEM 运行，等于管理员身份，ACL 挡不住；需要把应用池降到专用低权账户（安全基线本来也要求这样做）。
- 拿不到写者身份；需要"谁写的"审计时上 Windows 过滤驱动（minifilter）或 USN/ETW 方案，见 [先进技术调研](advanced-techniques.md)。
- 更完整的方案对比（minifilter 签名成本、完整性级别 MIC、USN 恢复）见 `docs/advanced-techniques.md`。

## 6. 自升级兼容性

- Agent 与服务端使用同一份 Ed25519 发布密钥签名 manifest；老版本 Agent（无升级通道）不受影响。
- 升级按 `os/arch` 选择产物，当前只支持与 Agent 相同的平台。
- 替换二进制后进程以 0 退出，由 systemd（`Restart=always`）拉起新版本；K8s 场景由 Pod 重建拉起。

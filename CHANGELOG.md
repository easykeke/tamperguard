# 变更记录

## 0.2.7（2026-11-27）

- **管理端支持 Windows 部署**：`tg-server` 新增 Windows 服务协议（`svc.Run`）、平台默认数据目录 `C:\ProgramData\TamperGuardServer`；新增 `install-server-service.ps1`（复制二进制、初始化 CA/管理员/令牌、注册 `TamperGuardServer` 服务、防火墙规则）；服务器证书 SAN 增加本机所有非回环 IP，便于 Agent 用 IP 连接；发布包新增 `tamperguard_<ver>_windows_amd64_server.zip`。

## 0.2.6（2026-11-27）

- **许可证调整为 PolyForm Shield 1.0.0**：源码可见、允许内部生产使用与修改分发，禁止提供与 TamperGuard 竞争的产品/服务；新增 NOTICE 版权声明。此前 v0.2.5 及更早版本仍按 Apache-2.0 授权，不可追溯撤销。

## 0.2.5（2026-11-27）

- **卸载状态兜底**：节点长时间停在「卸载中」时（离线/票据未消费/旧版 Agent 无完成回调），节点行新增「标记已卸载」，调用 `POST /nodes/{id}/mark-uninstalled` 完成收口；在线节点仍拒绝（409）。

## 0.2.4（2026-11-27）

- **修复重装时的残留服务键**：卸载删除 Watchdog 注册表键但 SCM 仍缓存服务条目，重装会报 `HKLM:\...\TamperGuardWatchdog` 路径不存在；安装脚本现在检测并重建缺失的服务键。

## 0.2.3（2026-11-27）

- **Agent 生命周期与防卸载**：新增两条且仅两条卸载路径——管理端「下发卸载」直接签发挑战码，或客户端 `tg-agent uninstall` 发起请求、管理员批准后返回挑战码；挑战码为控制面 Ed25519 签名的短时票据（绑定节点/请求/nonce/10 分钟有效期），客户端验签通过才执行清理，拒绝/超时/篡改均不删除。管理端新增「卸载审批」面板与节点「下发卸载」操作。文档 `docs/agent-lifecycle.md`，测试 `go test ./internal/uninstall`、`make e2e-uninstall`。
- **eBPF 链接固化（P6.1）**：LSM 链接与配置 map pin 到 bpffs，`kill -9` 后防护不再出现空窗（root 写入仍 EPERM），启动时清理旧 pin、卸载与 `tg-agent ebpf-detach` 显式解除；新增 `make e2e-ebpf-pin`。

- **Agent 自检（P6.2）**：自身二进制/unit/配置哈希基线，启动与每 5 分钟复核，变化写入审计链 `agent.selfcheck_failed`；`tg-agent selfcheck` 手动检查。
- **启动证据（P6.3）**：心跳上报 Secure Boot、TPM/PCR、IMA、cmdline 摘要为 `boot_digest`，节点详情展示，控制面记录摘要变化告警。是证据上报，不是 TPM quote 远程证明。

- **内核级 Agent 自保护**：eBPF 新增 `tg_self_pids` 映射，仅 Agent 进程可写自身 unit/config（二进制由自检与权限覆盖）；root 修改返回 EPERM，策略同步自动合并自身路径；`make e2e-selfprotect` 验证。

- **TPM AK 自动签发**：`tg-agent enroll --tpm-auto-ak --tpm-tcti ...` 自动创建 EK/AK、导出公钥登记到控制面，AK 上下文与 TCTI 存入 agent.json，运行时无需再传参数。swtpm 端到端通过。

- **管理端修复与增强**：修复节点详情接口返回 `{node,recent_audit}` 而前端把整个对象当节点渲染、导致详情字段全为 `—`、降级审批与卸载按钮缺失的问题；节点列表新增「操作」列可直接下发卸载。
- **管理员密码管理**：新增 `POST /api/v1/auth/password`（登录态 + 验证当前密码）与 `tg-server reset-admin-password`（break-glass，写入后立即生效，无需重启）；控制面登录改为读取磁盘哈希，CLI 重置即时可用。
- **自适应主题**：顶栏切换 自动/白天/夜间，自动模式跟随系统 `prefers-color-scheme`，偏好保存在 localStorage；新增完整浅色主题变量与组件覆盖。

- **发布端可视化管理**：发布页新增「发布端」面板与「生成注册令牌」（一次性 enroll 令牌，自动给出注册与启动命令）；新建发布请求的发布端改为下拉选择，目标节点只列出被保护节点。实测：令牌注册 → 发布端上线 → 创建请求 → 发布完成、站点内容更新。

- **跨机 pull 发布接入页面**：发布表单新增「发布方式：本机写入 / 跨机拉取」与「目标目录」（此前 UI 没有目标目录字段，导致发布端报 missing target_dir）；请求列表新增「方式」列（跨机拉取/本机写入）。实测：页面创建 pull 请求 → 发布端上传制品 → 目标节点拉取安装 → 状态 done、站点内容更新。

- **发布模式与手动触发**：发布请求新增 `mode`（full / incremental）。增量模式按 SHA-256 与目标目录（local）或上次成功发布清单（pull）比对，只写入变化文件；所有文件仍逐项哈希校验，local 写完后再读回复核。
- **发布端自触发同步**：`tg-publish sync --node --source --target --mode --delivery` 直接创建请求并等待完成，不再依赖管理页；新增 publish 角色接口 `/publish/sync`、`/publish/current`、`/publish/{id}`。页面新增「同步模式」选择与列表「模式」列。

- **发布端向导式同步**：`tg-publish sync` 无参数时交互式选择节点/源目录/目标目录/模式/方式，配置保存到发布端本地；之后一条 `tg-publish sync`（或 `tg-publish sync /srv/release`）即可同步，`--reset` 重新配置。参数可放在源目录前后，脚本模式保持不变。

- **同步任务集中配置**：管理端「发布」页新增「同步配置」（发布端/节点/源目录/目标目录/模式/方式），发布端只执行 `tg-publish sync`（多配置时编号选择，可用 `--profile` 指定）；管理端改路径后发布端下次触发自动生效。无管理端配置时仍可使用本地向导。

- **发布端多选执行 + 模式选择 + 执行记录**：`tg-publish sync` 列出管理端同步任务，支持多选（`1,3`/回车全部）、本次选择全量/增量、可选覆盖源目录/节点/目标目录；执行后发布请求带 `profile_id`，「同步配置」列表显示最近执行时间与结果。`--all`/`--profile` 供脚本使用。

- **发布后哈希闭环校验**：目标端（pull 由 Agent 回读落盘文件，local 由发布端回读）逐个比对清单哈希并计算发布摘要，控制面记录 `verify_digest/verified_files/verify_at`；发布端等待完成后与自身清单摘要比对并回显 `✓ 校验通过：目标端回读 N 个文件…`，不一致时同步失败。发布请求列表新增「校验」列。

- **审计明细增强**：目标端逐文件记录 `publish.file`（request/sha256/size/delivery），发布完成记录摘要；fanotify 在回滚前读取被篡改内容并记录 `tampered_sha256/size`，主体含 pid/uid/exe；审计页新增「详情」列。
- **管理端 Agent 下载与安装**：节点页新增「Agent 下载与安装」面板，可下载被防护端/发布端二进制、生成一次性安装令牌，并在弹窗中给出 CA、注册与常驻运行命令（`/api/v1/downloads/agent`）。

- **修复 Windows 安装包无法运行**：下载接口此前要求登录会话，会话失效时返回 52 字节 401 JSON 却被保存为 `tg-agent.exe`；现改为公开只读下载，并明确按 os/arch 返回 PE/ELF。Windows 无参数双击时显示用法并等待回车；新增 `install-service.ps1` 下载入口。

- **Agent 防停止/防卸载加固**：Windows 安装脚本新增 `TamperGuardWatchdog` 看护服务，服务 ACL 去掉 Administrators 的停止/删除/改配置权限，看护每 3 秒拉起被停服务并重刷 ACL；发布端也注册为受保护服务；卸载改由 SYSTEM 计划任务执行（管理员 ACL 已禁止直接 sc stop/delete）。Linux systemd 单元加 `RefuseManualStop=yes`，卸载改用 disable + kill。

- **Windows 托盘界面**：新增 `tg-agent-tray.ps1`，安装脚本自动创建开机启动快捷方式；托盘读取服务写入的 `TamperGuardStatus\status.json`（在线/执行层/降级/策略摘要/管理端地址），提供打开管理端、查看状态、退出托盘。托盘仅显示，不参与防护，退出不影响服务。

- **Windows 原生 GUI 客户端（C/S）+ 单一安装包**：新增 `tg-agent-gui.exe`（Win32 窗口 + 托盘），通过命名管道 `\\.\pipe\TamperGuardAgent` 读取 LocalSystem 服务状态并显示，关闭窗口最小化到托盘、退出客户端不影响服务；Windows 下载改为一个 `tamperguard-windows-amd64.zip`（防护端 + 发布端 + GUI + 安装/自检脚本）。原 PowerShell 托盘脚本不再作为界面使用。

- **修复 Windows 注册/安装卡点**：控制面新增公开 CA 下载（`?file=ca.crt`）；安装脚本改用 `New-Service` 写入带空格路径，失败不再静默；未注册时不锁状态目录、不强制启动服务，注册后再跑一次完成加固与启动。

- **一键注册**：Windows 管理页直接下载“一键安装包”（内嵌一次性令牌 + CA + 注册脚本，解压双击 `install.cmd` 完成注册与装服务）；Linux 生成一条 `curl ... | sudo bash` 命令，自动下载 CA/二进制、注册、写 systemd 并启动。自签控制面时脚本用 `curl -k` 拉取，之后 enroll 仍校验证书。

- **节点生命周期与清理**：卸载批准后节点状态 `uninstalling`，Agent 执行清理前回调 `/agent/uninstall/{id}/complete`，状态变为 `uninstalled`（已卸载）；节点列表支持行内删除离线/已卸载节点、批量「清理离线/已卸载」，在线节点删除返回 409。

## 0.2.2（2026-11-26）

新增 Web 层内容校验代理 `tg-proxy` 与控制面签名站点清单：磁盘被篡改时访问者仍拿到可信内容并留痕，签名清单模式使本地磁盘不再参与建立信任。


- **Web 层内容校验代理（P5.8）**：`tg-proxy` 把站点快照进内容寻址存储，逐请求校验磁盘文件；被篡改时返回可信副本并记 `web.tamper-detected`，清单外新增文件默认 404（可配置 upstream 转发动态请求）。Linux/Windows 通用，无需管理员或驱动。文档见 `docs/web-verification.md`，测试 `go test ./internal/webproxy`、`make e2e-proxy`。
- **签名清单模式**：`tg-proxy --sync --agent-state ...` 通过 mTLS 拉取控制面签发的站点清单（Ed25519，绑定节点/发布/目标目录/文件哈希），从控制面下载制品并逐个校验后建立可信存储；`--require-signed` 拒绝未签名或被篡改的清单，启动时用 policy 公钥复验签名。`GET /api/v1/agent/manifest`；测试 `make e2e-proxy-signed`。
## 0.2.1（2026-11-26）

相对 0.2.0：Windows 严格模式在真实主机验证通过（DACL + 自愈），MIC 改为自检式可选层；事件驱动自愈把篡改回滚窗口压到亚秒级；新增 Windows 服务安装脚本、测试工具与更完整的技术调研。


- **Windows 严格模式已在真实主机验证**（2026-11-26，Windows 11 26100）：SYSTEM agent 下严格 DACL 拒绝提权管理员的覆盖/新建、发布窗口授权与撤销生效、管理员绕过修改被自愈回滚并产生 `tamper.restored`、`unlock` 恢复维护。MIC 完整性标签在该主机上写入不生效（系统接受调用但 SACL 为空，`icacls` 也不支持 System 档），现已改为**启动自检、不支持则自动禁用并写明原因**，不再产生健康误报；在支持完整性标签的 Windows 上可通过 `--integrity-level system` 启用。
- **Windows 无驱动自愈 + 服务加固（替代 minifilter）**：受保护目录建立内容基线，每 30s（`TG_WIN_SCAN_SECONDS`）对照，被管理员绕过修改/删除的文件回滚、基线外新增文件删除，事件记 `tamper.restored`；发布窗口内的变更视为可信并在窗口结束后成为新基线。服务安装脚本把 Agent 以 LocalSystem 注册、失败自动重启、服务 ACL 只允许 SYSTEM 停止。
- **事件驱动自愈（P5.7）**：用 `ReadDirectoryChangesW`（overlapped I/O，无需驱动/管理员）监听受保护目录，变更立即触发一致性扫描，自愈窗口从 30s 降到亚秒级；定时扫描保留兜底。同时修正了同步目录读取在停止时阻塞的问题。
- **minifilter 驱动不纳入主计划**：驱动需要 WDK、测试签名/重启与微软签名，真实客户现场安装成本过高；保留为有签名能力客户的可选项。
- 新增 `cmd/tg-winacl-test`：在真实 Windows 主机上验证"提权管理员写入被拒 + 授予/撤销 + 自愈回滚"。
- `deploy/windows/`：服务安装脚本与部署说明。

## 0.2.0（2026-11-25）

相对 0.1.0 的主要变化：Windows 被防护端（ACL 严格模式 + MIC）、Landlock 进程自保护、fs-verity 发布固化、路径模型跨平台、Windows 交叉编译 CI 任务。
- **不可变发布模式（P5.6）**：新增 `docs/immutable.md` 与 `deploy/k8s/immutable/deployment.yaml`（只读根文件系统、站点来自镜像层、发布即新镜像、回滚即旧镜像），并说明它在混合环境里与文件级防护的分工。


- **fs-verity 发布固化（P5.3）**：`tg-publish run --verity`（本地发布）与 `tg-agent run --verity`（pull 交付）在写入完成后对每个文件启用 fs-verity——文件变为内核级只读、读取按 Merkle 树校验；`tg-agent verity enable|digest|check` 提供运维入口；`tg-agent probe` 报告可用性。运行环境需内核 `CONFIG_FS_VERITY` + 文件系统 `verity` 特性（开发用 WSL2 内核未启用，运行时验证待补，代码路径已用 ioctl 错误码验证）。
- **Windows 严格模式（P5.2 修正）**：默认不再给 Administrators 写权限，受保护路径标 **System + `NO_WRITE_UP`**——提权管理员的普通写入也被内核拒绝，只有发布窗口内临时降为 Medium 的路径允许授权发布账号写入；管理员只能通过取得所有权/重写 ACL/改 SACL/停 Agent 绕过（心跳重新施加约 15 s），这与 Linux root 的对抗能力对等；`--windows-allow-admins` 可恢复兼容模式，`--integrity=false` 关闭 MIC。
- **Landlock 进程自保护（P5.1）**：`tg-agent landlock [--allow-write DIR] -- <cmd>` 把 Web 进程及其子进程限制为只读视图，站点目录的写/删/改名由内核返回 `EACCES`；不需要 root 或 eBPF，约束不可撤销。默认放行 `/tmp`、`/var/tmp`、`/dev/shm` 与 `/dev/null` 等设备文件；`tg-agent landlock --check` 查看 ABI；`test/e2e/e2e-landlock.sh` 验证（含 Node.js 运行时演示）。
- **Windows 被防护端（实验性）**：ACL 锁定执行层（SYSTEM/Administrators 全权、Everyone 只读，发布窗口临时授权发布账号），`--publisher-sids` 配置授权账号；`tg-agent probe` 可检测平台并报告执行层；Agent 以管理员运行是前提。
- **路径模型跨平台**：策略/令牌路径统一支持 `C:\...` 与 UNC（内部规范为 `C:/...`，Windows 路径比较不区分大小写）；`tg-agent unlock` 恢复继承权限。
- **先进技术调研**：`docs/advanced-techniques.md` 梳理 Windows minifilter / 完整性级别 / USN、Linux Landlock / fs-verity / IMA 与不可变基础设施路线，并给出演进优先级。

## 0.1.0（首个完整版本）

### 防护能力

- **eBPF LSM 主执行层**：14 个 hook，写入在系统调用完成前被拒绝（`file_permission`、`file_open`、`inode_permission`、`inode_create/mkdir/unlink/rmdir/rename/link/setattr/setxattr`、`mmap_file`、`file_mprotect`、`d_instantiate`）。
- **保护继承**：授权窗口内新建的目录/文件由 `d_instantiate` 即时入索引并继承授权；撤权后立即受保护，不依赖下一次全量同步。
- **fanotify 降级层**：没有 bpf LSM 的内核上检测+回滚（覆盖写毫秒级回滚、删除/新建周期巡检恢复），队列溢出会触发重扫并上报 `enforcer.error`。
- **OverlayFS / 容器**：merged 路径拦截与 copy-up 已验证；K8s 以 privileged + hostPID DaemonSet 部署。
- **RASP**：Node.js（`fs` 包装）与 Java（`-javaagent` + SecurityManager）探针，观察优先、按路径策略热切换，事件进审计链。

### 发布与授权

- **跨机发布（pull 模式）**：发布端把制品与清单上传到控制面，目标节点 Agent 拉取后逐文件复核哈希再落盘；发布端不需要访问受保护主机。篡改制品会被节点拒绝并把请求标记为失败。

- **内容哈希绑定令牌**：Ed25519 签名，绑定发布端身份、目标节点、路径范围与 release manifest 的 SHA-256，TTL ≤ 15 分钟。
- **发布端与保护端分离**：发布端在本地复核每个文件哈希后原子落盘；令牌只在内存。
- **快速吊销**：吊销列表 + SSE 推送（心跳兜底），实测撤销后 2 秒内写入被拒。
- **授权传播确认**：`/publish/{id}/ready` 等目标节点确认 grant 已安装；发布端按 `EPERM` 重试兜底。
- **process 写者规则**：策略里的进程例外按 uid 合并进内核可消费 grant 的 uid 集合，策略变更即时生效。

### 审计

- 每条记录带单调 seq、prev hash、自身 hash 与 Ed25519 签名；服务端按 Agent 追踪 `(next_seq,last_hash)`，缺口/分叉即告警。
- 审计导出（JSONL / CSV，按节点与时间过滤）。
- 可选保留期（`audit_retention_days`），裁剪后仍可从现存最早记录开始校验。

### 运维

- `tg-agent probe` 能力探测（内核/LSM/BTF/执行层判定）。
- **签名自升级**：服务端签名 manifest，Agent 校验签名+大小+SHA-256 后原子替换自身二进制并退出等待重启；篡改产物被拒。
- 管理端：零依赖内嵌页面（总览/节点/策略/发布/审计/吊销），REST + mTLS。
- 部署形态：systemd、docker compose（仅管理端）、K8s DaemonSet。
- GitHub Actions CI：vet、单测、构建、用户态 e2e、eBPF 编译检查。

### 验证

| 测试 | 覆盖 |
|---|---|
| `go test ./...` | token/policy/audit/enforcer/rasp/release/agent 单测 |
| `test/e2e/e2e-sim.sh` | 用户态全链路（注册/策略/发布/审计/导出/吊销） |
| `test/e2e/e2e-ebpf.sh` | 内核同步阻断、授权发布、吊销后拒绝、审计验链 |
| `test/e2e/e2e-fanotify.sh` | 降级层回滚与巡检恢复 |
| `test/e2e/e2e-upgrade.sh` | 自升级：篡改拒绝、签名安装、退出等重启 |
| `test/e2e/e2e-rasp.sh` / `e2e-rasp-java.sh` | RASP 观察与热切换拦截 |

### 已知限制

- 不防 root：拿到 root 的攻击者可以杀死 Agent、卸载 BPF、改策略；产品只保证审计留痕与事后追溯。
- eBPF 主路径只在 Linux 6.6（WSL2）上验证；5.10–6.2 会因 hook 签名差异自动降级到 fanotify。
- RASP 只覆盖 Node.js 与 Java（JDK 16–21），PHP 等运行时没有探针。
- 容器仅验证 OverlayFS merged 路径；直接写 upperdir/lowerdir 属于宿主 root 行为，不在防护范围。
- fanotify 的删除/新建恢复有一个巡检周期（默认 30 秒）的窗口。
- 规模化（Postgres、多节点压测、审计归档）未做。

# TamperGuard 技术设计

> 文档状态：2026-11-25。P0 已落地：三端入口（`cmd/tg-server`、`cmd/tg-agent`、`cmd/tg-publish`）、核心包（`internal/token`、`internal/policy`、`internal/audit`，有单测）、控制面（REST、SQLite、mTLS、策略签名、15 秒心跳、审计链校验）、eBPF LSM 执行器代码（`bpf/tg_protect.bpf.c` 与 `internal/enforcer/ebpf_linux.go`：13 个 hook、inode 保护集合、grant map、ringbuf）以及用户态全链路 e2e（`test/e2e/e2e-sim.sh`）。执行器已在 Linux 6.6（WSL2，bpf LSM 启用）上完成真实阻断验证：`TestEBPFLSMEnforcement` 全部通过，`test/e2e/e2e-ebpf.sh` 全链路通过（webshell 写入 EPERM、发布放行、吊销后拒绝、审计验链通过）；仍标注“待补”的是 hook 覆盖缺口。fanotify 降级（检测+回滚+周期巡检）已实现并通过端到端验证；Agent 签名自升级通道（Ed25519 manifest + 哈希校验 + 原子替换）已实现并验证；RASP 已落地 Node.js 第一版（观察优先、策略热切换、审计接入），Java/PHP 待做。

## 1. 设计目标与非目标

### 1.1 目标

TamperGuard 面向 Linux 主机上的网页目录与发布产物，解决“未授权进程把内容写进受保护路径”这一类问题。设计目标按优先级排列：

| 优先级 | 目标 | 说明 |
|---|---|---|
| 1 | 内核层同步阻断 | 在写入发生前拒绝，而不是事后发现。P0 主路径是 eBPF LSM；加载失败时依次回退 fanotify（检测+回滚）与 observe（只记录），降级状态显式上报。 |
| 2 | 发布写入可授权 | 只有发布端 Agent 凭短时效令牌、且写入内容与已提交 manifest 的 SHA-256 摘要一致，才允许落盘。 |
| 3 | 审计可校验 | 每条审计记录带 seq、prev hash、自身 hash 与 Ed25519 签名，服务端逐条验链并在缺口/分叉时告警。 |
| 4 | 能力降级可解释 | 内核不支持 eBPF LSM 时降级到 fanotify，降级状态必须显式暴露，不能静默变成“看起来在防护”。 |
| 5 | 单机可部署 | 控制面 SQLite + 三端二进制，不依赖外部数据库、消息队列或容器编排。 |

### 1.2 非目标

| 非目标 | 原因或边界 |
|---|---|
| 不防 root | 拿到 root 的攻击者可以杀进程、卸载 BPF 程序、改策略文件、读 Agent 私钥。详见 `docs/threat-model.md`。 |
| RASP 只覆盖 Node.js | 当前 RASP 探针是 Node.js 版本（`rasp/node/tamperguard.js`），Java/PHP 运行时尚未提供；其它语言的应用层防护不成立。 |
| 不做恶意内容检测 | 不判断发布内容是否安全，只判断“写入者是否被授权、内容是否与已批准摘要一致”。 |
| 不做网络侧防护 | 不替代 WAF、IPS、EDR；不阻断 webshell 的网络回连与横向移动。 |
| 不承诺覆盖网络文件系统 | NFS/CIFS 上内核钩子与 fanotify 的支持都有限，见第 10 节。 |
| 不支持非 Linux 平台 | 保护端强依赖 Linux LSM/fanotify；管理端也按 Linux 部署设计。 |

### 1.3 设计原则

- 默认拒绝：受保护路径上，未在策略中列出的写入主体一律拒绝；未受保护路径不拦截，避免扩大故障面。
- 内核判定必须是用户态判定的子集：内核只看到已经由用户态校验过的授权，内核侧不能比用户态更宽松。
- 部分生效不算生效：hook 矩阵中任一 hook 挂载失败，整体回退到降级模式，不允许出现“挂了一半”的防护。
- 白名单而非黑名单：不枚举 webshell 特征，只枚举允许写入的身份。
- 审计先于信任：服务端不因为“Agent 说没事”就认为没事，链式校验和心跳对账独立执行。

## 2. 总体架构

### 2.1 架构图

```
                              ┌──────────────────────────────────────┐
  管理员浏览器 ──HTTPS───────▶│              tg-server               │
  （B/S 管理端）               │ REST /api/v1 · SQLite · 管理页面      │
                              │ CA · 令牌签发 · 策略签名 · 审计验链    │
                              └───────┬──────────────────────┬───────┘
                                      │ mTLS                  │ mTLS
                                      │ 策略 / 心跳 15s / 审计  │ 发布申请 / 令牌
                                      │ grant + 撤销下发        │
                                      ▼                       ▼
                 ┌────────────────────────────┐   ┌─────────────────────┐
                 │ 受保护节点：tg-agent         │   │ 发布端：tg-publish   │
                 │ 能力探测 · 策略缓存          │   │ 遍历源码树算哈希      │
                 │ eBPF LSM 执行/observe 回退     │   │ 提交 manifest        │
                 │ 用户态判定 · 审计链 Writer    │   │ 令牌持有（浏览器不接触）│
                 └─────────────┬──────────────┘   └──────────┬──────────┘
                               │ hook 决策                   │ 内容传输
                               ▼                            │（部署决定）
                 ┌────────────────────────────┐             │
                 │ Linux 内核 VFS · LSM · FS   │◀────────────┘
                 │ 受保护路径 /var/www/site    │
                 └────────────────────────────┘
```

发布端与被保护节点在生产环境默认分机部署，P0 演示可以同机。授权由服务端直接下发给目标节点的 `tg-agent`，不依赖发布端与本机的进程间通道；发布端到目标节点的内容传输通道（本地写入、rsync、SSH、共享存储等）不在本文定义，由部署方式决定。

### 2.2 三端职责

| 组件 | 职责 | 明确不负责 |
|---|---|---|
| `tg-server` | 管理端 HTTP 服务；REST API；面向 Agent/发布端的 mTLS 接入；SQLite 持久化；CA 与身份签发；策略快照 Ed25519 签名；发布令牌签发与吊销；审计链接收、验链、缺口告警；心跳响应与 SSE 推送（`GET /api/v1/agent/stream`）中的策略、grant 与撤销下发。 | 不执行任何文件系统拦截；不接触发布内容明文（只收 manifest 摘要与审计记录）。 |
| `tg-agent` | 受保护主机上的 root 守护进程：能力探测、策略同步与验签、eBPF LSM 执行 / fanotify 降级（检测+回滚）/ observe 回退、grant 与撤销校验、审计链记录与上报、15 秒心跳。 | 不存储发布内容；不做内容安全判断；普通容器内不可运行（K8s 需 privileged + hostPID，见 deploy/k8s）。 |
| `tg-publish` | 发布端 Agent：持有 mTLS 身份，拉取分配给自己的发布申请，遍历源码树计算 manifest，向服务端申请短时效令牌并持有，逐文件复核哈希后写入，上报完成状态。 | 浏览器永远不接触令牌；发布端不自行延长令牌有效期；不绕过目标节点的执行层写文件。 |

### 2.3 部署约束

| 组件 | 部署要求 |
|---|---|
| `tg-agent` | 必须宿主机 root，systemd 管理；普通容器不能运行。K8s 场景使用 privileged + hostPID 的 DaemonSet 把受保护路径 hostPath 挂入，见 deploy/k8s。 |
| `tg-publish` | 生产默认与被保护节点分机（两台机），P0 演示可同机；需要能访问服务端 mTLS 端口。令牌只在本机落盘。 |
| `tg-server` | 管理端可用 docker compose 部署；集中式单实例，SQLite 单写者。 |
| 开发/测试 | WSL2 Ubuntu 24.04，内核 6.6，已启用 bpf LSM（`lsm=...,bpf`）；eBPF 执行器代码已落地，`internal/enforcer/ebpf_linux_test.go` 提供 root 级 LSM 阻断测试，真实阻断结果待跑测确认。 |

发布端与节点分离不影响授权模型：令牌由发布端持有，grant 由服务端下发给目标节点的 Agent，二者通过服务端汇合，不需要发布端与目标节点之间存在额外信任通道。

### 2.4 代码结构现状

```
cmd/tg-server/          控制面入口（P0）
cmd/tg-agent/           保护端入口（P0）
cmd/tg-publish/         发布端入口（P0）
bpf/                    eBPF C 程序（tg_protect.bpf.c）与 vmlinux.h（P0）
internal/token/         发布令牌签发/校验/路径覆盖（已实现，含单测）
internal/policy/        策略模型、快照签名、决策函数（已实现，含单测）
internal/audit/         审计链 Writer/Verifier/文件续链（已实现，含单测）
Makefile                make build，产出 bin/ 下三个二进制（P0）
test/e2e/e2e-sim.sh     用户态全链路 e2e（P0，sim enforcer）
docs/api.md             HTTP API 合同（已写）
web/                    管理端静态资源（P0，实际目录名以实现为准）
```

## 3. 信任模型

### 3.1 谁信任谁

| 信任方 | 被信任方 | 依据 | 被破坏后的后果 |
|---|---|---|---|
| 管理员浏览器 | tg-server | HTTPS 服务端证书 + HttpOnly 会话 Cookie | 可被钓鱼/中间人；证书信任方式待部署约定 |
| tg-server | tg-agent / tg-publish | mTLS 客户端证书，服务端 CA 校验，证书 CN 映射为 agent ID | 持证者可冒充节点或发布端 |
| tg-agent | tg-server | mTLS 服务端证书 + TG CA；首次 enrollment 的服务端身份校验方式待确认 | 可被引导连接假控制面，接受假策略/假令牌 |
| tg-agent | 策略快照 | 快照 Ed25519 签名 + 摘要，公钥在 enrollment 时下发并固定 | 可下发任意策略，等于取消防护 |
| tg-agent | 发布令牌 | 令牌 Ed25519 签名，签发公钥在 enrollment 时下发并固定 | 可伪造写入授权 |
| Linux 内核 eBPF 执行器 | tg-agent 下发的策略与授权 map | 无签名校验，内核信任 root 侧写入的 map 内容 | 拿到 root 即可篡改判定状态，这是“不防 root”的直接体现 |
| tg-server | Agent 审计记录 | 每条记录的 Agent Ed25519 签名 + 链式 seq/prev | 私钥泄露后可伪造历史记录 |
| tg-publish | 自己的源码树与 manifest | 本地计算，无第三方证明 | 发布端被控制后会为恶意内容生成合法 manifest |

信任根是 tg-server 的 CA 私钥与两把 Ed25519 签名私钥。这三把密钥失守，防护模型整体失效；当前没有 HSM/TPM 保护，也没有密钥轮换设计。首次 enrollment 不使用 TOFU：Agent 必须通过带外交付的 CA 文件（`--ca`）或服务端证书的 SHA-256 指纹（`--ca-fingerprint`）校验服务端证书，两者都没有时拒绝注册。CA 文件与指纹的交付通道本身仍需带外保证。

### 3.2 密钥与证书

| 密钥/凭据 | 位置 | 用途 | 生命周期 |
|---|---|---|---|
| TG CA 私钥 | tg-server 数据目录（0600） | 签发 Agent/发布端客户端证书 | 当前无轮换设计 |
| 策略签名私钥（Ed25519） | tg-server | 签策略快照，Agent 验签 | 当前无轮换设计 |
| 令牌签发私钥（Ed25519） | tg-server | 签发布令牌，Agent 验签 | 当前无轮换设计 |
| Agent/发布端身份私钥 | 受保护主机本机（0600） | mTLS 客户端认证；Agent 另用它签审计记录 | enrollment 时本机生成，私钥不出主机 |
| 管理员口令 | tg-server，密码哈希 | 管理端登录 | `tg-server init` 生成并打印一次，重置方式待确认 |
| bootstrap token | 管理员经带外渠道交付 | 一次性 enrollment 凭据 | 单次使用；具体 TTL 与是否绑定主机待确认 |

### 3.3 enrollment 流程

1. 管理员在服务端登记节点（role = `protect` 或 `publish`），签发 bootstrap token，带外交付。
2. 主机安装 `tg-agent`（或注册发布端身份时用同一二进制），以 root 执行 `tg-agent enroll`，向 `POST /api/v1/agent/enroll` 提交 `bootstrap_token`、`hostname`、`role`、`csr_pem`、`agent_version`；同时必须用 `--ca` 或 `--ca-fingerprint` 校验服务端 TLS 证书。
3. 服务端校验 bootstrap token 存在、未使用、未过期、role 匹配，签发 CSR，生成 agent_id 写入证书 CN，返回 `cert_pem`、`ca_pem`、`server_time`、`issuer_public_key`、`policy_public_key`。
4. Agent 校验证书链，把私钥/证书落盘（0600），销毁 bootstrap token。此后所有请求走 mTLS，不再使用引导凭据。
5. 首次心跳上报能力探测结果（`bpf_lsm`、`fanotify`、`btf`、内核版本、执行层类型、是否降级）与初始审计 seq。
6. 服务端下发签名策略快照；Agent 验签后装载执行层。

注册接口的返回字段以 `docs/api.md` 为准。bootstrap token 按一次性使用设计；TTL 与是否绑定 hostname 需在实现时确定并写回本文。

### 3.4 撤销

| 撤销对象 | 生效方式 | 延迟上界 |
|---|---|---|
| 发布令牌 | `POST /revocations` 写入撤销列表；通过 SSE 推送即时下发，推送断线时回退心跳响应 | 正常亚秒级；断线兜底为 15 秒心跳周期 |
| 发布主体 | 同上，按 subject 撤销；已签发令牌一并失效 | ≤ 30 秒 |
| 节点身份 | `DELETE /nodes/{id}`，服务端拒绝该证书的后续 mTLS 请求 | 下一次请求；证书本身不吊销，靠服务端身份白名单 |
| 策略变更 | 重新签发快照，SSE 推送触发 Agent 立即同步；心跳兜底 | 推送亚秒级 / 兜底一个心跳周期 |

当前没有 CRL/OCSP；节点撤销依赖服务端对已登记身份的检查，证书在密码学意义上仍然有效。这是设计选择，不是遗漏，但需要在威胁模型中写明。

## 4. 防护模型

### 4.1 路径规则

策略由一组路径规则组成，规则结构见 `internal/policy`：

| 字段 | 含义 | 约束 |
|---|---|---|
| `path` | 受保护路径 | 必须是绝对路径且 clean；含 `..` 直接判非法 |
| `recursive` | 是否保护整棵子树 | 非递归规则只保护该文件本身，不保护兄弟路径 |
| `mode` | `enforce` / `observe` | 空值按 `enforce` 处理；`observe` 放行但记录 `write.observed` |

匹配规则：

- 多条规则命中时取最长前缀（最具体）的那条。`/var/www/site/cache` 的 observe 规则可以覆盖 `/var/www/site` 的 enforce 规则，用于灰度。
- 前缀匹配按路径分量进行，`/var/www/site` 不匹配 `/var/www/site-evil`。
- 未命中任何规则的路径不拦截，只做必要的记录（不记录也不影响功能，是否记录由执行层策略决定）。

### 4.2 写入主体

受保护路径上的写入主体只有两类：

| 类型 | 识别方式 | 说明 |
|---|---|---|
| 发布端 Agent（`publisher`） | mTLS 身份 + 令牌 + 目标节点上的 grant + 内核侧写入 uid | 正常发布通道。grant 在用户态校验后展开成内核 map 的 `(uid, dev, inode)` 授权；可消费 grant 的 uid 由 `tg-agent enroll --publisher-uids` 配置，默认 `0`（演示方便，生产必须改成发布端专用 uid）。fanotify 降级为检测+回滚，能力明显弱于 eBPF LSM。 |
| 登记进程（`process`） | `exe_path`（可加 `uid`） | 策略例外，例如本机 rsync、备份程序。每一条都应被视为例外，管理端单独展示。规则的 `uid` 会与 agent 的 `--publisher-uids` 合并成“可消费 grant 的 uid 集合”，在每次策略同步时写进内核 map 并重建 grant 表，因此策略变更即时生效、无需重启 agent。 |
| 其他进程 | 不匹配任何白名单 | 受保护路径上的一律拒绝。 |

发布端与登记进程的区别在于：登记进程是长期规则，发布端是短时授权。发布端的长期身份只证明“它是发布端”，真正允许写哪条路径由令牌给出，令牌过期或吊销后立即失效。

### 4.3 发布令牌

令牌实现已在 `internal/token` 完成。结构：

| 字段 | 含义 |
|---|---|
| `v` | 版本，当前固定 1 |
| `jti` | 令牌 ID，用于撤销 |
| `iss` | 签发者，当前为 tg-server |
| `sub` | 发布端身份 |
| `node` | 目标节点 ID |
| `aud` | 固定 `tg-agent` |
| `iat` / `nbf` / `exp` | 签发时间 / 生效时间 / 失效时间 |
| `paths` | 允许写入的绝对路径前缀，分量感知匹配 |
| `manifest` | 发布 manifest 的 SHA-256 摘要（十六进制） |
| `policy_rev` | 签发时参考的策略版本（可选） |

线格式：`tg1.<base64url(payload)>.<base64url(signature)>`，签名覆盖字面量 `tg1.<payload>`，Ed25519。校验顺序是签名、字段形状、时间窗口；调用方还必须额外检查撤销列表与节点绑定。

硬约束：

- TTL 上限 15 分钟（900 秒），服务端默认签发 5 分钟（300 秒）；超过上限直接拒绝签发，也拒绝校验通过。
- 允许时钟偏差 30 秒。
- 路径必须是绝对、clean、无 `..`；`/var/www/html` 不覆盖 `/var/www/html-evil`。
- 令牌的 `paths` 取目标节点当前策略中的全部受保护路径，不是发布请求里的 `target_dir`；`target_dir` 必须落在策略路径之内，否则发布端写前检查 `Covers` 会拒绝。
- `manifest` 为空表示“仅路径绑定”的弱令牌；带上摘要时，写入内容的摘要必须与令牌内摘要一致。
- 令牌只证明“谁可以写、写哪里、什么时候之前”，不证明“写的是批准内容”。内容是 manifest 摘要证明的，两者缺一不可。

### 4.4 manifest 与内容哈希绑定

发布 manifest 是发布内容的清单，当前实现（`internal/publish`）：

- 遍历源目录下的普通文件，逐文件计算 SHA-256 与大小。
- 文件列表按相对路径排序后，以 `相对路径\tSHA-256\n` 逐行拼接再做 SHA-256，得到 manifest 摘要；大小不参与摘要计算。
- 符号链接与非普通文件被直接拒绝，不跟随；空目录树被拒绝。这是为了防止发布树把受保护目录之外的文件带进来。
- 发布端在写入每个文件前重新读取并计算该文件摘要，与 manifest 条目比对；不一致立即中止。
- 目标路径必须落在 `target_dir` 内，且必须被令牌的路径范围覆盖。
- 每次成功写入都记录审计（`write.allowed`，带 token_id 与 manifest），可回溯“哪次发布写了哪个文件”。

关键限制：摘要绑定发生在服务端签发时与发布端写盘前，内核只按 uid/路径授权，不校验文件内容。因此内容哈希绑定防的是“令牌被拿去写别的内容”和“批准后内容被替换”，不防“发布端在提交 manifest 之前就被控制”。后者是发布通道的固有限制，见 `docs/threat-model.md` 第 5 节。

### 4.5 决策函数

用户态决策函数 `policy.Decide` 是唯一权威判定，内核侧只是它的预筛。伪代码与实现一致：

```text
Decide(req):
    path, ok = NormalizePath(req.Path)
    if not ok:                          return deny("invalid-path")

    rule, protected = MatchPath(path)   # 最长前缀；非递归规则要求精确相等
    if not protected:                   return allow("not-protected")
    if rule.Mode == observe:            return allow("observe-mode")

    if WriterAllowed(req.Subject):
        for grant in req.Grants:
            if grant.Subject 非空 且 != req.Subject.ID:   continue
            if grant.NodeID  非空 且 != req.NodeID:       continue
            if grant.ExpiresAt 非零 且 <= req.Now:        continue
            for p in grant.Paths:
                if PathCovered(p, path):                  return allow("token-granted")

    return deny("denied")
```

稳定的 reason 字符串：`not-protected`、`observe-mode`、`token-granted`、`denied`、`invalid-path`。这些字符串会进入审计记录与告警规则，改动需同步 UI 与文档。

注意：`Request.Manifest` 目前不参与 `Decide`。manifest 绑定发生在令牌签发与发布端写盘/传输前，不在内核判定路径上，这是有意设计，不是遗漏。

内核侧伪代码（当前实现）：

```text
on_hook(ctx):
    inode = ctx 目标 inode                  # create/unlink/rename 另取父目录 inode
    if inode 不在 protected_files 且 父目录不在 protected_dirs:
        return ALLOW                        # 未保护路径不拦
    if grants[(uid,dev,ino)] 或 grants[(uid,dev,父目录 ino)] 存在且未过期:
        return ALLOW
    if 规则模式为 observe 或 全局未启用强制:  return ALLOW   # 上报 would-deny
    return -EPERM
```

内核能可靠获取的身份是 uid；exe 路径需要额外解析且受上下文限制。发布端身份不能直接出现在内核判定里，这是 `publisher_uids` 存在的原因。授权粒度是 uid 而不是进程：令牌有效期内，同一 uid 的任何进程都能写被授权路径，默认 uid 0 意味着 root 在整个令牌窗口内可写，生产必须换成专用 uid。当前 Go 侧只把 `enforce` 规则写入保护集合，`observe` 规则在 eBPF 后端被跳过（见 5.5）。

### 4.6 授权下发：P0 与后续版本的边界

P0 实现（本轮）：

- eBPF LSM 执行器代码已落地：13 个 hook（`file_permission`、`file_open`、`inode_permission`、`inode_create/mkdir/unlink/rmdir/rename/link/setattr/setxattr`、`mmap_file`、`file_mprotect`）attach 成功后启用；任一 attach 失败整体回退 observe。
- 内核侧可识别的写入主体是 uid（exe 路径只能作为附加条件）。发布端以专用 uid 运行，该 uid 由 `tg-agent enroll --publisher-uids` 写入 Agent 状态，默认 `0`。令牌/grant 在用户态校验后展开为内核 map 的 `(uid, dev, inode)` + 到期时间授权，目录授权覆盖目录内新建操作。
- 真实阻断已在 Linux 6.6 + bpf LSM 上实测：受保护写入返回 EPERM、读放行、新建与删除被拒、令牌授权可写、撤权后再次被拒；其他内核版本与文件系统仍需分别验证。
- fanotify 降级（检测+回滚+周期巡检）已实现，能力边界见第 6 节。
- 发布端与被保护节点同机是 P0 唯一端到端流程。跨机传输不在代码里，需要部署侧 rsync/SSH/共享存储等外部通道，当前未实现。

后续版本：

- 授权表示从 uid 级细化到进程级（pid/exe），需要安全处理 pid 复用与进程身份解析，属于 P1 完善项。
- 完整 hook 矩阵、5.10 兼容、路径解析方案验证、压测与容器场景，见第 11 节。

## 5. 内核层设计

本节是 eBPF LSM 执行器的设计。执行器代码已落地（`bpf/tg_protect.bpf.c` + `internal/enforcer/ebpf_linux.go`），已在 Linux 6.6 + bpf LSM 上完成真实阻断验证；文中其余“待验证”表示尚未确认，“待补”表示当前实现与设计意图存在差距。

### 5.1 前提与加载流程

| 前提 | 检查方式 | 不满足时 |
|---|---|---|
| 内核 ≥ 5.10（推荐 6.1+） | `uname -r` | 回退 fanotify（检测+回滚）或 observe |
| `CONFIG_BPF_LSM=y` | 内核配置或 `/sys/kernel/security/lsm` 含 `bpf` | 回退 observe |
| LSM 列表包含 bpf | `cat /sys/kernel/security/lsm`，必要时 `lsm=...,bpf` 启动参数 | 回退 observe，需重启换内核 |
| BTF/CO-RE | `/sys/kernel/btf/vmlinux` 存在 | 回退 observe |
| 特权 | root（加载 BPF LSM 所需 capability 随内核版本不同，需实测） | 启动失败，回退 observe 并报 degraded |

加载流程：

1. 探测能力，结果写入心跳的 `caps` 字段。
2. 加载嵌入的 CO-RE 目标文件，逐 hook attach。
3. 任一 hook attach 失败：卸载已挂载程序，整体回退 fanotify，记录 `enforcer.degraded`，不允许部分生效。
4. 从已验签策略填充 map，启动 ringbuf 事件消费者。
5. 自检通过后上报 `enforcer=ebpf-lsm`；之后每隔心跳周期检查 link 与 map 状态。

5.10 与 6.1+ 的差异（可用的 BPF helper、hook 参数、是否允许 sleepable 程序）需要在真实内核上逐项验证，本文不假设 5.10 上所有 hook 都能按预期工作。

### 5.2 hook 矩阵

LSM 没有“所有文件写操作”的统一入口，每个 VFS 原语对应独立 hook。要完整覆盖写、改、删、移、链接、属性、映射，必须分别挂载。下表是当前实现矩阵；已知与设计意图不一致的地方在表后列出。

| LSM hook | 触发位置 | 拦什么 | 为什么必须单独挂 | 已知限制 |
|---|---|---|---|---|
| `file_permission` | 每次 `read`/`write` 系统调用进入 VFS 前（`rw_verify_area`） | 已打开 fd 的每次写入与追加（`MAY_WRITE`/`MAY_APPEND`） | open 之后 fd 可以长期持有，只在 open 时检查会被“先 open 再写”绕过；这是唯一能在每次 write 时看到写意图的位置 | 读写共用，必须只判写位，否则误伤读；取 file 的 inode 查表，不做路径解析 |
| `file_open` | `do_dentry_open`，open 成功前 | 以写意图打开已存在的受保护文件（`O_WRONLY`/`O_RDWR`/`O_APPEND`） | 在第一次 write 之前拒绝，避免“open 成功、write 才失败”带来的语义差异；覆盖打开后不立即写、但留下可写句柄的情况 | 新建文件时创建动作由 `inode_create` 负责；`O_TRUNC` 截断动作由 `inode_setattr` 先处理；必须放行纯读打开 |
| `inode_permission` | 路径解析过程中对每个目录组件与最终 inode 的权限检查 | 目录级写入门禁的纵深防御 | 不能作为主阻断点：对父目录只说明“能否在该目录内操作”，拿不到最终文件名，也不知道即将执行的是 create、unlink 还是 rename；最终 inode 的检查同样没有操作类型 | 当前实现只在 `MAY_WRITE` 时按目录 inode 做门禁；无法区分目标文件与操作，不能替代 create/unlink/rename 专用 hook |
| `inode_create` | `vfs_create`，新建文件 inode 之前 | 在受保护目录内新建文件（webshell 落盘、上传临时文件、`O_CREAT`） | 创建动作不经过已有的 file 写路径，`file_permission`/`file_open` 都看不到“新名字即将出现”；dentry 里能拿到文件名 | 只覆盖普通文件创建；目录、设备节点、符号链接有各自的 hook，见 5.2.1 |
| `inode_unlink` | `vfs_unlink`，删除前 | 删除受保护文件 | 删除不打开文件、不写内容，所有基于 file 的 hook 都看不到；重命名也不等于删除 | 只覆盖普通文件 unlink；目录删除走 `inode_rmdir` |
| `inode_rename` | `vfs_rename`，重命名前 | 把受保护文件移出、改名覆盖、把外部文件移入受保护目录、`RENAME_EXCHANGE` 两侧 | rename 是原子替换，能一次完成“删除旧文件 + 写入新名字”，不挂它等于留一个完整的绕过通道；必须同时检查旧路径与新路径 | 同名覆盖时旧目标 inode 被替换；rename 系统调用不能跨文件系统（EXDEV），用户态 `mv` 会退化为 copy + unlink，此时由 create/unlink hook 覆盖 |
| `inode_link` | `vfs_link`，创建硬链接前 | 在受保护目录内为外部 inode 建链 | 硬链接不写内容、不打开文件、也不产生 rename；一旦受保护文件有了未保护路径的别名，按路径匹配的写检查就失效 | 当前实现只检查新链接所在目录，未检查源 inode 是否受保护：把受保护文件硬链到未保护目录不在检查范围内，属已知缺口（待补） |
| `inode_setattr` | `notify_change`，属性/截断变更前 | `truncate`、`ftruncate`、`open(O_TRUNC)` 截断、`chmod`、`chown`、`utimes` | 截断与改权限不写文件内容、也不一定重新 open；`file_permission` 看不到这类破坏；改权限还可能让后续写变得更宽松 | `chattr` 走 ioctl，不在该 hook 内，见 10.2 |
| `inode_setxattr` | `vfs_setxattr` | 写受保护文件的扩展属性（`security.*`、`user.*` 等） | setxattr 是独立系统调用，不经过 open/write 路径 | 只覆盖 xattr 写入；读取与删除 xattr 有对应 hook |
| `mmap_file` | `mmap` 建立文件映射时 | 对受保护文件建立可写映射 | mmap 之后的写是内存写，完全不走 `write` 系统调用，`file_permission` 不参与；不挂它等于留一个完全绕过 | 当前实现只要 `prot` 含 `PROT_WRITE` 就按文件 inode 判定，不区分 `MAP_SHARED`/`MAP_PRIVATE`（私有可写映射可能被误拒），且不查父目录（待补） |
| `file_mprotect` | `mprotect` 改变映射保护时 | 给已有的共享文件映射追加 `PROT_WRITE` | 攻击者可以先以 `PROT_READ` 建立共享映射，再 `mprotect` 加写；`mmap_file` 只检查建立时参数，事后提权必须单独拦 | 当前实现与 `mmap_file` 一样只查文件自身 inode，不查父目录，递归规则下的文件存在可写映射缺口（待补） |

当前实现与设计意图的已知差异（视为未完成项，不作为已覆盖能力对外描述）：

- `mmap_file` / `file_mprotect` 只用文件自身 inode 判定，没有使用父目录保护集，递归规则内的文件可能建立 `PROT_WRITE` 共享映射。
- `inode_link` 只检查新链接所在目录，没有检查源 inode。
- 非递归单文件规则的 `unlink` / `rename` 依赖父目录判定；父目录未受保护时，这两个原语存在缺口。
- 策略里的 `process` 写入者规则没有进入内核判定：受保护路径上只有 grant 能放行，登记进程会被一并拒绝（待补）。
- `observe` 规则没有进入内核保护集合（Go 侧跳过），eBPF 节点上 observe 规则不阻断也不产生内核事件。
- 新建子目录不在 `protected_dirs` 索引中，要等下一次心跳触发的索引重建才进入保护集；窗口内其内部文件可能漏拦。

#### 5.2.1 补充 hook

以下原语不改变文件内容，但会改变受保护目录的结构或为绕过制造条件。当前实现只纳入 `inode_mkdir` / `inode_rmdir`；`inode_mknod`、`inode_symlink` 尚未纳入（待补）：

| LSM hook | 作用 | 为什么考虑纳入 |
|---|---|---|
| `inode_mkdir` / `inode_rmdir` | 创建/删除目录 | 保护目录本身被删或替换会影响路径匹配；Web 应用通常不需要在受保护目录建目录 |
| `inode_mknod` | 创建设备节点/FIFO | 在受保护目录里放 FIFO/设备节点可以被利用做写入或权限提升的跳板 |
| `inode_symlink` | 创建符号链接 | 在受保护目录内放符号链接，可能把后续写入引到预期之外的位置 |

### 5.3 hook 之间为什么不能合并

- `inode_permission` 只作用于路径解析过程中的目录与 inode，拿不到最终文件名，也不知道操作类型。它在目录组件上回答的是“能不能进入/操作这个目录”，无法替代 `inode_create`、`inode_unlink`、`inode_rename` 这些带 dentry、带具体操作语义的 hook。
- 删除、重命名、硬链接、属性变更、映射建立、每次写入分别是六条独立路径，没有公共的“写前”入口可以统一拦截。
- 文件内容写、目录项变更、inode 元数据变更、内存映射写属于不同的攻击面，少挂任何一个都会留下完整的绕过路径。

### 5.4 hook 与 policy.Op 映射

| hook | 归入的 `policy.Op` |
|---|---|
| `file_open`（写意图） | `open_write` |
| `file_permission`（写/追加） | `open_write` |
| `inode_create` | `create` |
| `inode_unlink` | `unlink` |
| `inode_rename` | `rename` |
| `inode_link` | `link` |
| `inode_setattr` | `setattr` |
| `inode_setxattr` | `setattr`（或单独审计 kind，待实现确认） |
| `mmap_file` / `file_mprotect` | `mmap_write` |
| `inode_rmdir` | `rmdir` |

### 5.5 匹配方式：inode 索引，不做内核内路径拼接

BPF hook 拿到的是 dentry、inode、file、vma。执行器当前方向是按 inode 索引匹配，而不是在 hook 内拼路径：

- 用户态按策略路径遍历受保护目录，把受保护目录与文件的 `(dev, inode)` 写入 `protected_dirs`、`protected_files` 两个 map。
- hook 取目标 inode（create/unlink/rename 另取父目录 inode）做 `(dev, ino)` 查表；命中即受保护。
- 发布授权 map 以 `(uid, dev, inode)` 为键并带到期时间，内核只按 uid 与目标 inode 放行。
- 内核不做字符串路径比较；路径只用于用户态的审计、展示与策略计算。

这样做的原因：`bpf_d_path` 在部分 hook 上下文和内核版本不可用，dentry 父链遍历的复杂度与锁语义风险高；inode 查表是 O(1)。

当前实现（`ebpf_linux.go`）：

- `Update()` 每次从已验签策略重建保护集：对 `enforce` 规则调用 `collectInodes`，递归规则把根目录及其所有子目录的 `(dev, ino)` 写入 `protected_dirs`；非递归文件规则把文件 inode 写入 `protected_files`。
- grant 同样按 inode 展开：对每条未过期、未撤销的 grant，遍历其路径的目录与文件集合，为 `publisher_uids` 中每个 uid 生成 `(uid, dev, ino) → 到期时间` 的 map 项。目录授权覆盖目录内的新建与删除操作。
- map 更新采用“先加后删”的差分方式，避免更新过程中出现保护集合为空的窗口；`Health()` 每次心跳检查 link 是否存活、config map 是否可读。
- 事件带 `(dev, ino)`，用户态用 `dirs`/`files` 索引回填路径；索引里没有的新 inode 会回填成 `inode:<号>`，路径补全待实现。

代价与待验证点：

- 索引必须随策略变更与文件创建、删除、rename 刷新；刷新窗口内可能漏拦或误判。
- inode 复用：文件删除后 inode 号可能被新文件复用，需要结合 dev 与索引有效期处理，避免把新文件当成旧受保护文件放行（待验证）。
- 新建文件在创建前没有 inode，只能按父目录 inode 命中 `protected_dirs`，因此“创建”的授权要落在目录 inode 上。
- rename/link 必须同时检查源与目标两侧 inode，包括父目录；当前实现尚未完全做到，见 5.2 的已知差异。
- overlayfs 的 copy-up 已验证不影响 inode 匹配，容器场景的边界见第 9 节。
- 策略路径很深或经常变化时，用户态遍历与刷新成本需要实测。

最长前缀、observe/enforce 判定与规则选择仍由用户态 `MatchPath` 完成；内核只持有最终生效的 inode 集合。当前 Go 侧只把 `enforce` 规则写入保护集合，`observe` 规则在 eBPF 后端被跳过（C 侧 `MODE_OBSERVE` 已预留，待接线）。

### 5.6 map 与事件通道

| map | 内容 | 说明 |
|---|---|---|
| `protected_dirs` | 受保护目录的 `(dev, ino)` 与模式字节 | 用户态按 `enforce` 策略遍历写入；策略变更时按差分重建 |
| `protected_files` | 受保护文件的 `(dev, ino)` 与模式字节 | 只用于非递归单文件规则；同样按差分重建 |
| `grants` | `(uid, dev, ino)` 与到期时间（boot 以来的 ns） | 发布授权；uid 来自 `--publisher-uids`，到期由内核检查 |
| `tg_config` | 全局 enforce 开关（1=强制，0=只观察） | 当前 Go 侧固定写 1，未暴露熔断开关 |
| `events` | ringbuf 拒绝/放行/观察事件 | 用户态消费后写审计链；消费失败不能阻断内核判定 |

事件只承载判定结果与最小上下文（pid、comm、dev/inode、操作、verdict）。路径由用户态按 inode 索引回填；查不到时保留 `inode:<号>`。C 侧 `MODE_OBSERVE` 与全局只观察模式均已接线：observe 规则进入内核 map 后只产生 `write.observed` 事件，不阻断。

### 5.7 失败与 fail-closed

| 故障 | 处理 |
|---|---|
| 程序加载/attach 失败 | 整体回退 fanotify，上报 `enforcer.degraded`，管理端标红 |
| ringbuf 消费失败或事件丢失 | 内核判定不受影响；用户态记录 `enforcer.error`，通过心跳暴露，审计缺口按链状态告警 |
| inode 索引为空或未就绪 | 内核侧会按未保护放行；用户态必须在索引填充完成后再启用 enforcement，并在心跳里暴露索引状态（待实现） |
| 索引刷新期间 | 新建、rename 的文件可能短暂漏拦；记录 `enforcer.error` 并告警（待实现） |
| Agent 进程退出 | 当前 link 由 Agent 进程持有、未 pin；进程退出或崩溃时 link 随 fd 关闭而 detach，受保护路径恢复放行，直到 Agent 重启重新加载。P0 已知风险，pinned link 或独立看护进程待评估 |
| 内核/系统重启 | BPF 程序随内核消失，agent 启动后重新加载；启动到重新加载之间的窗口没有阻断，只能靠审计记录与运维窗口约束 |

当前实现没有 pinned link：Agent 被杀或崩溃后，内核不再阻断，服务端要等 3 个心跳周期（45 秒）才判离线。这段时间里受保护路径实际处于放行状态，属于 P0 的已知风险。root 攻击者也可以直接 detach 或杀进程，这一点无法在内核层解决。

## 6. 降级层：fanotify（已实现，检测 + 回滚）

fanotify 是“需审批的弱防护”，不是 eBPF LSM 的等价替代。实现上有一个必须说清楚的事实：**fanotify 的权限事件（`FAN_OPEN_PERM`）不携带 open 的标志位**，无法区分读与写；直接用它做写入判定会把正常读取也拦死。目录项事件（`FAN_CREATE`/`FAN_DELETE`/`FAN_MOVED_FROM`/`FAN_MOVED_TO`）则要求 `FAN_REPORT_FID` 组并用 `open_by_handle_at` 解析路径，依赖文件系统是否支持导出句柄。

因此降级模式不是“阻断”，而是**检测 + 回滚 + 周期巡检**：

| 动作 | 机制 | 时延 |
|---|---|---|
| 覆盖写已保护文件 | `FAN_CLOSE_WRITE` 事件 → 策略判定 → 用基线副本原子回滚 | 毫秒级 |
| 新建文件 | 周期巡检发现基线中不存在的文件 → 删除 | 默认 30 秒（`TG_FAN_SCAN_SECONDS` 可调） |
| 删除文件 | 周期巡检发现基线存在但磁盘缺失 → 从基线重建 | 默认 30 秒 |
| 合法发布 | 写入 uid 在 `--publisher-uids` 且路径被有效 grant 覆盖 → 接受写入并更新基线 | 毫秒级 |

### 6.1 能力边界

| 能力 | eBPF LSM | fanotify 降级 |
|---|---|---|
| 写入发生前拦截 | 有 | **没有**：写入先落盘，再被回滚 |
| 每次 write 检查 | 有（`file_permission`） | 仅 `FAN_CLOSE_WRITE` 之后 |
| truncate/chmod/xattr | 有 | 内容回滚；元数据变化靠巡检发现 |
| rename/unlink/link | 有 | 事件不可得（需 FID）；靠巡检恢复 |
| mmap 写 | 有 | 无 |
| 打开但未关闭的写 fd | 下一次 write 即拒 | 关闭后才回滚 |
| 对抗 root 主动卸载 | 不能 | 不能 |

降级节点默认标记为不合规，需要管理员显式审批（`POST /nodes/{id}/degraded-approval`）。审批只表示“知悉并接受弱防护”，不改变上述能力差异。

### 6.2 实现要点

1. **基线**：策略首次下发时把受保护树快照到 `<state-dir>/baseline`（内容寻址 blob + 索引），保存内容哈希与权限位。
2. **标记**：对受保护树内每个目录加 mark（`FAN_MODIFY|FAN_CLOSE_WRITE|FAN_ONDIR|FAN_EVENT_ON_CHILD`）。
3. **事件处理**：`CLOSE_WRITE` 时解析 fd 路径，读取 `/proc/<pid>` 得到 uid 与 exe，走同一套 `policy.Decide`；拒绝则从基线原子回滚（临时文件 + rename），并写审计 `write.blocked`。
4. **合法写入**：uid 在 `--publisher-uids` 且 grant 覆盖该路径 → 接受并 `Take` 新内容作为基线。
5. **巡检**：默认 30 秒遍历一次受保护树，恢复被删除/被修改的文件、删除基线外新出现的文件；巡检时若该路径被有效 grant 覆盖则跳过，避免与发布冲突。
6. **防自激**：回滚产生的写事件按 pid 过滤；同一路径 500ms 内只回滚一次，避免攻击者循环触发风暴。
7. **重启**：基线持久化在磁盘索引里；mark 在每次 `Update` 时按目录重建。

### 6.3 已知限制

| 场景 | 影响 |
|---|---|
| 新建/删除文件 | 最长一个巡检周期（默认 30 秒）内可见；缩短周期会增加全树哈希开销 |
| 攻击者持有写 fd 不关闭 | 关闭前不回滚 |
| 超大文件树 | 巡检全量哈希成本随文件数线性增长，需要按站点规模调周期，或后续改增量索引 |
| 队列溢出（`FAN_Q_OVERFLOW`） | 尚未显式处理；漏掉的事件由巡检兜底 |
| 监听进程崩溃 | 重启后 mark 重建；崩溃窗口内的写入由巡检恢复 |

### 6.4 审批流与合规标记

- 节点首次以降级模式上线：`degraded=true`、`degraded_approved=false`，管理端标红，不计入合规统计。
- 管理员显式审批后为“已审批的降级节点”，仍不与 eBPF 等价；报表分开展示。
- 节点恢复 eBPF 后重新探测，审批标记失效，回到主执行层。
- 节点离线超过 3 个心跳周期（45 秒）标记 offline。

### 6.5 降级判定顺序（已实现）

1. eBPF LSM 加载并 attach 成功 → 主执行层。
2. 内核版本、`CONFIG_BPF_LSM`、LSM 列表、BTF 任一不满足，或加载/attach 失败 → fanotify。
3. fanotify 初始化也失败 → observe（只记录不阻断，不伪装成防护）。
4. 降级原因随心跳上报（`enforcer`/`caps`/`degraded` 字段），管理端可见。

端到端验证：`sudo bash test/e2e/e2e-fanotify.sh`（覆盖写回滚、新建删除、发布放行、吊销后回滚、审计验链）。

## 7. 审计链

### 7.1 记录结构

`internal/audit.Record` 已实现，字段与顺序是格式的一部分，不能随意重排：

| 字段 | 含义 |
|---|---|
| `seq` | 同一 Agent 内单调递增，从 1 开始，不允许跳号 |
| `agent` | Agent ID |
| `ts` | 事件时间（Unix 秒，Agent 时钟） |
| `kind` | 事件类型 |
| `decision` | 判定结果，如 allow/deny |
| `path` / `op` / `subject` | 路径、操作、写入主体描述 |
| `token_id` / `manifest` / `policy_rev` | 发布相关上下文 |
| `detail` | 补充说明 |
| `prev` | 前一条记录的 hash，链首为空 |
| `hash` | 本条规范化 JSON 的 SHA-256 |
| `sig` | Agent Ed25519 对本条 hash（十六进制字符串）的签名 |

事件类型至少包括：`write.blocked`、`write.allowed`、`write.observed`、`token.issued`、`token.revoked`、`token.rejected`、`policy.applied`、`enforcer.degraded`、`enforcer.error`、`agent.started`、`agent.heartbeat`、`publish.completed`、`publish.failed`。

### 7.2 哈希与签名

- 计算 hash 时把 `hash` 与 `sig` 置空，保留 `prev`，对规范化 JSON 做 SHA-256。规范化依赖 Go 的字段顺序，因此记录结构一旦发布就是冻结的格式，新增字段需要升版本。
- 签名对象是 hash 的十六进制字符串，不是原始字节。
- 单写者串行分配 seq 与 prev，保证链在线性顺序上不交错。
- 进程重启时从本地最后一条记录的 `(seq, hash)` 恢复，不能从 1 重新开始。

### 7.3 服务端链状态与缺口检测

服务端为每个 Agent 维护：

| 状态 | 用途 |
|---|---|
| `next_seq` | 期望的下一条 seq |
| `last_hash` | 已接受的最新 hash |
| `alert` | 缺口/分叉告警状态 |

校验逻辑（`internal/audit.Verifier`）：

- seq 必须等于期望值，否则 `audit: sequence gap or replay`。
- `prev` 必须等于 `last_hash`，否则链链接不匹配（分叉或重放）。
- hash 必须可复算且一致。
- 签名必须能由已登记 Agent 公钥验证。
- 每条记录通过后才推进 `(next_seq, last_hash)`，失败即告警并停止该 Agent 的推进。

### 7.4 删除、修改、伪造的检测边界

| 攻击动作 | 检测机制 | 结果 |
|---|---|---|
| 修改已有记录内容 | hash 变化，签名失效 | 可检测，告警 |
| 删除链中间某条 | 后继 seq 跳号、prev 不匹配 | 可检测，告警 |
| 删除链尾（尚未上传的部分） | 链本身仍自洽；下次上传 seq 跳号，或心跳里的 `audit_seq` 低于服务端 `next_seq`（心跳对账为设计项，当前未实现） | 在服务端已见过该 Agent 记录的前提下可检测；从未上传过的记录丢失不可恢复 |
| 删除全部本地日志并让 Agent 从 seq=1 重启 | 服务端期望的 next_seq 远大于 1，出现缺口/回退 | 可检测，告警 |
| 用窃取的 Agent 私钥伪造记录 | 签名可通过，链可自洽 | 无法区分，属于 root/密钥失守场景 |
| 删除服务端数据库中的记录 | 服务端不与自己比对，链校验仍可能通过 | 无告警；只能依赖外部导出/备份，当前未实现 |
| 整体截断且持续不心跳 | 服务端 3 个心跳周期后判离线 | 可检测（离线），但已丢失内容不可追溯 |

必须写清楚：链式哈希只能发现修改，防删除靠 seq 与服务端缺口检测。二者作用不同，缺一不可；但都依赖服务端已经观察到“正确状态”，服务端自身被攻破时保护失效。

### 7.5 本地落盘与上传

- Agent 以 JSON Lines 追加写 `<state-dir>/audit.log`，链状态在内存与磁盘间恢复；重启时读取最后一条有效记录继续，尾部损坏则拒绝启动，不会静默从 seq=1 重开。
- 按批上传到 `POST /api/v1/agent/audit`，每批最多 200 条，服务端逐条验链并返回 `ack_seq`；已确认的批次按内存队列滚动清理，本地文件保留（保留策略待确认）。
- 心跳携带 `audit_seq`；服务端按 `next_seq` 对账并在缺口/回退时告警属于设计项，当前心跳处理尚未执行这项对账，待补。
- 服务端被攻破或长期不可达时，审计只能留在本地；本地磁盘被 root 清空则记录丢失，这一点无法在现有架构内解决。

### 7.6 未做与待定

- 审计记录导出到外部 SIEM/WORM 存储：未实现。
- 服务端数据库加密、完整性保护：未实现。
- 时间来源可信性：`ts` 来自 Agent 时钟，服务端未做独立时间戳背书，时钟回拨的影响待评估。
- 审计保留与轮转：保留周期、磁盘配额未定。

## 8. 数据流

### 8.1 攻击写入

场景：webshell 通过上传漏洞尝试在受保护目录落盘。

P0（eBPF LSM 执行器）路径：

1. Web 进程执行 `open("/var/www/site/shell.php", O_WRONLY|O_CREAT)`。
2. VFS 进入 LSM hook：新建文件走 `inode_create`（查父目录 inode），打开已有文件写走 `file_open` / `file_permission`，截断走 `inode_setattr`；hook 用 `(dev, inode)` 查保护集合。
3. 当前进程没有有效 grant（内核不识别“登记进程”规则），hook 返回 `-EPERM`，open 失败，文件未创建。
4. 事件经 ringbuf 上报，`tg-agent` 写入审计链（`write.blocked`），随心跳批量上传；服务端验链后更新 `blocked_24h` 与最近审计列表。
5. 若执行器未加载成功，节点回退 observe：写入会成功；当前 observe 模拟器不拦截真实写入，也不会自动产生该次写入的审计事件。此时不能声称“已阻断”，管理端应显示 `enforcer=observe`、`degraded=true`。

P1 之后的完善项：补全 hook 边界（跨文件系统 rename、link 别名）、5.10 兼容、路径解析开销与事件限流。

无论哪个执行层，都不代表攻击者被踢出：Web 进程仍可能在内存中执行代码、发起网络请求；防护只覆盖受保护路径上的文件写入。

### 8.2 合法发布

1. 管理员在管理端创建发布申请：目标节点、发布端身份、源目录、目标目录、备注，状态 `pending`。
2. `tg-publish` 通过 mTLS 拉取 `GET /api/v1/publish/pending`，得到分配给自己且未完成的申请。
3. 发布端遍历源目录，生成文件清单（相对路径、sha256、size），计算 manifest 摘要后 `POST /api/v1/publish/{id}/manifest` 提交。
4. 服务端校验申请归属与发布端身份，要求 manifest 摘要非空；令牌的路径范围取目标节点策略的全部受保护路径。`files` 列表当前未在服务端逐项校验（待补）。签发令牌：绑定发布端主体、目标节点、策略路径范围、manifest 摘要，默认 TTL 300 秒、上限 900 秒；返回令牌、到期时间、token_id、允许路径，同时在目标节点名下记录对应的 grant。
5. 令牌由发布端在本机持有，浏览器始终不接触。令牌只在发布端进程内存中使用，不写磁盘。
6. 目标节点的 `tg-agent` 从心跳下发中拿到 grant，在用户态校验主体、路径、到期时间与撤销状态，再把 grant 展开为内核 grants map 的 `(uid, dev, inode)` 授权（代码已落地，内核验证待做）。
7. 发布端把文件写到发布端本机的 `target_dir`（P0 不实现跨机内容传输；分机部署需要 rsync/SSH/共享存储等外部通道，本文不定义）。写前重新计算文件哈希，与 manifest 条目和令牌摘要比对，不一致即中止。
8. 目标节点 enforcer 按 grant 与 `publisher_uids` 判定：由 eBPF LSM 在 hook 内放行或拒绝（代码已落地，待内核验证）；未加载时回退 observe（不阻断）。每次成功写入生成 `write.allowed` 审计，带 token_id 与 manifest 摘要。
9. 发布完成上报 `POST /api/v1/publish/{id}/complete`；服务端记录 `publish.completed`。令牌到期或被吊销后，服务端下发的 grant 随之失效，后续写入被拒。

### 8.3 吊销

1. 管理员通过管理端或 `POST /revocations` 撤销令牌、发布主体或节点，写入原因。
2. 服务端在授权与身份校验路径生效：节点撤销后该身份的 mTLS 请求被拒绝；令牌撤销后旧令牌不再被接受；发布主体撤销后不再下发 grant。已创建的发布申请不会自动取消。
3. 服务端通过 SSE（`GET /api/v1/agent/stream`）推送撤销事件，Agent 收到后立即同步；推送断线时回退到心跳响应（默认 15 秒）。
4. Agent 按 token_id / subject 删除用户态 grant；下一次心跳重建内核授权表时移除对应 `(uid, inode)` 授权，记录 `token.revoked`。
5. 之后的写入不再匹配授权，执行层返回拒绝，审计记录 `write.blocked`。
6. 残余窗口：从管理员点击撤销到 Agent 应用完成之间的写入仍可能成功；已完成的发布不回滚，也不自动删除已写入文件。

## 9. 容器与 OverlayFS（已验证）

结论先行：**在宿主侧保护 overlay 的 merged 路径，同时覆盖容器内写入**。因为 eBPF LSM 钩子作用在 overlay inode 上，而索引也来自 merged 路径，两者天然一致。`TestOverlayEnforcement` 用真实 overlay 挂载验证：写、创建、删除、rename、chmod 全部被拦；授权 copy-up 写入放行；撤权后即使底层 inode 已因 copy-up 变化仍被拦；授权窗口内新建的子树在撤权后立即受保护。

### 9.1 为什么 copy-up 没有造成漏拦

- 用户态遍历 merged 路径得到 `(dev, ino)`，写入时 `file_permission`/`inode_permission` 看到的也是 overlay 层 inode；copy-up 改变的是底层真实 inode，VFS 暴露给钩子的仍是同一个 overlay inode。
- 目录级判定用父目录 inode，覆盖“新文件”场景；`d_instantiate` 让新建子树即时入索引并继承授权。
- 因此不需要早期设想的“路径 + inode 双重匹配”补丁；那种失配只发生在**直接索引 lowerdir/upperdir 真实 inode** 的方案里。

### 9.2 仍然存在的边界

| 场景 | 影响 | 处理 |
|---|---|---|
| 直接从宿主写 upperdir/lowerdir | 绕过 merged 索引（写的是底层 inode） | 需要宿主 root，超出威胁模型；不要把 upperdir 暴露给业务 |
| 容器 volume / bind mount | 独立文件系统或独立挂载，需单独写策略路径 | 按挂载点分别加策略 |
| 容器内路径与宿主路径不同 | 命中判定基于 inode，与路径字符串无关 | 已验证不受影响；审计回填宿主视角路径 |
| 嵌套 overlay / 特殊存储驱动 | 未验证 | 上线前在目标环境用同款测试自测 |
| 容器内跑 Agent | 不支持 | 普通容器不行；K8s 用 privileged + hostPID DaemonSet |

### 9.3 命名空间与路径视角

- 写入判定不依赖路径字符串，mount namespace 差异不影响拦截。
- 路径只用于审计与排障，审计里是 Agent（宿主命名空间）视角。
- 预先存在的硬链接对 inode 保护天然覆盖（同一 inode）；bind mount 别名需要单独策略路径。

### 9.4 状态

| 项目 | 状态 |
|---|---|
| 普通目录（ext4/tmpfs）inode 匹配 | 已验证 |
| overlayfs merged 路径拦截与 copy-up | **已验证**（`TestOverlayEnforcement`） |
| 授权窗口内新建子树（overlay） | 已验证（继承 + 撤权后立即拦截） |
| 容器内路径视角 | 不影响判定；审计为宿主视角 |
| 容器内运行 Agent | 不支持（K8s 需 privileged + hostPID） |
| 部署形态 | systemd / docker compose（仅管理端）/ K8s DaemonSet，见 `deploy/README.md` |

## 10. 性能与限制

### 10.1 性能成本来源

成本点如下。第 10.1.1 节是当前构建在开发环境上的实测基线。

| 成本点 | 说明 |
|---|---|
| LSM hook 全局触发 | hook 对所有进程的文件操作触发，不只受保护路径；每次都要做 inode 查表，需保持 O(1) 级 map 查找 |
| 路径与 inode 索引 | 内核只做 inode 查表；成本主要在用户态维护索引（遍历、刷新、事件回填路径），文件数量大时需实测 |
| ringbuf 事件 | 大量拒绝事件可能淹没用户态；需要内核侧限频或用户态聚合 |
| fanotify 用户态往返 | 每次 open 权限判定都跨内核/用户态，延迟与队列深度是主要风险 |
| 审计写盘与上传 | JSON Lines 追加、签名、批量上传；事件风暴会放大磁盘与网络开销 |
| 服务端验链 | 每批记录逐条 SHA-256 与 Ed25519 校验，节点规模上升后是 CPU 主要消耗 |

### 10.1.1 实测基线（开发环境）

测量条件：WSL2 虚拟机内，Linux 6.6.87（bpf LSM 启用），16 vCPU，root；目标为 ext4 上单文件；`go test -bench`，每项 2000 次 × 2 轮，取较稳的一轮。命令：

```bash
sudo go test ./internal/enforcer -run NO_TESTS -bench . -benchtime=2000x
```

| 操作 | 无防护 | 开防护（授权有效） | 差值 |
|---|---|---|---|
| 覆盖写 32 字节文件 | 113.6 µs | 128.4 µs | +13% |
| 新建文件并写入 | 13.3 µs | 31.2 µs | +18 µs |
| 读取（open+read+close） | 2.80 µs | 4.05 µs | +1.25 µs |
| stat 已缓存路径 | 0.49 µs | 1.23 µs | +0.74 µs |

读放大来自路径解析与 `d_instantiate` 继承 hook；写/创建的主要成本仍在文件系统本身，LSM 判定是其中一部分。**这些是虚拟机上的开发环境数据，不是产品规格**：裸金属、不同内核与文件系统、不同工作负载都会明显不同，对外材料引用前必须在目标环境重测。

### 10.1.2 已知放大点

- 大量拒绝事件时 ringbuf 与审计写盘会成为瓶颈，需要内核侧限频或用户态聚合。
- 受保护目录极多时，每次策略同步的全量遍历成本随文件数线性增长；后续可改为增量索引（已用 `d_instantiate` 覆盖新建 inode，遍历仍用于基线）。

### 10.2 覆盖不到的原语

| 原语/场景 | 覆盖情况 | 说明 |
|---|---|---|
| mmap 写 | eBPF 已挂 `mmap_file` + `file_mprotect`，并已加入父目录判定；fanotify 不覆盖 | 共享映射写不经过 write 系统调用 |
| 已打开的 fd | eBPF 通过 `file_permission` 每次 write 检查，基本覆盖；fanotify 不覆盖 | 降级模式的最大缺口 |
| 硬链接别名 | `inode_link` 只检查新链接目录，源 inode 未检查（待补） | 把受保护文件硬链到未保护目录后用别名写入是已知缺口 |
| 新建子目录 | 新子目录要等下一次索引重建才进入 `protected_dirs` | 刷新窗口内其内部文件可能漏拦 |
| observe 规则 | eBPF 后端跳过，不阻断也不产生内核事件 | observe 灰度在 eBPF 节点上暂不可用，待接线 |
| `process` 写入者规则 | 未进入内核判定，受保护路径上只有 grant 放行 | 登记进程（rsync、备份）会被一并拒绝，待补 |
| NFS/CIFS 等网络文件系统 | 支持有限 | 内核 hook 与 fanotify 在网络文件系统上的行为与本地文件系统不同，不承诺阻断效果 |
| raw block device 直接写 | 不覆盖 | 属于 root 场景，绕过文件系统直接改块设备 |
| 动态内容 | 不在文件完整性语义内 | 模板渲染、反序列化、缓存生成的文件是应用运行产物；是否保护由策略决定，系统不区分“正常动态生成”与“恶意写入” |
| 预先存在的硬链接/绑定挂载别名 | 路径匹配覆盖不到，inode 匹配待验证 | 保护启用前就存在的别名是已知缺口 |
| `chattr`/`ioctl` 改文件标志 | 未覆盖 | LSM 没有对应 hook，需另行评估 |
| `io_uring` 写入路径 | 待验证 | 不同内核版本上是否经过 `file_permission` 需实测 |
| 内存中的 webshell 执行 | 不覆盖 | 只防文件写入，不防已驻留内存的代码执行 |
| 应用直接改数据库/配置 | 取决于策略是否覆盖 | 未列入保护路径的写入不受影响 |

### 10.3 其他限制

- 保护端必须 root 且不能容器化；容器内 Agent 无法保证看到宿主内核语义。
- Agent 退出或崩溃时 LSM link 随之 detach，阻断要等重启恢复；服务端 45 秒后才判离线，这段空窗没有自动兜底（待评估 pinned link）。
- 发布令牌有效期内，授权粒度是 uid：同一 uid 的所有进程都能写被授权路径。默认 `--publisher-uids 0` 意味着 root 在整个令牌窗口内可写，生产必须改成专用 uid。
- 发布流程依赖服务端在线：服务端不可达时不能签发新令牌，发布失败；已有令牌在有效期内仍可用。
- 单实例 SQLite 控制面，节点规模上限未测试。
- 不提供文件回滚、内容恢复、病毒查杀。
- 不防 root，不防物理接触，不防引导层/固件层攻击。

## 11. 版本路线

| 阶段 | 范围 | 当前状态 | 退出条件 |
|---|---|---|---|
| P0 骨架 | 三端工程结构、核心库、REST API、SQLite、mTLS enrollment、策略签发与同步、15 秒心跳、审计上报与验链、eBPF LSM 执行器（13 个 hook、inode 保护集合与授权 map、ringbuf）、observe 回退、用户态 e2e、`make build` | 核心库、控制面、两个 Agent、eBPF 执行器代码与 e2e 已落地；内核真实阻断已在 Linux 6.6 + bpf LSM 验证 | 同机 e2e + 内核验证：发布放行、webshell 写入被拒（需 bpf LSM 与 publisher uid 配置）、吊销后拒绝、审计验链 |
| P1 内核主阻断完善 | mmap 父目录、link 源 inode、单文件规则 unlink/rename、observe 接线、SSE 推送与授权确认、新建子树的内核继承（d_instantiate）、性能基准均已完成；5.10 兼容待做 | 基本完成 | 5.10 与 6.6 至少各验证一次 |
| P2 降级恢复 | fanotify 检测+回滚、基线、周期巡检、审批流、降级标红已完成；队列溢出处理与崩溃窗口恢复待补 | 基本完成 | `test/e2e/e2e-fanotify.sh` 通过 |
| P3 容器与规模化 | overlayfs/容器场景已验证（`TestOverlayEnforcement`），部署形态齐备，审计导出已实现；多节点规模、审计保留与归档、自升级签名未做 | 部分完成 | 容器边界清单见第 9.2 节，不靠推断 |
| P4 RASP | 运行期应用层防护 | Node.js 探针已实现（observe/ enforce 按路径切换、审计接入、e2e 通过）；Java/PHP 探针待做 | Node.js 场景可用；其它运行时另行评估 |

路线中的顺序不是强制的，但以下表述边界必须遵守：eBPF 执行器未在目标内核验证前，不能写“已实测拦截”；hook 矩阵未完整覆盖前，不能写“所有写入原语已覆盖”；P4 未实现前，不能出现“应用层防护”。

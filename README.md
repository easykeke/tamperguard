# TamperGuard

TamperGuard 是面向 Linux 主机的网页目录防篡改系统：内核层同步拒绝未授权写入，发布写入由内容哈希绑定的短时效令牌授权，所有写入行为进入可校验的链式审计。

先把边界写明：不防 root；当前版本没有应用层 RASP（P4 规划）；只覆盖策略列出的路径；仅支持 Linux。拿到 root 的攻击者可以停执行层、改策略、删审计，本产品只能留下事后可检测的痕迹，不做“全面防护”。

## 核心设计

| 设计 | 做什么 | 不做什么 |
|---|---|---|
| 内容哈希绑定令牌 | 令牌绑定发布端身份、目标节点、路径范围与 release manifest 的 SHA-256 摘要，TTL ≤15 分钟，可吊销。令牌只证明“谁可以写”，manifest 摘要才证明“写的是批准的内容”。 | 不判断发布内容是否安全；发布端在提交 manifest 前被控制时，摘要绑定无法阻止恶意内容。 |
| 链式审计 | 每条记录带单调 seq、prev hash、自身 hash 与 Ed25519 签名；服务端按 Agent 追踪 `(next_seq, last_hash)`，出现缺口或分叉立即告警。 | 链式哈希只能发现修改；防删除靠 seq 与服务端缺口检测；拿到 Agent 私钥的 root 可伪造。 |
| 内核同步阻断 | eBPF LSM 在 open/write/create/unlink/rename/setattr/mmap 等原语进入前拒绝未授权写入，不是事后扫描。内核不支持或加载失败时回退 observe（不阻断，也不会自动记录真实写入），并标记 degraded。 | 不覆盖网络文件系统保证、容器 OverlayFS（P3 验证）、已打开 fd 之外的任意 root 行为；P0 的 fanotify 降级尚未实现（P2）。 |

## 架构

```
                         ┌──────────────────────────────────┐
  管理员 ──HTTPS──▶      │            tg-server             │
  （REST API）           │ 策略签名 · 令牌签发 · 审计验链    │
                         │ SQLite · mTLS · 15s 心跳          │
                         └───────┬──────────────────┬───────┘
                                 │ mTLS             │ mTLS
                                 │ 策略/心跳/审计     │ 发布申请/令牌
                                 ▼                  ▼
                    ┌────────────────────┐  ┌──────────────────┐
                    │  tg-agent          │  │   tg-publish     │
                    │  eBPF LSM 执行     │  │ 计算 manifest     │
                    │  observe 回退      │  │ 复核哈希后写入    │
                    │  审计链 / 心跳      │  │ 令牌只在内存      │
                    └─────────┬──────────┘  └────────┬─────────┘
                              │ hook 决策            │ 写本机 target_dir
                              ▼                      ▼
                    ┌──────────────────────────────────────┐
                    │ Linux 内核 VFS / LSM / 文件系统        │
                    │ 受保护路径：/var/www/site 等           │
                    └──────────────────────────────────────┘
```

## 快速开始（5 分钟）

环境：Linux 或 WSL2 Ubuntu 24.04，root，内核带 bpf LSM（`cat /sys/kernel/security/lsm` 含 `bpf`）。完整步骤、策略创建、发布与吊销验证见 [docs/quickstart.md](docs/quickstart.md)。

```bash
make build

# 初始化控制面：管理员密码与两个 bootstrap token 只打印一次
sudo ./bin/tg-server init --data-dir /var/lib/tamperguard
sudo ./bin/tg-server serve --data-dir /var/lib/tamperguard

# 另开终端：注册并启动受保护节点（token 来自上一步输出）
sudo ./bin/tg-agent enroll --server https://127.0.0.1:8443 \
  --bootstrap '<protect-token>' \
  --ca /var/lib/tamperguard/keys/ca.crt \
  --state-dir /var/lib/tamperguard-agent
sudo ./bin/tg-agent run --state-dir /var/lib/tamperguard-agent
```

没有 bpf LSM 时执行器回退 observe：写入不会被拒绝，真实写入也不会自动进审计。用户态全链路可以先跑 `sudo bash test/e2e/e2e-sim.sh`；内核带 bpf LSM 的机器跑 `sudo bash test/e2e/e2e-ebpf.sh` 验证真实阻断。

## 当前状态（P0）

| 状态 | 内容 |
|---|---|
| 已验证 | 核心库单测（token/policy/audit，覆盖篡改、删除、重放、过期、错误密钥）；控制平面（REST、SQLite、mTLS 注册、策略签名下发、心跳、审计验链）；保护端与发布端全链路；**eBPF LSM 真实阻断**：14 个 hook，`TestEBPFLSMEnforcement` 全部通过（受保护写入 EPERM、读放行、新建/删除被拒、令牌授权可写、撤权后再次被拒、阻断事件上报用户态、observe 规则只记录不阻断）；**新建子树保护继承**（`d_instantiate`，`TestEBPFInheritance`）：授权窗口内新建的目录/文件在内核里即时入索引并继承授权，撤销后无需等待重新同步立即受保护；内核级端到端 `test/e2e/e2e-ebpf.sh` 全部通过（WebShell 写入被内核拒绝 → 发布端凭令牌写入成功 → 吊销后 2 秒内写入被拒 → 审计链校验通过）；**SSE 推送通道**（策略/吊销/授权变更即时下发，心跳作兜底）；**授权传播确认**（发布端等节点确认 grant 已安装再写，失败回退重试）；mmap/mprotect 父目录判定、link 源与目标 inode、单文件规则的 unlink/rename 已补齐；性能基准（design §10.1.1：覆盖写 +13%、读 +1.25µs、新建 +18µs）；GitHub Actions CI。 |
| 待完成 | `policy.writers` 里 `kind=process` 的规则尚未映射到内核 uid（当前用 agent 的 `--publisher-uids` 配置）；审计里新建文件的路径可能只回填 `inode:<号>`；5.10/6.1 内核兼容性未验证（当前只在 6.6 上验过）；eBPF 的 inode 匹配在 OverlayFS 上需要 P3 的 copy-up 映射。 |
| 未实现 | fanotify 降级与事件恢复（P2）；跨机发布内容传输；容器/OverlayFS（P3）；RASP（P4）。 |

已验证的边界：eBPF 的 inode 匹配在普通本地文件系统（ext4/xfs/tmpfs）上有效；OverlayFS 容器场景需要 P3 的 copy-up 映射，当前未验证。节点实际执行层以心跳上报的 `enforcer` 字段为准：`ebpf-lsm` 才是内核阻断，`observe` 表示没有阻断，也不会自动记录真实写入。

复现验证：

```bash
sudo go test ./internal/enforcer -run TestEBPFLSMEnforcement -v   # 内核阻断单测
sudo bash test/e2e/e2e-ebpf.sh                                    # 内核级端到端
```

## 目录结构

```
cmd/tg-server/      控制面入口（init / serve / bootstrap-token）
cmd/tg-agent/       保护端入口（enroll / run）
cmd/tg-publish/     发布端入口（run）
bpf/                eBPF C 程序（tg_protect.bpf.c）与 vmlinux.h
internal/token/     发布令牌签发、校验、路径匹配
internal/policy/    策略模型、快照签名、决策函数
internal/audit/     审计链 Writer/Verifier/文件续链
internal/server/    控制面 HTTP API、鉴权、策略与审计处理
internal/store/     SQLite 持久化
internal/agent/     保护端运行时与 mTLS 客户端
internal/enforcer/  eBPF LSM 执行器、observe 回退、ringbuf 事件
internal/publish/   发布端 manifest、令牌与写盘
internal/config/    数据目录、密钥、Agent 状态
internal/idgen/     ID 生成
web/                管理端静态资源（编译时嵌入二进制，浏览器访问 https://<server>/）
test/e2e/           用户态与内核级 e2e 脚本
docs/               design / threat-model / quickstart / api
Makefile            make build，产出 bin/ 下三个二进制
```

## 文档

- [技术设计](docs/design.md)：架构、信任模型、防护模型、内核 hook 矩阵、审计链、数据流、版本路线。
- [威胁模型](docs/threat-model.md)：资产、对手能力判定、发布通道滥用、降级与审计对抗、剩余风险、明确不做。
- [快速开始](docs/quickstart.md)：部署、策略、拦截验证、发布验证、吊销验证、常见问题。
- [HTTP API](docs/api.md)：REST 与 mTLS 接口合同。

## 许可证

Apache-2.0。

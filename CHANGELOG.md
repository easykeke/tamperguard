# 变更记录

## 0.1.0（首个完整版本）

### 防护能力

- **eBPF LSM 主执行层**：14 个 hook，写入在系统调用完成前被拒绝（`file_permission`、`file_open`、`inode_permission`、`inode_create/mkdir/unlink/rmdir/rename/link/setattr/setxattr`、`mmap_file`、`file_mprotect`、`d_instantiate`）。
- **保护继承**：授权窗口内新建的目录/文件由 `d_instantiate` 即时入索引并继承授权；撤权后立即受保护，不依赖下一次全量同步。
- **fanotify 降级层**：没有 bpf LSM 的内核上检测+回滚（覆盖写毫秒级回滚、删除/新建周期巡检恢复），队列溢出会触发重扫并上报 `enforcer.error`。
- **OverlayFS / 容器**：merged 路径拦截与 copy-up 已验证；K8s 以 privileged + hostPID DaemonSet 部署。
- **RASP**：Node.js（`fs` 包装）与 Java（`-javaagent` + SecurityManager）探针，观察优先、按路径策略热切换，事件进审计链。

### 发布与授权

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
- 跨机发布内容传输未实现（P0 的发布端写本机目标目录，跨机需外部传输通道）。
- 容器仅验证 OverlayFS merged 路径；直接写 upperdir/lowerdir 属于宿主 root 行为，不在防护范围。
- fanotify 的删除/新建恢复有一个巡检周期（默认 30 秒）的窗口。
- 规模化（Postgres、多节点压测、审计归档）未做。

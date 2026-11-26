# 贡献指南

## 环境

- Go 1.22+
- Linux 内核 ≥ 6.3 且 `lsm` 列表包含 `bpf`（用于真实内核测试）；否则用 fanotify / observe 路径
- 可选：clang + llvm + bpftool（重编 eBPF 对象）、Node.js（RASP Node 测试）、JDK 17（RASP Java 测试，需要 `-Djava.security.manager=allow`）

## 构建与测试

```bash
make build          # bin/ 下三个二进制
make test           # go test ./...
make e2e-sim        # 用户态全链路（任何 Linux + root）
make e2e-ebpf       # 内核同步阻断（需要 bpf LSM）
make e2e-fanotify   # 降级检测+回滚
make e2e-upgrade    # 签名自升级
make e2e-rasp       # Node.js 探针
make e2e-rasp-java  # Java 探针
make e2e-pull       # 跨机发布
make e2e-landlock   # Landlock 进程自保护（需要内核启用 Landlock）
make e2e-verity     # fs-verity 发布固化（内核不支持时跳过）
make bpf            # 重新生成 eBPF Go 绑定（需要 clang/bpftool）
make rasp-java      # 构建 Java 探针 jar
```

`make release VERSION=0.2.1` 产出 `dist/release/` 下的 linux amd64/arm64 包与校验和。

## 代码结构

```
cmd/            四个入口（server / agent / publish / bpfprobe）
internal/token/ 发布令牌签发与校验
internal/policy/策略模型、签名快照、决策函数
internal/audit/ 审计链
internal/store/ SQLite 持久化
internal/server/控制面 HTTP API
internal/agent/ 保护端运行时
internal/enforcer/eBPF LSM / fanotify / observe 三种执行层
internal/publish/发布端
internal/rasp/  RASP 探针 socket 服务
internal/release/发布清单签名
bpf/            eBPF C 程序
rasp/node/      Node.js 探针
rasp/java/      Java 探针
web/            管理端静态页面（编译期嵌入）
deploy/         systemd / compose / K8s
```

## 提交要求

1. 修改行为必须带测试：库代码加单测，防护/发布/审计链改动至少跑相关 e2e。
2. 不得降低防护语义：新增放行分支必须能说清"谁能用、在什么条件下、如何审计"。
3. 文档同步：改动用户可见行为时更新 `README` / `docs/`，破坏性变更写进 `CHANGELOG`。
4. 提交信息用英文祈使句，正文说明动机与验证方式。
5. 不要提交密钥、数据目录、`bin/`、`dist/`；`bpf/vmlinux.h` 由 `make vmlinux` 生成，不入库。

## 安全相关改动

涉及内核执行层、令牌、签名、审计链的 PR 需要在描述里给出威胁模型分析（攻击者能力、绕过路径、失败模式是否 fail-closed）。参见 `docs/threat-model.md` 与 `SECURITY.md`。

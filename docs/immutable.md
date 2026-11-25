# 不可变发布模式（进阶部署）

"文件防篡改"的终极形态是不给攻击者任何可写文件：站点内容打进只读镜像层，运行期文件系统只读，发布 = 构建新镜像 + 滚动替换，回滚 = 切回旧镜像。本文给出落地方式，以及在不可变环境里 TamperGuard 的定位。

## 1. 为什么不可变比"守文件"更强

| 维度 | 文件级防护（本产品主路径） | 不可变发布 |
|---|---|---|
| 攻击面 | 需要拦截所有写路径，漏一条就有风险 | 没有可写路径，RCE 也改不了文件 |
| 发布 | 受控写入（令牌 + 审计） | 新镜像 + 滚动发布 |
| 回滚 | 重新发布旧版本内容 | 切回旧镜像（秒级） |
| 适用范围 | 存量系统（IIS/传统 VM/无法容器化） | 云原生/容器化系统 |

两者不是替代：存量环境用文件级防护，容器化环境用不可变发布；TamperGuard 在不可变环境里的价值转向**发布编排、跨机分发与审计留痕**。

## 2. Kubernetes：只读根文件系统

关键配置（见 `deploy/k8s/immutable/deployment.yaml`）：

- `securityContext.readOnlyRootFilesystem: true`：容器根文件系统只读；
- 站点内容来自镜像层（构建时 COPY），不挂可写卷；
- 只把确需写的目录挂 `emptyDir`（如 `/tmp`、session、日志走 stdout）；
- 配合 `runAsNonRoot`、`allowPrivilegeEscalation: false`、`capabilities.drop: [ALL]`。

发布流程：CI 构建镜像 → 推送镜像仓库 → `kubectl set image` / GitOps 同步 → 滚动替换。回滚：`kubectl rollout undo`。

## 3. 传统 VM：只读挂载 + systemd 硬化

```ini
# /etc/systemd/system/nginx.service.d/hardening.conf
[Service]
ProtectSystem=strict
ReadOnlyPaths=/var/www
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
```

发布窗口内临时解除只读视图（或改用"发布到新目录 + 切换软链"的方式），其余时间服务进程看到的是只读树。容器外无法用 systemd 硬化的场景，用 `tg-agent landlock --allow-write ...` 给进程加沙箱（见 quickstart §15）。

## 4. 与 TamperGuard 配合的三种模式

| 模式 | 适用 | TamperGuard 角色 |
|---|---|---|
| 纯不可变 | 新建云原生系统 | 审计接入（可选）、发布审计 |
| 文件级防护 | 存量 VM / IIS / 无法容器化 | 主防护（eBPF/ACL/MIC/RASP/Landlock/verity） |
| 混合 | 迁移期、部分目录不可变 | 不可变部分交给镜像，可写部分（上传目录）交给文件级防护 |

## 5. 迁移检查清单

- [ ] 站点内容是否全部来自镜像层（不含运行时生成的可写文件）
- [ ] 上传/缓存/会话目录是否已迁出站点根（对象存储、独立卷）
- [ ] 日志是否改走 stdout（避免写站点目录）
- [ ] 镜像构建是否有可复现的流水线（内容哈希可追溯）
- [ ] 回滚演练：`kubectl rollout undo` 或镜像 tag 回切
- [ ] 发布审计：镜像 digest 与发布记录关联

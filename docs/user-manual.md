# TamperGuard 用户手册

版本：0.2.2，适用 Linux 服务器与 Windows Server，文档状态：试点可用（见 §0.3）

---

## 0. 开始之前

### 0.1 这份手册怎么用

- 想快速跑起来：看 §3～§6（安装、注册、策略、发布）。
- 准备上线评估：先看 §0.3 就绪度 与 §11 安全边界。
- 日常运维：§7 管理端、§9 平台能力、§10 运维手册。
- 排错：§10.5 故障排查表。
- 命令行速查：§12 附录。

### 0.2 产品是什么

TamperGuard 是网页防篡改系统，保护的是**站点文件的完整性**与**交付内容的真实性**，而不是"阻止所有攻击"。它由四层组成：

| 层 | 作用 | 依赖 |
|---|---|---|
| 文件层阻断 | 未授权的写入在 open/write/create/rename/delete 时被拒绝（Linux eBPF LSM；Windows 严格 ACL） | root / 管理员或 SYSTEM |
| 降级与自愈 | 内核不支持时 fanotify 检测+回滚；Windows 用内容基线自愈 | 无 |
| 运行时（RASP） | 应用进程写文件的 API 被拦截（Node.js / Java） | 应用侧加载探针 |
| Web 层校验 | 磁盘被改也保证访问者拿到可信内容（`tg-proxy` + 签名清单） | 部署代理 |

全链路行为写入**哈希链审计**，可导出、可验链。

### 0.3 就绪度：现在能不能直接用

**结论：可以用于单机/小规模试点，建议先 audit/observe 观察 1～2 周再切 enforce；不建议未经灰度直接大规模生产。**

| 能力 | 状态 | 说明 |
|---|---|---|
| Linux eBPF LSM 同步阻断 | ✅ 已验证 | 6.6 内核、14 个 hook、真实 EPERM；5.10–6.2 未实测，会自动降级 |
| fanotify 降级（检测+回滚） | ✅ 已验证 | 覆盖写毫秒级回滚，新增/删除靠巡检 |
| Windows 严格模式（DACL + 自愈） | ✅ 真机验证 | Windows 11 26100：管理员普通写入被拒、绕过修改被回滚并审计 |
| Windows MIC 完整性标签 | ⚠️ 环境相关 | 宿主不支持时启动自检自动禁用并写明原因 |
| 发布令牌 / 吊销 / 跨机 pull 发布 | ✅ e2e | 吊销 2 秒内生效（SSE+心跳兜底） |
| 审计链 / 导出 / 验链 / 保留期 | ✅ 验证 | 链断会告警，导出 JSONL/CSV |
| RASP（Node.js / Java） | ✅ e2e | PHP 等运行时未提供 |
| Web 校验代理 + 签名清单 | ✅ e2e | pull 模式发布才有签名清单 |
| fs-verity 发布固化 | ⚠️ 未真机验证 | WSL 内核未启用；需发行版内核 + verity 特性 |
| 控制面规模化 | ❌ 未做 | SQLite 单机、无 HA、无多实例；建议 < 200 节点 |
| 内核 minifilter（Windows 驱动级） | ❌ 不做 | 安装/签名成本不可接受，已用 DACL+MIC+自愈替代 |

**试点建议路径**：`observe` 模式接入 → 看审计与误报 → 单目录 `enforce` 灰度 → 全量。

---

## 1. 系统组成

| 组件 | 运行位置 | 默认端口 | 作用 |
|---|---|---|---|
| `tg-server` | 控制面（独立服务器） | 8443/TLS | 管理端、策略、令牌、审计、发布编排 |
| `tg-agent` | 被保护主机 | 出站 443 | 执行层（eBPF/fanotify/ACL）、自愈、RASP socket、自升级 |
| `tg-publish` | 发布主机 | 出站 443 | 构建清单、申请令牌、写文件 |
| `tg-proxy` | 被保护主机（可选） | 8080/80 | Web 层内容校验 |

数据目录：

| 路径 | 内容 | 保护要求 |
|---|---|---|
| `/var/lib/tamperguard` | 控制面 CA、签名密钥、SQLite、发布制品 | 仅 root 可读，异地备份 |
| `/var/lib/tamperguard-agent` | Agent 证书、策略缓存、审计链文件、基线 | 仅 root |
| `/var/lib/tamperguard-publish` | 发布端证书与缓存 | 专用账号（建议 `tgpublish`） |
| `/var/lib/tg-proxy` | 可信清单与内容寻址存储 | 代理账号 |

---

## 2. 部署前检查

### 2.1 Linux 被防护端

```bash
# 内核 6.3+、LSM 含 bpf、有 BTF 才能用主执行层
uname -r
cat /proc/cmdline | tr ' ' '\n' | grep '^lsm='
ls /sys/kernel/btf/vmlinux

# 权限与依赖
id -u          # 必须是 0（root）
command -v clang || echo "运行期不需要 clang，仅编译 eBPF 时需要"
```

### 2.2 Windows 被防护端

- Windows 10/11 或 Server 2016+，NTFS。
- Agent 以 **LocalSystem 服务**运行（`deploy/windows/install-service.ps1`），需要管理员权限安装。
- 如果站点应用池以 SYSTEM 运行，严格 ACL 对它无效；应改为专用低权账号（这也是安全基线要求）。

### 2.3 网络

| 方向 | 端口 | 用途 |
|---|---|---|
| Agent → 控制面 | TCP 8443 | mTLS 心跳、策略、审计、发布、SSE |
| 发布端 → 控制面 | TCP 8443 | mTLS 申请令牌、拉发布任务 |
| 管理员浏览器 → 控制面 | TCP 8443 | 管理端 |
| Web 校验代理 → 控制面 | TCP 8443 | 拉签名清单与制品（pull 模式） |
| 发布端 → 目标节点 | 无 | pull 模式不需要；local 模式发布端与目标同机 |

### 2.4 能力探测（推荐先跑一遍）

```bash
sudo ./tg-agent probe --state-dir /var/lib/tamperguard-agent
```

输出示例与含义：

```
os            : linux
kernel        : 6.6.87.2-microsoft-standard-WSL2
lsm active    : capability,landlock,yama,apparmor,bpf (bpf=true)
kernel BTF    : true
landlock      : ABI v3 (process self-protection available)
fs-verity     : unavailable: fs-verity: not supported by this kernel or filesystem
selected      : ebpf-lsm (degraded=false)
```

`selected` 是最终执行层：`ebpf-lsm`（同步阻断）> `fanotify`（检测+回滚）> `observe`（只记录）。

---

## 3. 安装控制面

### 3.1 获取二进制

```bash
# 方式 A：发行包
tar -xzf tamperguard_0.2.2_linux_amd64.tar.gz
sudo install -m 0755 tg-server tg-agent tg-publish tg-proxy /usr/local/bin/

# 方式 B：源码
git clone https://github.com/easykeke/tamperguard.git && cd tamperguard && make build
```

### 3.2 初始化（只做一次）

```bash
sudo tg-server init --data-dir /var/lib/tamperguard --listen :8443
```

输出里**必须记录**：

- `Admin password`：管理端首次登录密码（只显示一次）；
- `Bootstrap token (protect)` / `Bootstrap token (publish)`：一次性注册令牌；
- 数据目录下生成 `keys/ca.crt`、CA 私钥、策略/令牌/发布签名密钥。

### 3.3 启动服务

```bash
sudo cp deploy/systemd/tamperguard-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tamperguard-server
sudo journalctl -u tamperguard-server -n 20
curl -k https://127.0.0.1:8443/healthz     # {"status":"ok","version":"0.2.2"}
```

浏览器打开 `https://<控制面IP>:8443/`，用 `admin` + 初始密码登录。**先改密码**（管理端右上角）。

> TLS 使用自签名证书，浏览器会提示不受信任；内网可导入 `keys/ca.crt` 或前置反向代理换成正式证书。

### 3.4 关键配置（`/var/lib/tamperguard/server.json`）

| 键 | 默认 | 说明 |
|---|---|---|
| `heartbeat_seconds` | 15 | 心跳周期，也决定吊销/策略生效上限 |
| `token_ttl_seconds` | 300 | 发布令牌有效期 |
| `max_token_ttl_seconds` | 900 | 令牌 TTL 上限 |
| `audit_retention_days` | 0 | 0 = 永久保留；>0 按天清理（验链从现存最早记录开始） |

修改后 `sudo systemctl restart tamperguard-server`。

---

## 4. 注册被防护端与发布端

### 4.1 被防护端（Linux）

```bash
sudo tg-agent enroll \
  --server https://<控制面IP>:8443 \
  --bootstrap '<protect bootstrap token>' \
  --ca /tmp/ca.crt \
  --state-dir /var/lib/tamperguard-agent \
  --role protect \
  --publisher-uids 0
```

- `--publisher-uids`：允许消费发布令牌的**系统 uid**。`0` 仅用于同机 root 发布端/演示；生产应填专用发布账号 uid（如 `1001`）。
- Windows 用 `--publisher-sids 'CONTOSO\svc-publisher'`（账号名或 SID）。

安装服务：

```bash
sudo cp deploy/systemd/tamperguard-agent.service /etc/systemd/system/
sudo systemctl enable --now tamperguard-agent
```

### 4.2 发布端

注册（注意：发布端也用 `tg-agent enroll`，只是 `--role publish`）：

```bash
sudo -u tgpublish tg-agent enroll \
  --server https://<控制面IP>:8443 \
  --bootstrap '<publish bootstrap token>' \
  --ca /tmp/ca.crt \
  --state-dir /var/lib/tamperguard-publish \
  --role publish
```

启动发布服务：

```bash
sudo -u tgpublish tg-publish run --state-dir /var/lib/tamperguard-publish
```

（发布端账号需要目标目录的写权限；`deploy/systemd/tamperguard-publish.service` 已使用 `User=tgpublish`。）

### 4.3 确认上线

管理端「节点」页应看到 protect/publish 两类节点；被保护节点的「执行层」应为 `ebpf-lsm`（或预期的降级层）。CLI 方式：

```bash
curl -sk -b cookies https://<IP>:8443/api/v1/nodes
```

---

## 5. 策略

### 5.1 概念

一条策略 = 若干**路径规则** + 若干**写入主体** + 分配节点。

```json
{
  "name": "www-prod",
  "paths": [
    {"path": "/var/www/site", "recursive": true, "mode": "enforce"},
    {"path": "/var/www/uploads", "recursive": true, "mode": "observe"}
  ],
  "writers": [
    {"kind": "publisher", "id": "pub_xxx"},
    {"kind": "process", "exe_path": "/usr/bin/rsync", "uid": 1001}
  ],
  "assign_nodes": ["n_xxx"]
}
```

| 字段 | 说明 |
|---|---|
| `mode: enforce` | 未授权写入被拒绝 |
| `mode: observe` | 只记录放行（用于灰度、排误报） |
| `recursive` | 是否递归覆盖子目录 |
| `writers.publisher` | 允许发布端在令牌窗口内写 |
| `writers.process` | 允许指定进程（exe + uid）写 |
| Windows 路径 | 写 `C:\inetpub\wwwroot`，内部规范化为 `C:/inetpub/wwwroot`，大小写不敏感 |

### 5.2 创建与变更

管理端「策略」页新建/编辑；或 API：

```bash
curl -sk -b cookies -H 'Content-Type: application/json' \
  -d @policy.json https://<IP>:8443/api/v1/policies
```

保存后策略版本 +1，Agent 在下一次心跳/SSE 推送时生效（通常秒级；离线节点恢复后生效）。

### 5.3 灰度建议

1. 先对目标目录建 `observe` 规则，观察 1～2 周（审计中会出现 `write.observed`）；
2. 确认业务写路径都在 `writers` 里（发布端、备份、日志轮转等）；
3. 单目录改 `enforce`，观察 24 小时；
4. 再扩到全量。

---

## 6. 发布（更新站点）

### 6.1 两种模式

| 模式 | 适用 | 流程 |
|---|---|---|
| `local` | 发布端与被保护机同机（或有共享写权限） | 发布端构建清单 → 申请令牌 → 校验每个文件哈希 → 原子写入目标目录 |
| `pull` | 发布端与被保护机分离（跨机） | 发布端上传签名清单与制品到控制面 → 目标节点拉取、复核哈希、本机写入 |

### 6.2 操作步骤（local）

1. 管理端「发布」页新建发布请求：节点、发布端、源目录（如 `/srv/release`）、目标目录（如 `/var/www/site`）；
2. 发布端进程（`tg-publish run`）在 15 秒内轮询到任务：
   - 生成清单（SHA-256，拒绝符号链接）；
   - 提交清单换令牌（TTL ≤ 15 分钟，绑定路径与清单摘要）；
   - 等目标节点确认 grant 已安装；
   - 逐文件复核哈希后原子写入（临时文件 + rename）；
3. 完成状态变为 `done`；管理端可看到令牌、耗时、文件数。

### 6.3 跨机发布（pull）

创建请求时加 `"delivery":"pull"`：

1. 发布端上传制品（`POST /publish/{id}/artifact`）并提交清单；
2. 目标节点 Agent 自动拉取，重算清单摘要与每个文件哈希，原子落盘；
3. 任一哈希不符 → 请求标记 `failed`，文件不落盘（已实测）。

### 6.4 回滚与吊销

- **回滚**：用上一版内容重新发布一次；或吊销令牌后按修复流程重发。
- **吊销**：

```bash
curl -sk -b cookies -H 'Content-Type: application/json' \
  -d '{"kind":"token","value":"tok_xxx","reason":"incident"}' \
  https://<IP>:8443/api/v1/revocations
```

  SSE 即时下发；断线节点靠心跳（≤15 秒）。实测写入在 2 秒内被拒。

### 6.5 密钥与令牌安全

- 令牌只在发布端内存中，**不落盘**；
- 发布端私钥在 `/var/lib/tamperguard-publish`，仅发布账号可读；
- 不要用 root 运行发布端（否则等于放开 root 写权限窗口）。

---

## 7. 管理端使用

地址：`https://<控制面IP>:8443/`

| 页面 | 能做什么 |
|---|---|
| 总览 | 节点数/在线数/降级节点/24 小时拦截数/活跃令牌/审计链告警 |
| 节点 | 查看执行层、degraded 原因、最近事件；审批降级；吊销节点身份 |
| 策略 | 新建/编辑/删除；路径、模式、写入主体、分配节点 |
| 发布 | 新建发布请求（local/pull）、查看状态、取消 |
| 审计 | 按节点/类型/时间过滤；导出 JSONL/CSV；一键验链 |
| 吊销 | 按令牌/主体/节点吊销，立即生效 |

常见操作：

- **改密码**：右上角账号菜单；
- **确认节点是否真的在阻断**：节点页「执行层」必须是 `ebpf-lsm` 或 `windows-acl`；`observe` 表示只记录；
- **降级审批**：节点上报 degraded 后，需要管理员在节点页显式批准才会被接受（防止静默降级）。

---

## 8. 审计与证据

- 每条记录包含：序号、前一条哈希、自身哈希、Ed25519 签名、节点、类型、路径、主体、时间。
- 服务端按 Agent 维护 `next_seq/last_hash`，发现缺口或分叉会告警。
- 常见类型：`write.blocked`、`write.allowed`、`write.observed`、`token.issued/revoked`、`policy.applied`、`publish.completed/failed`、`rasp.observed/blocked`、`tamper.restored`、`enforcer.error`、`agent.*`。

导出：

```bash
curl -sk -b cookies \
  'https://<IP>:8443/api/v1/audit/export?node_id=n_xxx&format=csv' -o audit.csv
```

验链：

```bash
curl -sk -b cookies 'https://<IP>:8443/api/v1/audit/verify?node_id=n_xxx'
# {"ok":true,"records":1234,"from_seq":1}
```

保留期：`audit_retention_days>0` 时按天清理；清理后验链从现存最早记录开始，不误报。

---

## 9. 平台专属能力

### 9.1 RASP（Node.js）

```bash
NODE_OPTIONS="--require /usr/local/lib/tamperguard/tamperguard.js" \
TG_RASP_SOCKET=/var/lib/tamperguard-agent/rasp.sock \
node app.js
```

### 9.2 RASP（Java，JDK 16–21）

```bash
java -Djava.security.manager=allow \
  -javaagent:/opt/tamperguard/dist/tg-rasp.jar=socket=/var/lib/tamperguard-agent/rasp.sock \
  -jar app.jar
```

策略里路径设为 `mode: observe` 只记录；改 `enforce` 后同一进程的下一次写入被阻断（无需重启）。

### 9.3 Landlock 进程自保护（Linux）

把 Web 进程关进只读沙箱，即使被 RCE 也写不了站点：

```bash
sudo tg-agent landlock --allow-write /var/lib/php/sessions --allow-write /var/log/php \
  -- /usr/sbin/php-fpm --nodaemonize
```

默认放行 `/tmp`、`/var/tmp`、`/dev/shm` 与 `/dev/null` 等设备文件；`--no-defaults` 关闭默认。`--check` 查看 ABI。

### 9.4 fs-verity 发布固化（可选）

```bash
sudo tg-publish run --state-dir /var/lib/tamperguard-publish --verity
sudo tg-agent verity enable|digest|check /var/www/site/index.html
```

需要内核 `CONFIG_FS_VERITY` 且文件系统带 `verity` 特性；启用后文件只读、读取校验。

### 9.5 Windows 严格模式

安装（管理员 PowerShell）：

```powershell
# 1. 安装加固服务（LocalSystem、失败自动重启、服务 ACL 只允许 SYSTEM 停止）
.\deploy\windows\install-service.ps1

# 2. 注册
& 'C:\Program Files\TamperGuard\tg-agent.exe' enroll `
  --server https://<控制面IP>:8443 --bootstrap '<protect token>' `
  --ca C:\ca.crt --state-dir 'C:\ProgramData\TamperGuard' `
  --role protect --publisher-sids 'CONTOSO\svc-publisher'

# 3. 启动
Start-Service TamperGuardAgent
```

- 默认严格模式：DACL 不给 Administrators 写权限 + Self-heal 基线 +（宿主支持时）MIC System 标签；
- 自愈周期：环境变量 `TG_WIN_SCAN_SECONDS`（默认 30，最小 2）；
- 退出/维护：`tg-agent unlock --state-dir 'C:\ProgramData\TamperGuard'`；
- 想保留管理员写权限（不推荐）：`run --windows-allow-admins`；
- MIC 在不支持的宿主会自动禁用，capability 里会写明原因。

### 9.6 Web 层校验代理（强烈推荐）

```bash
# 签名清单模式（推荐）：从控制面拉取签名清单与制品
tg-proxy --root /var/www/site --state /var/lib/tg-proxy \
  --sync --agent-state /var/lib/tamperguard-agent --snapshot-only

tg-proxy --root /var/www/site --state /var/lib/tg-proxy \
  --listen 0.0.0.0:8080 --no-snapshot --require-signed \
  --agent-state /var/lib/tamperguard-agent \
  --upstream http://127.0.0.1:8000 --audit /var/log/tg-proxy/tamper.jsonl
```

效果：静态请求逐次校验，磁盘被篡改时返回可信副本（响应头 `X-TG-Integrity: restored`）并写 `web.tamper-detected`；清单外新增文件返回 404；动态请求转发 upstream。

Windows 部署：IIS 改监听 8080，`tg-proxy.exe` 监听 80/443（或以服务方式运行）。

---

## 10. 运维手册

### 10.1 日常巡检

- 总览：节点在线数、降级节点数、审计链告警必须为 0；
- 节点页：执行层是否意外降级；
- 审计：`enforcer.error`、`tamper.restored`、`publish.failed` 是否有异常；
- 磁盘：`/var/lib/tamperguard*` 与基线目录容量（fanotify/Windows 自愈基线会占空间）。

### 10.2 升级

```bash
# 控制面：发布一个新 Agent 版本（签名清单）
sudo tg-server release --data-dir /var/lib/tamperguard \
  --binary ./tg-agent --version 0.2.3 --os linux --arch amd64

# Agent 自动检查（默认 6 小时）并校验签名+哈希后原子替换，退出 0 等 systemd 拉起
sudo journalctl -u tamperguard-agent | grep upgraded
```

关闭自动升级：`tg-agent run --auto-upgrade=false`。

### 10.3 备份与恢复

- **必须备份**：控制面 `/var/lib/tamperguard`（含 CA、策略/审计密钥、数据库）、Agent 状态目录、发布端状态目录。
- 审计库可按天导出 JSONL 归档。
- 恢复：还原目录后启动服务；Agent 证书不匹配时需重新注册。

### 10.4 卸载

```bash
sudo systemctl disable --now tamperguard-agent
# Windows：先 unlock 恢复权限，再停止并删除服务
#   tg-agent unlock --state-dir C:\ProgramData\TamperGuard
#   sc.exe delete TamperGuardAgent
sudo rm -rf /var/lib/tamperguard-agent
```

控制面卸载前先导出审计；删除 `/var/lib/tamperguard` 会同时删除 CA，所有 Agent 证书失效。

### 10.5 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 节点执行层 `observe` | 内核不满足（无 bpf LSM/BTF）或加载失败 | `tg-agent probe` 看原因；适配内核或接受降级 |
| 节点 `degraded=true` | 使用了 fanotify/observe | 管理端确认并审批，或修内核 |
| 发布写入 `EPERM` 但策略正确 | grant 还未传播到节点 | 发布端会自动重试；确认节点在线、`--publisher-uids` 含发布账号 uid |
| 发布令牌过期 | TTL ≤ 15 分钟 | 重新创建发布请求 |
| 审计链告警 | 序号缺口/分叉/节点重建 | 用 `/audit/state` 定位；导出证据；必要时重建节点 |
| 吊销不生效 | SSE 断线且心跳未到 | 最多等 15 秒；检查网络 |
| Windows 管理员仍能写 | 应用池以 SYSTEM 运行 / 宿主不支持 MIC | 降应用池权限；接受 DACL+自愈语义 |
| Windows 服务无法启动 | 权限不足或 exe 被低完整性标记 | 用 `install-service.ps1` 安装（SYSTEM 运行）；不要把 exe 放在沙箱目录 |
| `tg-proxy` 返回 404 | 请求路径不在签名清单 | 重新发布/同步；确认 `--sync` 成功 |
| `tg-proxy` 启动失败 `signature does not verify` | 清单被改或公钥不匹配 | 重新 `--sync`；确认 agent state 与节点一致 |
| `--require-signed` 拒绝启动 | 用了本地快照 | 先 `--sync`，或去掉 `--require-signed`（不推荐） |
| RASP 不生效 | 探针未加载/socket 路径不一致 | 检查 `NODE_OPTIONS` / `-javaagent` 与 `TG_RASP_SOCKET` |
| Java 探针无拦截 | JDK 版本超出 16–21 或未加 `-Djava.security.manager=allow` | 看应用启动日志里的探针警告 |
| fs-verity `not supported` | 内核/文件系统不支持 | 换发行版内核或跳过该层 |
| 管理端证书告警 | 自签名证书 | 导入 CA 到受信任根，或前置正式证书反代 |

---

## 11. 安全边界（务必阅读）

- **不防 root / Windows 管理员主动对抗**：他们可以停 Agent、卸载 BPF、改策略、删审计；产品只保证留下可检测的痕迹。Windows 上管理员"随手改"会被 ACL 拒绝，绕过（取得所有权/改标签）会被自愈回滚并审计，但无法阻止"先改后读"的短窗口。
- **fanotify/Windows 自愈是检测+回滚**，存在一个巡检周期的时间窗（Linux 默认 30 秒、Windows 组合了事件驱动后通常亚秒级，但以实测为准）。
- **RASP 只覆盖 Node.js 与 Java**；PHP 等运行时没有应用层探针。
- **文件保护只覆盖策略列出的路径**；上传目录等业务可写路径不要放进 enforce 规则。
- **Web 校验只覆盖经代理的静态请求**；绕过代理直连后端不在范围内。
- **不防网络文件系统（NFS/CIFS）**；容器需用 OverlayFS 场景，已验证 merged 路径。
- **不是合规认证产品**：可用于等保"网页防篡改"条款的技术支撑，但审计材料需结合你的运维流程。
- **密钥即权限**：控制面 CA/签名密钥、发布端私钥泄露等于防护失效，按最高等级保护并异地备份。

---

## 12. 附录

### 12.1 命令行速查

```text
tg-server init [--data-dir DIR] [--listen ADDR]
tg-server serve [--data-dir DIR]
tg-server bootstrap-token [--data-dir DIR] [--role protect|publish]
tg-server release --data-dir DIR --binary PATH --version V [--os linux] [--arch amd64]

tg-agent enroll --server URL --bootstrap TOKEN --ca FILE [--role protect|publish]
                 [--state-dir DIR] [--publisher-uids 1001] [--publisher-sids 'DOMAIN\acct']
tg-agent run    [--state-dir DIR] [--enforcer auto|ebpf|fanotify|windows-acl|observe]
                 [--auto-upgrade=true] [--upgrade-interval 6h] [--rasp=true]
                 [--rasp-socket PATH] [--integrity-level system|high|medium|off]
                 [--windows-allow-admins] [--verity]
tg-agent probe  [--state-dir DIR]
tg-agent landlock [--allow-write DIRS] [--no-defaults] [--check] -- CMD [ARGS...]
tg-agent verity enable|digest|check PATH
tg-agent unlock [--state-dir DIR]

tg-publish run [--state-dir DIR] [--verity]

tg-proxy --root DIR --state DIR [--listen ADDR] [--upstream URL] [--audit FILE]
          [--snapshot-only] [--no-snapshot] [--sync --agent-state DIR] [--require-signed]
```

### 12.2 常用 API

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/healthz` | 健康与版本 |
| POST | `/auth/login` | 管理端登录 |
| GET | `/nodes` | 节点列表 |
| POST | `/policies` | 创建策略 |
| POST | `/publish-requests` | 创建发布请求（`delivery: local\|pull`） |
| POST | `/revocations` | 吊销令牌/主体/节点 |
| GET | `/audit` / `/audit/export` / `/audit/verify` | 审计查询/导出/验链 |
| POST | `/agent/heartbeat` | Agent 心跳（mTLS） |
| GET | `/agent/manifest` | 签名站点清单（pull 发布，mTLS） |
| GET | `/agent/upgrade` | 自升级检查（mTLS） |

完整合同见 `docs/api.md`。

### 12.3 环境变量

| 变量 | 作用 |
|---|---|
| `TG_RASP_SOCKET` / `TG_RASP_APP` | RASP 探针 socket 与上报的进程名 |
| `TG_WIN_SCAN_SECONDS` | Windows 自愈扫描周期（默认 30，最小 2） |
| `TG_FAN_SCAN_SECONDS` | fanotify 巡检周期（默认 30） |
| `TG_FAN_DEBUG` | fanotify 调试日志 |

### 12.4 版本与支持

- 当前版本：0.2.2，仓库：https://github.com/easykeke/tamperguard
- 问题反馈：仓库 Issues；安全问题请走 `SECURITY.md` 的私有渠道。
- 兼容性矩阵：`docs/compat.md`；已知限制：`CHANGELOG.md` 的"已知限制"章节。

# TamperGuard 快速开始（P0）

本文从空环境走一遍完整部署：能力探测、初始化控制面、注册节点、创建策略、验证内核拦截、发布与吊销、审计导出、签名自升级、RASP 接入。命令在 WSL2 Ubuntu 24.04 上可直接执行，发行版 Linux 同理。

先看三条前提：

- 保护端必须宿主机 root，不能跑在普通容器里；K8s 场景用 privileged + hostPID 的 DaemonSet（见 `deploy/k8s/`）。
- 执行层优先级：eBPF LSM（写入前同步阻断）→ fanotify（检测+回滚）→ observe（只记录，不伪装成防护）。用 `tg-agent probe` 查看本机实际会选哪一层，内核与文件系统兼容性见 `docs/compat.md`。
- RASP 只覆盖 Node.js 与 Java（JDK 16–21），其它运行时没有应用层探针。

命令里的 `tg-server`、`tg-agent`、`tg-publish` 均指 `make build` 产出的 `bin/` 下二进制。可消费发布令牌的 uid 由 `tg-agent enroll --publisher-uids` 配置，默认 `0`（演示方便），生产必须改成发布端专用 uid，具体见 6.3 与 9.2。

## 1. 环境准备

### 1.1 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y golang-go make clang llvm pkg-config libbpf-dev curl jq
go version
```

要求 Go 1.22.x（Ubuntu 24.04 的 `golang-go` 即为 1.22）。`clang`、`llvm`、`libbpf-dev` 在 P0 编译阶段可能用不到，但 eBPF 执行器构建与后续验证需要，一并安装。

`bpftool` 只用于排查，P0 编译不依赖它：

```bash
# 能装就装；WSL 上发行版工具包常与内核版本不匹配，装不上不影响 P0
sudo apt-get install -y linux-tools-common linux-tools-generic 2>/dev/null || true
command -v bpftool && bpftool version | head -2 || echo "bpftool 不可用，跳过"
```

### 1.2 内核能力自检

```bash
uname -r
cat /sys/kernel/security/lsm
ls -l /sys/kernel/btf/vmlinux
```

判断标准：

| 检查项 | 期望 | 不满足时的后果 |
|---|---|---|
| 内核版本 ≥ 5.10（推荐 6.1+） | `uname -r` | 只能回退 observe |
| LSM 列表包含 `bpf` | `cat /sys/kernel/security/lsm` 输出里有 `bpf` 一项 | 只能回退 observe |
| BTF 存在 | `/sys/kernel/btf/vmlinux` 可读 | CO-RE 程序无法加载，回退 observe |
| 特权 | root | 加载失败，回退 observe |

`/sys/kernel/security/lsm` 不存在时先挂 securityfs：

```bash
sudo mount -t securityfs securityfs /sys/kernel/security
cat /sys/kernel/security/lsm
```

WSL2 的内核由 `.wslconfig` 或发行版自带内核决定，不同机器结果不同。没有 `bpf` 时不要继续期待“写入被拒”，按第 7 节的 observe 路径验证用户态链路即可。

## 2. 编译

```bash
cd /mnt/e/AI-learn/Tamper-proof    # 换成你的仓库路径

# 首次构建会下载 Go 模块；网络受限时先设代理
go env -w GOPROXY=https://goproxy.cn,direct

make build
ls -l bin/
```

期望产出 `bin/tg-server`、`bin/tg-agent`、`bin/tg-publish`。依赖版本已固定在 `go.mod`/`go.sum`（含 `modernc.org/sqlite`、`cilium/ebpf` 等），后续构建不需要再解析版本。

## 3. 初始化控制面

```bash
sudo ./bin/tg-server init --data-dir /var/lib/tamperguard
```

输出包含（只打印一次，不写明文文件）：

- 管理员用户名 `admin`
- 管理员密码
- protect 角色的 bootstrap token（注册保护节点用）
- publish 角色的 bootstrap token（注册发布端用）

立即把密码与两个 token 存进密码管理器。初始化会做这些事：

| 产物 | 说明 |
|---|---|
| `/var/lib/tamperguard/server.json` | 控制面配置（0600） |
| `/var/lib/tamperguard/keys/ca.crt`、`ca.key` | 产品 CA（私钥 0600） |
| `keys/server.crt`、`server.key` | 控制面 TLS 证书（SAN 含 localhost、主机名、tg-server、127.0.0.1、::1） |
| `keys/token-signing.key`、`policy-signing.key` | 令牌与策略签名私钥（0600） |
| `keys/token-signing.pub`、`policy-signing.pub` | 对应公钥，enrollment 时分发给 Agent |
| `/var/lib/tamperguard/tamperguard.db` | SQLite（WAL） |

注意事项：

- `server.json` 已存在时 `init` 会拒绝执行。重跑必须删数据目录，这会让所有已注册 Agent 的证书与审计链参照全部失效，只能在测试环境做。
- 服务端证书的 SAN 只有 `localhost`、初始化时的主机名、`tg-server`、`127.0.0.1`、`::1`。用别的 IP 访问会 TLS 校验失败，要么用主机名访问，要么用第 5.1 节的 `--ca-fingerprint`。生产应扩展证书 SAN，当前属待确认改动。
- 默认监听 `:8443`，可用 `--listen` 改。

## 4. 启动控制面

### 4.1 前台启动（先验证）

```bash
sudo ./bin/tg-server serve --data-dir /var/lib/tamperguard
```

另开终端验证：

```bash
curl -sS --cacert /var/lib/tamperguard/keys/ca.crt https://127.0.0.1:8443/healthz
```

期望 `{"status":"ok","version":"0.2.4",...}`。

### 4.2 systemd 托管（长期运行）

```bash
sudo install -m 0755 bin/tg-server /usr/local/bin/
sudo tee /etc/systemd/system/tamperguard-server.service >/dev/null <<'EOF'
[Unit]
Description=TamperGuard control plane
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tg-server serve --data-dir /var/lib/tamperguard
Restart=always
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tamperguard-server
sudo systemctl status tamperguard-server --no-pager
```

WSL2 需要 `/etc/wsl.conf` 里 `[boot] systemd=true` 并执行 `wsl --shutdown` 后重启发行版，systemd 才可用；没有 systemd 就继续用前台进程。

管理页面说明：当前构建未把管理端静态资源嵌入二进制，直接访问 `https://127.0.0.1:8443/` 会返回 `admin UI not bundled in this build`。P0 的验证全部走 REST API，见第 5 节。管理页面打包落地后，入口仍是同一个地址。

## 5. 登录管理 API

```bash
CA=/var/lib/tamperguard/keys/ca.crt
BASE=https://127.0.0.1:8443
ADMIN_PW='<init 输出的管理员密码>'

curl -sS --cacert "$CA" -c /tmp/tg.cookies \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" \
  "$BASE/api/v1/auth/login"
```

期望返回 `{"username":"admin","role":"admin"}`，Cookie 存到 `/tmp/tg.cookies`。后续所有管理请求都要带 `-b /tmp/tg.cookies`，变更类请求必须带 `Content-Type: application/json`，否则服务端按 CSRF 防护拒绝。

## 6. 注册并启动两个 Agent

### 6.1 注册受保护节点

```bash
sudo install -m 0755 bin/tg-agent /usr/local/bin/
sudo /usr/local/bin/tg-agent enroll \
  --server https://127.0.0.1:8443 \
  --bootstrap '<init 输出的 protect token>' \
  --ca /var/lib/tamperguard/keys/ca.crt \
  --role protect \
  --state-dir /var/lib/tamperguard-agent \
  --poll 5 \
  --publisher-uids 0    # 演示：root 可消费发布 grant；生产改成发布端专用 uid
```

说明：

- `--state-dir` 与服务器数据目录分开，避免 `agent.json` 与 `server.json` 混放；生产环境在各自主机上可以用默认 `/var/lib/tamperguard`。
- `--poll 5` 只在演示时用，把心跳从默认 15 秒缩短到 5 秒；生产保持默认。
- `--publisher-uids 0` 表示允许 root 消费发布 grant（演示方便）。生产改成发布端专用非 root uid，可逗号分隔多个；该值保存在 Agent 状态里，改后重新 enroll。
- 必须提供 `--ca` 或 `--ca-fingerprint`，enroll 不接受“信任任何证书”。跨机部署时把 `ca.crt` 通过安全通道复制过去。
- bootstrap token 一次性使用；需要新节点时用 `sudo ./bin/tg-server bootstrap-token --data-dir /var/lib/tamperguard --role protect` 再签一个。

### 6.2 注册发布端

生产环境发布端是另一台机器。P0 的端到端流程要求发布端与被保护节点同机（`tg-publish` 直接写本机 `target_dir`，跨机传输没有实现）。演示时用第二个 state-dir：

```bash
sudo /usr/local/bin/tg-agent enroll \
  --server https://127.0.0.1:8443 \
  --bootstrap '<init 输出的 publish token>' \
  --ca /var/lib/tamperguard/keys/ca.crt \
  --role publish \
  --state-dir /var/lib/tamperguard-publish \
  --poll 5
```

### 6.3 systemd 托管

```bash
sudo tee /etc/systemd/system/tamperguard-agent.service >/dev/null <<'EOF'
[Unit]
Description=TamperGuard protection agent
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tg-agent run --state-dir /var/lib/tamperguard-agent
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/tamperguard-publish.service >/dev/null <<'EOF'
[Unit]
Description=TamperGuard release agent
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tg-publish run --state-dir /var/lib/tamperguard-publish
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now tamperguard-agent tamperguard-publish
```

`tg-publish` 只接受 role 为 publish 的身份；拿 protect 状态的目录去跑会直接报错。

上面的演示 unit 用 root 运行发布端，配合 protect 节点 enroll 时的 `--publisher-uids 0`，发布写入会被内核放行。生产环境应让 `tg-publish` 以专用非 root 用户运行，在 protect 节点重新 enroll 时用 `--publisher-uids` 指定该 uid，并让该用户对 `target_dir` 有写权限。不要把 root 长期放进发布白名单，否则等于把整台主机的 root 写入都放行。`--publisher-uids` 的值保存在 Agent 状态里，改完要重新 enroll 或重新写 `agent.json`，以 `tg-agent enroll --help` 为准。

### 6.4 确认节点已注册

```bash
CA=/var/lib/tamperguard/keys/ca.crt
BASE=https://127.0.0.1:8443

curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/nodes" | jq .
PROT_ID=$(curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/nodes" \
  | jq -r '.[] | select(.role=="protect") | .id' | head -1)
PUB_ID=$(curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/nodes" \
  | jq -r '.[] | select(.role=="publish") | .id' | head -1)
echo "PROT_ID=$PROT_ID PUB_ID=$PUB_ID"
```

## 7. 创建保护策略

### 7.1 先准备受保护目录

策略生效后再建初始文件会按受保护路径处理，所以先把演示目录和初始文件准备好：

```bash
sudo mkdir -p /var/www/site
printf '<html>v0</html>\n' | sudo tee /var/www/site/index.html
```

### 7.2 创建策略

`writers` 需要包含发布端身份 `{"kind":"publisher","id":"pub_..."}`：用户态 `Decide` 与 e2e/sim 路径依赖它，eBPF 内核授权则由 grant 与 `--publisher-uids` 决定，两边保持一致可以避免切换执行层后行为变化。`target_dir` 必须落在策略路径内。

```bash
cat > /tmp/tg-policy.json <<EOF
{
  "name": "webroot",
  "paths": [
    {"path": "/var/www/site", "recursive": true, "mode": "enforce"}
  ],
  "writers": [
    {"kind": "publisher", "id": "$PUB_ID"}
  ],
  "assign_nodes": ["$PROT_ID"]
}
EOF

curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  -H 'Content-Type: application/json' \
  --data @/tmp/tg-policy.json \
  "$BASE/api/v1/policies" | jq .
```

### 7.3 等待 Agent 同步

```bash
sleep 10
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/nodes/$PROT_ID" \
  | jq '.node | {enforcer, degraded, degraded_approved, policy_id, policy_version, policy_digest}'
```

`policy_digest` 非空说明已同步。`enforcer` 是 `ebpf-lsm` 表示内核执行器已加载；是 `observe` 表示没有内核阻断，真实写入也不会自动产生审计记录（按第 11 节排查）。

## 8. 验证 A：webshell 写入被拒

本节需要内核支持 bpf LSM 且 eBPF 执行器已加载（`enforcer=ebpf-lsm`）。可以先做一次执行器自检，它会 attach 真实 LSM 程序并对临时目录验证“写被拒、读放行、grant 放行、撤 grant 后再拒”：

```bash
sudo go test ./internal/enforcer -run TestEBPFLSMEnforcement -v
```

需要 root 与 bpf LSM，否则测试 skip。测试通过说明这台内核能真正阻断；不通过或 skip 时，部署后节点会回退 observe。

如果刚刚完成过第 9 节的发布，令牌默认 300 秒内 root 持有有效 grant（演示配置 `--publisher-uids 0`），此时下面的 `sudo tee` 会被放行。先等令牌过期，或先把该发布主体/令牌撤销，再跑本测试。

Agent 侧验证：

```bash
echo '<?php echo "shell"; ?>' | sudo tee /var/www/site/shell.php
echo "exit=$?"
```

observe 状态下写入会成功，而且不会自动产生这次写入的审计记录，不能证明拦截。

`enforcer=ebpf-lsm` 时期望：

```
tee: /var/www/site/shell.php: Permission denied
exit=1
```

同一个 shell 再验证改写已有文件：

```bash
printf '<html>hacked</html>\n' | sudo tee /var/www/site/index.html
```

同样应被拒绝。查询审计：

```bash
curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  "$BASE/api/v1/audit?node_id=$PROT_ID&limit=20" | jq '.[] | {seq,kind,decision,path,op,subject}'
curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  "$BASE/api/v1/audit/verify?node_id=$PROT_ID" | jq .
```

`/audit/verify` 返回 `{"ok":true,...}` 说明审计链完整。若 `enforcer=observe`，写入会成功，但不会自动产生这次写入的审计记录，只有策略同步、心跳等 Agent 事件会进审计；这是“没有执行层”，不是“拦截失败”。

如果暂时没有 bpf LSM，可以先用官方的用户态全链路脚本验证控制面、注册、策略、发布、审计、吊销：

```bash
sudo bash test/e2e/e2e-sim.sh
```

脚本使用 `/tmp` 下的临时数据、端口 18443，最后打印 `E2E PASS`。脚本里的 `REPO=` 是硬编码路径，仓库不在该路径时先改这一行；依赖 `go`、`curl`、`jq`。

## 9. 验证 B：发布端凭令牌写入

### 9.1 准备发布源

```bash
rm -rf /tmp/tg-release
mkdir -p /tmp/tg-release/sub
printf '<html>v1</html>\n' > /tmp/tg-release/index.html
printf 'body{}\n' > /tmp/tg-release/sub/site.css
```

### 9.2 创建发布申请

```bash
REQ_ID=$(curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  -H 'Content-Type: application/json' \
  -d "{\"node_id\":\"$PROT_ID\",\"publisher_id\":\"$PUB_ID\",\"source_dir\":\"/tmp/tg-release\",\"target_dir\":\"/var/www/site\",\"note\":\"quickstart\"}" \
  "$BASE/api/v1/publish-requests" | jq -r '.id')
echo "REQ_ID=$REQ_ID"
```

`tg-publish` 正在运行时会在下一轮轮询里取到这个申请，遍历 `source_dir` 算 manifest，提交后拿令牌，再逐文件复核并写入 `target_dir`。观察状态：

```bash
for i in $(seq 1 20); do
  curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/publish-requests/$REQ_ID" \
    | jq -c '{status,manifest,token_id,error}'
  sleep 1
done
```

期望 `status` 从 `pending` 变成 `done`，`manifest` 与 `token_id` 非空，内容是：

```bash
cat /var/www/site/index.html
cat /var/www/site/sub/site.css
```

发布端写文件前会逐文件核对哈希，manifest 与令牌摘要不符会直接失败；令牌默认 300 秒有效，超过就重新创建发布申请，不复用旧请求。

内核侧只认 uid：发布端以哪个 uid 运行，protect 节点 enroll 时就用 `--publisher-uids` 登记哪个 uid（可以逗号分隔多个）。演示默认 `0`，所以 `tg-publish` 以 root 运行、root 可消费 grant。生产应改用专用非 root uid，否则令牌有效期内该 uid 的所有进程都能写被授权路径。授权只在该次发布令牌有效期内存在，`done` 后不会自动续期。

## 9.1 跨机发布（发布端与被保护机分离）

发布请求里加 `"delivery":"pull"`：发布端只把制品与签名清单上传到控制面，目标节点 Agent 拉取、复核每个文件哈希后在本机落盘。发布端不需要访问受保护主机。

```bash
curl -sS --cacert "$CA" -b /tmp/tg.cookies -H 'Content-Type: application/json' \
  -d "{\"node_id\":\"$PROT_ID\",\"publisher_id\":\"$PUB_ID\",\"source_dir\":\"/tmp/tg-release\",\"target_dir\":\"/var/www/site\",\"delivery\":\"pull\"}" \
  "$BASE/api/v1/publish-requests"
```

随后发布端进程上传制品；目标节点的 Agent 在下一次心跳周期拉取并安装，请求状态从 `token_issued` 变为 `done`。完整验证脚本：`sudo bash test/e2e/e2e-pull.sh`（含"发布端不写目标目录"与"篡改制品被拒"两条断言）。

## 10. 验证 C：吊销后再次被拒

```bash
curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  -H 'Content-Type: application/json' \
  -d "{\"kind\":\"subject\",\"value\":\"$PUB_ID\",\"reason\":\"quickstart revoke\"}" \
  "$BASE/api/v1/revocations" | jq .
```

撤销通过 SSE 推送即时下发（Agent 心跳周期默认 15 秒，仅作为推送断线时的兜底）。等 2 秒后，新建一次发布申请并观察结果：

```bash
sleep 2
REQ2=$(curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  -H 'Content-Type: application/json' \
  -d "{\"node_id\":\"$PROT_ID\",\"publisher_id\":\"$PUB_ID\",\"source_dir\":\"/tmp/tg-release\",\"target_dir\":\"/var/www/site\",\"note\":\"after revoke\"}" \
  "$BASE/api/v1/publish-requests" | jq -r '.id')

sleep 5
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/publish-requests/$REQ2" \
  | jq '{status,error}'
```

期望：发布失败或被列为失败状态，节点侧出现拒绝记录。observe 模式下不会产生拒绝，只能看到吊销列表已下发（`GET /api/v1/revocations`），不能把“撤销成功”写成“写入被阻断”。eBPF 节点上的撤销已在 `test/e2e/e2e-ebpf.sh` 中实测：撤销后 2 秒内同一 uid 的写入被内核拒绝；以发布请求状态、Agent 日志与审计记录为准。

吊销只影响后续授权，不回滚已完成的发布。撤销发布主体后，要恢复发布需要用新的发布端身份或管理员处理撤销记录（当前没有“取消撤销”接口）。

## 11. 验证 D：签名自升级

服务端发布一个 Agent 版本（manifest 用发布私钥签名）：

```bash
sudo ./bin/tg-server release --data-dir /var/lib/tamperguard \
  --binary ./bin/tg-agent --version 0.2.0 --os linux --arch amd64
```

Agent 启动时和每 6 小时检查一次；发现新版本会校验签名、大小与 SHA-256，然后原子替换自身二进制并以 0 退出：

```bash
sudo systemctl restart tamperguard-agent   # 由 systemd 拉起新版本
sudo journalctl -u tamperguard-agent -n 50 | grep upgraded
```

校验失败（产物被替换、签名不对、版本路径非法）时不会升级，日志里给出原因。
关闭通道：`tg-agent run ... --auto-upgrade=false`。完整验证脚本：`sudo bash test/e2e/e2e-upgrade.sh`。

## 12. 验证 E：RASP 接入

RASP 探针连的是 Agent 的 Unix socket（默认 `/var/lib/tamperguard-agent/rasp.sock`），规则随策略热下发。

Node.js：

```bash
NODE_OPTIONS="--require /opt/tamperguard/rasp/node/tamperguard.js" \
TG_RASP_SOCKET=/var/lib/tamperguard-agent/rasp.sock \
node app.js
```

Java（JDK 16–21）：

```bash
java -Djava.security.manager=allow \
  -javaagent:/opt/tamperguard/dist/tg-rasp.jar=socket=/var/lib/tamperguard-agent/rasp.sock \
  -jar app.jar
```

策略里把该路径写成 `mode: "observe"` 时只产生 `rasp.observed` 审计；改成 `enforce` 后，同一应用进程的下一次写入会被就地阻断（Node 抛 `EPERM`，Java 抛 `SecurityException`），无需重启。验证脚本：`sudo bash test/e2e/e2e-rasp.sh` 与 `sudo bash test/e2e/e2e-rasp-java.sh`。

## 13. 审计导出与保留

```bash
# 证据导出（JSONL 或 CSV，可按节点与时间过滤）
curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  "$BASE/api/v1/audit/export?node_id=$PROT_ID&format=csv" -o audit.csv

# 链校验（返回 ok / records / from_seq）
curl -sS --cacert "$CA" -b /tmp/tg.cookies \
  "$BASE/api/v1/audit/verify?node_id=$PROT_ID" | jq .
```

默认永久保留审计记录。需要按天裁剪时在 `server.json` 里设置 `audit_retention_days`（例如 180）；裁剪后 `/audit/verify` 从现存最早记录开始校验，不会因为头部被删而误报。

## 14. 能力探测与兼容性

```bash
sudo ./bin/tg-agent probe --state-dir /var/lib/tamperguard-agent
```

输出会说明内核版本、LSM 列表、BTF 是否可用、eBPF 与 fanotify 是否可加载，以及最终选择的执行层。5.10–6.2 与无 bpf LSM 的内核会自动降级，矩阵见 `docs/compat.md`。

## 15. 验证 F：进程自保护（Landlock）

除了系统级阻断，还可以把 Web 进程本身关进只读沙箱——即使它被 RCE，也写不了站点目录：

```bash
# systemd 里把 ExecStart 换成这条；Node / Java / PHP-FPM 同理
sudo ./bin/tg-agent landlock --allow-write /var/lib/php/sessions --allow-write /var/log/php \
  -- /usr/sbin/php-fpm --nodaemonize
```

不显式允许的路径一律只读（写入/删除/重命名返回 `EACCES`），且约束**不可撤销**、子进程继承。默认放行 `/tmp`、`/var/tmp`、`/dev/shm` 与 `/dev/null` 等设备文件，避免破坏正常运行时。

```bash
sudo ./bin/tg-agent landlock --check        # 查看内核 Landlock ABI
sudo bash test/e2e/e2e-landlock.sh          # 端到端验证
```

## 15.1 发布固化（fs-verity，可选）

在支持 fs-verity 的内核与文件系统上，可以让发布安装后的文件变成内核级只读并校验读取：

```bash
sudo ./bin/tg-publish run --state-dir /var/lib/tamperguard-publish --verity   # 本地发布
sudo ./bin/tg-agent run  --state-dir /var/lib/tamperguard --verity            # pull 交付时固化
```

`tg-agent probe` 会显示 `fs-verity : available/unavailable`；也可单独操作：

```bash
sudo ./bin/tg-agent verity enable /var/www/site/index.html
sudo ./bin/tg-agent verity digest /var/www/site/index.html
sudo ./bin/tg-agent verity check  /var/www/site/index.html
```

启用后文件不可再写（`EPERM`），下次发布通过 rename 替换旧文件，不冲突。验证脚本：`sudo bash test/e2e/e2e-verity.sh`（内核不支持时自动跳过）。

## 16. 常见问题

### 11.1 内核没有 bpf LSM，只能 observe

先按 1.2 节确认 `lsm` 列表。若没有 `bpf`：

- 换内核或调整启动参数，使 `lsm=...,bpf` 生效；WSL2 需要自定义内核并配置 `.wslconfig`。
- 不能改内核时，P0 只能跑 observe：没有写入阻断，真实写入也不会自动产生审计记录（只有策略同步、心跳等 Agent 自身事件会进审计）。
- fanotify 是 P2，当前构建没有，不能拿 fanotify 顶替。

### 11.2 怎么判断节点是否降级

```bash
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/nodes/$PROT_ID" \
  | jq '.node | {enforcer,degraded,degraded_approved,status}'
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/overview" | jq .
```

- `enforcer=observe`、`degraded=true`：当前没有内核阻断。
- `enforcer=ebpf-lsm`、`degraded=false`：执行器已加载。
- `degraded_approved` 只是管理员表示“知悉并接受弱防护”（`POST /api/v1/nodes/$PROT_ID/degraded-approval`，body `{"approved":true}`），不改变 observe 不阻断的事实，也不要把这类节点计入合规。
- 当前 eBPF 后端只把 `enforce` 规则写入内核保护集，`observe` 规则在 eBPF 节点上不生效（不阻断也不产生内核事件）；灰度观察要用 sim 环境或等 P1 接线。
- 节点 3 个心跳周期（默认 45 秒）没有心跳会变成 offline。

### 11.3 审计链告警怎么查

```bash
# 每个 Agent 的 next_seq、last_hash、alert
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/audit/state" | jq .
# 重新验一遍服务端已存记录
curl -sS --cacert "$CA" -b /tmp/tg.cookies "$BASE/api/v1/audit/verify?node_id=$PROT_ID" | jq .
```

同时看两处日志：

- `journalctl -u tamperguard-server -n 100`：出现 `audit chain broken` 即服务端验链失败。
- `journalctl -u tamperguard-agent -n 100`：出现 `control plane rejected audit chain` 表示 Agent 上传被 409 拒绝。

常见原因：本地 `audit.log` 被修改/截断；Agent 删了 state-dir 里的记录后从 seq=1 重启；服务端数据库被换掉而 Agent 状态没变。处理原则：保留现场，不要删日志或重置 state-dir，先比对服务端 `next_seq` 与 Agent 日志末尾的 seq；确认是测试环境后再按“重新注册 + 重建链”处理，生产这样做等于丢一段审计。

### 11.4 发布失败

按顺序检查：

| 现象 | 检查 |
|---|---|
| `token` 签发失败 | 目标节点是否已分配策略；策略路径是否为空；发布端身份是否已撤销 |
| `request is missing source_dir or target_dir` | 发布申请必须同时带 `source_dir` 与 `target_dir` |
| `publisher_id must reference a publish agent` | 用 `GET /nodes` 里 role=publish 的 id |
| `token does not authorise <path>` | `target_dir` 必须落在策略路径内 |
| 发布端没反应 | `systemctl status tamperguard-publish`；目录里的 `agent.json` 是否 role=publish |
| 写入被拒（eBPF 节点） | 发布进程 uid 是否在 protect 节点 enroll 时用 `--publisher-uids` 登记；当前值可在 `/var/lib/tamperguard-agent/agent.json` 的 `publisher_uids` 字段确认 |
| 发布超过 5 分钟 | 令牌默认 300 秒过期，重新创建发布申请 |

### 11.5 管理页面打不开或 404

当前构建没有嵌入管理端静态资源，`GET /` 返回 `admin UI not bundled in this build`。P0 用本文的 REST API 完成全部操作。管理页面落地后，地址仍为 `https://<控制面地址>:8443/`，首次访问需要把 `ca.crt` 导入浏览器信任库，或临时跳过证书警告（仅演示环境）。

### 11.6 跨机发布不可用

P0 的 `tg-publish` 直接写本机的 `target_dir`，不实现内容传输。发布端与节点分机时，需要部署侧用 rsync/SSH/共享存储把文件送到目标节点并保证写入经由目标节点的执行层，当前没有现成实现。quickstart 的端到端流程只适用于同机。

## 18. 数据目录与文件

| 路径 | 内容 |
|---|---|
| `/var/lib/tamperguard/server.json` | 控制面配置（0600） |
| `/var/lib/tamperguard/keys/*` | CA、服务端证书、令牌/策略签名密钥（私钥 0600） |
| `/var/lib/tamperguard/tamperguard.db` | SQLite（节点、策略、令牌、发布申请、审计、撤销） |
| `/var/lib/tamperguard-agent/agent.json` | 保护端身份（含私钥，0600） |
| `/var/lib/tamperguard-agent/audit.log` | 本地审计链（JSON Lines，0600） |
| `/var/lib/tamperguard-publish/agent.json` | 发布端身份（含私钥，0600） |

卸载/升级时不要把 `keys/` 或 Agent 的 `agent.json` 当缓存清掉；清掉等于换身份，需要重新注册并会打断审计链。

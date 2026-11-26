# Agent 生命周期管理

本文件说明管理端能对 Agent 做什么，重点是**卸载控制**：只有两条卸载路径，都必须经过控制面。

## 1. 管理端能做什么

| 操作 | 位置 | 说明 |
|---|---|---|
| 查看节点 | 节点列表 / 详情 | 状态、执行层、策略版本、最后心跳、能力探测、最近审计 |
| 审批降级 | 节点详情 → 批准/撤销降级防护 | 内核能力不足时显式接受降级 |
| 吊销身份 | 节点详情 → 吊销节点身份 | 证书立即失效，节点无法再上报 |
| 查看卸载请求 | 节点页 → 卸载审批 | 客户端发起的卸载请求（原因、时间） |
| 批准/拒绝卸载 | 卸载审批 → 批准/拒绝 | 批准后返回一次性挑战码（10 分钟有效） |
| 下发卸载 | 节点详情 → 下发卸载 | 管理端直接生成挑战码并推送，节点在线时自动执行 |

当前**没有**远程"重启/停止/采集日志"等通用指令通道；这些属于后续能力，不在本版本假装支持。

## 2. 两条且仅两条卸载路径

### 路径 A：管理端下发

```
管理员点击「下发卸载」
   └─ 控制面生成请求 + 用 policy 私钥签发 10 分钟票据
        ├─ SSE 推送到在线节点 → 节点验签 → 分离式清理脚本执行
        └─ 返回挑战码 → 管理员可转交离线主机执行：
             sudo tg-agent uninstall --state-dir ... --ticket <挑战码>
```

### 路径 B：客户端发起 + 管理员审批

```
主机执行 tg-agent uninstall
   ├─ 生成随机 nonce，POST /agent/uninstall/request（mTLS）
   ├─ 打印 request_id，轮询审批结果（默认等待 10 分钟）
   ├─ 管理员在「卸载审批」批准
   │     └─ 控制面签发票据：绑定 node_id + request_id + nonce + 10 分钟有效期
   ├─ 客户端用 policy 公钥验签：动作、节点、nonce、有效期
   └─ 验签通过 → 停止服务、删除 unit/二进制/状态目录
```

拒绝或超时都不会删除任何文件。

## 3. 票据格式

```json
{
  "version": 1,
  "node_id": "n_...",
  "request_id": "ur_...",
  "nonce": "...",
  "action": "uninstall",
  "issued_at": 1795656771,
  "expires_at": 1795657371,
  "signature": "<base64 Ed25519>"
}
```

签名覆盖规范化字段（版本、节点、请求、nonce、动作、签发/过期时间）。挑战码是票据的 URL-safe base64，可直接复制粘贴。

## 4. 接口

| 方法 | 路径 | 角色 | 说明 |
|---|---|---|---|
| POST | `/api/v1/agent/uninstall/request` | protect mTLS | `{nonce,reason}` → `{request_id,status}` |
| GET | `/api/v1/agent/uninstall/{id}` | protect mTLS | `{request_id,status,ticket}` |
| GET | `/api/v1/uninstall-requests?status=pending` | admin | 待审批列表 |
| POST | `/api/v1/uninstall-requests/{id}/approve` | admin | 批准并返回挑战码 |
| POST | `/api/v1/uninstall-requests/{id}/deny` | admin | 拒绝 |
| POST | `/api/v1/nodes/{id}/uninstall` | admin | 管理端直接下发，返回挑战码 |

## 5. 安全边界（如实）

- 防的是"**本地随意卸载**"和"绕过流程卸载"：没有通过控制面校验的票据，`tg-agent uninstall` 不会执行清理；直接把二进制删掉也不会走正常卸载（服务、状态、审计仍在，节点随后离线告警）。
- **不防拥有 root/SYSTEM 的攻击者**：他们可以 stop 服务、删除文件、改 systemd unit。产品能做的是让这类动作留下痕迹（节点离线、审计中断、控制面记录），而不是在文件系统层面阻止 root。这与 Linux eBPF 防护模型的边界一致。
- 票据一次性、短有效期；批准记录（谁、何时）保存在控制面的卸载请求表中，审计链记录由 Agent 在卸载前尽力上传。
- `--dry-run` 只验签不删除，用于演练与排错。

## 6. 客户端使用

```bash
# 发起请求并等待审批（默认 10 分钟）
sudo tg-agent uninstall --state-dir /var/lib/tamperguard-agent --reason "host retired"

# 管理员已把挑战码给到你（离线主机）
sudo tg-agent uninstall --state-dir /var/lib/tamperguard-agent --ticket '<挑战码>'

# 只验证挑战码，不删除
sudo tg-agent uninstall --state-dir /var/lib/tamperguard-agent --ticket '<挑战码>' --dry-run

# 调整等待时间
sudo tg-agent uninstall --timeout 30m --reason "..."
```

执行时会：停止并禁用 systemd 服务、删除 unit 文件、删除二进制、删除状态目录。Windows 停止并删除服务，二进制与目录由延迟脚本清理。

## 7. 验证

```bash
go test ./internal/uninstall          # 票据签名/篡改/过期/编码
make e2e-uninstall                    # 拒绝、批准、管理端下发、篡改票据
```

# Web 层内容校验（tg-proxy）

文件层防护回答"能不能写"；Web 层校验回答"**用户能不能拿到被篡改的内容**"。`tg-proxy` 是一个校验型静态内容服务器/反向代理：站点在发布后快照进内容寻址存储，每个静态请求都会重新校验磁盘文件，磁盘被改就返回可信副本并记 `web.tamper-detected`。

## 1. 工作方式

```
浏览器 ──> tg-proxy ──(清单命中)──> 校验磁盘文件
                       │                ├─ 哈希一致 → 直接返回（X-TG-Integrity: verified）
                       │                └─ 哈希不一致 → 返回快照副本（X-TG-Integrity: restored）
                       └─(清单未命中)──> 转发给 upstream（动态应用）
```

- 快照：`--root` 全量哈希 → `<state>/manifest.json` + `<state>/blobs/<sha256>`（内容寻址，天然去重）
- 拒绝符号链接（避免通过链接把站点外内容纳入可信清单）
- 清单外的新文件默认 404（攻击者丢进目录的 webshell 页面不会被访问到）；配置 `--upstream` 时转发给后端应用
- 审计：`--audit` 指定 JSONL 文件，篡改事件包含路径、期望哈希、实际哈希、动作

## 2. 命令

```bash
# 发布后生成可信快照（建议放在发布流程最后一步）
tg-proxy --root /var/www/site --state /var/lib/tg-proxy --snapshot-only

# 启动校验代理
tg-proxy --root /var/www/site --state /var/lib/tg-proxy \
  --listen 0.0.0.0:8080 --upstream http://127.0.0.1:8000 \
  --audit /var/log/tg-proxy/tamper.jsonl

# 不重新快照，使用已有清单
tg-proxy --root /var/www/site --state /var/lib/tg-proxy --no-snapshot --listen 127.0.0.1:8080
```

健康检查：`GET /healthz` 返回文件数与快照时间。

## 3. 部署形态

**Linux（替换静态处理）**：nginx/IIS 等后端只处理动态请求，静态请求由 tg-proxy 直接服务；或者把 tg-proxy 放在最前面，`--upstream` 指向原 Web Server。

**Windows（IIS 前置）**：IIS 站点改为监听 8080，`tg-proxy.exe` 监听 80/443（证书由前置完成），静态命中直接由代理返回，未命中转发 IIS。代理以普通服务账号运行即可，不需要管理员、不需要驱动。

```powershell
# 快照（发布后执行一次）
.\tg-proxy.exe --root C:\inetpub\wwwroot --state C:\ProgramData\tg-proxy --snapshot-only
# 运行
.\tg-proxy.exe --root C:\inetpub\wwwroot --state C:\ProgramData\tg-proxy `
  --listen 0.0.0.0:80 --upstream http://127.0.0.1:8080 --audit C:\ProgramData\tg-proxy\tamper.jsonl
```

## 4. 与文件层防护的关系

| 层 | 作用 | 依赖 |
|---|---|---|
| eBPF / ACL+MIC / Landlock | 阻止写入 | 内核/管理员权限 |
| 自愈 | 写成功后被回滚 | 文件层执行器 |
| **Web 校验（本层）** | **磁盘被改也交付可信内容** | 仅需部署代理 |

三者叠加后：写不进去 → 写进去也会被回滚 → 即使回滚前的一瞬间，用户拿到的仍是校验过的内容。

## 5. 限制（如实）

- 快照是"首次信任"：如果站点在快照时已被篡改，可信基线就是被篡改的内容。应与签名发布流程配合（快照前校验发布清单哈希），后续可把控制面的 `publish_files` 清单接入。
- 只覆盖经代理的静态请求；绕过代理直连后端、或后端动态渲染的内容不在范围内。
- 目录列表、Range 请求可用（`http.ServeContent`），但对超大文件每请求都会做一次哈希校验（CPU 开销，通常可接受）。
- 清单外路径 404 可防止新增文件被访问，但动态应用需要 `--upstream`，此时动态程序若读取站点根目录，仍可能拿到被篡改文件——需要动态程序本身不直接读被保护目录。

## 6. 验证

```bash
go test ./internal/webproxy        # 单测：校验/回退/审计/穿越/符号链接
make e2e-proxy                     # 端到端：篡改后仍返回可信内容 + 审计 + 动态转发
```

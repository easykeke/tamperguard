# 部署形态

三种部署方式，按场景选一种：

| 场景 | 方式 | 目录 |
|---|---|---|
| 普通服务器 / 虚拟机 | systemd 单元 | `deploy/systemd/` |
| 管理端容器化 | docker compose | `deploy/docker-compose.yml` + `deploy/Dockerfile.server` |
| Kubernetes 节点防护 | DaemonSet（privileged + hostPID） | `deploy/k8s/` |

## 前提

- 保护端必须能接触宿主内核与宿主文件系统，因此**不能**用普通容器跑；K8s 场景使用 privileged + hostPID 的 DaemonSet，并把受保护路径按相同路径 hostPath 挂进来。
- 内核要求：eBPF LSM 主路径需要内核 ≥ 5.10（推荐 6.1+，`CONFIG_BPF_LSM=y` 且 LSM 列表含 `bpf`）；不满足时自动降级到 fanotify（检测+回滚）。自检：

```bash
uname -r
cat /proc/cmdline | tr ' ' '\n' | grep lsm
cat /sys/kernel/security/lsm   # 需要 mount -t securityfs securityfs /sys/kernel/security
```

## systemd

```bash
sudo install -m 0755 bin/tg-server bin/tg-agent bin/tg-publish /usr/local/bin/
sudo install -m 0644 deploy/systemd/*.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tgpublish || true

sudo tg-server init --data-dir /var/lib/tamperguard           # 记下密码与 token
sudo systemctl enable --now tamperguard-server
sudo tg-agent enroll --server https://127.0.0.1:8443 \
  --bootstrap '<protect-token>' --ca /var/lib/tamperguard/keys/ca.crt \
  --state-dir /var/lib/tamperguard-agent --publisher-uids 1002
sudo systemctl enable --now tamperguard-agent

# 发布端（用专用账号，uid 必须与 --publisher-uids 一致）
sudo -u tgpublish tg-agent enroll --server https://127.0.0.1:8443 \
  --bootstrap '<publish-token>' --role publish \
  --ca /var/lib/tamperguard/keys/ca.crt --state-dir /var/lib/tamperguard-publish
sudo systemctl enable --now tamperguard-publish
```

> 注意：`tamperguard-publish.service` 里 `User=tgpublish` 的 uid 必须与受保护节点
> enroll 时的 `--publisher-uids` 一致，否则内核不认发布写入。

## docker compose（仅管理端）

```bash
docker compose -f deploy/docker-compose.yml run --rm server tg-server init --data-dir /data
docker compose -f deploy/docker-compose.yml up -d
```

管理端容器只监听 8443，卷 `tamperguard-data` 保存 CA、密钥与 SQLite。发布端与保护端仍装在主机上。

## Kubernetes DaemonSet

```bash
kubectl apply -f deploy/k8s/secret.example.yaml   # 先填入真实 CA 与 bootstrap token
kubectl apply -f deploy/k8s/daemonset.yaml
kubectl -n tamperguard logs -l app.kubernetes.io/name=tamperguard-agent --tail=50
```

DaemonSet 每次启动时，若 `/var/lib/tamperguard-agent/agent.json` 不存在则先用 bootstrap
token 注册，再执行 `tg-agent run`。受保护路径通过 hostPath 以相同路径挂入（示例为
`/srv/www`），策略里写的路径必须是宿主机视角的路径。

## 升级

当前版本没有内置自升级通道（P4 规划）：替换二进制后 `systemctl restart tamperguard-agent`。
生产环境请对二进制做签名校验后再分发。

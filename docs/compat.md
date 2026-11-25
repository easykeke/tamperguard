# 兼容性与能力探测

## 1. 如何自查

```bash
sudo tg-agent probe --state-dir /var/lib/tamperguard-agent
```

输出示例（Linux 6.6 + bpf LSM 已启用）：

```
kernel        : 6.6.87
cmdline       : ... lsm=lockdown,capability,landlock,yama,apparmor,bpf
lsm active    : capability,landlock,yama,apparmor,bpf (bpf=true)
kernel BTF    : true
eBPF LSM      : available
fanotify      : available
selected      : ebpf-lsm (degraded=false)
```

探测会真的加载并挂载 eBPF 程序、初始化 fanotify，因此结论就是这台机器实际会使用的执行层。

## 2. 执行层矩阵

| 内核条件 | 执行层 | 能力 | 状态 |
|---|---|---|---|
| ≥ 6.3，`CONFIG_BPF_LSM=y`，`lsm=` 含 `bpf`，有 BTF | eBPF LSM | 写入前同步阻断，14 个 hook | **已在 6.6 验证** |
| 5.10 – 6.2（上述条件中的 BTF/LSM 满足） | 大概率回退 fanotify | 检测+回滚 | 未验证；LSM hook 签名在 6.3 前后有差异，加载失败即自动降级 |
| 无 bpf LSM / 无 BTF / 无 BPF 权限 | fanotify | 检测+回滚（覆盖写毫秒级回滚、新建/删除巡检恢复） | 已在 6.6 验证 |
| 无 fanotify 或无 CAP_SYS_ADMIN | observe | 只记录不阻断，节点标记 degraded | 已验证（显式降级，不伪装） |

关键约束：

- eBPF 对象按 6.6 的 LSM hook 签名编译（例如 `inode_create(dir, dentry, mode)`、`inode_setxattr(idmap, ...)`）。6.3 之前部分 hook 没有 `mnt_idmap` 参数，整对象加载会失败，此时自动降级到 fanotify，不会出现“挂了一半”的防护。
- 未启用 `lsm=...,bpf` 时，`CONFIG_BPF_LSM=y` 也不生效；启动参数必须显式包含 `bpf`。
- WSL2 的默认内核 `CONFIG_LSM` 不含 `bpf`，需要在 `%UserProfile%\.wslconfig` 增加 `kernelCommandLine=lsm=...,bpf` 后 `wsl --shutdown`。
- 普通容器内不能运行 Agent（需要宿主内核与宿主文件系统）；K8s 用 privileged + hostPID DaemonSet，见 `deploy/k8s/`。

## 3. 文件系统矩阵

| 场景 | 结果 | 说明 |
|---|---|---|
| ext4 / xfs / tmpfs | 已验证 | inode 索引直接匹配 |
| OverlayFS（容器可写层） | 已验证 | 钩子作用在 overlay inode，与 merged 路径索引一致；`TestOverlayEnforcement` |
| NFS / CIFS | 不承诺 | 内核钩子与 fanotify 在网络文件系统上行为不同 |
| 直接写 upperdir/lowerdir | 不覆盖 | 需要宿主 root，超出威胁模型 |

## 4. 自升级兼容性

- Agent 与服务端使用同一份 Ed25519 发布密钥签名 manifest；老版本 Agent（无升级通道）不受影响。
- 升级按 `os/arch` 选择产物，当前只支持与 Agent 相同的平台。
- 替换二进制后进程以 0 退出，由 systemd（`Restart=always`）拉起新版本；K8s 场景由 Pod 重建拉起。

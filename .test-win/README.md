# Windows 本机验证沙箱

本目录用于在本机 Windows 上验证**无驱动**严格模式的真实行为。全部测试只操作本目录下的
临时目录，结束自动清理；不改动系统设置或任何真实站点目录。

## 两个测试

### 1) `run-test.ps1` — ACL / 发布窗口 / 自愈

以管理员 PowerShell 运行：

```powershell
cd E:\AI-learn\Tamper-proof\.test-win
Set-ExecutionPolicy -Scope Process Bypass -Force
.\run-test.ps1
```

验证（以 High 完整性标签运行，因为 Windows 不允许进程给自己之上打标签）：

| 断言 | 说明 |
|---|---|
| 提权管理员覆盖/新建被拒 | 严格 DACL 不给管理员数据写权限 |
| 读取正常 | Everyone 只读 |
| 策略外路径可写 | 不误伤 |
| 发布窗口内授权账号可写 | 标签临时降为 Medium + DACL 授权 |
| 撤销后再次被拒 | 恢复锁定 |
| 管理员绕过被自愈回滚 | 改标签 + 夺取所有权 + 重写 → 内容被还原 + `tamper.restored` |
| `unlock` 后可维护 | 继承权限恢复 |

结果写到 `results.log`（程序逐行 flush + 120s 看门狗）。

### 2) `run-mic-demo.ps1` — 管理员写入被 System 标签拒绝

这个 case 需要 **SYSTEM** 才能把标签设为 System（管理员只能设到 High），脚本用一次性
计划任务以 SYSTEM 执行标签设置，然后回到管理员会话尝试写入：

```powershell
.\run-mic-demo.ps1
```

预期：`[ok] administrator overwrite denied`、`[ok] administrator create denied`、
`RESULT: PASS`，日志 `mic-demo.log`。

## 为什么 minifilter 不在本机测

驱动需要 WDK、测试签名/重启与微软签名，真实客户现场无法接受安装成本；详见
`docs/advanced-techniques.md` 与 `docs/windows-stronger-options.md`。

## 生产部署要求

严格模式要把受保护路径标为 **System**，Agent 必须以 **LocalSystem 服务**运行
（`deploy/windows/install-service.ps1`）；以普通管理员运行时会自动降级为 High，
并在日志与 capability 里注明。

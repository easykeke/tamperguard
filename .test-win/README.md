# Windows 本机验证沙箱

这个目录用来在本机 Windows 上验证 **无驱动** 的严格模式（ACL + 完整性级别），
包括"提权管理员写入被拒"这一核心语义。目录内容不提交（`.gitignore` 已排除）。

## 目录

```
.test-win/
├─ README.md              本说明
├─ run-test.ps1           提权后运行的一键脚本（写 results.log）
├─ tg-winacl-test.exe     测试程序（交叉编译产物）
├─ sandbox/               测试时自动创建/删除
└─ results.log            运行结果（由脚本写出）
```

## 怎么跑

需要**管理员权限**（设置 SACL 需要 `SeSecurityPrivilege`）：

1. 开始菜单搜索 PowerShell → 右键 **以管理员身份运行**
2. 执行：

```powershell
cd E:\AI-learn\Tamper-proof\.test-win
Set-ExecutionPolicy -Scope Process Bypass -Force
.\run-test.ps1
```

脚本会输出 PASS/FAIL 表，并把结果写到 `results.log`。

## 测试覆盖的断言

| 断言 | 说明 |
|---|---|
| 提权管理员无法覆盖受保护文件 | 严格 DACL（无 Administrators 写）+ System 完整性标签 |
| 提权管理员无法新建文件 | 同上 |
| 读取不受影响 | Everyone 只读 ACE |
| 策略外路径可正常写 | 不影响未保护目录 |
| 授权发布窗口内可写 | 标签临时降为 Medium + DACL 临时授权发布账号 |
| 撤销后再次被拒 | 恢复 System 标签与锁定 DACL |
| 管理员绕过被自愈回滚 | 模拟"改标签 + 夺取所有权 + 重写文件"，扫描周期内内容恢复，并产生 `tamper.restored` 事件 |
| `unlock` 后可维护 | 继承权限与 Medium 标签恢复 |

## 为什么不能在本机测 minifilter 驱动

minifilter 是内核驱动，需要：

1. 安装 WDK（Windows Driver Kit，数 GB）与 VS 构建工具；
2. 加载未签名驱动必须 `bcdedit /set testsigning on` 并**重启**，或每次开机按 F8 选择
   "禁用驱动程序强制签名"；
3. 即使是测试签名，也需要管理员权限和重启，且蓝屏风险由本机承担。

这三点都需要改动你本机的启动配置，不适合由自动化流程擅自执行。真要做驱动原型，
建议用一台**可快照的 Windows 测试 VM**；原型目标、签名路径与风险见
`docs/advanced-techniques.md` 的 P5.5。

# GlobalShutdownHook

全局拦截 Windows 关机/注销 API 的内核驱动。通过 inline-hook 用户态 `user32!ExitWindowsEx` 和 `advapi32!InitiateSystemShutdownEx(A/W)`，阻止系统关机、重启和注销。

## 原理

```
应用程序调用 ExitWindowsEx()
        │
        ▼
  user32.dll 中的函数入口
        │  被驱动覆盖为: mov rax, 1; ret
        ▼
  函数立即返回 TRUE（假装成功），不执行实际关机
```

- **不涉及 PatchGuard**：只修改用户态 DLL 的代码页，PatchGuard 不保护用户态内存
- **不修改系统调用表**：不 hook SSDT，不碰内核关键结构
- **全局覆盖**：通过 `PsSetLoadImageNotifyRoutine` 捕获所有新加载的 DLL，结合进程枚举覆盖已有进程

## 架构

```
┌──────────────────────────────────────────────────────┐
│                    Kernel Mode                       │
│                                                      │
│  DriverEntry                                         │
│    ├─ Init StateTable (PID+Func → Hook状态)          │
│    ├─ Init FailLog   (失败记录环形缓冲区)            │
│    ├─ Init WorkerThread (PASSIVE_LEVEL 执行hook)     │
│    ├─ PsSetLoadImageNotifyRoutine(ImageLoadCB)       │
│    └─ EnumerateAllProcesses() → 入队                 │
│                                                      │
│  ImageLoadCallback (可能 DISPATCH_LEVEL)             │
│    └─ 判断 user32.dll/advapi32.dll → 入队            │
│                                                      │
│  WorkerThread                                        │
│    └─ Dequeue → Attach Process → PE解析 → InlineHook │
│         ├─ 成功 → State=HOOKED, 保存原始字节         │
│         └─ 失败 → State=FAILED, 写入FailLog          │
│                                                      │
│  IOCTL Interface (\\.\GlobalShutdownHook)            │
│    ├─ GET_STATUS     统计信息                        │
│    ├─ GET_HOOKED_LIST 所有hook条目                   │
│    ├─ GET_FAIL_LOG   失败记录                        │
│    ├─ CLEAR_FAIL_LOG 清空失败记录                    │
│    └─ UNHOOK_ALL     恢复所有hook                    │
└──────────────────────────────────────────────────────┘
         │ IOCTL (DeviceIoControl)
         ▼
┌─────────────────────────────────────────────────────┐
│                  User Mode                          │
│                                                     │
│  ShutdownHookClient.exe                             │
│    status / list / failures / clear / unhook        │
│    test / test-advapi / monitor                     │
└─────────────────────────────────────────────────────┘
```

## 项目结构

```
GlobalShutdownHook/
├── driver/                          # 内核驱动
│   ├── gsh_common.h                 # 公共定义（IOCTL码、数据结构）
│   ├── gsh_driver.c                 # DriverEntry、卸载、IOCTL分发
│   ├── gsh_state.c/.h              # Hook状态哈希表（链表+自旋锁）
│   ├── gsh_worker.c/.h             # 工作队列 + 系统工作线程
│   ├── gsh_pe.c/.h                 # 用户态PE解析（PEB→LDR→导出表）
│   ├── gsh_hook.c/.h               # Inline hook核心（attach、改内存、恢复）
│   ├── gsh_faillog.c/.h            # 失败记录环形缓冲区
│   ├── gsh_notify.c/.h             # LoadImage回调 + 进程枚举
│   ├── GlobalShutdownHook.vcxproj   # WDK驱动项目
│   ├── GlobalShutdownHook.vcxproj.filters
│   └── GlobalShutdownHook.inf       # 安装信息
├── userapp/                         # 用户态客户端
│   ├── ShutdownHookClient.c         # 控制台控制/监控程序
│   ├── ShutdownHookClient.vcxproj
│   └── ShutdownHookClient.vcxproj.filters
├── test/
│   └── test_shutdown.c              # 独立测试程序（菜单式）
├── scripts/
│   ├── build.bat                    # Windows编译脚本
│   ├── install_and_test.bat         # VM内安装测试脚本
│   └── qemu_run.sh                  # QEMU启动脚本
├── QEMU_TESTING.md                  # QEMU测试详细指南
├── GlobalShutdownHook.sln           # VS解决方案
└── README.md
```

## 编译

### 前置要求

- Visual Studio 2022（17.x），含 C++ 桌面开发工作负载
- Windows Driver Kit (WDK) 10.0.22621 或更高版本（与 SDK 版本匹配）
- 目标平台：x64（Windows 10/11 64位）

### 编译步骤

```cmd
:: 打开 "x64 Native Tools Command Prompt for VS 2022"
cd GlobalShutdownHook
scripts\build.bat Release
```

或在 Visual Studio 中打开 `GlobalShutdownHook.sln`，选择 `Release|x64`，生成解决方案。

编译产物位于 `bin\x64\Release\`：
- `GlobalShutdownHook.sys` — 内核驱动
- `ShutdownHookClient.exe` — 用户态控制程序

## 安装与使用

### 1. 开启测试签名（必须）

由于驱动未经过微软签名，需要开启测试签名模式：

```cmd
:: 以管理员身份运行
bcdedit /set testsigning on
shutdown /r /t 0
```

重启后桌面右下角显示"测试模式"水印。

### 2. 加载驱动

```cmd
:: 创建服务
sc create GSH type= kernel binPath= C:\path\GlobalShutdownHook.sys

:: 启动
sc start GSH

:: 查看状态
sc query GSH
```

或使用自动脚本：
```cmd
scripts\install_and_test.bat
```

### 3. 使用客户端

```cmd
:: 查看统计
ShutdownHookClient.exe status

:: 列出所有hook条目
ShutdownHookClient.exe list

:: 查看失败记录
ShutdownHookClient.exe failures

:: 实时监控
ShutdownHookClient.exe monitor 2

:: 测试拦截（调用ExitWindowsEx，应返回TRUE但不注销）
ShutdownHookClient.exe test

:: 测试InitiateSystemShutdownEx
ShutdownHookClient.exe test-advapi

:: 恢复所有hook（驱动仍运行）
ShutdownHookClient.exe unhook

:: 清空失败日志
ShutdownHookClient.exe clear
```

### 4. 卸载

```cmd
sc stop GSH      :: 停止（自动恢复所有hook）
sc delete GSH    :: 删除服务
```

## Hook 字节

| 架构 | 字节 | 指令 | 效果 |
|------|------|------|------|
| x64 | `48 C7 C0 01 00 00 00 C3` | `mov rax, 1; ret` | 返回TRUE，不执行关机 |
| x86 | `B8 01 00 00 00 C3 90 90` | `mov eax, 1; ret; nop; nop` | 同上 |

覆盖函数前 8 字节，保存原始字节用于卸载时恢复。

## 限制与已知问题

### 无法 hook 的进程

| 类型 | 原因 | 示例 |
|------|------|------|
| PPL（受保护进程） | 无法写内存 | csrss.exe, lsass.exe, WinDefend |
| ACG（任意代码防护） | 无法修改代码页保护 | Edge, Chrome, 部分UWP应用 |
| CIG（代码完整性防护） | 修改代码页触发校验 | 部分系统进程 |
| 未加载目标DLL | 纯内核/控制台进程可能不加载user32 | smss.exe, 部分服务进程 |
| Wow64（32位进程） | 当前版本做最佳尝试，可能失败 | 旧版32位程序 |

### 其他限制

- 仅支持 x64 Windows 10/11（32位 Windows 不支持）
- 不拦截通过 `NtShutdownSystem` 直接发起的内核级关机
- 不拦截 `AbortSystemShutdown`（这是取消关机的API）
- 驱动加载前已发起的关机超时无法取消
- 某些应用可能使用未文档化的替代路径发起关机

## 技术细节

### IRQL 安全

- `PsSetLoadImageNotifyRoutine` 回调可能在 DISPATCH_LEVEL 触发
- 回调中只做：模块名判断 → 查状态表 → 入队（无锁队列 + 自旋锁）
- 实际 inline-hook 由系统工作线程在 PASSIVE_LEVEL 执行
- 工作线程中可以安全调用 `KeStackAttachProcess`、`ZwProtectVirtualMemory` 等

### 竞态避免

- 先注册 LoadImage 回调，再枚举现有进程
- 枚举期间新加载的模块由回调捕获，不会遗漏
- 状态表按 (PID, FunctionId) 去重，重复入队不会重复 hook
- hook 前检查是否已 HOOKED，已 hook 的直接跳过

### PE 解析

- attach 到目标进程后，通过 `ZwQueryInformationProcess(ProcessBasicInformation)` 获取 PEB
- 遍历 PEB→Ldr→InMemoryOrderModuleList 查找模块基址
- 解析 PE 导出表（AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions）
- 支持 64 位原生 PE 和 32 位 PE（Wow64）
- Wow64 进程通过 64 位 PEB 的 WoW64Process 字段（偏移 0x330）获取 32 位 PEB

### 内存修改

- `ZwProtectVirtualMemory` 将代码页改为 `PAGE_EXECUTE_READWRITE`
- 写入 hook 字节后恢复原保护属性
- 使用 `ProbeForRead/Write` + `__try/__except` 保护所有用户态内存访问
- x86/x64 强一致性架构，自修改代码自动同步指令缓存

## QEMU 测试

详见 [QEMU_TESTING.md](QEMU_TESTING.md)，包含：
- QEMU 环境搭建
- Windows VM 安装
- 测试签名配置
- 驱动安装与功能验证
- 覆盖率测试
- WinDbg 内核调试
- 故障排查

快速启动：
```bash
cd scripts
chmod +x qemu_run.sh
./qemu_run.sh
```

## 故障排查

| 问题 | 解决方案 |
|------|---------|
| `sc start` 错误 577 | 开启 testsigning：`bcdedit /set testsigning on` 后重启 |
| `sc start` 错误 2 | 检查 binPath 路径是否正确，文件是否存在 |
| 蓝屏 | 用 WinDbg 查看崩溃转储，检查 attach 和内存访问 |
| HookedCount=0 | 查看 DbgPrint 输出，检查失败日志 |
| 客户端打不开设备 | 驱动未启动，或符号链接创建失败 |
| 某些进程未拦截 | 查看失败日志，可能是 PPL/ACG/Wow64 限制 |

## 调试输出

驱动使用 `DbgPrint` 输出调试信息。查看方法：
- **DebugView**（Sysinternals）：启用 "Capture Kernel"
- **WinDbg** 内核调试：`ed nt!Kd_DEFAULT_MASK 0xFFFFFFFF`
- 串口输出：配置 `bcdedit /dbgsettings serial`

关键调试输出：
```
GSH: DriverEntry loading
GSH: Enumerated X processes, enqueued for module check
GSH: Driver loaded successfully
GSH: Hook failed PID=X func=ExitWindowsEx reason=0xC0000022
GSH: Unloading driver
GSH: Restored X hooks, Y failed
```

## 许可证

本项目仅供学习和研究使用。请勿用于非法用途。

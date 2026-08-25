# QEMU 测试指南

## 概述

本指南说明如何在 QEMU 虚拟机中测试 GlobalShutdownHook 驱动。

## 1. 环境准备

### 1.1 安装 QEMU 和依赖

```bash
# Ubuntu/Debian
sudo apt install qemu-system-x86 qemu-utils ovmf samba

# 验证
qemu-system-x86_64 --version
```

### 1.2 获取 Windows 镜像

下载 Windows 10/11 x64 ISO（从微软官方或你已有的授权）：
- Windows 11 22H2 x64 ISO（推荐，与目标环境一致）
- 或 Windows 10 22H2 x64 ISO

### 1.3 创建虚拟磁盘并安装 Windows

```bash
# 创建 64G 虚拟磁盘
qemu-img create -f qcow2 win11.qcow2 64G

# 首次启动，从 ISO 安装（需要 OVMF UEFI 固件）
qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -smp 4 -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive file=win11.qcow2,format=qcow2,if=virtio \
    -cdrom /path/to/Win11_22H2_x64.iso \
    -boot d -usb -device usb-tablet -vga virtio -display gtk
```

安装完成后关闭虚拟机。

### 1.4 安装 VirtIO 驱动（可选但推荐）

在 Windows 安装过程中，如果找不到磁盘，需要加载 VirtIO 驱动：
- 下载 Fedora VirtIO 驱动 ISO：https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/
- 加载 `vioscsi` 或 `viostor` 驱动

## 2. 编译驱动

在 Windows 开发机上（或在 VM 中安装 Visual Studio + WDK）：

```cmd
:: 打开 "x64 Native Tools Command Prompt for VS 2022"
cd GlobalShutdownHook
scripts\build.bat Release
```

编译产物位于 `bin\x64\Release\`：
- `GlobalShutdownHook.sys` — 内核驱动
- `ShutdownHookClient.exe` — 用户态控制程序

## 3. 配置 VM 测试环境

### 3.1 启动 VM 并开启测试签名

```bash
# 使用项目提供的启动脚本（先编辑脚本中的路径）
cd GlobalShutdownHook/scripts
chmod +x qemu_run.sh
./qemu_run.sh
```

在 VM 中，以管理员身份打开 cmd：

```cmd
:: 开启测试签名（必须，否则未签名驱动无法加载）
bcdedit /set testsigning on

:: 可选：开启内核调试（通过串口连接 WinDbg）
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

:: 重启使设置生效
shutdown /r /t 0
```

重启后桌面右下角会显示"测试模式"水印。

### 3.2 复制编译产物到 VM

通过 QEMU 的 SMB 共享文件夹（脚本中已配置）：
- 在 VM 中打开文件资源管理器
- 地址栏输入 `\\10.0.2.4\shared`
- 将 `GlobalShutdownHook.sys` 和 `ShutdownHookClient.exe` 复制到 `C:\GSH\`

或者直接将编译产物放入宿主机的 `shared/` 目录。

## 4. 安装和测试驱动

### 4.1 自动安装测试

在 VM 中以管理员身份运行：

```cmd
cd C:\GSH
install_and_test.bat
```

脚本会自动：
1. 检查管理员权限和 testsigning 状态
2. 创建并启动驱动服务
3. 等待 worker 线程处理
4. 显示驱动状态、hook 列表和失败日志

### 4.2 手动安装（如果脚本失败）

```cmd
:: 创建服务
sc create GSH type= kernel binPath= C:\GSH\GlobalShutdownHook.sys

:: 启动驱动
sc start GSH

:: 查看状态
sc query GSH

:: 查看驱动输出（需要 DebugView 或 WinDbg）
```

### 4.3 使用客户端程序

```cmd
:: 查看统计
ShutdownHookClient.exe status

:: 列出所有 hook 条目
ShutdownHookClient.exe list

:: 查看失败记录
ShutdownHookClient.exe failures

:: 清空失败记录
ShutdownHookClient.exe clear

:: 实时监控（每2秒刷新）
ShutdownHookClient.exe monitor 2

:: 测试 ExitWindowsEx 拦截
ShutdownHookClient.exe test

:: 测试 InitiateSystemShutdownEx 拦截
ShutdownHookClient.exe test-advapi

:: 恢复所有 hook（驱动仍运行，新进程仍会被 hook）
ShutdownHookClient.exe unhook
```

### 4.4 使用独立测试程序

```cmd
:: 编译测试程序（在 VS Developer Prompt 中）
cl /nologo test_shutdown.c user32.lib advapi32.lib

:: 运行
test_shutdown.exe
```

选择菜单项测试不同的关机 API。如果 hook 生效，调用会返回 TRUE 但系统不会关机。

## 5. 验证拦截效果

### 5.1 功能验证

1. 启动驱动后，运行 `ShutdownHookClient.exe status`
   - 应看到 `HookedCount > 0`（至少当前进程和 explorer.exe 被 hook）
2. 运行 `ShutdownHookClient.exe test`
   - 调用 `ExitWindowsEx(EWX_LOGOFF, 0)`
   - 如果返回 TRUE 且系统没有注销，说明拦截成功
3. 打开"开始菜单 → 电源 → 关机"
   - 如果系统没有关机，说明 explorer.exe 中的调用也被拦截

### 5.2 覆盖率验证

运行 `ShutdownHookClient.exe list` 查看所有进程的 hook 状态：
- `HOOKED` — 成功拦截
- `FAILED` — 拦截失败（查看 `failures` 命令了解原因）
- `PENDING` — 等待 worker 线程处理

常见失败原因：
- `Protect change failed (ACG?)` — 进程启用了 Arbitrary Code Guard（如 Edge、Chrome）
- `Write memory failed (PPL?)` — 受保护进程（如 csrss、lsass、Defender）
- `Module not found` — 进程未加载 user32.dll/advapi32.dll（如纯控制台进程）
- `Wow64 unsupported` — 32位进程（当前版本仅完整支持64位）

### 5.3 新进程验证

驱动加载后启动新程序（如 notepad.exe），然后运行 `list`：
- notepad.exe 应该出现在列表中且状态为 HOOKED
- 这验证了 `PsSetLoadImageNotifyRoutine` 回调正常工作

## 6. 内核调试（可选）

### 6.1 通过串口连接 WinDbg

1. VM 中已配置 `bcdedit /debug on` 和串口设置
2. 宿主机上启动 WinDbg（需要 Windows 虚拟机或双系统）：
   ```
   WinDbg.exe -k com:port=\\.\pipe\gsh_serial,baud=115200
   ```
   （Linux 上可用 `minicom` 或 `socat` 连接 `/tmp/gsh_serial`）

3. 在驱动代码中使用 `DbgPrint` 输出调试信息
4. WinDbg 中启用调试输出：`ed nt!Kd_DEFAULT_MASK 0xFFFFFFFF`

### 6.2 常用 WinDbg 命令

```
!drvobj GlobalShutdownHook 2   ; 查看驱动对象
!process 0 0                    ; 列出进程
bp GlobalShutdownHook!HookPerform  ; 下断点
g                               ; 继续
dds poi(peb+18)                ; 查看 LDR（在 attach 后）
u user32!ExitWindowsEx L10     ; 反汇编查看 hook 是否生效
```

### 6.3 验证 hook 字节

在 WinDbg 中 attach 到某个进程后：

```
.process /r /p <EPROCESS地址>
u user32!ExitWindowsEx L2
```

如果 hook 生效，应看到：
```
mov rax, 1
ret
```
而不是正常的函数 prologue。

## 7. 卸载驱动

```cmd
:: 停止驱动（会自动恢复所有 hook）
sc stop GSH

:: 删除服务
sc delete GSH
```

驱动卸载时会：
1. 停止工作线程
2. 取消 LoadImage 回调
3. 恢复所有被 hook 的函数（写回原始字节）
4. 删除设备对象

## 8. 故障排查

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| `sc start` 失败，错误 577 | 驱动未签名 / testsigning 未开 | `bcdedit /set testsigning on` 后重启 |
| `sc start` 失败，错误 2 | 驱动路径错误 | 检查 binPath 路径是否正确 |
| 蓝屏 (BSOD) | hook 时访问了无效内存 | 用 WinDbg 查看崩溃转储，检查 attach 和内存访问逻辑 |
| HookedCount 为 0 | worker 线程未启动 / 所有进程都失败 | 查看 DbgPrint 输出，检查失败日志 |
| 某些进程未被拦截 | ACG / PPL / Wow64 | 查看失败日志，这些是预期的限制 |
| 新进程未被 hook | LoadImage 回调未注册 | 检查 `PsSetLoadImageNotifyRoutine` 返回值 |

## 9. 性能测试

在 VM 中可以观察：
- 驱动加载时间（`sc start` 到 worker 处理完所有进程）
- 内存占用（任务管理器 → 详细信息 → 查看非分页池使用）
- 系统稳定性（长时间运行是否有蓝屏或性能下降）

建议测试场景：
1. 冷启动后加载驱动，统计 hook 成功率
2. 驱动运行时反复启动/关闭大量程序
3. 运行 24 小时稳定性测试
4. 在不同 Windows 版本上测试（Win10 21H2/22H2, Win11 21H2/22H2/23H2）

/*
 * gsh_infinityhook.h - InfinityHook 系统调用拦截框架接口
 *
 * 基于 zhutingxf/InfinityHookPro，通过 ETW CKCL trace 机制拦截系统调用。
 * 支持 Win7 - Win11 全版本，虚拟机和物理机环境。
 *
 * 拦截目标：
 *   - NtUnloadDriver      阻止卸载驱动
 *   - NtTerminateProcess  阻止关闭 BgSrv
 *   - NtShutdownSystem    阻止关机
 *   - NtInitiatePowerAction 阻止关机/休眠
 */
#pragma once

#include <ntddk.h>

/* 初始化 InfinityHook 并开始拦截 */
NTSTATUS InfinityHookInitialize(VOID);

/* 停止拦截并清理 */
VOID InfinityHookShutdown(VOID);

/* 查询拦截统计 */
ULONG InfinityHookGetBlockedCount(VOID);

/* 设置 BgSrv 进程 PID (用于 NtTerminateProcess 过滤) */
VOID InfinityHookSetBgSrvPid(HANDLE pid);

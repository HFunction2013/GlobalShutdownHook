/*
 * GlobalShutdownHook - 公共定义（驱动与用户态共享）
 *
 * 拦截 user32!ExitWindowsEx 和 advapi32!InitiateSystemShutdownEx(A/W)
 * 内核 inline-hook 用户态函数，不涉及 PatchGuard。
 */
#ifndef GSH_COMMON_H
#define GSH_COMMON_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>

/* ntifs.h redefines PEPROCESS/PETHREAD in some SDK versions (C2371),
   causing cascading syntax errors. Manually declare the two functions
   we need instead of including the full ntifs.h header. */
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
    );

/* STATUS_PROTECTION_VIOLATION may not exist in all SDK versions. */
#ifndef STATUS_PROTECTION_VIOLATION
#define STATUS_PROTECTION_VIOLATION  ((NTSTATUS)0xC0000005L)
#endif

/* KAPC_STATE may not be defined in all SDK wdm.h versions */
#ifndef _KAPC_STATE_DEFINED
#define _KAPC_STATE_DEFINED
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PVOID      Process;
    BOOLEAN    KernelApcInProgress;
    BOOLEAN    KernelApcPending;
    BOOLEAN    UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
#endif

/* KeStackAttachProcess / KeUnstackDetachProcess may be missing in some SDKs */
NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_   PRKAPC_STATE ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
    );

/* PsGetProcessImageFileName may be missing in some SDKs */
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );
#else
#include <windows.h>
#endif

/* ---- 设备与符号链接 ---- */
#define GSH_DEVICE_NAME  L"\\Device\\GlobalShutdownHook"
#define GSH_SYMLINK_NAME L"\\DosDevices\\GlobalShutdownHook"
#define GSH_WIN32_NAME   L"\\\\.\\GlobalShutdownHook"

/* ---- IOCTL 码 ---- */
#define GSH_IOCTL_BASE 0x800

#define IOCTL_GSH_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GSH_GET_FAIL_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GSH_CLEAR_FAIL_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GSH_UNHOOK_ALL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GSH_GET_HOOKED_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_GET_QUEUE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_LOCK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_UNLOCK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_SET_PASS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_RM_PASS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_SHUTDOWN_NOW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GSH_QUERY_LOCK_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, GSH_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- 目标函数 ID ---- */
#define FUNC_EXIT_WINDOWS_EX                0
#define FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A  1
#define FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W  2
#define FUNC_COUNT                          3

/* ---- Hook 状态 ---- */
#define HOOK_STATE_NONE       0
#define HOOK_STATE_NEED_HOOK  1
#define HOOK_STATE_HOOKED     2
#define HOOK_STATE_FAILED     3

/* ---- 锁状态 ---- */
#define GSH_LOCKED    1
#define GSH_UNLOCKED  0

/* ---- 密码最大长度 ---- */
#define GSH_MAX_PASS_LEN  64

/* ---- 失败原因码 ---- */
#define FAIL_PROCESS_TERMINATED    0x01
#define FAIL_MODULE_NOT_FOUND      0x02
#define FAIL_EXPORT_NOT_FOUND      0x03
#define FAIL_ATTACH_FAILED         0x04
#define FAIL_PROTECT_CHANGE        0x05
#define FAIL_WRITE_MEMORY          0x06
#define FAIL_ALLOC_MEMORY          0x07
#define FAIL_THREAD_SUSPEND        0x08
#define FAIL_PROTECTED_PROCESS     0x09
#define FAIL_WOW64_UNSUPPORTED     0x0A
#define FAIL_PEEK_MEMORY           0x0B
#define FAIL_UNKNOWN               0xFF

/* ---- 常量 ---- */
#define GSH_MAX_FAIL_RECORDS   1024
#define GSH_MAX_HOOK_ENTRIES   4096
#define GSH_PROCESS_NAME_LEN   16
#define GSH_MODULE_NAME_LEN    32
#define GSH_HOOK_BYTE_COUNT    8   /* 覆盖的字节数：64位 mov rax,1+ret 或 32位 mov eax,1+ret+nop */

/* ---- 数据结构 ---- */
#pragma pack(push, 8)

typedef struct _GSH_FAIL_RECORD {
    ULONG         Pid;
    ULONG         FunctionId;
    ULONG         FailReason;
    ULONG         Reserved;
    LARGE_INTEGER Timestamp;
    WCHAR         ProcessName[GSH_PROCESS_NAME_LEN];
    WCHAR         ModuleName[GSH_MODULE_NAME_LEN];
} GSH_FAIL_RECORD, *PGSH_FAIL_RECORD;

typedef struct _GSH_DRIVER_STATUS {
    ULONG TotalProcessesSeen;
    ULONG HookedCount;
    ULONG FailedCount;
    ULONG PendingCount;
    ULONG FailLogCount;
    ULONG Reserved[3];
} GSH_DRIVER_STATUS, *PGSH_DRIVER_STATUS;

typedef struct _GSH_HOOKED_ENTRY {
    ULONG Pid;
    ULONG FunctionId;
    ULONG State;
    ULONG Reserved;
    WCHAR ProcessName[GSH_PROCESS_NAME_LEN];
    WCHAR ModuleName[GSH_MODULE_NAME_LEN];
} GSH_HOOKED_ENTRY, *PGSH_HOOKED_ENTRY;

/* 变长输出：Count 后跟 Count 条记录 */
typedef struct _GSH_FAIL_LOG_OUTPUT {
    ULONG Count;
    GSH_FAIL_RECORD Records[1];
} GSH_FAIL_LOG_OUTPUT;

typedef struct _GSH_HOOKED_LIST_OUTPUT {
    ULONG Count;
    GSH_HOOKED_ENTRY Entries[1];
} GSH_HOOKED_LIST_OUTPUT;

/* 工作队列条目（待处理的 hook 任务） */
typedef struct _GSH_QUEUE_ENTRY {
    ULONG Pid;
    ULONG FunctionId;
    WCHAR ModuleName[GSH_MODULE_NAME_LEN];
} GSH_QUEUE_ENTRY, *PGSH_QUEUE_ENTRY;

typedef struct _GSH_QUEUE_OUTPUT {
    ULONG Count;
    GSH_QUEUE_ENTRY Entries[1];
} GSH_QUEUE_OUTPUT;

/* 密码输入：旧密码 + 新密码（set_pass 用；rm_pass 只用 OldPassword） */
typedef struct _GSH_PASSWORD_INPUT {
    WCHAR OldPassword[GSH_MAX_PASS_LEN];
    WCHAR NewPassword[GSH_MAX_PASS_LEN];
} GSH_PASSWORD_INPUT, *PGSH_PASSWORD_INPUT;

/* 锁状态查询输出 */
typedef struct _GSH_LOCK_STATUS {
    ULONG LockState;       /* GSH_LOCKED / GSH_UNLOCKED */
    ULONG PasswordSet;     /* 1 = 密码已设置, 0 = 无密码 */
    ULONG HookedCount;
    ULONG FailedCount;
    ULONG PendingCount;
    ULONG BlockedCount;    /* 被拦截的关机次数统计 */
    ULONG Reserved[2];
} GSH_LOCK_STATUS, *PGSH_LOCK_STATUS;

#pragma pack(pop)

#endif /* GSH_COMMON_H */

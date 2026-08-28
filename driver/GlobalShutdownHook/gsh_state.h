/*
 * gsh_state.h - (PID, Module, Function) Hook 状态表
 *
 * 用全局链表 + 自旋锁管理所有 hook 条目，支持：
 *   - 查询是否已入队/已 hook（去重）
 *   - 插入新条目
 *   - 更新状态
 *   - 遍历（用于卸载时恢复、用户态查询）
 */
#ifndef GSH_STATE_H
#define GSH_STATE_H

#include "gsh_common.h"

typedef struct _GSH_HOOK_ENTRY {
    LIST_ENTRY     ListEntry;
    HANDLE         Pid;
    ULONG          FunctionId;
    ULONG          State;
    PVOID          TargetAddress;       /* 用户态函数地址 */
    UCHAR          OriginalBytes[GSH_HOOK_BYTE_COUNT];
    ULONG          OriginalProtection;  /* 原内存保护属性 */
    PEPROCESS      Process;             /* 引用的 EPROCESS，恢复时用 */
    BOOLEAN        IsWow64;
    WCHAR          ProcessName[GSH_PROCESS_NAME_LEN];
    WCHAR          ModuleName[GSH_MODULE_NAME_LEN];
} GSH_HOOK_ENTRY, *PGSH_HOOK_ENTRY;

VOID     StateInitialize(VOID);
VOID     StateDestroy(VOID);

/* 查找条目；不存在返回 NULL */
PGSH_HOOK_ENTRY StateFind(HANDLE Pid, ULONG FunctionId);

/* 查找或创建条目（原子操作，返回已存在或新建的条目） */
PGSH_HOOK_ENTRY StateFindOrCreate(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId);

/* 更新状态 */
VOID     StateSetState(PGSH_HOOK_ENTRY Entry, ULONG NewState);

/* 统计 */
VOID     StateGetCounts(PULONG Hooked, PULONG Failed, PULONG Pending, PULONG Total);

/* 遍历回调：返回 FALSE 停止遍历 */
typedef BOOLEAN (*GSH_STATE_ENUM_CALLBACK)(PGSH_HOOK_ENTRY Entry, PVOID Context);
VOID     StateEnumerate(GSH_STATE_ENUM_CALLBACK Callback, PVOID Context);

/* 移除并释放一个条目（调用者需确保不再使用） */
VOID     StateRemove(PGSH_HOOK_ENTRY Entry);

#endif /* GSH_STATE_H */

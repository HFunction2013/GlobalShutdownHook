/*
 * gsh_worker.h - 工作队列与工作线程
 *
 * LoadImage 回调和进程枚举只负责入队（可能在 DISPATCH_LEVEL），
 * 实际 inline-hook 由系统工作线程在 PASSIVE_LEVEL 执行。
 */
#ifndef GSH_WORKER_H
#define GSH_WORKER_H

#include "gsh_common.h"

typedef struct _GSH_WORK_ITEM {
    LIST_ENTRY ListEntry;
    HANDLE     Pid;
    ULONG     FunctionId;
    WCHAR     ModuleName[GSH_MODULE_NAME_LEN];
} GSH_WORK_ITEM, *PGSH_WORK_ITEM;

NTSTATUS WorkerInitialize(VOID);
VOID     WorkerShutdown(VOID);

/* 入队（可在 DISPATCH_LEVEL 调用） */
VOID     WorkerEnqueue(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId);

/* 工作线程主循环（内部使用） */
VOID     WorkerThreadRoutine(PVOID Context);

/* 查询当前队列中的待处理任务（返回条目数） */
ULONG    WorkerGetQueue(PGSH_QUEUE_ENTRY Buffer, ULONG MaxCount);
#endif /* GSH_WORKER_H */

/*
 * gsh_worker.c - 工作队列与工作线程
 */
#include "gsh_worker.h"
#include "gsh_hook.h"
#include "gsh_state.h"
#include "gsh_faillog.h"
#include "gsh_pe.h"

static LIST_ENTRY      g_WorkQueue;
static KSPIN_LOCK      g_WorkQueueLock;
static KEVENT          g_WorkEvent;
static volatile BOOLEAN g_WorkerRunning = FALSE;
static PVOID           g_WorkerThreadObj = NULL;

NTSTATUS WorkerInitialize(VOID)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;

    InitializeListHead(&g_WorkQueue);
    KeInitializeSpinLock(&g_WorkQueueLock);
    KeInitializeEvent(&g_WorkEvent, NotificationEvent, FALSE);

    g_WorkerRunning = TRUE;

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        WorkerThreadRoutine,
        NULL);

    if (!NT_SUCCESS(status)) {
        g_WorkerRunning = FALSE;
        return status;
    }

    /* 获取线程对象指针，便于等待 */
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        KernelMode,
        &g_WorkerThreadObj,
        NULL);

    ZwClose(threadHandle);
    return status;
}

VOID WorkerShutdown(VOID)
{
    g_WorkerRunning = FALSE;
    KeSetEvent(&g_WorkEvent, IO_NO_INCREMENT, FALSE);

    if (g_WorkerThreadObj) {
        KeWaitForSingleObject(g_WorkerThreadObj, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThreadObj);
        g_WorkerThreadObj = NULL;
    }

    /* 清空队列 */
    KIRQL irql;
    KeAcquireSpinLock(&g_WorkQueueLock, &irql);
    while (!IsListEmpty(&g_WorkQueue)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_WorkQueue);
        PGSH_WORK_ITEM item = CONTAINING_RECORD(entry, GSH_WORK_ITEM, ListEntry);
        ExFreePoolWithTag(item, 'WShG');
    }
    KeReleaseSpinLock(&g_WorkQueueLock, irql);
}

VOID WorkerEnqueue(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId)
{
    PGSH_WORK_ITEM item;
    KIRQL irql;

    if (!g_WorkerRunning) return;

    item = (PGSH_WORK_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(GSH_WORK_ITEM), 'WShG');
    if (!item) return;

    RtlZeroMemory(item, sizeof(GSH_WORK_ITEM));
    item->Pid = Pid;
    item->FunctionId = FunctionId;
    if (ModuleName) {
        RtlCopyMemory(item->ModuleName, ModuleName,
                      min(wcslen(ModuleName) + 1, GSH_MODULE_NAME_LEN) * sizeof(WCHAR));
    }

    KeAcquireSpinLock(&g_WorkQueueLock, &irql);
    InsertTailList(&g_WorkQueue, &item->ListEntry);
    KeReleaseSpinLock(&g_WorkQueueLock, irql);

    KeSetEvent(&g_WorkEvent, IO_NO_INCREMENT, FALSE);
}

VOID WorkerThreadRoutine(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    while (g_WorkerRunning) {
        PGSH_WORK_ITEM item = NULL;
        KIRQL irql;

        KeAcquireSpinLock(&g_WorkQueueLock, &irql);
        if (!IsListEmpty(&g_WorkQueue)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_WorkQueue);
            item = CONTAINING_RECORD(entry, GSH_WORK_ITEM, ListEntry);
        }
        KeReleaseSpinLock(&g_WorkQueueLock, irql);

        if (item) {
            /* 执行实际 hook */
            NTSTATUS hookStatus = HookPerform(item->Pid, item->ModuleName, item->FunctionId);

            /* 对真实失败记录日志（模块未加载/进程已退出属于正常情况，不记录） */
            if (!NT_SUCCESS(hookStatus) &&
                hookStatus != STATUS_NOT_FOUND &&
                hookStatus != STATUS_PROCESS_IS_TERMINATING &&
                hookStatus != STATUS_INVALID_PARAMETER) {

                ULONG reason = FAIL_UNKNOWN;
                switch (hookStatus) {
                    case STATUS_ACCESS_DENIED:       reason = FAIL_PROTECTED_PROCESS; break;
                    case STATUS_INVALID_PAGE_PROTECTION:
                    case STATUS_PROTECTION_VIOLATION: reason = FAIL_PROTECT_CHANGE; break;
                    case STATUS_NOT_SUPPORTED:        reason = FAIL_WOW64_UNSUPPORTED; break;
                    case STATUS_INSUFFICIENT_RESOURCES: reason = FAIL_ALLOC_MEMORY; break;
                    default:                           reason = FAIL_UNKNOWN; break;
                }

                /* 获取进程名用于日志 */
                WCHAR procName[GSH_PROCESS_NAME_LEN] = {0};
                PEPROCESS tmpProc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId(item->Pid, &tmpProc))) {
                    PeGetProcessName(tmpProc, procName, GSH_PROCESS_NAME_LEN);
                    ObDereferenceObject(tmpProc);
                }

                FailLogAdd(item->Pid, procName, item->ModuleName,
                           item->FunctionId, reason);

                /* 更新状态表为失败 */
                PGSH_HOOK_ENTRY he = StateFind(item->Pid, item->FunctionId);
                if (he) {
                    StateSetState(he, HOOK_STATE_FAILED);
                }

                DbgPrint("GSH: Hook failed PID=%lu func=%s reason=0x%X\n",
                         PtrToUint(item->Pid), HookGetFunctionName(item->FunctionId), hookStatus);
            }

            ExFreePoolWithTag(item, 'WShG');
        } else {
            /* 队列空，等待新任务 */
            KeWaitForSingleObject(&g_WorkEvent, Executive, KernelMode, FALSE, NULL);
            KeClearEvent(&g_WorkEvent);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

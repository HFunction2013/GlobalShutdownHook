/*
 * gsh_faillog.c - 失败记录环形缓冲区
 */
#include "gsh_faillog.h"

static GSH_FAIL_RECORD g_FailRecords[GSH_MAX_FAIL_RECORDS];
static volatile LONG   g_FailWriteIndex = 0;  /* 下一个写入位置 */
static volatile LONG   g_FailCount = 0;       /* 总记录数（可能超过容量） */
static KSPIN_LOCK      g_FailLock;

VOID FailLogInitialize(VOID)
{
    RtlZeroMemory(g_FailRecords, sizeof(g_FailRecords));
    g_FailWriteIndex = 0;
    g_FailCount = 0;
    KeInitializeSpinLock(&g_FailLock);
}

VOID FailLogDestroy(VOID)
{
    /* 静态分配，无需释放 */
}

VOID FailLogAdd(HANDLE Pid, PCWSTR ProcessName, PCWSTR ModuleName,
                ULONG FunctionId, ULONG FailReason)
{
    KIRQL irql;
    LONG idx;
    PGSH_FAIL_RECORD rec;

    KeAcquireSpinLock(&g_FailLock, &irql);

    idx = g_FailWriteIndex % GSH_MAX_FAIL_RECORDS;
    rec = &g_FailRecords[idx];

    rec->Pid = PtrToUint(Pid);
    rec->FunctionId = FunctionId;
    rec->FailReason = FailReason;
    rec->Reserved = 0;
    KeQuerySystemTime(&rec->Timestamp);

    RtlZeroMemory(rec->ProcessName, sizeof(rec->ProcessName));
    RtlZeroMemory(rec->ModuleName, sizeof(rec->ModuleName));

    if (ProcessName) {
        RtlCopyMemory(rec->ProcessName, ProcessName,
                      min(wcslen(ProcessName) + 1, GSH_PROCESS_NAME_LEN) * sizeof(WCHAR));
    }
    if (ModuleName) {
        RtlCopyMemory(rec->ModuleName, ModuleName,
                      min(wcslen(ModuleName) + 1, GSH_MODULE_NAME_LEN) * sizeof(WCHAR));
    }

    g_FailWriteIndex++;
    if (g_FailCount < GSH_MAX_FAIL_RECORDS) {
        g_FailCount++;
    }

    KeReleaseSpinLock(&g_FailLock, irql);
}

ULONG FailLogGet(PGSH_FAIL_RECORD Buffer, ULONG MaxCount)
{
    KIRQL irql;
    ULONG count, i, start;

    if (!Buffer || MaxCount == 0) return 0;

    KeAcquireSpinLock(&g_FailLock, &irql);

    count = (ULONG)min(g_FailCount, (LONG)MaxCount);

    /* 从最旧的记录开始复制 */
    if (g_FailCount >= GSH_MAX_FAIL_RECORDS) {
        start = g_FailWriteIndex % GSH_MAX_FAIL_RECORDS;
    } else {
        start = 0;
    }

    for (i = 0; i < count; i++) {
        ULONG srcIdx = (start + i) % GSH_MAX_FAIL_RECORDS;
        RtlCopyMemory(&Buffer[i], &g_FailRecords[srcIdx], sizeof(GSH_FAIL_RECORD));
    }

    KeReleaseSpinLock(&g_FailLock, irql);
    return count;
}

ULONG FailLogCount(VOID)
{
    return (ULONG)g_FailCount;
}

VOID FailLogClear(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_FailLock, &irql);
    g_FailWriteIndex = 0;
    g_FailCount = 0;
    RtlZeroMemory(g_FailRecords, sizeof(g_FailRecords));
    KeReleaseSpinLock(&g_FailLock, irql);
}

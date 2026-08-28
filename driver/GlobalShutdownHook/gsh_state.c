/*
 * gsh_state.c - Hook 状态表实现
 */
#include "gsh_state.h"

static LIST_ENTRY g_StateList;
static KSPIN_LOCK g_StateLock;
static ULONG      g_TotalSeen = 0;

VOID StateInitialize(VOID)
{
    InitializeListHead(&g_StateList);
    KeInitializeSpinLock(&g_StateLock);
    g_TotalSeen = 0;
}

VOID StateDestroy(VOID)
{
    KIRQL irql;
    PLIST_ENTRY entry, next;

    KeAcquireSpinLock(&g_StateLock, &irql);
    entry = g_StateList.Flink;
    while (entry != &g_StateList) {
        next = entry->Flink;
        PGSH_HOOK_ENTRY he = CONTAINING_RECORD(entry, GSH_HOOK_ENTRY, ListEntry);
        if (he->Process) {
            ObDereferenceObject(he->Process);
        }
        ExFreePoolWithTag(he, 'HShG');
        entry = next;
    }
    InitializeListHead(&g_StateList);
    KeReleaseSpinLock(&g_StateLock, irql);
}

PGSH_HOOK_ENTRY StateFind(HANDLE Pid, ULONG FunctionId)
{
    KIRQL irql;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&g_StateLock, &irql);
    entry = g_StateList.Flink;
    while (entry != &g_StateList) {
        PGSH_HOOK_ENTRY he = CONTAINING_RECORD(entry, GSH_HOOK_ENTRY, ListEntry);
        if (he->Pid == Pid && he->FunctionId == FunctionId) {
            KeReleaseSpinLock(&g_StateLock, irql);
            return he;
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&g_StateLock, irql);
    return NULL;
}

PGSH_HOOK_ENTRY StateFindOrCreate(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    PGSH_HOOK_ENTRY he;

    KeAcquireSpinLock(&g_StateLock, &irql);

    /* 先查找 */
    entry = g_StateList.Flink;
    while (entry != &g_StateList) {
        he = CONTAINING_RECORD(entry, GSH_HOOK_ENTRY, ListEntry);
        if (he->Pid == Pid && he->FunctionId == FunctionId) {
            KeReleaseSpinLock(&g_StateLock, irql);
            return he;
        }
        entry = entry->Flink;
    }

    /* 不存在，创建 */
    he = (PGSH_HOOK_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(GSH_HOOK_ENTRY), 'HShG');
    if (!he) {
        KeReleaseSpinLock(&g_StateLock, irql);
        return NULL;
    }
    RtlZeroMemory(he, sizeof(GSH_HOOK_ENTRY));
    he->Pid = Pid;
    he->FunctionId = FunctionId;
    he->State = HOOK_STATE_NEED_HOOK;
    he->TargetAddress = NULL;
    he->Process = NULL;
    he->IsWow64 = FALSE;

    if (ModuleName) {
        RtlCopyMemory(he->ModuleName, ModuleName,
                      min(wcslen(ModuleName) + 1, GSH_MODULE_NAME_LEN) * sizeof(WCHAR));
    }

    InsertTailList(&g_StateList, &he->ListEntry);
    g_TotalSeen++;

    KeReleaseSpinLock(&g_StateLock, irql);
    return he;
}

VOID StateSetState(PGSH_HOOK_ENTRY Entry, ULONG NewState)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_StateLock, &irql);
    Entry->State = NewState;
    KeReleaseSpinLock(&g_StateLock, irql);
}

VOID StateGetCounts(PULONG Hooked, PULONG Failed, PULONG Pending, PULONG Total)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    ULONG h = 0, f = 0, p = 0;

    KeAcquireSpinLock(&g_StateLock, &irql);
    entry = g_StateList.Flink;
    while (entry != &g_StateList) {
        PGSH_HOOK_ENTRY he = CONTAINING_RECORD(entry, GSH_HOOK_ENTRY, ListEntry);
        switch (he->State) {
            case HOOK_STATE_HOOKED: h++; break;
            case HOOK_STATE_FAILED: f++; break;
            case HOOK_STATE_NEED_HOOK: p++; break;
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&g_StateLock, irql);

    if (Hooked)  *Hooked = h;
    if (Failed)  *Failed = f;
    if (Pending) *Pending = p;
    if (Total)   *Total = g_TotalSeen;
}

VOID StateEnumerate(GSH_STATE_ENUM_CALLBACK Callback, PVOID Context)
{
    KIRQL irql;
    PLIST_ENTRY entry;

    if (!Callback) return;

    KeAcquireSpinLock(&g_StateLock, &irql);
    entry = g_StateList.Flink;
    while (entry != &g_StateList) {
        PGSH_HOOK_ENTRY he = CONTAINING_RECORD(entry, GSH_HOOK_ENTRY, ListEntry);
        PLIST_ENTRY next = entry->Flink;
        KeReleaseSpinLock(&g_StateLock, irql);

        if (!Callback(he, Context)) {
            return;
        }

        KeAcquireSpinLock(&g_StateLock, &irql);
        entry = next;
    }
    KeReleaseSpinLock(&g_StateLock, irql);
}

VOID StateRemove(PGSH_HOOK_ENTRY Entry)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_StateLock, &irql);
    if (!IsListEmpty(&Entry->ListEntry)) {
        RemoveEntryList(&Entry->ListEntry);
    }
    KeReleaseSpinLock(&g_StateLock, irql);

    if (Entry->Process) {
        ObDereferenceObject(Entry->Process);
    }
    ExFreePoolWithTag(Entry, 'HShG');
}

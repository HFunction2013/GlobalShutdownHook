/*
 * gsh_hook.c - inline hook 核心
 *
 * 流程：
 *   1. PsLookupProcessByProcessId
 *   2. KeStackAttachProcess
 *   3. PeGetModuleBase → PeFindExport
 *   4. 保存原始字节
 *   5. ZwProtectVirtualMemory 改为 RWX
 *   6. 写入 hook 字节（mov eax/rax, 1; ret）
 *   7. 恢复原保护属性
 *   8. 记录状态 / 失败日志
 *   9. KeUnstackDetachProcess
 */
#include "gsh_hook.h"
#include "gsh_pe.h"
#include "gsh_faillog.h"

/* ---- 需手动声明的 API ---- */
NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

#define PAGE_EXECUTE_READWRITE 0x40

/* ---- Hook 字节模板 ---- */
/* 64 位：48 C7 C0 01 00 00 00 C3  = mov rax, 1; ret */
static const UCHAR g_HookBytes64[GSH_HOOK_BYTE_COUNT] = {
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3
};
/* 32 位：B8 01 00 00 00 C3 90 90  = mov eax, 1; ret; nop; nop */
static const UCHAR g_HookBytes32[GSH_HOOK_BYTE_COUNT] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90
};

/* ---- 辅助：安全写用户态内存 ---- */
static NTSTATUS SafeWrite(PVOID Dst, PVOID Src, SIZE_T Size)
{
    if (!Dst || !Src || Size == 0) return STATUS_INVALID_PARAMETER;
    __try {
        ProbeForWrite(Dst, Size, 1);
        RtlCopyMemory(Dst, Src, Size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

/* ---- 公开：函数名/模块名映射 ---- */
PCWSTR HookGetFunctionName(ULONG FunctionId)
{
    switch (FunctionId) {
        case FUNC_EXIT_WINDOWS_EX:               return L"ExitWindowsEx";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A: return L"InitiateSystemShutdownExA";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W: return L"InitiateSystemShutdownExW";
        default:                                 return L"Unknown";
    }
}

PCWSTR HookGetModuleName(ULONG FunctionId)
{
    switch (FunctionId) {
        case FUNC_EXIT_WINDOWS_EX:               return L"user32.dll";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A: return L"advapi32.dll";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W: return L"advapi32.dll";
        default:                                 return L"unknown.dll";
    }
}

PCSTR HookGetExportName(ULONG FunctionId)
{
    switch (FunctionId) {
        case FUNC_EXIT_WINDOWS_EX:               return "ExitWindowsEx";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A: return "InitiateSystemShutdownExA";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W: return "InitiateSystemShutdownExW";
        default:                                 return "";
    }
}

/* ---- 核心：执行 hook ---- */
NTSTATUS HookPerform(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    KAPC_STATE apcState;
    PVOID moduleBase = NULL;
    PVOID funcAddr = NULL;
    BOOLEAN isWow64 = FALSE;
    UCHAR originalBytes[GSH_HOOK_BYTE_COUNT];
    ULONG oldProtect = 0;
    SIZE_T regionSize = GSH_HOOK_BYTE_COUNT;
    PVOID targetAddr = NULL;
    WCHAR processName[GSH_PROCESS_NAME_LEN] = {0};
    PGSH_HOOK_ENTRY entry = NULL;

    UNREFERENCED_PARAMETER(ModuleName);

    /* 0. 快速检查：如果已经 hook 成功，跳过（去重） */
    {
        PGSH_HOOK_ENTRY existing = StateFind(Pid, FunctionId);
        if (existing && existing->State == HOOK_STATE_HOOKED) {
            return STATUS_SUCCESS;
        }
    }

    /* 1. 查找进程对象 */
    status = PsLookupProcessByProcessId(Pid, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 检查进程是否已终止 */
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    PeGetProcessName(process, processName, GSH_PROCESS_NAME_LEN);

    /* 跳过系统关键进程（PPL 等），避免写内存失败或系统不稳定 */
    /* 这里不做硬性跳过，让实际写入结果决定 */

    /* 2. Attach 到目标进程 */
    KeStackAttachProcess(process, &apcState);

    /* 3. 获取模块基址 */
    status = PeGetModuleBase(process, HookGetModuleName(FunctionId),
                             &moduleBase, &isWow64);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        /* 模块未加载不算错误，可能是进程还没加载该 DLL */
        return status;
    }

    /* 4. 查找导出函数 */
    status = PeFindExport(moduleBase, HookGetExportName(FunctionId), &funcAddr);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return status;
    }

    targetAddr = funcAddr;

    /* 5. 保存原始字节 */
    __try {
        ProbeForRead(targetAddr, GSH_HOOK_BYTE_COUNT, 1);
        RtlCopyMemory(originalBytes, targetAddr, GSH_HOOK_BYTE_COUNT);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return status;
    }

    /* 6. 修改内存保护为可写 */
    PVOID protectAddr = targetAddr;
    SIZE_T protectSize = GSH_HOOK_BYTE_COUNT;
    status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &protectAddr,
        &protectSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return status;
    }

    /* 7. 写入 hook 字节 */
    const UCHAR *hookBytes = isWow64 ? g_HookBytes32 : g_HookBytes64;
    status = SafeWrite(targetAddr, (PVOID)hookBytes, GSH_HOOK_BYTE_COUNT);

    /* 8. 恢复原保护属性（无论写入成功与否） */
    PVOID restoreAddr = targetAddr;
    SIZE_T restoreSize = GSH_HOOK_BYTE_COUNT;
    ULONG dummyProtect;
    ZwProtectVirtualMemory(NtCurrentProcess(), &restoreAddr, &restoreSize,
                           oldProtect, &dummyProtect);

    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
        return status;
    }

    /* 9. 刷新指令缓存（用户态代码，保险起见） */
    // NtFlushInstructionCache 不需要在 attach 后特别调用，CPU 会自动处理
    // 但跨核心修改代码页时，建议调用
    __try {
        /* 直接使用内核导出的 FlushInstructionCache 等价操作 */
        /* KeInvalidateAllCaches 是内核函数，但可能过于重量级 */
        /* 实际上 x86/x64 是强一致性架构，自修改代码会自动同步 */
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        (VOID)GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    /* 10. 记录到状态表 */
    entry = StateFindOrCreate(Pid, HookGetModuleName(FunctionId), FunctionId);
    if (entry) {
        entry->TargetAddress = targetAddr;
        RtlCopyMemory(entry->OriginalBytes, originalBytes, GSH_HOOK_BYTE_COUNT);
        entry->OriginalProtection = oldProtect;
        entry->IsWow64 = isWow64;
        RtlCopyMemory(entry->ProcessName, processName,
                      (wcslen(processName) + 1) * sizeof(WCHAR));
        /* 转移进程对象引用给状态表（若已有旧引用则先释放） */
        if (entry->Process) {
            ObDereferenceObject(entry->Process);
        }
        entry->Process = process;
        StateSetState(entry, HOOK_STATE_HOOKED);
    } else {
        ObDereferenceObject(process);
    }

    return STATUS_SUCCESS;
}

/* ---- 恢复单个 hook ---- */
NTSTATUS HookRestore(PGSH_HOOK_ENTRY Entry)
{
    NTSTATUS status;
    KAPC_STATE apcState;
    ULONG oldProtect = 0;

    if (!Entry || Entry->State != HOOK_STATE_HOOKED || !Entry->Process) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess(Entry->Process, &apcState);

    /* 改可写 */
    PVOID addr = Entry->TargetAddress;
    SIZE_T size = GSH_HOOK_BYTE_COUNT;
    status = ZwProtectVirtualMemory(NtCurrentProcess(), &addr, &size,
                                    PAGE_EXECUTE_READWRITE, &oldProtect);
    if (NT_SUCCESS(status)) {
        /* 写回原始字节 */
        __try {
            ProbeForWrite(Entry->TargetAddress, GSH_HOOK_BYTE_COUNT, 1);
            RtlCopyMemory(Entry->TargetAddress, Entry->OriginalBytes, GSH_HOOK_BYTE_COUNT);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }

        /* 恢复保护 */
        PVOID addr2 = Entry->TargetAddress;
        SIZE_T size2 = GSH_HOOK_BYTE_COUNT;
        ULONG dummy;
        ZwProtectVirtualMemory(NtCurrentProcess(), &addr2, &size2,
                               Entry->OriginalProtection, &dummy);
    }

    KeUnstackDetachProcess(&apcState);

    if (NT_SUCCESS(status)) {
        StateSetState(Entry, HOOK_STATE_NONE);
    }

    return status;
}

/* ---- 恢复所有 hook ---- */
typedef struct _RESTORE_CTX {
    ULONG Restored;
    ULONG Failed;
} RESTORE_CTX;

static BOOLEAN RestoreCallback(PGSH_HOOK_ENTRY Entry, PVOID Context)
{
    RESTORE_CTX *ctx = (RESTORE_CTX *)Context;
    if (Entry->State == HOOK_STATE_HOOKED) {
        NTSTATUS status = HookRestore(Entry);
        if (NT_SUCCESS(status)) {
            ctx->Restored++;
        } else {
            ctx->Failed++;
        }
    }
    return TRUE;
}

VOID HookRestoreAll(VOID)
{
    RESTORE_CTX ctx = {0, 0};
    StateEnumerate(RestoreCallback, &ctx);
    DbgPrint("GSH: Restored %u hooks, %u failed\n", ctx.Restored, ctx.Failed);
}

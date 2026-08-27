/*
 * gsh_notify.c - 映像加载回调与进程枚举
 *
 * 策略：
 *   - 先注册回调，再枚举进程，避免竞态遗漏
 *   - 回调中只做模块名判断 + 入队（可能在 DISPATCH_LEVEL）
 *   - 枚举时对每个有 PEB 的进程入队，由 Worker 实际检查模块是否加载
 */
#include "gsh_notify.h"
#include "gsh_worker.h"
#include "gsh_hook.h"
#include "gsh_state.h"

/* ---- ZwQuerySystemInformation (documented, zero DKOM) ---- */
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
#define SystemProcessInformation 5

/* Minimal SYSTEM_PROCESS_INFORMATION: only fields we need.
   Layout stable on x64 since Windows XP:
     0x00 NextEntryOffset (ULONG)
     0x04 NumberOfThreads (ULONG)
     0x08 Reserved[48]
     0x38 ImageName (UNICODE_STRING, 16 bytes on x64)
     0x48 BasePriority (LONG)
     0x4C padding (4 bytes for HANDLE alignment)
     0x50 UniqueProcessId (HANDLE) */
typedef struct _SYSTEM_PROCESS_INFORMATION_MIN {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    UCHAR          Reserved1[48];
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    ULONG          Reserved2;  /* padding for HANDLE alignment */
    HANDLE         UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION_MIN, *PSYSTEM_PROCESS_INFORMATION_MIN;

/* ---- 判断路径是否以指定文件名结尾（不区分大小写） ---- */
static BOOLEAN PathEndsWith(PCUNICODE_STRING Path, PCWSTR FileName)
{
    if (!Path || !Path->Buffer || !FileName) return FALSE;

    ULONG nameLen = (ULONG)wcslen(FileName);
    ULONG pathLen = Path->Length / sizeof(WCHAR);

    if (pathLen < nameLen) return FALSE;

    PCWSTR suffix = Path->Buffer + (pathLen - nameLen);
    for (ULONG i = 0; i < nameLen; i++) {
        WCHAR a = suffix[i], b = FileName[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* ---- 根据模块名确定需要 hook 的函数 ID 列表 ---- */
static VOID EnqueueForModule(HANDLE Pid, PCWSTR ModuleName)
{
    if (wcscmp(ModuleName, L"user32.dll") == 0) {
        WorkerEnqueue(Pid, ModuleName, FUNC_EXIT_WINDOWS_EX);
    } else if (wcscmp(ModuleName, L"advapi32.dll") == 0) {
        WorkerEnqueue(Pid, ModuleName, FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A);
        WorkerEnqueue(Pid, ModuleName, FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W);
    }
}

/* ---- PsSetLoadImageNotifyRoutine 回调 ---- */
VOID NotifyImageLoad(PUNICODE_STRING FullImageName,
                     HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    /* ProcessId == 0 表示系统级镜像加载（驱动），忽略 */
    if (ProcessId == 0 || ProcessId == NULL) return;

    /* 只关心 user32.dll 和 advapi32.dll */
    if (PathEndsWith(FullImageName, L"user32.dll")) {
        EnqueueForModule(ProcessId, L"user32.dll");
    } else if (PathEndsWith(FullImageName, L"advapi32.dll")) {
        EnqueueForModule(ProcessId, L"advapi32.dll");
    }
}

/* ---- 注册回调 ---- */
NTSTATUS NotifyRegister(VOID)
{
    return PsSetLoadImageNotifyRoutine(NotifyImageLoad);
}

/* ---- 注销回调 ---- */
VOID NotifyUnregister(VOID)
{
    PsRemoveLoadImageNotifyRoutine(NotifyImageLoad);
}

/* ---- 枚举所有现存进程（双路：ZwQuerySystemInformation + PID 暴力扫描） ----
 *
 * 为什么双路：
 *   ZwQuerySystemInformation 内部遍历 PsActiveProcessHead（EPROCESS 链表），
 *   经典 DKOM 隐藏就是从这个链表摘除 EPROCESS 节点 → 会漏。
 *   PsLookupProcessByProcessId 走 CID 哈希表，被 DKOM 摘除链表的进程
 *   其 PID 仍在 CID 表中（否则进程无法被系统调度/查找）→ 能找到。
 *   两路合并去重，宁可慢也要找全。
 */
#define GSH_PID_SCAN_MAX  0x40000   /* 扫描 PID 上限：262144 */
#define GSH_PID_SCAN_STEP 4          /* PID 总是 4 的倍数 */

static VOID EnqueueProcess(HANDLE Pid)
{
    /* 立即创建 PENDING 状态条目（去重由 StateFindOrCreate 保证） */
    StateFindOrCreate(Pid, L"user32.dll", FUNC_EXIT_WINDOWS_EX);
    StateFindOrCreate(Pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A);
    StateFindOrCreate(Pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W);
    /* 入队由 Worker 实际执行 hook */
    WorkerEnqueue(Pid, L"user32.dll", FUNC_EXIT_WINDOWS_EX);
    WorkerEnqueue(Pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A);
    WorkerEnqueue(Pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W);
}

VOID NotifyEnumerateProcesses(VOID)
{
    NTSTATUS status;
    ULONG bufSize = 0;
    PVOID buffer = NULL;
    ULONG count = 0;
    ULONG hiddenCount = 0;

    /* ====== 第一路：ZwQuerySystemInformation（快速，拿可见进程） ====== */
    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH && bufSize > 0) {
        bufSize += 4096;
        buffer = ExAllocatePoolWithTag(PagedPool, bufSize, 'QSyG');
        if (buffer) {
            ULONG retLen = 0;
            status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufSize, &retLen);
            if (NT_SUCCESS(status)) {
                PSYSTEM_PROCESS_INFORMATION_MIN proc =
                    (PSYSTEM_PROCESS_INFORMATION_MIN)buffer;
                while (TRUE) {
                    HANDLE pid = proc->UniqueProcessId;
                    if (pid != 0) {
                        EnqueueProcess(pid);
                        count++;
                    }
                    if (proc->NextEntryOffset == 0) break;
                    proc = (PSYSTEM_PROCESS_INFORMATION_MIN)
                        ((PUCHAR)proc + proc->NextEntryOffset);
                }
            }
            ExFreePoolWithTag(buffer, 'QSyG');
        }
    }
    DbgPrint("GSH: ZwQuerySystemInformation found %u processes\n", count);

    /* ====== 第二路：PID 暴力扫描（走 CID 表，拿被 DKOM 隐藏的进程） ======
     * 扫描 0..GSH_PID_SCAN_MAX，步长 4（Windows PID 总是 4 的倍数）。
     * PsLookupProcessByProcessId 成功 → 进程存在（即使不在 EPROCESS 链表中）。
     * StateFindOrCreate 自动去重，已处理的 PID 不会重复入队。
     */
    ULONG pidVal;
    for (pidVal = 4; pidVal < GSH_PID_SCAN_MAX; pidVal += GSH_PID_SCAN_STEP) {
        PEPROCESS proc = NULL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pidVal, &proc);
        if (NT_SUCCESS(status)) {
            /* 检查进程是否已终止 */
            if (PsGetProcessExitStatus(proc) == STATUS_PENDING) {
                /* 只统计不在第一路中的（通过 StateFind 去重判断） */
                if (StateFind((HANDLE)(ULONG_PTR)pidVal, FUNC_EXIT_WINDOWS_EX) == NULL) {
                    EnqueueProcess((HANDLE)(ULONG_PTR)pidVal);
                    hiddenCount++;
                }
            }
            ObDereferenceObject(proc);
        }
    }
    DbgPrint("GSH: PID brute-force scan found %u hidden processes (DKOM?)\n", hiddenCount);
    DbgPrint("GSH: Total processes enumerated: %u\n", count + hiddenCount);
}

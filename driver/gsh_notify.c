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

/* ---- 枚举所有现存进程 ---- */
VOID NotifyEnumerateProcesses(VOID)
{
    PEPROCESS process = NULL;
    ULONG count = 0;

    /* 遍历所有进程（从 System 进程开始） */
    process = PsGetNextProcess(NULL);
    while (process) {
        HANDLE pid = PsGetProcessId(process);
        ULONG_PTR exitStatus = PsGetProcessExitStatus(process);

        /* 跳过已终止进程和 System 空闲进程（PID 0/4 通常不加载 user32） */
        if (pid != 0 && exitStatus == STATUS_PENDING) {
            /*
             * 不在这里 attach 检查模块，原因：
             * 1. DriverEntry 中遍历大量进程 + attach 会拖慢启动
             * 2. 由 Worker 线程统一处理，它会 attach 并检查模块是否加载
             * 3. 模块未加载时 Worker 直接返回，不记录失败
             *
             * 对每个进程同时入队 user32 和 advapi32 的检查。
             * 实际是否 hook 由 Worker 决定。
             */
            WorkerEnqueue(pid, L"user32.dll", FUNC_EXIT_WINDOWS_EX);
            WorkerEnqueue(pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A);
            WorkerEnqueue(pid, L"advapi32.dll", FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W);
            count++;
        }

        PEPROCESS next = PsGetNextProcess(process);
        ObDereferenceObject(process);
        process = next;
    }

    DbgPrint("GSH: Enumerated %u processes, enqueued for module check\n", count);
}

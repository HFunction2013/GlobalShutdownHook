/*
 * gsh_infinityhook.c - InfinityHook 系统调用拦截框架实现
 *
 * 基于 zhutingxf/InfinityHookPro (MIT License)
 * 通过 ETW CKCL (Circular Kernel Context Logger) trace 机制拦截系统调用。
 * 替换 CKCL 的 GetCpuClock 函数指针，在每次 syscall 时检查并可重定向。
 *
 * 拦截目标：
 *   - NtUnloadDriver      -> 阻止卸载驱动
 *   - NtTerminateProcess  -> 阻止关闭 BgSrv
 *   - NtShutdownSystem    -> 阻止关机
 *   - NtInitiatePowerAction -> 阻止关机/休眠
 *
 * 函数地址获取优先级：MmGetSystemRoutineAddress > 硬编码 syscall 号
 */
#include "gsh_infinityhook.h"
#include "gsh_lock.h"
#include <ntddk.h>
#include <wdm.h>

/* ============================================================
 *  未文档化结构体定义
 * ============================================================ */

typedef struct _WNODE_HEADER {
    ULONG BufferSize;
    ULONG ProviderId;
    union {
        ULONG64 HistoricalContext;
        struct { ULONG Version; ULONG Linkage; };
    };
    union { HANDLE KernelHandle; LARGE_INTEGER TimeStamp; };
    GUID Guid;
    ULONG ClientContext;
    ULONG Flags;
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    union { LONG AgeLimit; LONG FlushThreshold; } DUMMYUNIONNAME;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERTIES {
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    union { LONG AgeLimit; LONG FlushThreshold; } DUMMYUNIONNAME;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

typedef enum _ETWP_TRACE_TYPE {
    EtwpStartTrace = 1,
    EtwpStopTrace = 2,
    EtwpQueryTrace = 3,
    EtwpUpdateTrace = 4,
    EtwpFlushTrace = 5
} ETWP_TRACE_TYPE;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG_PTR ulModuleCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef void (__fastcall *INFINITY_CALLBACK)(ULONG nCallIndex, PVOID *pCallAddress);

/* ============================================================
 *  跨版本 syscall 号查找表 (从 nt-per-syscall.json 自动生成)
 *  支持 Windows 10 1507 到 Windows 11 24H2 / Server 2025
 * ============================================================ */
typedef struct _SYSCALL_LOOKUP_ENTRY {
    ULONG BuildNumber;
    ULONG NtUnloadDriver;
    ULONG NtTerminateProcess;
    ULONG NtShutdownSystem;
    ULONG NtInitiatePowerAction;
} SYSCALL_LOOKUP_ENTRY, *PSYSCALL_LOOKUP_ENTRY;

static const SYSCALL_LOOKUP_ENTRY g_SyscallLookupTable[] = {
    { 10240, 425, 44, 408, 241 },
    { 10586, 428, 44, 411, 243 },
    { 14393, 434, 44, 417, 245 },
    { 15063, 440, 44, 423, 248 },
    { 16299, 444, 44, 426, 249 },
    { 17134, 446, 44, 428, 250 },
    { 17763, 447, 44, 429, 251 },
    { 18362, 448, 44, 430, 252 },
    { 18363, 448, 44, 430, 252 },
    { 19041, 454, 44, 436, 257 },
    { 19042, 454, 44, 436, 257 },
    { 19043, 454, 44, 436, 257 },
    { 19044, 456, 44, 438, 258 },
    { 19045, 456, 44, 438, 258 },
    { 20348, 462, 44, 444, 262 },
    { 22000, 466, 44, 447, 263 },
    { 22621, 470, 44, 451, 264 },
    { 22631, 470, 44, 451, 264 },
    { 25398, 472, 44, 453, 265 },
    { 26100, 473, 44, 454, 266 },
};
static const ULONG g_SyscallLookupCount = 20;

/* 根据 build number 查找最接近的 syscall 表项 (向下取整) */
static const SYSCALL_LOOKUP_ENTRY* SyscallFindEntry(ULONG buildNumber)
{
    const SYSCALL_LOOKUP_ENTRY* best = NULL;
    for (ULONG i = 0; i < g_SyscallLookupCount; i++) {
        if (g_SyscallLookupTable[i].BuildNumber <= buildNumber) {
            best = &g_SyscallLookupTable[i];
        } else {
            break;
        }
    }
    return best;
}


typedef NTSTATUS (NTAPI *PFN_NtTraceControl)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* ============================================================
 *  全局变量
 * ============================================================ */

static INFINITY_CALLBACK g_InfinityCallback = NULL;
static ULONG g_BuildNumber = 0;
static PVOID g_SystemCallTable = NULL;
static ULONG g_NtoskrnlSize = 0;
static PVOID g_EtwpDebuggerData = NULL;
static PVOID g_CkclWmiLoggerContext = NULL;
static PVOID *g_GetCpuClock = NULL;
static PVOID g_OriginalGetCpuClock = NULL;
static volatile BOOLEAN g_HookActive = FALSE;
static volatile LONG g_BlockedCount = 0;

/* 目标函数地址 */
static PVOID g_pNtUnloadDriver = NULL;
static PVOID g_pNtTerminateProcess = NULL;
static PVOID g_pNtShutdownSystem = NULL;
static PVOID g_pNtInitiatePowerAction = NULL;

/* 目标 syscall 号（后备，当 MmGetSystemRoutineAddress 失败时使用） */
static ULONG g_syscallNtUnloadDriver = 0;
static ULONG g_syscallNtTerminateProcess = 0;
static ULONG g_syscallNtShutdownSystem = 0;
static ULONG g_syscallNtInitiatePowerAction = 0;

/* BgSrv 进程标识（用于 NtTerminateProcess 过滤） */
static HANDLE g_BgSrvPid = NULL;

/* ============================================================
 *  工具函数
 * ============================================================ */

static PFN_NtTraceControl g_pNtTraceControl = NULL;
static PFN_ZwQuerySystemInformation g_pZwQuerySystemInformation = NULL;

/* 获取系统构建号 */
static ULONG GetSystemBuildNumber(VOID)
{
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (NT_SUCCESS(RtlGetVersion(&osvi))) {
        return osvi.dwBuildNumber;
    }
    return 0;
}

/* 获取 ntoskrnl.exe 基址 */
static PVOID GetNtoskrnlBase(VOID)
{
    if (!g_pZwQuerySystemInformation) return NULL;

    ULONG len = 0;
    g_pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    if (len == 0) return NULL;

    PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)
        ExAllocatePoolWithTag(NonPagedPool, len, 'MIFG');
    if (!pMods) return NULL;

    PVOID base = NULL;
    if (NT_SUCCESS(g_pZwQuerySystemInformation(SystemModuleInformation, pMods, len, &len))) {
        if (pMods->ulModuleCount > 0) {
            base = pMods->Modules[0].Base;
            g_NtoskrnlSize = pMods->Modules[0].Size;
        }
    }
    ExFreePoolWithTag(pMods, 'MIFG');
    return base;
}

/* 安全的特征码搜索 - 逐页检查 MmIsAddressValid，防止访问无效内存导致蓝屏 */
static PVOID FindPattern(PVOID base, ULONG size, const UCHAR *pattern, const CHAR *mask)
{
    if (!base || !pattern || !mask) return NULL;
    ULONG patternLen = (ULONG)strlen(mask);
    if (patternLen == 0 || size < patternLen) return NULL;

    PUCHAR pBase = (PUCHAR)base;
    const ULONG pageSize = 0x1000;

    /* 逐页搜索，每页开始前检查有效性 */
    for (ULONG pageStart = 0; pageStart < size; pageStart += pageSize) {
        ULONG pageEnd = pageStart + pageSize;
        if (pageEnd > size) pageEnd = size;

        /* 检查页起始地址是否有效 */
        if (!MmIsAddressValid(pBase + pageStart)) continue;

        /* 在当前页内搜索 */
        ULONG searchEnd = pageEnd;
        if (searchEnd > size - patternLen + 1) searchEnd = size - patternLen + 1;

        for (ULONG i = pageStart; i < searchEnd && i < pageEnd; i++) {
            /* 检查模式匹配范围是否都有效 (可能跨页) */
            BOOLEAN rangeValid = TRUE;
            for (ULONG j = 0; j < patternLen; j += pageSize) {
                if (!MmIsAddressValid(pBase + i + j)) {
                    rangeValid = FALSE;
                    break;
                }
            }
            if (!rangeValid) continue;

            BOOLEAN found = TRUE;
            for (ULONG j = 0; j < patternLen; j++) {
                if (mask[j] != '?' && pBase[i + j] != pattern[j]) {
                    found = FALSE;
                    break;
                }
            }
            if (found) return (PVOID)(pBase + i);
        }
    }
    return NULL;
}

/* 在 ntoskrnl 模块中搜索特征码 - 使用实际模块大小 */
static PVOID FindPatternInNtos(PVOID ntosBase, const UCHAR *pattern, const CHAR *mask)
{
    ULONG searchSize = g_NtoskrnlSize;
    if (searchSize == 0) searchSize = 0x200000; /* 后备：2MB */
    return FindPattern(ntosBase, searchSize, pattern, mask);
}

/* 获取 SSDT (KiServiceTable) 基址 */
/* TODO: 特征码搜索暂时禁用，防止蓝屏。后续改用安全方式获取 KiServiceTable */
static PVOID GetSyscallTable(PVOID ntosBase)
{
    UNREFERENCED_PARAMETER(ntosBase);
    return NULL;
#if 0
    /* 特征码: 4C 8D 15 ?? ?? ?? ??  (lea r10, KiServiceTable) */
    UCHAR pattern[] = { 0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00 };
    CHAR mask[] = "xxx????";
    PVOID found = FindPatternInNtos(ntosBase, pattern, mask);
    if (!found) return NULL;

    /* 计算 RIP 相对地址 */
    LONG offset = *(PLONG)((PUCHAR)found + 3);
    return (PVOID)((PUCHAR)found + 7 + offset);
}

/* ============================================================
 *  CKCL Trace 控制
 * ============================================================ */

static NTSTATUS EventTraceControl(ETWP_TRACE_TYPE nType)
{
    if (!g_pNtTraceControl) return STATUS_NOT_SUPPORTED;

    const ULONG nTag = 'IHFG';
    PCKCL_TRACE_PROPERTIES pProperty = (PCKCL_TRACE_PROPERTIES)
        ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, nTag);
    if (!pProperty) return STATUS_MEMORY_NOT_ALLOCATED;

    PWCHAR szProviderName = (PWCHAR)
        ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), nTag);
    if (!szProviderName) {
        ExFreePoolWithTag(pProperty, nTag);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(pProperty, PAGE_SIZE);
    RtlZeroMemory(szProviderName, 256 * sizeof(WCHAR));
    RtlCopyMemory(szProviderName, L"Circular Kernel Context Logger",
                   sizeof(L"Circular Kernel Context Logger"));
    RtlInitUnicodeString(&pProperty->ProviderName, szProviderName);

    GUID guidCkclSession = { 0x54dea73a, 0xed1f, 0x42a4,
        { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

    pProperty->Wnode.BufferSize = PAGE_SIZE;
    pProperty->Wnode.Flags = 0x00020000; /* WNODE_FLAG_TRACED_GUID */
    pProperty->Wnode.Guid = guidCkclSession;
    pProperty->Wnode.ClientContext = 3;
    pProperty->BufferSize = sizeof(ULONG);
    pProperty->MinimumBuffers = 2;
    pProperty->MaximumBuffers = 2;
    pProperty->LogFileMode = 0x04000000; /* EVENT_TRACE_BUFFERING_MODE */

    if (nType == EtwpUpdateTrace) {
        pProperty->EnableFlags = 0x00000080; /* EVENT_TRACE_FLAG_SYSTEMCALL */
    }

    ULONG nLength = 0;
    NTSTATUS ntStatus = g_pNtTraceControl((ULONG)nType, pProperty, PAGE_SIZE,
                                            pProperty, PAGE_SIZE, &nLength);

    ExFreePoolWithTag(szProviderName, nTag);
    ExFreePoolWithTag(pProperty, nTag);
    return ntStatus;
}

/* ============================================================
 *  核心 Hook: SelfGetCpuClock (替换 CKCL 的 GetCpuClock)
 *
 *  在每次 syscall 时被调用，通过栈特征码找到当前 syscall，
 *  然后调用回调函数，可以修改函数指针来重定向 syscall。
 * ============================================================ */

#define INFINITYHOOK_MAGIC_501802  ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_601802  ((ULONG)0x601802)
#define INFINITYHOOK_MAGIC_F33     ((USHORT)0xF33)

static __int64 __fastcall SelfGetCpuClock(VOID)
{
    /* 放过内核模式调用 */
    if (ExGetPreviousMode() == KernelMode) return __rdtsc();

    /* 获取当前线程 (KTHREAD) */
    PKTHREAD pCurrentThread = (PKTHREAD)__readgsqword(0x188);

    /* 从 KTHREAD 获取 syscall 号 */
    ULONG nCallIndex = 0;
    if (g_BuildNumber <= 7601) {
        nCallIndex = *(PULONG)((PUCHAR)pCurrentThread + 0x1f8);
    } else {
        nCallIndex = *(PULONG)((PUCHAR)pCurrentThread + 0x80);
    }

    /* 获取栈范围 */
    PVOID *pStackMax = (PVOID *)__readgsqword(0x1a8);
    PVOID *pStackFrame = (PVOID *)_AddressOfReturnAddress();

    /* 在栈中搜索 syscall 特征码 */
    for (PVOID *pStackCurrent = pStackMax; pStackCurrent > pStackFrame; --pStackCurrent) {
        PULONG pValue1 = (PULONG)pStackCurrent;
        if (*pValue1 != INFINITYHOOK_MAGIC_501802 &&
            *pValue1 != INFINITYHOOK_MAGIC_601802) {
            continue;
        }

        --pStackCurrent;
        PUSHORT pValue2 = (PUSHORT)pStackCurrent;
        if (*pValue2 != INFINITYHOOK_MAGIC_F33) {
            continue;
        }

        /* 特征码匹配，正向搜索 SSDT 函数指针 */
        for (; pStackCurrent < pStackMax; ++pStackCurrent) {
            PULONG64 pllValue = (PULONG64)pStackCurrent;
            if (!(PAGE_ALIGN(*pllValue) >= g_SystemCallTable &&
                  PAGE_ALIGN(*pllValue) < (PVOID)((PUCHAR)g_SystemCallTable + PAGE_SIZE * 2))) {
                continue;
            }

            /* 找到 syscall 函数指针，pSystemCallFunction 指向栈中的函数指针位置 */
            PVOID *pSystemCallFunction = &pStackCurrent[9];

            /* 调用回调 */
            if (g_InfinityCallback) {
                g_InfinityCallback(nCallIndex, pSystemCallFunction);
            }
            break;
        }
        break;
    }

    return __rdtsc();
}

/* ============================================================
 *  拦截 Stub 函数
 * ============================================================ */

/* 通用拒绝 stub - 直接返回 STATUS_ACCESS_DENIED */
static NTSTATUS __fastcall GenericDeniedStub(VOID)
{
    InterlockedIncrement(&g_BlockedCount);
    return STATUS_ACCESS_DENIED;
}

/* NtTerminateProcess hook - 只阻止终止 BgSrv */
typedef NTSTATUS (NTAPI *PFN_NtTerminateProcess)(HANDLE, NTSTATUS);
static PFN_NtTerminateProcess g_OriginalNtTerminateProcess = NULL;

static NTSTATUS NTAPI HookNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    /* 检查目标进程是否是 BgSrv */
    if (ProcessHandle != NULL && ProcessHandle != (HANDLE)-1 && g_BgSrvPid != NULL) {
        PEPROCESS pProc = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0x1000,
                                                   *PsProcessType, KernelMode, &pProc, NULL))) {
            HANDLE pid = PsGetProcessId(pProc);
            ObDereferenceObject(pProc);
            if (pid == g_BgSrvPid) {
                InterlockedIncrement(&g_BlockedCount);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    /* 其他进程正常终止 */
    if (g_OriginalNtTerminateProcess) {
        return g_OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
    }
    return STATUS_ACCESS_DENIED;
}

/* ============================================================
 *  InfinityHook 回调 - 判断目标 syscall 并重定向
 * ============================================================ */

static BOOLEAN IsTargetSyscall(ULONG nCallIndex, PVOID callAddress)
{
    /* 优先通过函数地址判断（更可靠） */
    if (callAddress) {
        if (callAddress == g_pNtUnloadDriver ||
            callAddress == g_pNtTerminateProcess ||
            callAddress == g_pNtShutdownSystem ||
            callAddress == g_pNtInitiatePowerAction) {
            return TRUE;
        }
    }

    /* 后备：通过 syscall 号判断 */
    if (nCallIndex == g_syscallNtUnloadDriver ||
        nCallIndex == g_syscallNtTerminateProcess ||
        nCallIndex == g_syscallNtShutdownSystem ||
        nCallIndex == g_syscallNtInitiatePowerAction) {
        return TRUE;
    }

    return FALSE;
}

static void __fastcall InfinityCallback(ULONG nCallIndex, PVOID *pCallAddress)
{
    if (!pCallAddress || !g_HookActive) return;

    PVOID callAddress = *pCallAddress;

    /* 检查是否是目标 syscall */
    if (!IsTargetSyscall(nCallIndex, callAddress)) return;

    /* 只在 LOCKED 状态下拦截 */
    if (!LockIsLocked()) return;

    /* NtTerminateProcess 特殊处理：保存原始函数，使用专门 hook */
    if (callAddress == g_pNtTerminateProcess || nCallIndex == g_syscallNtTerminateProcess) {
        if (!g_OriginalNtTerminateProcess) {
            g_OriginalNtTerminateProcess = (PFN_NtTerminateProcess)callAddress;
        }
        *pCallAddress = (PVOID)HookNtTerminateProcess;
        return;
    }

    /* 其他目标 syscall：直接替换为拒绝 stub */
    *pCallAddress = (PVOID)GenericDeniedStub;
}

/* ============================================================
 *  初始化 / 启动 / 停止
 * ============================================================ */

static NTSTATUS InfinityHookStart(VOID)
{
    if (!g_GetCpuClock || !g_OriginalGetCpuClock) return STATUS_NOT_SUPPORTED;

    /* 替换 GetCpuClock 函数指针 */
    *g_GetCpuClock = (PVOID)SelfGetCpuClock;
    g_HookActive = TRUE;

    DbgPrint("GSH: InfinityHook started, GetCpuClock replaced\n");
    return STATUS_SUCCESS;
}

static VOID InfinityHookStop(VOID)
{
    if (g_GetCpuClock && g_OriginalGetCpuClock) {
        *g_GetCpuClock = g_OriginalGetCpuClock;
    }
    g_HookActive = FALSE;
    DbgPrint("GSH: InfinityHook stopped, GetCpuClock restored\n");
}

static NTSTATUS InfinityHookInit(VOID)
{
    /* 获取未文档化函数 */
    UNICODE_STRING nameNtTraceControl = RTL_CONSTANT_STRING(L"NtTraceControl");
    UNICODE_STRING nameZwQuerySysInfo = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    g_pNtTraceControl = (PFN_NtTraceControl)
        MmGetSystemRoutineAddress(&nameNtTraceControl);
    g_pZwQuerySystemInformation = (PFN_ZwQuerySystemInformation)
        MmGetSystemRoutineAddress(&nameZwQuerySysInfo);

    if (!g_pNtTraceControl || !g_pZwQuerySystemInformation) {
        DbgPrint("GSH: InfinityHook init failed: cannot resolve NtTraceControl/ZwQuerySystemInformation\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* 获取目标函数地址 */
    UNICODE_STRING nameUnload = RTL_CONSTANT_STRING(L"NtUnloadDriver");
    UNICODE_STRING nameTerminate = RTL_CONSTANT_STRING(L"NtTerminateProcess");
    UNICODE_STRING nameShutdown = RTL_CONSTANT_STRING(L"NtShutdownSystem");
    UNICODE_STRING namePowerAction = RTL_CONSTANT_STRING(L"NtInitiatePowerAction");
    g_pNtUnloadDriver = MmGetSystemRoutineAddress(&nameUnload);
    g_pNtTerminateProcess = MmGetSystemRoutineAddress(&nameTerminate);
    g_pNtShutdownSystem = MmGetSystemRoutineAddress(&nameShutdown);
    g_pNtInitiatePowerAction = MmGetSystemRoutineAddress(&namePowerAction);

    DbgPrint("GSH: Target addresses: Unload=%p Terminate=%p Shutdown=%p PowerAction=%p\n",
             g_pNtUnloadDriver, g_pNtTerminateProcess, g_pNtShutdownSystem, g_pNtInitiatePowerAction);

    /* 如果 MmGetSystemRoutineAddress 获取失败，从跨版本查找表中根据 build number 获取 syscall 号 */
    if (!g_pNtUnloadDriver || !g_pNtTerminateProcess ||
        !g_pNtShutdownSystem || !g_pNtInitiatePowerAction) {
        const SYSCALL_LOOKUP_ENTRY* entry = SyscallFindEntry(g_BuildNumber);
        if (entry) {
            if (!g_pNtUnloadDriver) g_syscallNtUnloadDriver = entry->NtUnloadDriver;
            if (!g_pNtTerminateProcess) g_syscallNtTerminateProcess = entry->NtTerminateProcess;
            if (!g_pNtShutdownSystem) g_syscallNtShutdownSystem = entry->NtShutdownSystem;
            if (!g_pNtInitiatePowerAction) g_syscallNtInitiatePowerAction = entry->NtInitiatePowerAction;
            DbgPrint("GSH: Syscall lookup for build %lu: Unload=%lu Terminate=%lu Shutdown=%lu PowerAction=%lu\n",
                     g_BuildNumber, g_syscallNtUnloadDriver, g_syscallNtTerminateProcess,
                     g_syscallNtShutdownSystem, g_syscallNtInitiatePowerAction);
        } else {
            DbgPrint("GSH: WARNING: No syscall lookup entry for build %lu\n", g_BuildNumber);
        }
    }

    /* 启用 CKCL syscall trace */
    if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace))) {
        if (!NT_SUCCESS(EventTraceControl(EtwpStartTrace))) {
            DbgPrint("GSH: InfinityHook: start CKCL failed\n");
            return STATUS_UNSUCCESSFUL;
        }
        if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace))) {
            DbgPrint("GSH: InfinityHook: enable syscall trace failed\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* 获取系统版本 */
    g_BuildNumber = GetSystemBuildNumber();
    DbgPrint("GSH: InfinityHook: build number %lu\n", g_BuildNumber);
    if (!g_BuildNumber) return STATUS_UNSUCCESSFUL;

    /* 获取 ntoskrnl 基址 */
    PVOID ntosBase = GetNtoskrnlBase();
    DbgPrint("GSH: InfinityHook: ntoskrnl base %p\n", ntosBase);
    if (!ntosBase) return STATUS_UNSUCCESSFUL;

    /* TODO: 特征码搜索 EtwpDebuggerData - 暂时禁用，防止访问无效内存导致蓝屏
     * 原因: FindPattern 在 ntoskrnl 中搜索时可能访问未映射内存页
     * 修复方案: 后续改用更安全的方式获取 EtwpDebuggerData (如从已知导出符号偏移)
    UCHAR etwpPattern[] = { 0x00, 0x00, 0x2c, 0x08, 0x04, 0x38, 0x0c };
    CHAR etwpMask[] = "??xxxxx";
    g_EtwpDebuggerData = FindPatternInNtos(ntosBase, etwpPattern, etwpMask);
    */
    g_EtwpDebuggerData = NULL;
    DbgPrint("GSH: InfinityHook: EtwpDebuggerData pattern search DISABLED (TODO)\n");
    if (!g_EtwpDebuggerData) return STATUS_NOT_SUPPORTED;

    /* 获取 CkclWmiLoggerContext */
    PVOID *pSilo = *(PVOID **)((PUCHAR)g_EtwpDebuggerData + 0x10);
    if (!pSilo) return STATUS_UNSUCCESSFUL;
    g_CkclWmiLoggerContext = pSilo[0x2];
    DbgPrint("GSH: InfinityHook: CkclWmiLoggerContext %p\n", g_CkclWmiLoggerContext);
    if (!g_CkclWmiLoggerContext) return STATUS_UNSUCCESSFUL;

    /* 获取 GetCpuClock 函数指针位置 */
    if (g_BuildNumber <= 7601 || g_BuildNumber >= 22000) {
        g_GetCpuClock = (PVOID *)((PUCHAR)g_CkclWmiLoggerContext + 0x18);
    } else {
        g_GetCpuClock = (PVOID *)((PUCHAR)g_CkclWmiLoggerContext + 0x28);
    }
    DbgPrint("GSH: InfinityHook: GetCpuClock ptr %p, value %p\n", g_GetCpuClock,
             MmIsAddressValid(g_GetCpuClock) ? *g_GetCpuClock : NULL);
    if (!MmIsAddressValid(g_GetCpuClock)) return STATUS_UNSUCCESSFUL;

    /* 保存原始 GetCpuClock */
    g_OriginalGetCpuClock = *g_GetCpuClock;

    /* 获取 SSDT 基址 */
    g_SystemCallTable = PAGE_ALIGN(GetSyscallTable(ntosBase));
    DbgPrint("GSH: InfinityHook: SystemCallTable %p\n", g_SystemCallTable);
    if (!g_SystemCallTable) return STATUS_UNSUCCESSFUL;

    /* 设置回调 */
    g_InfinityCallback = InfinityCallback;

    DbgPrint("GSH: InfinityHook initialized successfully\n");
    return STATUS_SUCCESS;
}

/* ============================================================
 *  公开接口
 * ============================================================ */

NTSTATUS InfinityHookInitialize(VOID)
{
    /* 尝试获取 BgSrv PID（通过进程名查找） */
    /* 注意：BgSrv 由 client 启动，PID 在驱动加载时可能还不存在 */
    /* 后续可以通过 IOCTL 设置 BgSrv PID */

    NTSTATUS status = InfinityHookInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: InfinityHookInitialize failed: 0x%X\n", status);
        return status;
    }

    status = InfinityHookStart();
    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: InfinityHookStart failed: 0x%X\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID InfinityHookShutdown(VOID)
{
    InfinityHookStop();

    /* 停止 CKCL trace */
    if (g_pNtTraceControl) {
        EventTraceControl(EtwpStopTrace);
    }

    g_InfinityCallback = NULL;
    g_OriginalNtTerminateProcess = NULL;
}

ULONG InfinityHookGetBlockedCount(VOID)
{
    return (ULONG)InterlockedCompareExchange(&g_BlockedCount, 0, 0);
}

/* 设置 BgSrv PID（供 IOCTL 调用） */
VOID InfinityHookSetBgSrvPid(HANDLE pid)
{
    g_BgSrvPid = pid;
    DbgPrint("GSH: InfinityHook BgSrv PID set to %p\n", pid);
}

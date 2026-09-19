/*
 * Auxiliary.sys - InfinityHook 系统调用拦截驱动
 * 基于 zhutingxf/InfinityHookPro 最小改动嵌入
 *
 * 拦截目标:
 *   - NtUnloadDriver: 阻止卸载驱动
 *   - NtTerminateProcess: 阻止终止 BgSrv 进程
 *   - NtShutdownSystem: 阻止关机
 *   - NtInitiatePowerAction: 阻止关机/休眠
 */

#pragma warning(disable : 4201 4819 4311 4302)

#include "hook.hpp"
#include "imports.hpp"
#include "Auxiliary.h"

/* ============================================================
 *  全局变量
 * ============================================================ */

/* 原始 syscall 函数指针 */
static PVOID g_OriginalNtUnloadDriver = NULL;
static PVOID g_OriginalNtTerminateProcess = NULL;
static PVOID g_OriginalNtShutdownSystem = NULL;
static PVOID g_OriginalNtInitiatePowerAction = NULL;

/* syscall 函数地址 (用于在 InfinityCallback 中识别) */
static PVOID g_pNtUnloadDriver = NULL;
static PVOID g_pNtTerminateProcess = NULL;
static PVOID g_pNtShutdownSystem = NULL;
static PVOID g_pNtInitiatePowerAction = NULL;

/* 状态 */
static volatile LONG g_BlockedCount = 0;
static HANDLE g_BgSrvPid = NULL;
static volatile bool g_Quitting = false;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DosDeviceName;

/* 是否使用 syscall 号匹配 (当 MmGetSystemRoutineAddress 解析失败时启用) */
static bool g_UseSyscallIndex = false;
static ULONG g_SyscallUnload = 0;
static ULONG g_SyscallTerminate = 0;
static ULONG g_SyscallShutdown = 0;
static ULONG g_SyscallPowerAction = 0;

/* 从 nt-per-syscall.json 提取的跨版本 syscall 查找表 */
typedef struct _AUX_SYSCALL_ENTRY
{
    ULONG Build;
    ULONG Unload;
    ULONG Terminate;
    ULONG Shutdown;
    ULONG PowerAction;
} AUX_SYSCALL_ENTRY;

static const AUX_SYSCALL_ENTRY g_AuxSyscallTable[] = {
    {10240, 425, 44, 408, 241},
    {10586, 428, 44, 411, 243},
    {14393, 434, 44, 417, 245},
    {15063, 440, 44, 423, 248},
    {16299, 444, 44, 426, 249},
    {17134, 446, 44, 428, 250},
    {17763, 447, 44, 429, 251},
    {18362, 448, 44, 430, 252},
    {18363, 448, 44, 430, 252},
    {19041, 454, 44, 436, 257},
    {19042, 454, 44, 436, 257},
    {19043, 454, 44, 436, 257},
    {19044, 456, 44, 438, 258},
    {19045, 456, 44, 438, 258},
    {20348, 462, 44, 444, 262},
    {22000, 466, 44, 447, 263},
    {22621, 470, 44, 451, 264},
    {22631, 470, 44, 451, 264},
    {26100, 473, 44, 454, 266},
};
static const ULONG g_AuxSyscallTableCount = 19;

/* 根据 build number 查找 syscall 号 (向下取整) */
static bool AuxLookupSyscallNumbers(ULONG buildNumber)
{
    const AUX_SYSCALL_ENTRY *best = NULL;
    for (ULONG i = 0; i < g_AuxSyscallTableCount; i++)
    {
        if (g_AuxSyscallTable[i].Build <= buildNumber)
        {
            best = &g_AuxSyscallTable[i];
        }
        else
        {
            break;
        }
    }
    if (!best)
        return false;
    g_SyscallUnload = best->Unload;
    g_SyscallTerminate = best->Terminate;
    g_SyscallShutdown = best->Shutdown;
    g_SyscallPowerAction = best->PowerAction;
    DbgPrintEx(0, 0, "[Auxiliary] Syscall lookup for build %lu: Unload=%lu Terminate=%lu Shutdown=%lu PowerAction=%lu\n",
               buildNumber, g_SyscallUnload, g_SyscallTerminate, g_SyscallShutdown, g_SyscallPowerAction);
    return true;
}

/* ============================================================
 *  syscall 函数类型定义
 * ============================================================ */

typedef NTSTATUS(NTAPI *NtUnloadDriver_t)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI *NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI *NtShutdownSystem_t)(ULONG ShutdownAction);
typedef NTSTATUS(NTAPI *NtInitiatePowerAction_t)(
    POWER_ACTION Action,
    SYSTEM_POWER_STATE MinSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous);

/* ============================================================
 *  假的 syscall 函数 (拦截逻辑)
 * ============================================================ */

/* 自定义宽字符串子串查找（不依赖 CRT wcsstr，内核安全） */
static PWCHAR AuxFindSubstring(PWCHAR str, PWCHAR search)
{
    if (!str || !search || !*search)
        return str;
    for (; *str; str++)
    {
        PWCHAR s1 = str, s2 = search;
        while (*s1 && *s2 && (*s1 == *s2))
        {
            s1++;
            s2++;
        }
        if (!*s2)
            return str;
    }
    return NULL;
}

/* ============================================================
 *  PPL / DKOM 实现 (照抄 itm4n/PPLcontrol 的 OffsetFinder + Utils + Controller)
 *  仓库: https://github.com/itm4n/PPLcontrol
 * ============================================================ */

/* ---- 照抄 PPLcontrol common.h: PS_PROTECTED_TYPE / PS_PROTECTED_SIGNER ---- */
typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerWinSystem = 7,
    PsProtectedSignerApp = 8,
    PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

/* ---- 照抄 PPLcontrol Utils.h: SE_SIGNING_LEVEL 常量 (ntddk.h 已定义, 加 #ifndef 防重定义) ---- */
#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED       0x00
#endif
#ifndef SE_SIGNING_LEVEL_UNSIGNED
#define SE_SIGNING_LEVEL_UNSIGNED        0x01
#endif
#ifndef SE_SIGNING_LEVEL_ENTERPRISE
#define SE_SIGNING_LEVEL_ENTERPRISE     0x02
#endif
#ifndef SE_SIGNING_LEVEL_DEVELOPER
#define SE_SIGNING_LEVEL_DEVELOPER      0x03
#endif
#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE   0x04
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_2
#define SE_SIGNING_LEVEL_CUSTOM_2       0x05
#endif
#ifndef SE_SIGNING_LEVEL_STORE
#define SE_SIGNING_LEVEL_STORE          0x06
#endif
#ifndef SE_SIGNING_LEVEL_ANTIMALWARE
#define SE_SIGNING_LEVEL_ANTIMALWARE    0x07
#endif
#ifndef SE_SIGNING_LEVEL_MICROSOFT
#define SE_SIGNING_LEVEL_MICROSOFT      0x08
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_4
#define SE_SIGNING_LEVEL_CUSTOM_4        0x09
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_5
#define SE_SIGNING_LEVEL_CUSTOM_5        0x0A
#endif
#ifndef SE_SIGNING_LEVEL_DYNAMIC_CODEGEN
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN 0x0B
#endif
#ifndef SE_SIGNING_LEVEL_WINDOWS
#define SE_SIGNING_LEVEL_WINDOWS        0x0C
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_7
#define SE_SIGNING_LEVEL_CUSTOM_7       0x0D
#endif
#ifndef SE_SIGNING_LEVEL_WINDOWS_TCB
#define SE_SIGNING_LEVEL_WINDOWS_TCB    0x0E
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_6
#define SE_SIGNING_LEVEL_CUSTOM_6        0x0F
#endif

/* EPROCESS 偏移（运行时动态查找，照抄 PPLcontrol OffsetFinder） */
static LONG g_OffsetProtection = -1;
static LONG g_OffsetSignatureLevel = -1;
static LONG g_OffsetSectionSignatureLevel = -1;
static LONG g_OffsetActiveProcessLinks = -1;
static LONG g_OffsetUniqueProcessId = -1;

/* ---- 照抄 PPLcontrol OffsetFinder.cpp: 偏移查找 ---- */

/*
 * 照抄 FindProcessUniqueProcessIdOffset:
 *   PsGetProcessId (x64): mov eax, [rcx+disp16]  ->  disp16 在函数偏移 +3 处
 */
static bool AuxFindProcessUniqueProcessIdOffset(void)
{
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsGetProcessId");
    PVOID pPsGetProcessId = MmGetSystemRoutineAddress(&funcName);
    if (!pPsGetProcessId)
        return false;

    WORD wUniqueProcessIdOffset = 0;
    RtlCopyMemory(&wUniqueProcessIdOffset, (PUCHAR)pPsGetProcessId + 3, sizeof(WORD));

    if (wUniqueProcessIdOffset > 0x0FFF)
        return false;

    g_OffsetUniqueProcessId = wUniqueProcessIdOffset;
    return true;
}

/*
 * 照抄 FindProcessActiveProcessLinksOffset:
 *   ActiveProcessLinks = UniqueProcessId + sizeof(HANDLE)
 */
static bool AuxFindProcessActiveProcessLinksOffset(void)
{
    if (g_OffsetUniqueProcessId <= 0)
        return false;

    g_OffsetActiveProcessLinks = g_OffsetUniqueProcessId + (LONG)sizeof(HANDLE);
    return true;
}

/*
 * 照抄 FindProcessProtectionOffset:
 *   PsIsProtectedProcess / PsIsProtectedProcessLight (x64):
 *   mov al, [cl+disp16]  ->  disp16 在函数偏移 +2 处
 *   两个函数交叉验证偏移一致
 */
static bool AuxFindProcessProtectionOffset(void)
{
    UNICODE_STRING funcName;

    RtlInitUnicodeString(&funcName, L"PsIsProtectedProcess");
    PVOID pPsIsProtectedProcess = MmGetSystemRoutineAddress(&funcName);
    if (!pPsIsProtectedProcess)
        return false;

    RtlInitUnicodeString(&funcName, L"PsIsProtectedProcessLight");
    PVOID pPsIsProtectedProcessLight = MmGetSystemRoutineAddress(&funcName);
    if (!pPsIsProtectedProcessLight)
        return false;

    WORD wProtectionOffsetA = 0, wProtectionOffsetB = 0;
    RtlCopyMemory(&wProtectionOffsetA, (PUCHAR)pPsIsProtectedProcess + 2, sizeof(WORD));
    RtlCopyMemory(&wProtectionOffsetB, (PUCHAR)pPsIsProtectedProcessLight + 2, sizeof(WORD));

    if (wProtectionOffsetA != wProtectionOffsetB || wProtectionOffsetA > 0x0FFF)
        return false;

    g_OffsetProtection = wProtectionOffsetA;
    return true;
}

/*
 * 照抄 FindProcessSignatureLevelOffset:
 *   SignatureLevel = Protection - 2 (2 字节之前)
 */
static bool AuxFindProcessSignatureLevelOffset(void)
{
    if (g_OffsetProtection <= 0)
        return false;

    g_OffsetSignatureLevel = g_OffsetProtection - (2 * (LONG)sizeof(UCHAR));
    return true;
}

/*
 * 照抄 FindProcessSectionSignatureLevelOffset:
 *   SectionSignatureLevel = Protection - 1 (1 字节之前)
 */
static bool AuxFindProcessSectionSignatureLevelOffset(void)
{
    if (g_OffsetProtection <= 0)
        return false;

    g_OffsetSectionSignatureLevel = g_OffsetProtection - (LONG)sizeof(UCHAR);
    return true;
}

/* 照抄 FindAllOffsets */
static bool AuxFindAllOffsets(void)
{
    if (!AuxFindProcessUniqueProcessIdOffset())
        return false;
    if (!AuxFindProcessActiveProcessLinksOffset())
        return false;
    if (!AuxFindProcessProtectionOffset())
        return false;
    if (!AuxFindProcessSignatureLevelOffset())
        return false;
    if (!AuxFindProcessSectionSignatureLevelOffset())
        return false;
    return true;
}

/* 兜底偏移（Win10 1903+ / Win11 常见值） */
static void AuxApplyFallbackOffsets(void)
{
    if (g_OffsetProtection < 0)
        g_OffsetProtection = 0x6FA;
    if (g_OffsetSignatureLevel < 0)
        g_OffsetSignatureLevel = g_OffsetProtection - 2;
    if (g_OffsetSectionSignatureLevel < 0)
        g_OffsetSectionSignatureLevel = g_OffsetProtection - 1;
    if (g_OffsetUniqueProcessId < 0)
        g_OffsetUniqueProcessId = 0x440;
    if (g_OffsetActiveProcessLinks < 0)
        g_OffsetActiveProcessLinks = g_OffsetUniqueProcessId + (LONG)sizeof(HANDLE);
}

/* ---- 照抄 PPLcontrol Utils.cpp: 保护编码 / 签名级别查表 ---- */

/* 照抄 Utils::GetProtectionLevel: Protection & 0x07 */
static UCHAR AuxGetProtectionLevel(UCHAR Protection)
{
    return Protection & 0x07;
}

/* 照抄 Utils::GetSignerType: (Protection & 0xF0) >> 4 */
static UCHAR AuxGetSignerType(UCHAR Protection)
{
    return (Protection & 0xF0) >> 4;
}

/* 照抄 Utils::GetProtection: (SignerType << 4) | ProtectionLevel */
static UCHAR AuxGetProtection(UCHAR ProtectionLevel, UCHAR SignerType)
{
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

/* 照抄 Utils::GetSignatureLevel: 根据 SignerType 查 SignatureLevel */
static UCHAR AuxGetSignatureLevel(UCHAR SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS_TCB;
    default:
        return 0xFF;
    }
}

/* 照抄 Utils::GetSectionSignatureLevel: 根据 SignerType 查 SectionSignatureLevel */
static UCHAR AuxGetSectionSignatureLevel(UCHAR SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_STORE;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_MICROSOFT;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        /* 照抄 PPLcontrol: WinTcb 的 SectionSignatureLevel 实际是 Windows */
        return SE_SIGNING_LEVEL_WINDOWS;
    default:
        return 0xFF;
    }
}

/* ---- 照抄 PPLcontrol Controller.cpp: ProtectProcess / UnprotectProcess ---- */

/*
 * 照抄 Controller::ProtectProcess:
 *   1. 写 Protection 字节 = (SignerType << 4) | ProtectionLevel
 *   2. 写 SignatureLevel (根据 SignerType 查表)
 *   3. 写 SectionSignatureLevel (根据 SignerType 查表)
 */
static NTSTATUS AuxProtectProcess(PEPROCESS pEProcess, UCHAR bProtectionLevel, UCHAR bSignerType)
{
    PUCHAR pProc = (PUCHAR)pEProcess;

    /* 步骤1: SetProcessProtection (照抄 Controller::SetProcessProtection(Addr, Protection)) */
    UCHAR bProtectionNew = AuxGetProtection(bProtectionLevel, bSignerType);
    *(PUCHAR)(pProc + g_OffsetProtection) = bProtectionNew;

    /* 步骤2: SetProcessSignatureLevel (照抄 Controller::SetProcessSignatureLevel) */
    UCHAR bSignatureLevel = AuxGetSignatureLevel(bSignerType);
    if (bSignatureLevel != 0xFF)
    {
        *(PUCHAR)(pProc + g_OffsetSignatureLevel) = bSignatureLevel;
    }

    /* 步骤3: SetProcessSectionSignatureLevel (照抄 Controller::SetProcessSectionSignatureLevel) */
    UCHAR bSectionSignatureLevel = AuxGetSectionSignatureLevel(bSignerType);
    if (bSectionSignatureLevel != 0xFF)
    {
        *(PUCHAR)(pProc + g_OffsetSectionSignatureLevel) = bSectionSignatureLevel;
    }

    DbgPrintEx(0, 0, "[Auxiliary] ProtectProcess: protection=0x%02X sig=0x%02X secsig=0x%02X\n",
               bProtectionNew, bSignatureLevel, bSectionSignatureLevel);
    return STATUS_SUCCESS;
}

/*
 * 照抄 Controller::UnprotectProcess:
 *   1. 写 Protection = 0
 *   2. 写 SignatureLevel = SE_SIGNING_LEVEL_UNCHECKED (0x00)
 *   3. 写 SectionSignatureLevel = SE_SIGNING_LEVEL_UNCHECKED (0x00)
 */
static NTSTATUS AuxUnprotectProcess(PEPROCESS pEProcess)
{
    PUCHAR pProc = (PUCHAR)pEProcess;

    /* 步骤1: SetProcessProtection(Addr, 0) */
    *(PUCHAR)(pProc + g_OffsetProtection) = 0;

    /* 步骤2: SetProcessSignatureLevel(Addr, SE_SIGNING_LEVEL_UNCHECKED) */
    *(PUCHAR)(pProc + g_OffsetSignatureLevel) = SE_SIGNING_LEVEL_UNCHECKED;

    /* 步骤3: SetProcessSectionSignatureLevel(Addr, SE_SIGNING_LEVEL_UNCHECKED) */
    *(PUCHAR)(pProc + g_OffsetSectionSignatureLevel) = SE_SIGNING_LEVEL_UNCHECKED;

    DbgPrintEx(0, 0, "[Auxiliary] UnprotectProcess\n");
    return STATUS_SUCCESS;
}

/*
 * 统一入口: 照抄 PPLcontrol 的 SetProcessProtection(DWORD Pid, ...) 流程
 *   - 输入 protectionLevel 为 PPLcontrol 编码格式: (SignerType << 4) | Level
 *   - Level == 0 -> UnprotectProcess
 *   - Level > 0  -> ProtectProcess
 */
static NTSTATUS AuxSetProcessProtection(HANDLE pid, UCHAR protectionLevel)
{
    /* 照抄 OffsetFinder::FindAllOffsets */
    if (g_OffsetProtection < 0 || g_OffsetSignatureLevel < 0 || g_OffsetSectionSignatureLevel < 0)
    {
        if (!AuxFindAllOffsets())
        {
            DbgPrintEx(0, 0, "[Auxiliary] AuxFindAllOffsets failed, using fallback offsets\n");
            AuxApplyFallbackOffsets();
        }
    }

    PEPROCESS pEProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &pEProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[Auxiliary] PsLookupProcessByProcessId failed: 0x%lX\n", status);
        return status;
    }

    /* 照抄 Controller::SetProcessProtection 中的解码逻辑 */
    UCHAR bProtectionLevel = AuxGetProtectionLevel(protectionLevel);
    UCHAR bSignerType = AuxGetSignerType(protectionLevel);

    /* 照抄 Controller::ProtectProcess / UnprotectProcess 分支 */
    if (bProtectionLevel == PsProtectedTypeNone)
    {
        /* UnprotectProcess 流程 */
        AuxUnprotectProcess(pEProcess);
    }
    else
    {
        /* ProtectProcess 流程 */
        AuxProtectProcess(pEProcess, bProtectionLevel, bSignerType);
    }

    ObDereferenceObject(pEProcess);
    DbgPrintEx(0, 0, "[Auxiliary] SetProtection PID=%p input=0x%02X level=%u signer=%u at offsets P=%ld S=%ld SS=%ld\n",
               pid, protectionLevel, bProtectionLevel, bSignerType,
               g_OffsetProtection, g_OffsetSignatureLevel, g_OffsetSectionSignatureLevel);
    return STATUS_SUCCESS;
}

/* 保存被隐藏进程的原始链表指针，用于恢复 */
static LIST_ENTRY g_HiddenProcessLinks;
static HANDLE g_HiddenPid = NULL;
static bool g_bProcessHidden = false;

static NTSTATUS AuxHideProcess(HANDLE pid)
{
    if (g_OffsetActiveProcessLinks < 0)
    {
        if (!AuxFindAllOffsets())
            AuxApplyFallbackOffsets();
    }
    if (g_bProcessHidden)
        return STATUS_SUCCESS;

    PEPROCESS pEProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &pEProcess);
    if (!NT_SUCCESS(status))
        return status;

    PUCHAR pProc = (PUCHAR)pEProcess;
    PLIST_ENTRY pList = (PLIST_ENTRY)(pProc + g_OffsetActiveProcessLinks);

    /* 保存原始前后指针 */
    g_HiddenProcessLinks.Flink = pList->Flink;
    g_HiddenProcessLinks.Blink = pList->Blink;
    g_HiddenPid = pid;

    /* 从链表摘除：前一个的Flink指向后一个，后一个的Blink指向前一个 */
    pList->Blink->Flink = pList->Flink;
    pList->Flink->Blink = pList->Blink;

    /* 自引用，防止被误遍历 */
    pList->Flink = pList;
    pList->Blink = pList;

    g_bProcessHidden = true;
    ObDereferenceObject(pEProcess);
    DbgPrintEx(0, 0, "[Auxiliary] HideProcess PID=%p at offset=%ld\n", pid, g_OffsetActiveProcessLinks);
    return STATUS_SUCCESS;
}

static NTSTATUS AuxUnhideProcess(HANDLE pid)
{
    if (!g_bProcessHidden || g_HiddenPid != pid)
        return STATUS_SUCCESS;
    if (g_OffsetActiveProcessLinks < 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS pEProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &pEProcess);
    if (!NT_SUCCESS(status))
        return status;

    PUCHAR pProc = (PUCHAR)pEProcess;
    PLIST_ENTRY pList = (PLIST_ENTRY)(pProc + g_OffsetActiveProcessLinks);

    /* 恢复到原始位置 */
    pList->Flink = g_HiddenProcessLinks.Flink;
    pList->Blink = g_HiddenProcessLinks.Blink;
    g_HiddenProcessLinks.Flink->Blink = pList;
    g_HiddenProcessLinks.Blink->Flink = pList;

    g_bProcessHidden = false;
    g_HiddenPid = NULL;
    ObDereferenceObject(pEProcess);
    DbgPrintEx(0, 0, "[Auxiliary] UnhideProcess PID=%p\n", pid);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI FakeNtUnloadDriver(PUNICODE_STRING DriverServiceName)
{
    /* quitting 状态下放行所有卸载（包括我们自己的驱动） */
    if (g_Quitting)
    {
        return ((NtUnloadDriver_t)g_OriginalNtUnloadDriver)(DriverServiceName);
    }
    /* 只阻止卸载我们自己的两个驱动: Auxiliary.sys 和 GlobalShutdownHook.sys */
    if (DriverServiceName)
    {
        USHORT len = 0;
        PWCHAR userBuf = NULL;
        PWCHAR safeBuf = NULL;
        bool blocked = false;

        /* BUG1修复: 用 __try/__except 安全访问用户态 UNICODE_STRING，避免 TOCTOU */
        __try
        {
            ProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), 1);
            len = DriverServiceName->Length;
            userBuf = DriverServiceName->Buffer;
            if (userBuf && len > 0)
            {
                ProbeForRead(userBuf, len, 1);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            len = 0;
            userBuf = NULL;
        }

        if (userBuf && len > 0)
        {
            /* 复制到内核缓冲区 */
            safeBuf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, len + sizeof(WCHAR), 'AuxU');
            if (safeBuf)
            {
                RtlZeroMemory(safeBuf, len + sizeof(WCHAR));
                __try
                {
                    RtlCopyMemory(safeBuf, userBuf, len);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    ExFreePoolWithTag(safeBuf, 'AuxU');
                    safeBuf = NULL;
                }
            }

            if (safeBuf)
            {
                /* BUG2修复: 使用自定义宽字符串查找，不依赖 CRT wcsstr */
                if (AuxFindSubstring(safeBuf, L"Auxiliary") ||
                    AuxFindSubstring(safeBuf, L"GlobalShutdownHook"))
                {
                    blocked = true;
                    InterlockedIncrement(&g_BlockedCount);
                    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtUnloadDriver\n");
                }
                ExFreePoolWithTag(safeBuf, 'AuxU');
            }
        }

        if (blocked)
        {
            return STATUS_ACCESS_DENIED;
        }
    }

    /* 其他驱动正常卸载 */
    return ((NtUnloadDriver_t)g_OriginalNtUnloadDriver)(DriverServiceName);
}

static NTSTATUS NTAPI FakeNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    /* 检查是否是终止 BgSrv 进程 */
    if (g_BgSrvPid != NULL)
    {
        PEPROCESS pProcess = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0x1000,
                                                 NULL, KernelMode, (PVOID *)&pProcess, NULL)))
        {
            HANDLE targetPid = PsGetProcessId(pProcess);
            ObDereferenceObject(pProcess);
            if (targetPid == g_BgSrvPid)
            {
                InterlockedIncrement(&g_BlockedCount);
                DbgPrintEx(0, 0, "[Auxiliary] Blocked NtTerminateProcess on BgSrv (PID=%p)\n", g_BgSrvPid);
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    /* 其他进程正常终止 */
    return ((NtTerminateProcess_t)g_OriginalNtTerminateProcess)(ProcessHandle, ExitStatus);
}

static NTSTATUS NTAPI FakeNtShutdownSystem(ULONG ShutdownAction)
{
    UNREFERENCED_PARAMETER(ShutdownAction);
    InterlockedIncrement(&g_BlockedCount);
    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtShutdownSystem\n");
    return STATUS_ACCESS_DENIED;
}

static NTSTATUS NTAPI FakeNtInitiatePowerAction(
    POWER_ACTION Action,
    SYSTEM_POWER_STATE MinSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous)
{
    UNREFERENCED_PARAMETER(Action);
    UNREFERENCED_PARAMETER(MinSystemState);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Asynchronous);
    InterlockedIncrement(&g_BlockedCount);
    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtInitiatePowerAction\n");
    return STATUS_ACCESS_DENIED;
}

/* ============================================================
 *  InfinityHook 回调函数
 *  在 syscall 入口被调用，可以替换 syscall 函数指针
 * ============================================================ */

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID *pSsdtAddress)
{
    if (!pSsdtAddress)
        return;

    /* 优先使用函数地址匹配 (MmGetSystemRoutineAddress 成功时) */
    if (!g_UseSyscallIndex)
    {
        if (*pSsdtAddress == g_pNtUnloadDriver)
        {
            g_OriginalNtUnloadDriver = *pSsdtAddress;
            *pSsdtAddress = FakeNtUnloadDriver;
        }
        else if (*pSsdtAddress == g_pNtTerminateProcess)
        {
            g_OriginalNtTerminateProcess = *pSsdtAddress;
            *pSsdtAddress = FakeNtTerminateProcess;
        }
        else if (*pSsdtAddress == g_pNtShutdownSystem)
        {
            g_OriginalNtShutdownSystem = *pSsdtAddress;
            *pSsdtAddress = FakeNtShutdownSystem;
        }
        else if (*pSsdtAddress == g_pNtInitiatePowerAction)
        {
            g_OriginalNtInitiatePowerAction = *pSsdtAddress;
            *pSsdtAddress = FakeNtInitiatePowerAction;
        }
    }
    else
    {
        /* 地址解析失败时，使用 syscall 号匹配 (从 nt-per-syscall.json 提取) */
        if (nCallIndex == g_SyscallUnload)
        {
            g_OriginalNtUnloadDriver = *pSsdtAddress;
            *pSsdtAddress = FakeNtUnloadDriver;
        }
        else if (nCallIndex == g_SyscallTerminate)
        {
            g_OriginalNtTerminateProcess = *pSsdtAddress;
            *pSsdtAddress = FakeNtTerminateProcess;
        }
        else if (nCallIndex == g_SyscallShutdown)
        {
            g_OriginalNtShutdownSystem = *pSsdtAddress;
            *pSsdtAddress = FakeNtShutdownSystem;
        }
        else if (nCallIndex == g_SyscallPowerAction)
        {
            g_OriginalNtInitiatePowerAction = *pSsdtAddress;
            *pSsdtAddress = FakeNtInitiatePowerAction;
        }
    }
}

/* ============================================================
 *  获取 syscall 函数地址
 * ============================================================ */

static bool GetSyscallAddresses()
{
    UNICODE_STRING str;
    ULONG resolvedCount = 0;

    WCHAR nameUnload[] = L"NtUnloadDriver";
    RtlInitUnicodeString(&str, nameUnload);
    g_pNtUnloadDriver = MmGetSystemRoutineAddress(&str);
    if (g_pNtUnloadDriver)
        resolvedCount++;
    DbgPrintEx(0, 0, "[Auxiliary] NtUnloadDriver: %p\n", g_pNtUnloadDriver);

    WCHAR nameTerminate[] = L"NtTerminateProcess";
    RtlInitUnicodeString(&str, nameTerminate);
    g_pNtTerminateProcess = MmGetSystemRoutineAddress(&str);
    if (g_pNtTerminateProcess)
        resolvedCount++;
    DbgPrintEx(0, 0, "[Auxiliary] NtTerminateProcess: %p\n", g_pNtTerminateProcess);

    WCHAR nameShutdown[] = L"NtShutdownSystem";
    RtlInitUnicodeString(&str, nameShutdown);
    g_pNtShutdownSystem = MmGetSystemRoutineAddress(&str);
    if (g_pNtShutdownSystem)
        resolvedCount++;
    DbgPrintEx(0, 0, "[Auxiliary] NtShutdownSystem: %p\n", g_pNtShutdownSystem);

    WCHAR namePower[] = L"NtInitiatePowerAction";
    RtlInitUnicodeString(&str, namePower);
    g_pNtInitiatePowerAction = MmGetSystemRoutineAddress(&str);
    if (g_pNtInitiatePowerAction)
        resolvedCount++;
    DbgPrintEx(0, 0, "[Auxiliary] NtInitiatePowerAction: %p\n", g_pNtInitiatePowerAction);

    /* 如果全部解析成功，使用函数地址匹配 */
    if (resolvedCount == 4)
    {
        g_UseSyscallIndex = false;
        DbgPrintEx(0, 0, "[Auxiliary] All 4 syscall addresses resolved, using address matching\n");
        return true;
    }

    /* 部分或全部解析失败，回退到 syscall 号匹配 (从 nt-per-syscall.json) */
    DbgPrintEx(0, 0, "[Auxiliary] Only %lu/4 addresses resolved, falling back to syscall index matching\n", resolvedCount);
    g_UseSyscallIndex = true;

    /* 获取当前系统 build number */
    RTL_OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (!NT_SUCCESS(RtlGetVersion(&osvi)))
    {
        DbgPrintEx(0, 0, "[Auxiliary] RtlGetVersion failed\n");
        return false;
    }

    /* 从查找表获取 syscall 号 */
    if (!AuxLookupSyscallNumbers(osvi.dwBuildNumber))
    {
        DbgPrintEx(0, 0, "[Auxiliary] No syscall lookup entry for build %lu\n", osvi.dwBuildNumber);
        return false;
    }

    return true;
}

/* ============================================================
 *  IOCTL 分发
 * ============================================================ */

static NTSTATUS AuxIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_AUX_GET_BLOCKED_COUNT:
    {
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG))
        {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = (ULONG)InterlockedCompareExchange(&g_BlockedCount, 0, 0);
            info = sizeof(ULONG);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_AUX_SET_BGSRV_PID:
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE))
        {
            g_BgSrvPid = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            DbgPrintEx(0, 0, "[Auxiliary] BgSrv PID set to %p\n", g_BgSrvPid);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_AUX_SET_QUITTING:
        g_Quitting = true;
        DbgPrintEx(0, 0, "[Auxiliary] QUITTING state set - all blocks disabled\n");
        break;

    case IOCTL_AUX_SET_PROTECTION:
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AUX_PROTECTION_INPUT))
        {
            PAUX_PROTECTION_INPUT pIn = (PAUX_PROTECTION_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status = AuxSetProcessProtection(pIn->Pid, pIn->ProtectionLevel);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_AUX_HIDE_PROCESS:
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AUX_HIDE_INPUT))
        {
            PAUX_HIDE_INPUT pIn = (PAUX_HIDE_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status = AuxHideProcess(pIn->Pid);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_AUX_UNHIDE_PROCESS:
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AUX_HIDE_INPUT))
        {
            PAUX_HIDE_INPUT pIn = (PAUX_HIDE_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status = AuxUnhideProcess(pIn->Pid);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ============================================================
 *  创建/关闭处理
 * ============================================================ */

static NTSTATUS AuxCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ============================================================
 *  驱动卸载
 * ============================================================ */

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    DbgPrintEx(0, 0, "[Auxiliary] Unloading Auxiliary.sys\n");

    /* 停止 InfinityHook */
    KHook::Stop();

    /* 等待所有 CPU 退出 hook 回调，避免卸载后仍有 CPU 执行已释放的回调
     * GetCpuClock 恢复后，已进入回调的 CPU 可能仍在执行 InfinityCallback。
     * 等待 10s 确保所有并发实例退出。
     */
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -500 * 10000 * 20; /* 10s，确保所有 CPU 退出回调 */
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    DbgPrintEx(0, 0, "[Auxiliary] Waited 2s for all CPUs to exit hook callback\n");
    DbgPrintEx(0, 0, "[Auxiliary] Waited 500ms for all CPUs to exit hook callback\n");

    /* 删除符号链接和设备对象 */
    if (g_DosDeviceName.Buffer)
    {
        IoDeleteSymbolicLink(&g_DosDeviceName);
        g_DosDeviceName.Buffer = NULL;
        g_DosDeviceName.Length = 0;
        g_DosDeviceName.MaximumLength = 0;
        DbgPrintEx(0, 0, "[Auxiliary] Deleting SymbolicLink\n");
    }
    if (driver && driver->DeviceObject)
    {
        DbgPrintEx(0, 0, "[Auxiliary] Deleting device %p\n", driver->DeviceObject);
        IoDeleteDevice(driver->DeviceObject);
        driver->DeviceObject = NULL;
    }

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys unloaded\n");
}

/* ============================================================
 *  DriverEntry
 * ============================================================ */

EXTERN_C
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driver,
    PUNICODE_STRING registe)
{
    UNREFERENCED_PARAMETER(registe);
    NTSTATUS status;
    UNICODE_STRING deviceName;

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys loading (InfinityHook syscall interceptor)\n");

    /* 设置卸载例程 */
    driver->DriverUnload = DriverUnload;

    /* 设置分发例程 */
    driver->MajorFunction[IRP_MJ_CREATE] = AuxCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = AuxCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AuxIoctlDispatch;

    /* 创建设备对象 */
    RtlInitUnicodeString(&deviceName, AUX_DEVICE_NAME);
    status = IoCreateDevice(driver, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[Auxiliary] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    /* 创建符号链接 */
    RtlInitUnicodeString(&g_DosDeviceName, AUX_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&g_DosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[Auxiliary] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys loaded, initializing InfinityHook...\n");

    /* 直接在 DriverEntry 中初始化并启动 KHook，不需要单独的 IOCTL */
    if (!GetSyscallAddresses())
    {
        DbgPrintEx(0, 0, "[Auxiliary] GetSyscallAddresses failed\n");
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_NOT_FOUND;
    }

    if (!KHook::Initialize(InfinityCallback))
    {
        DbgPrintEx(0, 0, "[Auxiliary] KHook::Initialize failed\n");
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_UNSUCCESSFUL;
    }

    if (!KHook::Start())
    {
        DbgPrintEx(0, 0, "[Auxiliary] KHook::Start failed\n");
        KHook::Stop();
        IoDeleteSymbolicLink(&g_DosDeviceName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(0, 0, "[Auxiliary] InfinityHook started successfully\n");
    return STATUS_SUCCESS;
}

#pragma once

#include "common.h"

// 照抄 PPLcontrol OffsetFinder.h (去掉 HMODULE，内核态用 MmGetSystemRoutineAddress)

#define OF_STR_PSINITIALSYSTEMPROCESS_SYMBOL_NAME_A     "PsInitialSystemProcess"
#define OF_STR_PSGETPROCESSID_PROC_NAME_A                "PsGetProcessId"
#define OF_STR_PSISPROTECTEDPROCESS_PROC_NAME_A         "PsIsProtectedProcess"
#define OF_STR_PSISPROTECTEDPROCESSLIGHT_PROC_NAME_A    "PsIsProtectedProcessLight"

enum class Offset
{
    KernelPsInitialSystemProcess,
    ProcessActiveProcessLinks,
    ProcessUniqueProcessId,
    ProcessProtection,
    ProcessSignatureLevel,
    ProcessSectionSignatureLevel
};

class OffsetFinder
{
public:
    OffsetFinder();
    ~OffsetFinder();
    DWORD GetOffset(Offset Name);
    bool FindAllOffsets();
    ULONG_PTR GetPsInitialSystemProcessAddr() { return m_PsInitialSystemProcessAddr; }

private:
    // 照抄 PPLcontrol 的全部 Find 函数
    bool FindKernelPsInitialSystemProcessOffset();
    bool FindProcessActiveProcessLinksOffset();
    bool FindProcessUniqueProcessIdOffset();
    bool FindProcessProtectionOffset();
    bool FindProcessSignatureLevelOffset();
    bool FindProcessSectionSignatureLevelOffset();

private:
    // 内核态: PsInitialSystemProcess 是 64 位内核地址，不能存在 DWORD offset map 里
    ULONG_PTR m_PsInitialSystemProcessAddr;
    DWORD _OffsetMap[6]; // 对应 enum class Offset 的 6 个值
};

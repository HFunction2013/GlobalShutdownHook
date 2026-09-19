#include "OffsetFinder.h"

// 照抄 PPLcontrol OffsetFinder.cpp 的全部逻辑
// 最小内核适配: LoadLibrary/GetProcAddress → MmGetSystemRoutineAddress
//               std::map → 数组 (内核态无 STL)

OffsetFinder::OffsetFinder()
{
    // 照抄 PPLcontrol: 构造时初始化
    // 用户态: _KernelModule = LoadLibraryW(OF_STR_KERNEL_IMAGE_FILE_NAME_W);
    // 内核态: 不需要 LoadLibrary，直接清零偏移数组
    m_PsInitialSystemProcessAddr = 0;
    for (int i = 0; i < 6; i++)
        _OffsetMap[i] = 0xFFFFFFFF; // 未找到标记
}

OffsetFinder::~OffsetFinder()
{
    // 照抄 PPLcontrol: FreeLibrary
    // 内核态: 不需要
}

DWORD OffsetFinder::GetOffset(Offset Name)
{
    // 照抄 PPLcontrol: return _OffsetMap[Name];
    return _OffsetMap[(int)Name];
}

bool OffsetFinder::FindAllOffsets()
{
    // 照抄 PPLcontrol: 依次调用全部 Find 函数
    if (!FindKernelPsInitialSystemProcessOffset())
        return false;

    if (!FindProcessUniqueProcessIdOffset())
        return false;

    if (!FindProcessProtectionOffset())
        return false;

    if (!FindProcessActiveProcessLinksOffset())
        return false;

    if (!FindProcessSignatureLevelOffset())
        return false;

    if (!FindProcessSectionSignatureLevelOffset())
        return false;

    return true;
}

bool OffsetFinder::FindKernelPsInitialSystemProcessOffset()
{
    // 照抄 PPLcontrol FindKernelPsInitialSystemProcessOffset:
    //   用户态: pPsInitialSystemProcess = GetProcAddress(_KernelModule, "PsInitialSystemProcess")
    //           dwOffset = pPsInitialSystemProcess - (ULONG_PTR)_KernelModule
    //   内核态: 直接用 MmGetSystemRoutineAddress 得到虚拟地址
    //           PsInitialSystemProcess 是全局变量，我们直接存它的地址

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsInitialSystemProcess");
    PVOID pPsInitialSystemProcess = MmGetSystemRoutineAddress(&funcName);
    if (!pPsInitialSystemProcess)
        return false;

    // 用户态: dwPsInitialSystemProcessOffset = (DWORD)(pPsInitialSystemProcess - (ULONG_PTR)_KernelModule);
    // 内核态: 64 位内核地址存到单独的成员变量 (不能存到 DWORD offset map)
    m_PsInitialSystemProcessAddr = (ULONG_PTR)pPsInitialSystemProcess;

    return true;
}

bool OffsetFinder::FindProcessActiveProcessLinksOffset()
{
    // 照抄 PPLcontrol FindProcessActiveProcessLinksOffset:
    //   wActiveProcessLinks = (WORD)_OffsetMap[Offset::ProcessUniqueProcessId] + sizeof(HANDLE);

    if (_OffsetMap[(int)Offset::ProcessUniqueProcessId] == 0xFFFFFFFF)
        return false;

    WORD wActiveProcessLinks = (WORD)_OffsetMap[(int)Offset::ProcessUniqueProcessId] + (WORD)sizeof(HANDLE);
    _OffsetMap[(int)Offset::ProcessActiveProcessLinks] = wActiveProcessLinks;

    return true;
}

bool OffsetFinder::FindProcessUniqueProcessIdOffset()
{
    // 照抄 PPLcontrol FindProcessUniqueProcessIdOffset:
    //   pPsGetProcessId = GetProcAddress(_KernelModule, "PsGetProcessId")
    //   memcpy_s(&wUniqueProcessIdOffset, ..., (PVOID)((ULONG_PTR)pPsGetProcessId + 3), ...)

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsGetProcessId");
    PVOID pPsGetProcessId = MmGetSystemRoutineAddress(&funcName);
    if (!pPsGetProcessId)
        return false;

    WORD wUniqueProcessIdOffset = 0;
    // 照抄 PPLcontrol: x64 下从 +3 处读 WORD
    RtlCopyMemory(&wUniqueProcessIdOffset, (PVOID)((ULONG_PTR)pPsGetProcessId + 3), sizeof(WORD));

    if (wUniqueProcessIdOffset > 0x0fff)
        return false;

    _OffsetMap[(int)Offset::ProcessUniqueProcessId] = wUniqueProcessIdOffset;

    return true;
}

bool OffsetFinder::FindProcessProtectionOffset()
{
    // 照抄 PPLcontrol FindProcessProtectionOffset:
    //   pPsIsProtectedProcess = GetProcAddress(_KernelModule, "PsIsProtectedProcess")
    //   pPsIsProtectedProcessLight = GetProcAddress(_KernelModule, "PsIsProtectedProcessLight")
    //   memcpy_s(&wProtectionOffsetA, ..., (PVOID)((ULONG_PTR)pPsIsProtectedProcess + 2), ...)
    //   memcpy_s(&wProtectionOffsetB, ..., (PVOID)((ULONG_PTR)pPsIsProtectedProcessLight + 2), ...)
    //   交叉验证两个偏移一致

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
    // 照抄 PPLcontrol: 从 +2 处读 WORD
    RtlCopyMemory(&wProtectionOffsetA, (PVOID)((ULONG_PTR)pPsIsProtectedProcess + 2), sizeof(WORD));
    RtlCopyMemory(&wProtectionOffsetB, (PVOID)((ULONG_PTR)pPsIsProtectedProcessLight + 2), sizeof(WORD));

    if (wProtectionOffsetA != wProtectionOffsetB || wProtectionOffsetA > 0x0fff)
        return false;

    _OffsetMap[(int)Offset::ProcessProtection] = wProtectionOffsetA;

    return true;
}

bool OffsetFinder::FindProcessSignatureLevelOffset()
{
    // 照抄 PPLcontrol FindProcessSignatureLevelOffset:
    //   wSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - (2 * sizeof(UCHAR));

    if (_OffsetMap[(int)Offset::ProcessProtection] == 0xFFFFFFFF)
        return false;

    WORD wSignatureLevel = (WORD)_OffsetMap[(int)Offset::ProcessProtection] - (2 * (WORD)sizeof(UCHAR));
    _OffsetMap[(int)Offset::ProcessSignatureLevel] = wSignatureLevel;

    return true;
}

bool OffsetFinder::FindProcessSectionSignatureLevelOffset()
{
    // 照抄 PPLcontrol FindProcessSectionSignatureLevelOffset:
    //   wSectionSignatureLevel = (WORD)_OffsetMap[Offset::ProcessProtection] - sizeof(UCHAR);

    if (_OffsetMap[(int)Offset::ProcessProtection] == 0xFFFFFFFF)
        return false;

    WORD wSectionSignatureLevel = (WORD)_OffsetMap[(int)Offset::ProcessProtection] - (WORD)sizeof(UCHAR);
    _OffsetMap[(int)Offset::ProcessSectionSignatureLevel] = wSectionSignatureLevel;

    return true;
}

#include "Controller.h"

// 照抄 PPLcontrol Controller.cpp 的全部逻辑
// 最小内核适配:
//   1. LPCWSTR 字符串参数 → UCHAR 数值参数 (内核不需要字符串解析)
//   2. GetProcessKernelAddress → PsLookupProcessByProcessId (内核直接 API)
//   3. wprintf/ERROR/SUCCESS 宏 → DbgPrintEx 或去掉
//   4. FALSE/TRUE → false/true

Controller::Controller()
{
    // 照抄 PPLcontrol Controller::Controller()
    _rtc = new RTCore();
    _of = new OffsetFinder();

    _of->FindAllOffsets();
}

Controller::~Controller()
{
    // 照抄 PPLcontrol: 清理
    if (_rtc) { delete _rtc; _rtc = NULL; }
    if (_of)  { delete _of;  _of = NULL; }
}

// 照抄 PPLcontrol Controller::GetProcessKernelAddress
// 内核适配: 照抄 PPLcontrol 的 GetProcessList 逻辑，遍历 ActiveProcessLinks 找 EPROCESS
//           (不用 PsLookupProcessByProcessId，避免多次调用导致引用计数泄漏)
bool Controller::GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr)
{
    // 照抄 PPLcontrol GetInitialSystemProcessAddress:
    //   pPsInitialSystemProcess = GetKernelAddress(pKernelBase, Offset::KernelPsInitialSystemProcess)
    //   pInitialSystemProcess = *pPsInitialSystemProcess
    // 内核适配: OffsetFinder 提供 GetPsInitialSystemProcessAddr() 获取 64 位内核地址
    ULONG_PTR pPsInitialSystemProcess = _of->GetPsInitialSystemProcessAddr();
    if (!pPsInitialSystemProcess)
        return false;

    ULONG_PTR pInitialSystemProcess = 0;
    if (!_rtc->ReadPtr(pPsInitialSystemProcess, &pInitialSystemProcess))
        return false;

    // 照抄 PPLcontrol GetProcessList 中的遍历逻辑:
    //   do { 读 PID, 找匹配 } while (pProcess != pInitialSystemProcess)
    ULONG_PTR pProcess = pInitialSystemProcess;
    do
    {
        DWORD64 dwProcessId = 0;
        if (!_rtc->Read64(pProcess + _of->GetOffset(Offset::ProcessUniqueProcessId), &dwProcessId))
            break;

        if ((DWORD)dwProcessId == Pid)
        {
            *Addr = pProcess;
            return true;
        }

        // 走到下一个进程: ActiveProcessLinks.Flink
        ULONG_PTR pNext = 0;
        if (!_rtc->ReadPtr(pProcess + _of->GetOffset(Offset::ProcessActiveProcessLinks), &pNext))
            break;
        pProcess = pNext - _of->GetOffset(Offset::ProcessActiveProcessLinks);

    } while (pProcess != pInitialSystemProcess);

    return false;
}

// ============================================================
// 照抄 PPLcontrol Controller.cpp 底层读写函数
// ============================================================

bool Controller::GetProcessProtection(ULONG_PTR Addr, PUCHAR Protection)
{
    UCHAR bProtection;

    // 照抄 PPLcontrol: _rtc->Read8(Addr + _of->GetOffset(Offset::ProcessProtection), &bProtection)
    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessProtection), &bProtection)))
        return false;

    *Protection = bProtection;
    return true;
}

bool Controller::SetProcessProtection(ULONG_PTR Addr, UCHAR Protection)
{
    // 照抄 PPLcontrol: _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessProtection), Protection)
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessProtection), Protection);
}

bool Controller::GetProcessSignatureLevel(ULONG_PTR Addr, PUCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    // 照抄 PPLcontrol: _rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), &bSignatureLevel)
    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), &bSignatureLevel)))
        return false;

    *SignatureLevel = bSignatureLevel;
    return true;
}

bool Controller::SetProcessSignatureLevel(ULONG_PTR Addr, UCHAR SignatureLevel)
{
    // 照抄 PPLcontrol: _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), SignatureLevel)
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSignatureLevel), SignatureLevel);
}

bool Controller::GetProcessSectionSignatureLevel(ULONG_PTR Addr, PUCHAR SectionSignatureLevel)
{
    UCHAR bSectionSignatureLevel;

    // 照抄 PPLcontrol: _rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), &bSectionSignatureLevel)
    if (!(_rtc->Read8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), &bSectionSignatureLevel)))
        return false;

    *SectionSignatureLevel = bSectionSignatureLevel;
    return true;
}

bool Controller::SetProcessSectionSignatureLevel(ULONG_PTR Addr, UCHAR SectionSignatureLevel)
{
    // 照抄 PPLcontrol: _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), SectionSignatureLevel)
    return _rtc->Write8(Addr + _of->GetOffset(Offset::ProcessSectionSignatureLevel), SectionSignatureLevel);
}

// ============================================================
// 照抄 PPLcontrol Controller.cpp 中层函数 (带 Pid 参数的版本)
// ============================================================

// 照抄 PPLcontrol Controller::SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
// 内核适配: LPCWSTR 参数 → UCHAR 数值参数 (直接传数值，不需要字符串解析)
bool Controller::SetProcessProtection(DWORD Pid, UCHAR bProtectionLevel, UCHAR bSignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtectionOld, bProtectionNew, bProtectionEffective;

    // 照抄 PPLcontrol: bProtectionNew = Utils::GetProtection(bProtectionLevel, bSignerType)
    bProtectionNew = Utils::GetProtection(bProtectionLevel, bSignerType);

    // 照抄 PPLcontrol: if (!GetProcessKernelAddress(Pid, &pProcess))
    if (!GetProcessKernelAddress(Pid, &pProcess))
        return false;

    // 照抄 PPLcontrol: if (!GetProcessProtection(pProcess, &bProtectionOld))
    if (!GetProcessProtection(pProcess, &bProtectionOld))
        return false;

    // 照抄 PPLcontrol: if (bProtectionOld == bProtectionNew)
    if (bProtectionOld == bProtectionNew)
    {
        DbgPrintEx(0, 0, "[PPL] Process PID %d already has protection 0x%02X\n", Pid, bProtectionNew);
        return false;
    }

    // 照抄 PPLcontrol: if (!SetProcessProtection(pProcess, bProtectionNew))
    if (!SetProcessProtection(pProcess, bProtectionNew))
    {
        DbgPrintEx(0, 0, "[PPL] Failed to set protection 0x%02X on PID %d\n", bProtectionNew, Pid);
        return false;
    }

    // 照抄 PPLcontrol: if (!GetProcessProtection(pProcess, &bProtectionEffective))
    if (!GetProcessProtection(pProcess, &bProtectionEffective))
        return false;

    // 照抄 PPLcontrol: if (bProtectionNew != bProtectionEffective)
    if (bProtectionNew != bProtectionEffective)
    {
        DbgPrintEx(0, 0, "[PPL] Protection mismatch: expected 0x%02X, got 0x%02X\n", bProtectionNew, bProtectionEffective);
        return false;
    }

    DbgPrintEx(0, 0, "[PPL] SetProcessProtection: PID %d old=0x%02X new=0x%02X\n", Pid, bProtectionOld, bProtectionNew);
    return true;
}

// 照抄 PPLcontrol Controller::SetProcessSignatureLevels(DWORD Pid, LPCWSTR SignerType)
// 内核适配: LPCWSTR 参数 → UCHAR 数值参数
bool Controller::SetProcessSignatureLevels(DWORD Pid, UCHAR bSignerType)
{
    ULONG_PTR pProcess;
    UCHAR bSignatureLevel, bSectionSignatureLevel;

    // 照抄 PPLcontrol: bSignatureLevel = Utils::GetSignatureLevel(bSignerType)
    if ((bSignatureLevel = Utils::GetSignatureLevel(bSignerType)) == 0xff)
        return false;

    // 照抄 PPLcontrol: bSectionSignatureLevel = Utils::GetSectionSignatureLevel(bSignerType)
    if ((bSectionSignatureLevel = Utils::GetSectionSignatureLevel(bSignerType)) == 0xff)
        return false;

    // 照抄 PPLcontrol: if (!GetProcessKernelAddress(Pid, &pProcess))
    if (!GetProcessKernelAddress(Pid, &pProcess))
        return false;

    // 照抄 PPLcontrol: if (!SetProcessSignatureLevel(pProcess, bSignatureLevel))
    if (!SetProcessSignatureLevel(pProcess, bSignatureLevel))
        return false;

    // 照抄 PPLcontrol: if (!SetProcessSectionSignatureLevel(pProcess, bSectionSignatureLevel))
    if (!SetProcessSectionSignatureLevel(pProcess, bSectionSignatureLevel))
        return false;

    DbgPrintEx(0, 0, "[PPL] SetProcessSignatureLevels: PID %d sig=0x%02X secsig=0x%02X\n",
               Pid, bSignatureLevel, bSectionSignatureLevel);
    return true;
}

// ============================================================
// 照抄 PPLcontrol Controller.cpp 顶层函数
// ============================================================

// 照抄 PPLcontrol Controller::ProtectProcess(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
// 内核适配: LPCWSTR 参数 → UCHAR 数值参数
bool Controller::ProtectProcess(DWORD Pid, UCHAR bProtectionLevel, UCHAR bSignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    // 照抄 PPLcontrol: if (!GetProcessKernelAddress(Pid, &pProcess))
    if (!GetProcessKernelAddress(Pid, &pProcess))
        return false;

    // 照抄 PPLcontrol: if (!GetProcessProtection(pProcess, &bProtection))
    if (!GetProcessProtection(pProcess, &bProtection))
        return false;

    // 照抄 PPLcontrol: if (bProtection > 0) — 已经被保护了
    if (bProtection > 0)
    {
        DbgPrintEx(0, 0, "[PPL] Process PID %d is already protected (0x%02X)\n", Pid, bProtection);
        return false;
    }

    // 照抄 PPLcontrol: if (!SetProcessProtection(Pid, ProtectionLevel, SignerType))
    if (!SetProcessProtection(Pid, bProtectionLevel, bSignerType))
        return false;

    // 照抄 PPLcontrol: if (!SetProcessSignatureLevels(Pid, SignerType))
    if (!SetProcessSignatureLevels(Pid, bSignerType))
        return false;

    // 照抄 PPLcontrol: SUCCESS 日志
    DbgPrintEx(0, 0, "[PPL] ProtectProcess SUCCESS: PID %d level=%u signer=%u\n",
               Pid, bProtectionLevel, bSignerType);

    return true;
}

// 照抄 PPLcontrol Controller::UnprotectProcess(DWORD Pid)
bool Controller::UnprotectProcess(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    // 照抄 PPLcontrol: if (!GetProcessKernelAddress(Pid, &pProcess))
    if (!GetProcessKernelAddress(Pid, &pProcess))
        return false;

    // 照抄 PPLcontrol: if (!GetProcessProtection(pProcess, &bProtection))
    if (!GetProcessProtection(pProcess, &bProtection))
        return false;

    // 照抄 PPLcontrol: if (bProtection == 0) — 没有被保护
    if (bProtection == 0)
    {
        DbgPrintEx(0, 0, "[PPL] Process PID %d is not protected, nothing to unprotect\n", Pid);
        return false;
    }

    // 照抄 PPLcontrol: if (!SetProcessProtection(pProcess, 0))
    if (!SetProcessProtection(pProcess, 0))
    {
        DbgPrintEx(0, 0, "[PPL] Failed to set Protection=0 on PID %d\n", Pid);
        return false;
    }

    // 照抄 PPLcontrol: if (!GetProcessProtection(pProcess, &bProtection))
    if (!GetProcessProtection(pProcess, &bProtection))
    {
        return false;
    }

    // 照抄 PPLcontrol: if (bProtection != 0)
    if (bProtection != 0)
    {
        DbgPrintEx(0, 0, "[PPL] PID %d still appears protected after clear (0x%02X)\n", Pid, bProtection);
        return false;
    }

    // 照抄 PPLcontrol: if (!SetProcessSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    if (!SetProcessSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        DbgPrintEx(0, 0, "[PPL] Failed to set SignatureLevel=UNCHECKED on PID %d\n", Pid);
        return false;
    }

    // 照抄 PPLcontrol: if (!SetProcessSectionSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    if (!SetProcessSectionSignatureLevel(pProcess, SE_SIGNING_LEVEL_UNCHECKED))
    {
        DbgPrintEx(0, 0, "[PPL] Failed to set SectionSignatureLevel=UNCHECKED on PID %d\n", Pid);
        return false;
    }

    // 照抄 PPLcontrol: SUCCESS 日志
    DbgPrintEx(0, 0, "[PPL] UnprotectProcess SUCCESS: PID %d\n", Pid);

    return true;
}

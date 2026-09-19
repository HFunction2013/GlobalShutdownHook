#pragma once

#include "RTCore.h"
#include "OffsetFinder.h"
#include "Utils.h"

// 照抄 PPLcontrol Controller.h 的结构
// 最小内核适配: 去掉进程枚举列表 (不需要)，保留核心 Protect/Unprotect 接口

class Controller
{
public:
    Controller();
    ~Controller();

    // 照抄 PPLcontrol Controller.h 的核心接口
    bool ProtectProcess(DWORD Pid, UCHAR ProtectionLevel, UCHAR SignerType);
    bool UnprotectProcess(DWORD Pid);

private:
    RTCore* _rtc;
    OffsetFinder* _of;

private:
    // 照抄 PPLcontrol Controller.h 的私有函数
    bool GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr);

    bool GetProcessProtection(ULONG_PTR Addr, PUCHAR Protection);
    bool SetProcessProtection(ULONG_PTR Addr, UCHAR Protection);

    bool GetProcessSignatureLevel(ULONG_PTR Addr, PUCHAR SignatureLevel);
    bool SetProcessSignatureLevel(ULONG_PTR Addr, UCHAR SignatureLevel);

    bool GetProcessSectionSignatureLevel(ULONG_PTR Addr, PUCHAR SectionSignatureLevel);
    bool SetProcessSectionSignatureLevel(ULONG_PTR Addr, UCHAR SectionSignatureLevel);

    // 照抄 PPLcontrol Controller::SetProcessSignatureLevels (带 Pid 参数的版本)
    bool SetProcessSignatureLevels(DWORD Pid, UCHAR SignerType);

    // 照抄 PPLcontrol Controller::SetProcessProtection (带 Pid 参数的版本)
    bool SetProcessProtection(DWORD Pid, UCHAR ProtectionLevel, UCHAR SignerType);
};

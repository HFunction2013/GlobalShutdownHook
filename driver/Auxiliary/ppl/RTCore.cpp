#include "RTCore.h"

// 照抄 PPLcontrol RTCore.cpp 的接口
// 最小内核适配: 用户态通过 RTCore64 驱动 IOCTL 读写物理内存
//               内核态直接读写虚拟地址即可

RTCore::RTCore()
{
    // 照抄 PPLcontrol: 初始化设备句柄
    // 内核态: 不需要
}

RTCore::~RTCore()
{
    // 照抄 PPLcontrol: 关闭设备句柄
    // 内核态: 不需要
}

// ---- 照抄 PPLcontrol RTCore.cpp: Read8 ----
// 用户态: _rtc->Read8(addr, &val) → 通过 IOCTL 读物理内存
// 内核态: 直接读虚拟地址
bool RTCore::Read8(ULONG_PTR Address, PBYTE Value)
{
    *Value = *(PBYTE)Address;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Read16 ----
bool RTCore::Read16(ULONG_PTR Address, PWORD Value)
{
    *Value = *(PWORD)Address;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Read32 ----
bool RTCore::Read32(ULONG_PTR Address, PDWORD Value)
{
    *Value = *(PDWORD)Address;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Read64 ----
bool RTCore::Read64(ULONG_PTR Address, PDWORD64 Value)
{
    *Value = *(PDWORD64)Address;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: ReadPtr ----
bool RTCore::ReadPtr(ULONG_PTR Address, PULONG_PTR Value)
{
    *Value = *(PULONG_PTR)Address;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Write8 ----
// 用户态: _rtc->Write8(addr, val) → 通过 IOCTL 写物理内存
// 内核态: 直接写虚拟地址
bool RTCore::Write8(ULONG_PTR Address, BYTE Value)
{
    *(PBYTE)Address = Value;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Write16 ----
bool RTCore::Write16(ULONG_PTR Address, WORD Value)
{
    *(PWORD)Address = Value;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Write32 ----
bool RTCore::Write32(ULONG_PTR Address, DWORD Value)
{
    *(PDWORD)Address = Value;
    return true;
}

// ---- 照抄 PPLcontrol RTCore.cpp: Write64 ----
bool RTCore::Write64(ULONG_PTR Address, DWORD64 Value)
{
    *(PDWORD64)Address = Value;
    return true;
}

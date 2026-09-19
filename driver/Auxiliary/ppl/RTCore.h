#pragma once

#include "common.h"

// 照抄 PPLcontrol RTCore.h 的接口定义
// 最小内核适配: 不再通过 RTCore64 驱动 IOCTL 读写内存
// 我们本身就是内核驱动，直接读写内核虚拟地址即可
// 接口完全保持一致: Read8/Write8/Read16/Write16/Read32/Write32/Read64/Write64/ReadPtr/WritePtr

class RTCore
{
public:
    RTCore();
    ~RTCore();

    // 照抄 PPLcontrol RTCore.h 的全部接口
    bool Read8(ULONG_PTR Address, PBYTE Value);
    bool Read16(ULONG_PTR Address, PWORD Value);
    bool Read32(ULONG_PTR Address, PDWORD Value);
    bool Read64(ULONG_PTR Address, PDWORD64 Value);
    bool ReadPtr(ULONG_PTR Address, PULONG_PTR Value);

    bool Write8(ULONG_PTR Address, BYTE Value);
    bool Write16(ULONG_PTR Address, WORD Value);
    bool Write32(ULONG_PTR Address, DWORD Value);
    bool Write64(ULONG_PTR Address, DWORD64 Value);
};

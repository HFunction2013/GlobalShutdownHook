#pragma once

#include "common.h"

// 照抄 PPLcontrol Utils.h (去掉用户态字符串相关，只保留核心函数)

// The following signing levels are defined in winnt.h (see type SE_SIGNING_LEVEL)
// 照抄 PPLcontrol Utils.h 中的字符串宏对应的数值
// 注意: ntddk.h 已定义 SE_SIGNING_LEVEL_*，这里用 #ifndef 防重定义

#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED     0x00
#endif
#ifndef SE_SIGNING_LEVEL_UNSIGNED
#define SE_SIGNING_LEVEL_UNSIGNED       0x01
#endif
#ifndef SE_SIGNING_LEVEL_ENTERPRISE
#define SE_SIGNING_LEVEL_ENTERPRISE     0x02
#endif
#ifndef SE_SIGNING_LEVEL_DEVELOPER
#define SE_SIGNING_LEVEL_DEVELOPER      0x03
#endif
#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE  0x04
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
#define SE_SIGNING_LEVEL_CUSTOM_4       0x09
#endif
#ifndef SE_SIGNING_LEVEL_CUSTOM_5
#define SE_SIGNING_LEVEL_CUSTOM_5       0x0A
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
#define SE_SIGNING_LEVEL_CUSTOM_6       0x0F
#endif

class Utils
{
public:
    // 照抄 PPLcontrol Utils.cpp 的全部函数 (去掉字符串相关，只保留数值计算)
    static UCHAR GetProtectionLevel(UCHAR Protection);
    static UCHAR GetSignerType(UCHAR Protection);
    static UCHAR GetProtection(UCHAR ProtectionLevel, UCHAR SignerType);
    static UCHAR GetSignatureLevel(UCHAR SignerType);
    static UCHAR GetSectionSignatureLevel(UCHAR SignerType);
};

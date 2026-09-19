#include "Utils.h"

// 照抄 PPLcontrol Utils.cpp 的全部核心函数 (去掉字符串/psapi 相关)

UCHAR Utils::GetProtectionLevel(UCHAR Protection)
{
    // 照抄: return Protection & 0x07;
    return Protection & 0x07;
}

UCHAR Utils::GetSignerType(UCHAR Protection)
{
    // 照抄: return (Protection & 0xf0) >> 4;
    return (Protection & 0xf0) >> 4;
}

UCHAR Utils::GetProtection(UCHAR ProtectionLevel, UCHAR SignerType)
{
    // 照抄: return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

UCHAR Utils::GetSignatureLevel(UCHAR SignerType)
{
    // 照抄 PPLcontrol Utils.cpp GetSignatureLevel (https://www.alex-ionescu.com/?p=146)
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
    }

    return 0xff;
}

UCHAR Utils::GetSectionSignatureLevel(UCHAR SignerType)
{
    // 照抄 PPLcontrol Utils.cpp GetSectionSignatureLevel (https://www.alex-ionescu.com/?p=146)
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
    //case PsProtectedSignerWinTcb:
    //    return SE_SIGNING_LEVEL_WINDOWS_TCB;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS; // Section signature level is actually 'Windows' in this case.
    }

    return 0xff;
}

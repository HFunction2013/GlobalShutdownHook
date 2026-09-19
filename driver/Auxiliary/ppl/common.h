#pragma once

// 照抄 PPLcontrol common.h (用户态 printf 宏去掉，只保留类型定义)

// 内核模式 C++ new/delete 实现 (内核态无默认 new/delete)
inline void* __cdecl operator new(size_t size)
{
    return ExAllocatePoolWithTag(NonPagedPool, size, 'PPL1');
}
inline void __cdecl operator delete(void* p)
{
    if (p) ExFreePoolWithTag(p, 'PPL1');
}
inline void* __cdecl operator new[](size_t size)
{
    return ExAllocatePoolWithTag(NonPagedPool, size, 'PPL1');
}
inline void __cdecl operator delete[](void* p)
{
    if (p) ExFreePoolWithTag(p, 'PPL1');
}

#define NOOP do {} while(0)

typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,      // 0
    PsProtectedSignerAuthenticode,  // 1
    PsProtectedSignerCodeGen,       // 2
    PsProtectedSignerAntimalware,   // 3
    PsProtectedSignerLsa,           // 4
    PsProtectedSignerWindows,       // 5
    PsProtectedSignerWinTcb,        // 6
    PsProtectedSignerWinSystem,     // 7
    PsProtectedSignerApp,           // 8
    PsProtectedSignerMax            // 9
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

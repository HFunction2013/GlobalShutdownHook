#pragma once

// 包含内核头文件 (提供 UCHAR/DWORD/ULONG_PTR/PVOID/NonPagedPool 等类型和函数)
#include "../headers.hpp"

// 内核态类型适配: PPLControl 用户态指针类型 → 内核态等价类型 (只加别名，不改原代码)
typedef PUCHAR  PBYTE;
typedef PUSHORT  PWORD;
typedef PULONG   PDWORD;
typedef PULONG64 PDWORD64;

// 照抄 PPLcontrol common.h (用户态 printf 宏去掉，只保留类型定义)

// 内核模式 C++ new/delete 实现 (内核态无默认 new/delete)
// 注意: 不能用 inline (C4595), 直接放头文件里重复定义也没事, 链接器会合并
void* __cdecl operator new(size_t size);
void  __cdecl operator delete(void* p);
void* __cdecl operator new[](size_t size);
void  __cdecl operator delete[](void* p);

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

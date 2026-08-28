/*
 * gsh_pe.c - 用户态进程 PE 解析
 *
 * 在 attach 到目标进程后：
 *   1. ZwQueryInformationProcess 取 PEB
 *   2. 遍历 PEB->Ldr->InMemoryOrderModuleList 找模块基址
 *   3. 解析 PE 导出表找目标函数
 *
 * 支持 64 位原生进程；Wow64 进程做最佳尝试。
 */
#include "gsh_pe.h"
/* PE structures: winnt.h is user-mode and conflicts with kernel headers.
   Manually define the PE types needed for export table parsing. */
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE                 0x5A4D
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE                  0x00004550
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT        0
#endif
#ifndef IMAGE_NUMBEROF_DIRECTORY_ENTRIES
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#endif

typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    SHORT  e_ss;
    USHORT e_sp;
    USHORT e_csum;
    SHORT  e_ip;
    SHORT  e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT    Magic;
    UCHAR     MajorLinkerVersion;
    UCHAR     MinorLinkerVersion;
    ULONG     SizeOfCode;
    ULONG     SizeOfInitializedData;
    ULONG     SizeOfUninitializedData;
    ULONG     AddressOfEntryPoint;
    ULONG     BaseOfCode;
    ULONGLONG ImageBase;
    ULONG     SectionAlignment;
    ULONG     FileAlignment;
    USHORT    MajorOperatingSystemVersion;
    USHORT    MinorOperatingSystemVersion;
    USHORT    MajorImageVersion;
    USHORT    MinorImageVersion;
    USHORT    MajorSubsystemVersion;
    USHORT    MinorSubsystemVersion;
    ULONG     Win32VersionValue;
    ULONG     SizeOfImage;
    ULONG     SizeOfHeaders;
    ULONG     CheckSum;
    USHORT    Subsystem;
    USHORT    DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG     LoaderFlags;
    ULONG     NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG                     Signature;
    IMAGE_FILE_HEADER         FileHeader;
    IMAGE_OPTIONAL_HEADER64   OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

/* ntddk.h only forward-declares PIMAGE_NT_HEADERS32 (no full struct).
   Define the structs ourselves, but skip PIMAGE_NT_HEADERS32 typedef
   to avoid C2371 redefinition conflict. */
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG  SizeOfStackReserve;
    ULONG  SizeOfStackCommit;
    ULONG  SizeOfHeapReserve;
    ULONG  SizeOfHeapCommit;
    ULONG  LoaderFlags;
    ULONG  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_NT_HEADERS32 {
    ULONG                     Signature;
    IMAGE_FILE_HEADER         FileHeader;
    IMAGE_OPTIONAL_HEADER32   OptionalHeader;
} IMAGE_NT_HEADERS32;  /* PIMAGE_NT_HEADERS32 provided by ntddk.h */

typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG  Characteristics;
    ULONG  TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG  Name;
    ULONG  Base;
    ULONG  NumberOfFunctions;
    ULONG  NumberOfNames;
    ULONG  AddressOfFunctions;
    ULONG  AddressOfNames;
    ULONG  AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
/* LIST_ENTRY64 / UNICODE_STRING64 / LIST_ENTRY32 / UNICODE_STRING32 /
   PROCESS_BASIC_INFORMATION are provided by the Windows SDK (ntdef.h / ntddk.h). */

/* ---- 未文档化/需手动声明的 API ---- */
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define ProcessWow64Information 26

/* ---- 64 位 PEB / LDR 结构（Win10/11 偏移） ---- */
typedef struct _PEB64 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64 Ldr;                      /* 0x18 */
    /* ... 其余字段不关心 ... */
    UCHAR Padding[0x330 - 0x20];
    ULONG64 WoW64Process;             /* 0x330: 指向 32 位 PEB */
} PEB64, *PPEB64;

typedef struct _PEB_LDR_DATA64 {
    ULONG Length;
    UCHAR Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;     /* 0x10 */
    LIST_ENTRY64 InMemoryOrderModuleList;   /* 0x20 */
    LIST_ENTRY64 InInitializationOrderModuleList; /* 0x30 */
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;          /* 0x00 */
    LIST_ENTRY64 InMemoryOrderLinks;        /* 0x10 */
    LIST_ENTRY64 InInitializationOrderLinks;/* 0x20 */
    ULONG64 DllBase;                        /* 0x30 */
    ULONG64 EntryPoint;                     /* 0x38 */
    ULONG SizeOfImage;                      /* 0x40 */
    ULONG Pad0;
    UNICODE_STRING64 FullDllName;           /* 0x48 */
    UNICODE_STRING64 BaseDllName;           /* 0x58 */
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

/* ---- 32 位 PEB / LDR 结构（用于 Wow64） ---- */
typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;                      /* 0x0C */
} PEB32, *PPEB32;

typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;     /* 0x0C */
    LIST_ENTRY32 InMemoryOrderModuleList;   /* 0x14 */
    LIST_ENTRY32 InInitializationOrderModuleList; /* 0x1C */
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;          /* 0x00 */
    LIST_ENTRY32 InMemoryOrderLinks;        /* 0x08 */
    LIST_ENTRY32 InInitializationOrderLinks;/* 0x10 */
    ULONG DllBase;                          /* 0x18 */
    ULONG EntryPoint;                       /* 0x1C */
    ULONG SizeOfImage;                      /* 0x20 */
    UNICODE_STRING32 FullDllName;           /* 0x24 */
    UNICODE_STRING32 BaseDllName;           /* 0x2C */
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

/* ---- 安全读取用户态内存 ---- */
static NTSTATUS SafeRead(PVOID Src, PVOID Dst, SIZE_T Size)
{
    if (!Src || !Dst || Size == 0) return STATUS_INVALID_PARAMETER;
    __try {
        ProbeForRead(Src, Size, 1);
        RtlCopyMemory(Dst, Src, Size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS SafeReadUserString(ULONG64 BufferAddr, USHORT Length,
                                   PWCHAR OutBuf, ULONG OutBufChars)
{
    if (Length == 0 || !BufferAddr) return STATUS_INVALID_PARAMETER;
    ULONG bytes = min((ULONG)Length, (OutBufChars - 1) * sizeof(WCHAR));
    NTSTATUS status = SafeRead((PVOID)BufferAddr, OutBuf, bytes);
    if (NT_SUCCESS(status)) {
        OutBuf[bytes / sizeof(WCHAR)] = L'\0';
    }
    return status;
}

/* ---- 不区分大小写的宽字符串比较（限定长度） ---- */
static BOOLEAN WStringEqualI(PCWSTR A, PCWSTR B)
{
    if (!A || !B) return FALSE;
    while (*A && *B) {
        WCHAR a = *A, b = *B;
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
        A++; B++;
    }
    return *A == *B;
}

/* ---- 64 位模块查找 ---- */
static NTSTATUS FindModule64(ULONG64 PebAddr, PCWSTR ModuleName,
                             ULONG64 *ModuleBase)
{
    PEB64 peb;
    PEB_LDR_DATA64 ldr;
    ULONG64 head, cur;
    NTSTATUS status;

    status = SafeRead((PVOID)PebAddr, &peb, sizeof(peb));
    if (!NT_SUCCESS(status)) return status;
    if (!peb.Ldr) return STATUS_NOT_FOUND;

    status = SafeRead((PVOID)peb.Ldr, &ldr, sizeof(ldr));
    if (!NT_SUCCESS(status)) return status;

    head = peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InMemoryOrderModuleList);
    cur = ldr.InMemoryOrderModuleList.Flink;

    while (cur != head && cur != 0) {
        LDR_DATA_TABLE_ENTRY64 entry;
        ULONG64 entryAddr = cur - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

        status = SafeRead((PVOID)entryAddr, &entry, sizeof(entry));
        if (!NT_SUCCESS(status)) return status;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            WCHAR name[64] = {0};
            status = SafeReadUserString(entry.BaseDllName.Buffer,
                                        entry.BaseDllName.Length,
                                        name, 64);
            if (NT_SUCCESS(status) && WStringEqualI(name, ModuleName)) {
                *ModuleBase = entry.DllBase;
                return STATUS_SUCCESS;
            }
        }

        cur = entry.InMemoryOrderLinks.Flink;
    }

    return STATUS_NOT_FOUND;
}

/* ---- 32 位模块查找（Wow64） ---- */
static NTSTATUS FindModule32(ULONG PebAddr32, PCWSTR ModuleName,
                             ULONG *ModuleBase)
{
    PEB32 peb;
    PEB_LDR_DATA32 ldr;
    ULONG head, cur;
    NTSTATUS status;

    status = SafeRead((PVOID)(ULONG64)PebAddr32, &peb, sizeof(peb));
    if (!NT_SUCCESS(status)) return status;
    if (!peb.Ldr) return STATUS_NOT_FOUND;

    status = SafeRead((PVOID)(ULONG64)peb.Ldr, &ldr, sizeof(ldr));
    if (!NT_SUCCESS(status)) return status;

    head = peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA32, InMemoryOrderModuleList);
    cur = ldr.InMemoryOrderModuleList.Flink;

    while (cur != head && cur != 0) {
        LDR_DATA_TABLE_ENTRY32 entry;
        ULONG entryAddr = cur - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

        status = SafeRead((PVOID)(ULONG64)entryAddr, &entry, sizeof(entry));
        if (!NT_SUCCESS(status)) return status;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            WCHAR name[64] = {0};
            status = SafeReadUserString(entry.BaseDllName.Buffer,
                                        entry.BaseDllName.Length,
                                        name, 64);
            if (NT_SUCCESS(status) && WStringEqualI(name, ModuleName)) {
                *ModuleBase = entry.DllBase;
                return STATUS_SUCCESS;
            }
        }

        cur = entry.InMemoryOrderLinks.Flink;
    }

    return STATUS_NOT_FOUND;
}

/* ---- 导出表解析（64 位 PE） ---- */
static NTSTATUS FindExport64(ULONG64 ModuleBase, PCSTR FunctionName,
                             ULONG64 *FuncAddr)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_EXPORT_DIRECTORY expDir;
    NTSTATUS status;
    ULONG64 expRva, expAddr;
    ULONG i;

    status = SafeRead((PVOID)ModuleBase, &dos, sizeof(dos));
    if (!NT_SUCCESS(status)) return status;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    status = SafeRead((PVOID)(ModuleBase + dos.e_lfanew), &nt, sizeof(nt));
    if (!NT_SUCCESS(status)) return status;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    expRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0) return STATUS_NOT_FOUND;

    expAddr = ModuleBase + expRva;
    status = SafeRead((PVOID)expAddr, &expDir, sizeof(expDir));
    if (!NT_SUCCESS(status)) return status;

    /* 读取函数名数组 */
    ULONG *nameRvas = (ULONG *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfNames * sizeof(ULONG), 'PShG');
    if (!nameRvas) return STATUS_INSUFFICIENT_RESOURCES;

    status = SafeRead((PVOID)(ModuleBase + expDir.AddressOfNames),
                      nameRvas, expDir.NumberOfNames * sizeof(ULONG));
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(nameRvas, 'PShG');
        return status;
    }

    /* 读取序号数组 */
    USHORT *ordinals = (USHORT *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfNames * sizeof(USHORT), 'PShG');
    if (!ordinals) {
        ExFreePoolWithTag(nameRvas, 'PShG');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = SafeRead((PVOID)(ModuleBase + expDir.AddressOfNameOrdinals),
                      ordinals, expDir.NumberOfNames * sizeof(USHORT));
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(ordinals, 'PShG');
        ExFreePoolWithTag(nameRvas, 'PShG');
        return status;
    }

    /* 读取函数地址数组 */
    ULONG *funcRvas = (ULONG *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfFunctions * sizeof(ULONG), 'PShG');
    if (!funcRvas) {
        ExFreePoolWithTag(ordinals, 'PShG');
        ExFreePoolWithTag(nameRvas, 'PShG');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = SafeRead((PVOID)(ModuleBase + expDir.AddressOfFunctions),
                      funcRvas, expDir.NumberOfFunctions * sizeof(ULONG));
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(funcRvas, 'PShG');
        ExFreePoolWithTag(ordinals, 'PShG');
        ExFreePoolWithTag(nameRvas, 'PShG');
        return status;
    }

    /* 线性搜索函数名（导出表通常按名排序，可二分，但线性更安全） */
    *FuncAddr = 0;
    for (i = 0; i < expDir.NumberOfNames; i++) {
        CHAR funcName[128] = {0};
        status = SafeRead((PVOID)(ModuleBase + nameRvas[i]),
                          funcName, sizeof(funcName) - 1);
        if (!NT_SUCCESS(status)) continue;

        if (strcmp(funcName, FunctionName) == 0) {
            USHORT ord = ordinals[i];
            if (ord < expDir.NumberOfFunctions) {
                ULONG rva = funcRvas[ord];
                /* 检查是否转发（RVA 落在导出目录范围内） */
                if (rva >= expRva && rva < expRva +
                    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                    /* 转发函数，不支持 */
                    status = STATUS_NOT_SUPPORTED;
                } else {
                    *FuncAddr = ModuleBase + rva;
                    status = STATUS_SUCCESS;
                }
                goto cleanup;
            }
        }
    }

    status = STATUS_NOT_FOUND;

cleanup:
    ExFreePoolWithTag(funcRvas, 'PShG');
    ExFreePoolWithTag(ordinals, 'PShG');
    ExFreePoolWithTag(nameRvas, 'PShG');
    return status;
}

/* ---- 导出表解析（32 位 PE，Wow64） ---- */
static NTSTATUS FindExport32(ULONG ModuleBase, PCSTR FunctionName,
                             ULONG *FuncAddr)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    IMAGE_EXPORT_DIRECTORY expDir;
    NTSTATUS status;
    ULONG expRva;
    ULONG i;

    status = SafeRead((PVOID)(ULONG64)ModuleBase, &dos, sizeof(dos));
    if (!NT_SUCCESS(status)) return status;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    status = SafeRead((PVOID)(ULONG64)(ModuleBase + dos.e_lfanew), &nt, sizeof(nt));
    if (!NT_SUCCESS(status)) return status;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    expRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0) return STATUS_NOT_FOUND;

    status = SafeRead((PVOID)(ULONG64)(ModuleBase + expRva), &expDir, sizeof(expDir));
    if (!NT_SUCCESS(status)) return status;

    ULONG *nameRvas = (ULONG *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfNames * sizeof(ULONG), 'PShG');
    USHORT *ordinals = (USHORT *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfNames * sizeof(USHORT), 'PShG');
    ULONG *funcRvas = (ULONG *)ExAllocatePoolWithTag(
        NonPagedPool, expDir.NumberOfFunctions * sizeof(ULONG), 'PShG');

    if (!nameRvas || !ordinals || !funcRvas) {
        if (nameRvas) ExFreePoolWithTag(nameRvas, 'PShG');
        if (ordinals) ExFreePoolWithTag(ordinals, 'PShG');
        if (funcRvas) ExFreePoolWithTag(funcRvas, 'PShG');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SafeRead((PVOID)(ULONG64)(ModuleBase + expDir.AddressOfNames),
             nameRvas, expDir.NumberOfNames * sizeof(ULONG));
    SafeRead((PVOID)(ULONG64)(ModuleBase + expDir.AddressOfNameOrdinals),
             ordinals, expDir.NumberOfNames * sizeof(USHORT));
    SafeRead((PVOID)(ULONG64)(ModuleBase + expDir.AddressOfFunctions),
             funcRvas, expDir.NumberOfFunctions * sizeof(ULONG));

    *FuncAddr = 0;
    for (i = 0; i < expDir.NumberOfNames; i++) {
        CHAR funcName[128] = {0};
        SafeRead((PVOID)(ULONG64)(ModuleBase + nameRvas[i]), funcName, sizeof(funcName) - 1);
        if (strcmp(funcName, FunctionName) == 0) {
            USHORT ord = ordinals[i];
            if (ord < expDir.NumberOfFunctions) {
                ULONG rva = funcRvas[ord];
                if (rva >= expRva && rva < expRva +
                    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                    status = STATUS_NOT_SUPPORTED;
                } else {
                    *FuncAddr = ModuleBase + rva;
                    status = STATUS_SUCCESS;
                }
                goto cleanup32;
            }
        }
    }
    status = STATUS_NOT_FOUND;

cleanup32:
    ExFreePoolWithTag(funcRvas, 'PShG');
    ExFreePoolWithTag(ordinals, 'PShG');
    ExFreePoolWithTag(nameRvas, 'PShG');
    return status;
}

/* ---- 公开接口 ---- */

NTSTATUS PeGetModuleBase(PEPROCESS Process, PCWSTR ModuleName,
                         PVOID *ModuleBase, BOOLEAN *IsWow64)
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG64 pebAddr;
    ULONG_PTR wow64 = 0;
    PEB64 peb64;

    UNREFERENCED_PARAMETER(Process);

    /* 获取 PEB（当前已 attach，用当前进程句柄） */
    status = ZwQueryInformationProcess(
        NtCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL);
    if (!NT_SUCCESS(status)) return status;

    pebAddr = (ULONG64)pbi.PebBaseAddress;
    if (!pebAddr) return STATUS_NOT_FOUND;

    /* 检测 Wow64 */
    status = ZwQueryInformationProcess(
        NtCurrentProcess(),
        (PROCESSINFOCLASS)ProcessWow64Information,
        &wow64,
        sizeof(wow64),
        NULL);
    BOOLEAN isWow64 = (NT_SUCCESS(status) && wow64 != 0);

    if (IsWow64) *IsWow64 = isWow64;

    if (isWow64) {
        /* 从 64 位 PEB 取 32 位 PEB 指针 */
        status = SafeRead((PVOID)pebAddr, &peb64, sizeof(peb64));
        if (!NT_SUCCESS(status) || !peb64.WoW64Process) {
            return STATUS_NOT_SUPPORTED;
        }
        ULONG base32 = 0;
        status = FindModule32((ULONG)peb64.WoW64Process, ModuleName, &base32);
        if (NT_SUCCESS(status)) {
            *ModuleBase = (PVOID)(ULONG64)base32;
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_FOUND;
    }

    /* 64 位原生 */
    ULONG64 base64 = 0;
    status = FindModule64(pebAddr, ModuleName, &base64);
    if (NT_SUCCESS(status)) {
        *ModuleBase = (PVOID)base64;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS PeFindExport(PVOID ModuleBase, PCSTR FunctionName, PVOID *FunctionAddress)
{
    /* 根据 ModuleBase 所在进程是否 Wow64 来决定用哪个解析器。
       调用者应已知架构；这里通过读 PE 头的 Magic 判断。 */
    IMAGE_DOS_HEADER dos;
    NTSTATUS status = SafeRead(ModuleBase, &dos, sizeof(dos));
    if (!NT_SUCCESS(status)) return status;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;

    USHORT magic;
    status = SafeRead((PVOID)((ULONG64)ModuleBase + dos.e_lfanew +
                              FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader.Magic)),
                      &magic, sizeof(magic));
    if (!NT_SUCCESS(status)) return status;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ULONG64 addr = 0;
        status = FindExport64((ULONG64)ModuleBase, FunctionName, &addr);
        if (NT_SUCCESS(status)) *FunctionAddress = (PVOID)addr;
        return status;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        ULONG addr = 0;
        status = FindExport32((ULONG)(ULONG64)ModuleBase, FunctionName, &addr);
        if (NT_SUCCESS(status)) *FunctionAddress = (PVOID)(ULONG64)addr;
        return status;
    }

    return STATUS_INVALID_IMAGE_FORMAT;
}

VOID PeGetProcessName(PEPROCESS Process, PWCHAR Buffer, ULONG BufferLen)
{
    if (!Process || !Buffer || BufferLen == 0) return;
    RtlZeroMemory(Buffer, BufferLen * sizeof(WCHAR));

    /* PsGetProcessImageFileName 返回 ANSI 字符串 */
    PCSTR name = PsGetProcessImageFileName(Process);
    if (name) {
        ULONG i = 0;
        while (name[i] && i < BufferLen - 1) {
            Buffer[i] = (WCHAR)name[i];
            i++;
        }
        Buffer[i] = L'\0';
    }
}

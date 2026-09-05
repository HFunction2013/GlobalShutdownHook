/*
 * Auxiliary.sys - InfinityHook 系统调用拦截 + PPL/DKOM 保护驱动
 * 基于 zhutingxf/InfinityHookPro 最小改动嵌入
 *
 * 功能:
 *   - InfinityHook syscall 拦截 (NtUnloadDriver/NtTerminateProcess/NtShutdownSystem/NtInitiatePowerAction)
 *   - PPL 进程保护 (设置 WinTCB 保护级别)
 *   - DKOM 进程隐藏 (从 ActiveProcessLinks 摘除)
 *   - quitting 状态 (quit 时才允许 terminate/unload)
 */

#pragma warning(disable : 4201 4819 4311 4302)

#include "hook.hpp"
#include "imports.hpp"
#include "Auxiliary.h"

/* ============================================================
 *  全局变量
 * ============================================================ */

static PVOID g_OriginalNtUnloadDriver = NULL;
static PVOID g_OriginalNtTerminateProcess = NULL;
static PVOID g_OriginalNtShutdownSystem = NULL;
static PVOID g_OriginalNtInitiatePowerAction = NULL;

static PVOID g_pNtUnloadDriver = NULL;
static PVOID g_pNtTerminateProcess = NULL;
static PVOID g_pNtShutdownSystem = NULL;
static PVOID g_pNtInitiatePowerAction = NULL;

static volatile LONG g_BlockedCount = 0;
static HANDLE g_BgSrvPid = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DosDeviceName;

/* quitting 状态: true 时允许 terminate BgSrv 和 unload GSH */
static volatile LONG g_Quitting = 0;

static bool g_UseSyscallIndex = false;
static ULONG g_SyscallUnload = 0;
static ULONG g_SyscallTerminate = 0;
static ULONG g_SyscallShutdown = 0;
static ULONG g_SyscallPowerAction = 0;

/* ============================================================
 *  PPL/DKOM 偏移 (动态查找, 基于 PPLcontrol OffsetFinder)
 * ============================================================ */

typedef struct _AUX_OFFSETS {
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG Protection;
    ULONG SignatureLevel;
    ULONG SectionSignatureLevel;
} AUX_OFFSETS, *PAUX_OFFSETS;

static AUX_OFFSETS g_Offsets = { 0 };
static bool g_OffsetsReady = false;
static LIST_ENTRY g_SavedBgSrvLinks = { 0 };
static bool g_BgSrvHidden = false;

/* syscall 查找表 */
typedef struct _AUX_SYSCALL_ENTRY {
    ULONG Build; ULONG Unload; ULONG Terminate; ULONG Shutdown; ULONG PowerAction;
} AUX_SYSCALL_ENTRY;

static const AUX_SYSCALL_ENTRY g_AuxSyscallTable[] = {
    { 10240, 425, 44, 408, 241 }, { 10586, 428, 44, 411, 243 },
    { 14393, 434, 44, 417, 245 }, { 15063, 440, 44, 423, 248 },
    { 16299, 444, 44, 426, 249 }, { 17134, 446, 44, 428, 250 },
    { 17763, 447, 44, 429, 251 }, { 18362, 448, 44, 430, 252 },
    { 18363, 448, 44, 430, 252 }, { 19041, 454, 44, 436, 257 },
    { 19042, 454, 44, 436, 257 }, { 19043, 454, 44, 436, 257 },
    { 19044, 456, 44, 438, 258 }, { 19045, 456, 44, 438, 258 },
    { 20348, 462, 44, 444, 262 }, { 22000, 466, 44, 447, 263 },
    { 22621, 470, 44, 451, 264 }, { 22631, 470, 44, 451, 264 },
    { 26100, 473, 44, 454, 266 },
};
static const ULONG g_AuxSyscallTableCount = 19;

/* ============================================================
 *  PPL 动态偏移查找 (基于 PPLcontrol, 内核版)
 * ============================================================ */

static bool AuxFindOffsets()
{
    UNICODE_STRING str; PUCHAR pFunc; USHORT offset;

    WCHAR n1[]=L"PsGetProcessId"; RtlInitUnicodeString(&str,n1);
    pFunc=(PUCHAR)MmGetSystemRoutineAddress(&str);
    if(!pFunc) return false;
    offset=*(PUSHORT)(pFunc+3); g_Offsets.UniqueProcessId=offset;

    g_Offsets.ActiveProcessLinks=g_Offsets.UniqueProcessId+sizeof(HANDLE);

    WCHAR n2[]=L"PsIsProtectedProcess"; RtlInitUnicodeString(&str,n2);
    pFunc=(PUCHAR)MmGetSystemRoutineAddress(&str);
    if(!pFunc) return false;
    offset=*(PUSHORT)(pFunc+3); g_Offsets.Protection=offset;

    g_Offsets.SignatureLevel=g_Offsets.Protection-2;
    g_Offsets.SectionSignatureLevel=g_Offsets.Protection-1;
    g_OffsetsReady=true;
    DbgPrintEx(0,0,"[Aux] Offsets: PID=0x%X Links=0x%X Prot=0x%X\n",
        g_Offsets.UniqueProcessId,g_Offsets.ActiveProcessLinks,g_Offsets.Protection);
    return true;
}

/* ============================================================
 *  PPL: 设置进程保护级别
 * ============================================================ */

static NTSTATUS AuxSetProcessProtection(HANDLE Pid, UCHAR ProtectionLevel)
{
    if(!g_OffsetsReady) return STATUS_NOT_SUPPORTED;
    PEPROCESS pProcess=NULL;
    NTSTATUS status=PsLookupProcessByProcessId(Pid,&pProcess);
    if(!NT_SUCCESS(status)) return status;
    PUCHAR pEproc=(PUCHAR)pProcess;
    *(PUCHAR)(pEproc+g_Offsets.Protection)=ProtectionLevel;
    if(ProtectionLevel==PROTECTION_LEVEL_WINTCB) {
        *(PUCHAR)(pEproc+g_Offsets.SignatureLevel)=0x7;
        *(PUCHAR)(pEproc+g_Offsets.SectionSignatureLevel)=0x7;
    }
    DbgPrintEx(0,0,"[Aux] Set protection 0x%02X on PID %p\n",ProtectionLevel,Pid);
    ObDereferenceObject(pProcess);
    return STATUS_SUCCESS;
}

/* ============================================================
 *  DKOM: 隐藏/恢复进程
 * ============================================================ */

static NTSTATUS AuxHideProcess(HANDLE Pid)
{
    if(!g_OffsetsReady) return STATUS_NOT_SUPPORTED;
    PEPROCESS pProcess=NULL;
    NTSTATUS status=PsLookupProcessByProcessId(Pid,&pProcess);
    if(!NT_SUCCESS(status)) return status;
    PUCHAR pEproc=(PUCHAR)pProcess;
    PLIST_ENTRY pLinks=(PLIST_ENTRY)(pEproc+g_Offsets.ActiveProcessLinks);
    g_SavedBgSrvLinks=*pLinks;
    pLinks->Blink->Flink=pLinks->Flink;
    pLinks->Flink->Blink=pLinks->Blink;
    pLinks->Flink=pLinks; pLinks->Blink=pLinks;
    g_BgSrvHidden=true;
    DbgPrintEx(0,0,"[Aux] DKOM hidden PID %p\n",Pid);
    ObDereferenceObject(pProcess);
    return STATUS_SUCCESS;
}

static NTSTATUS AuxUnhideProcess(HANDLE Pid)
{
    if(!g_OffsetsReady||!g_BgSrvHidden) return STATUS_SUCCESS;
    PEPROCESS pProcess=NULL;
    NTSTATUS status=PsLookupProcessByProcessId(Pid,&pProcess);
    if(!NT_SUCCESS(status)) return status;
    PUCHAR pEproc=(PUCHAR)pProcess;
    PLIST_ENTRY pLinks=(PLIST_ENTRY)(pEproc+g_Offsets.ActiveProcessLinks);
    pLinks->Flink=g_SavedBgSrvLinks.Flink;
    pLinks->Blink=g_SavedBgSrvLinks.Blink;
    pLinks->Blink->Flink=pLinks;
    pLinks->Flink->Blink=pLinks;
    g_BgSrvHidden=false;
    DbgPrintEx(0,0,"[Aux] DKOM unhidden PID %p\n",Pid);
    ObDereferenceObject(pProcess);
    return STATUS_SUCCESS;
}

/* ============================================================
 *  syscall 查找
 * ============================================================ */

static bool AuxLookupSyscallNumbers(ULONG buildNumber)
{
    const AUX_SYSCALL_ENTRY* best=NULL;
    for(ULONG i=0;i<g_AuxSyscallTableCount;i++) {
        if(g_AuxSyscallTable[i].Build<=buildNumber) best=&g_AuxSyscallTable[i];
        else break;
    }
    if(!best) return false;
    g_SyscallUnload=best->Unload; g_SyscallTerminate=best->Terminate;
    g_SyscallShutdown=best->Shutdown; g_SyscallPowerAction=best->PowerAction;
    return true;
}

typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE,NTSTATUS);
typedef NTSTATUS(NTAPI* NtShutdownSystem_t)(ULONG);
typedef NTSTATUS(NTAPI* NtInitiatePowerAction_t)(POWER_ACTION,SYSTEM_POWER_STATE,ULONG,BOOLEAN);

/* ============================================================
 *  假 syscall 函数
 * ============================================================ */

static PWCHAR AuxFindSubstring(PWCHAR str,PWCHAR search)
{
    if(!str||!search||!*search) return str;
    for(;*str;str++) { PWCHAR s1=str,s2=search; while(*s1&&*s2&&(*s1==*s2)){s1++;s2++;} if(!*s2) return str; }
    return NULL;
}

static NTSTATUS NTAPI FakeNtUnloadDriver(PUNICODE_STRING DriverServiceName)
{
    if(InterlockedCompareExchange(&g_Quitting,0,0)==1)
        return ((NtUnloadDriver_t)g_OriginalNtUnloadDriver)(DriverServiceName);
    if(DriverServiceName) {
        USHORT len=0; PWCHAR userBuf=NULL,safeBuf=NULL; bool blocked=false;
        __try { ProbeForRead(DriverServiceName,sizeof(UNICODE_STRING),1); len=DriverServiceName->Length;
            userBuf=DriverServiceName->Buffer; if(userBuf&&len>0) ProbeForRead(userBuf,len,1);
        } __except(EXCEPTION_EXECUTE_HANDLER){len=0;userBuf=NULL;}
        if(userBuf&&len>0) {
            safeBuf=(PWCHAR)ExAllocatePoolWithTag(NonPagedPool,len+sizeof(WCHAR),'AuxU');
            if(safeBuf){ RtlZeroMemory(safeBuf,len+sizeof(WCHAR));
                __try{RtlCopyMemory(safeBuf,userBuf,len);}__except(EXCEPTION_EXECUTE_HANDLER){ExFreePoolWithTag(safeBuf,'AuxU');safeBuf=NULL;} }
            if(safeBuf){ if(AuxFindSubstring(safeBuf,L"Auxiliary")||AuxFindSubstring(safeBuf,L"GlobalShutdownHook")){blocked=true;InterlockedIncrement(&g_BlockedCount);} ExFreePoolWithTag(safeBuf,'AuxU'); }
        }
        if(blocked) return STATUS_ACCESS_DENIED;
    }
    return ((NtUnloadDriver_t)g_OriginalNtUnloadDriver)(DriverServiceName);
}

static NTSTATUS NTAPI FakeNtTerminateProcess(HANDLE ProcessHandle,NTSTATUS ExitStatus)
{
    if(InterlockedCompareExchange(&g_Quitting,0,0)==1)
        return ((NtTerminateProcess_t)g_OriginalNtTerminateProcess)(ProcessHandle,ExitStatus);
    if(g_BgSrvPid!=NULL) {
        PEPROCESS pProcess=NULL;
        if(NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle,0x1000,NULL,KernelMode,(PVOID*)&pProcess,NULL))) {
            HANDLE targetPid=PsGetProcessId(pProcess); ObDereferenceObject(pProcess);
            if(targetPid==g_BgSrvPid){ InterlockedIncrement(&g_BlockedCount); return STATUS_ACCESS_DENIED; }
        }
    }
    return ((NtTerminateProcess_t)g_OriginalNtTerminateProcess)(ProcessHandle,ExitStatus);
}

static NTSTATUS NTAPI FakeNtShutdownSystem(ULONG a){UNREFERENCED_PARAMETER(a);InterlockedIncrement(&g_BlockedCount);return STATUS_ACCESS_DENIED;}
static NTSTATUS NTAPI FakeNtInitiatePowerAction(POWER_ACTION a,SYSTEM_POWER_STATE b,ULONG c,BOOLEAN d)
{UNREFERENCED_PARAMETER(a);UNREFERENCED_PARAMETER(b);UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(d);InterlockedIncrement(&g_BlockedCount);return STATUS_ACCESS_DENIED;}

/* ============================================================
 *  InfinityHook 回调
 * ============================================================ */

void __fastcall InfinityCallback(unsigned long nCallIndex,PVOID* pSsdtAddress)
{
    if(!pSsdtAddress) return;
    if(!g_UseSyscallIndex) {
        if(*pSsdtAddress==g_pNtUnloadDriver){g_OriginalNtUnloadDriver=*pSsdtAddress;*pSsdtAddress=FakeNtUnloadDriver;}
        else if(*pSsdtAddress==g_pNtTerminateProcess){g_OriginalNtTerminateProcess=*pSsdtAddress;*pSsdtAddress=FakeNtTerminateProcess;}
        else if(*pSsdtAddress==g_pNtShutdownSystem){g_OriginalNtShutdownSystem=*pSsdtAddress;*pSsdtAddress=FakeNtShutdownSystem;}
        else if(*pSsdtAddress==g_pNtInitiatePowerAction){g_OriginalNtInitiatePowerAction=*pSsdtAddress;*pSsdtAddress=FakeNtInitiatePowerAction;}
    } else {
        if(nCallIndex==g_SyscallUnload){g_OriginalNtUnloadDriver=*pSsdtAddress;*pSsdtAddress=FakeNtUnloadDriver;}
        else if(nCallIndex==g_SyscallTerminate){g_OriginalNtTerminateProcess=*pSsdtAddress;*pSsdtAddress=FakeNtTerminateProcess;}
        else if(nCallIndex==g_SyscallShutdown){g_OriginalNtShutdownSystem=*pSsdtAddress;*pSsdtAddress=FakeNtShutdownSystem;}
        else if(nCallIndex==g_SyscallPowerAction){g_OriginalNtInitiatePowerAction=*pSsdtAddress;*pSsdtAddress=FakeNtInitiatePowerAction;}
    }
}

static bool GetSyscallAddresses()
{
    UNICODE_STRING str; ULONG cnt=0;
    WCHAR n1[]=L"NtUnloadDriver";RtlInitUnicodeString(&str,n1);g_pNtUnloadDriver=MmGetSystemRoutineAddress(&str);if(g_pNtUnloadDriver)cnt++;
    WCHAR n2[]=L"NtTerminateProcess";RtlInitUnicodeString(&str,n2);g_pNtTerminateProcess=MmGetSystemRoutineAddress(&str);if(g_pNtTerminateProcess)cnt++;
    WCHAR n3[]=L"NtShutdownSystem";RtlInitUnicodeString(&str,n3);g_pNtShutdownSystem=MmGetSystemRoutineAddress(&str);if(g_pNtShutdownSystem)cnt++;
    WCHAR n4[]=L"NtInitiatePowerAction";RtlInitUnicodeString(&str,n4);g_pNtInitiatePowerAction=MmGetSystemRoutineAddress(&str);if(g_pNtInitiatePowerAction)cnt++;
    if(cnt==4){g_UseSyscallIndex=false;return true;}
    g_UseSyscallIndex=true;
    RTL_OSVERSIONINFOW osvi={0};osvi.dwOSVersionInfoSize=sizeof(osvi);
    if(!NT_SUCCESS(RtlGetVersion(&osvi))) return false;
    return AuxLookupSyscallNumbers(osvi.dwBuildNumber);
}

/* ============================================================
 *  IOCTL
 * ============================================================ */

static NTSTATUS AuxIoctlDispatch(PDEVICE_OBJECT dev,PIRP Irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status=STATUS_SUCCESS; ULONG info=0;
    switch(sp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_AUX_GET_BLOCKED_COUNT:
        if(sp->Parameters.DeviceIoControl.OutputBufferLength>=sizeof(ULONG)){*(PULONG)Irp->AssociatedIrp.SystemBuffer=(ULONG)InterlockedCompareExchange(&g_BlockedCount,0,0);info=sizeof(ULONG);}
        else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_AUX_SET_BGSRV_PID:
        if(sp->Parameters.DeviceIoControl.InputBufferLength>=sizeof(HANDLE)) g_BgSrvPid=*(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
        else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_AUX_SET_PROTECTION:
        if(sp->Parameters.DeviceIoControl.InputBufferLength>=sizeof(AUX_PROTECTION_INPUT)){
            PAUX_PROTECTION_INPUT inp=(PAUX_PROTECTION_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status=AuxSetProcessProtection(inp->Pid,inp->ProtectionLevel);
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_AUX_HIDE_PROCESS:
        if(sp->Parameters.DeviceIoControl.InputBufferLength>=sizeof(AUX_HIDE_INPUT)){
            PAUX_HIDE_INPUT inp=(PAUX_HIDE_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status=AuxHideProcess(inp->Pid);
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_AUX_UNHIDE_PROCESS:
        if(sp->Parameters.DeviceIoControl.InputBufferLength>=sizeof(AUX_HIDE_INPUT)){
            PAUX_HIDE_INPUT inp=(PAUX_HIDE_INPUT)Irp->AssociatedIrp.SystemBuffer;
            status=AuxUnhideProcess(inp->Pid);
        } else status=STATUS_BUFFER_TOO_SMALL; break;
    case IOCTL_AUX_SET_QUITTING:
        InterlockedExchange(&g_Quitting,1);
        DbgPrintEx(0,0,"[Aux] QUITTING state set\n"); break;
    default: status=STATUS_INVALID_DEVICE_REQUEST; break;
    }
    Irp->IoStatus.Status=status; Irp->IoStatus.Information=info;
    IoCompleteRequest(Irp,IO_NO_INCREMENT); return status;
}

static NTSTATUS AuxCreateClose(PDEVICE_OBJECT dev,PIRP Irp)
{UNREFERENCED_PARAMETER(dev);Irp->IoStatus.Status=STATUS_SUCCESS;Irp->IoStatus.Information=0;IoCompleteRequest(Irp,IO_NO_INCREMENT);return STATUS_SUCCESS;}

/* ============================================================
 *  卸载 (KHook::Stop 只在这里)
 * ============================================================ */

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    DbgPrintEx(0,0,"[Aux] Unloading\n");
    if(g_BgSrvHidden&&g_BgSrvPid) AuxUnhideProcess(g_BgSrvPid);
    KHook::Stop();
    { LARGE_INTEGER d; d.QuadPart=-200*10000; KeDelayExecutionThread(KernelMode,FALSE,&d); }
    if(g_DosDeviceName.Buffer){IoDeleteSymbolicLink(&g_DosDeviceName);RtlFreeUnicodeString(&g_DosDeviceName);}
    if(driver->DeviceObject) IoDeleteDevice(driver->DeviceObject);
}

/* ============================================================
 *  DriverEntry
 * ============================================================ */

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    NTSTATUS status; UNICODE_STRING dn;
    driver->DriverUnload=DriverUnload;
    driver->MajorFunction[IRP_MJ_CREATE]=AuxCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE]=AuxCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=AuxIoctlDispatch;
    RtlInitUnicodeString(&dn,AUX_DEVICE_NAME);
    status=IoCreateDevice(driver,0,&dn,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&g_DeviceObject);
    if(!NT_SUCCESS(status)) return status;
    RtlInitUnicodeString(&g_DosDeviceName,AUX_DOS_DEVICE_NAME);
    status=IoCreateSymbolicLink(&g_DosDeviceName,&dn);
    if(!NT_SUCCESS(status)){IoDeleteDevice(g_DeviceObject);return status;}
    AuxFindOffsets();
    if(!GetSyscallAddresses()){IoDeleteSymbolicLink(&g_DosDeviceName);RtlFreeUnicodeString(&g_DosDeviceName);IoDeleteDevice(g_DeviceObject);return STATUS_NOT_FOUND;}
    if(!KHook::Initialize(InfinityCallback)){IoDeleteSymbolicLink(&g_DosDeviceName);RtlFreeUnicodeString(&g_DosDeviceName);IoDeleteDevice(g_DeviceObject);return STATUS_UNSUCCESSFUL;}
    if(!KHook::Start()){KHook::Stop();IoDeleteSymbolicLink(&g_DosDeviceName);RtlFreeUnicodeString(&g_DosDeviceName);IoDeleteDevice(g_DeviceObject);return STATUS_UNSUCCESSFUL;}
    DbgPrintEx(0,0,"[Aux] Loaded OK\n");
    return STATUS_SUCCESS;
}

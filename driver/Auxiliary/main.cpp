/*
 * Auxiliary.sys - InfinityHook 系统调用拦截驱动
 * 基于 zhutingxf/InfinityHookPro 最小改动嵌入
 *
 * 拦截目标:
 *   - NtUnloadDriver: 阻止卸载驱动
 *   - NtTerminateProcess: 阻止终止 BgSrv 进程
 *   - NtShutdownSystem: 阻止关机
 *   - NtInitiatePowerAction: 阻止关机/休眠
 */

#pragma warning(disable : 4201 4819 4311 4302)

#include "hook.hpp"
#include "imports.hpp"
#include "Auxiliary.h"

/* ============================================================
 *  全局变量
 * ============================================================ */

/* 原始 syscall 函数指针 */
static PVOID g_OriginalNtUnloadDriver = NULL;
static PVOID g_OriginalNtTerminateProcess = NULL;
static PVOID g_OriginalNtShutdownSystem = NULL;
static PVOID g_OriginalNtInitiatePowerAction = NULL;

/* syscall 函数地址 (用于在 InfinityCallback 中识别) */
static PVOID g_pNtUnloadDriver = NULL;
static PVOID g_pNtTerminateProcess = NULL;
static PVOID g_pNtShutdownSystem = NULL;
static PVOID g_pNtInitiatePowerAction = NULL;

/* 状态 */
static volatile LONG g_BlockedCount = 0;
static HANDLE g_BgSrvPid = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DosDeviceName;

/* ============================================================
 *  syscall 函数类型定义
 * ============================================================ */

typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI* NtShutdownSystem_t)(ULONG ShutdownAction);
typedef NTSTATUS(NTAPI* NtInitiatePowerAction_t)(
    POWER_ACTION Action,
    SYSTEM_POWER_STATE MinSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous);

/* ============================================================
 *  假的 syscall 函数 (拦截逻辑)
 * ============================================================ */

static NTSTATUS NTAPI FakeNtUnloadDriver(PUNICODE_STRING DriverServiceName)
{
    UNREFERENCED_PARAMETER(DriverServiceName);
    InterlockedIncrement(&g_BlockedCount);
    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtUnloadDriver\n");
    return STATUS_ACCESS_DENIED;
}

static NTSTATUS NTAPI FakeNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    /* 检查是否是终止 BgSrv 进程 */
    if (g_BgSrvPid != NULL)
    {
        PEPROCESS pProcess = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0x1000,
            NULL, KernelMode, (PVOID*)&pProcess, NULL)))
        {
            HANDLE targetPid = PsGetProcessId(pProcess);
            ObDereferenceObject(pProcess);
            if (targetPid == g_BgSrvPid)
            {
                InterlockedIncrement(&g_BlockedCount);
                DbgPrintEx(0, 0, "[Auxiliary] Blocked NtTerminateProcess on BgSrv (PID=%p)\n", g_BgSrvPid);
                return STATUS_ACCESS_DENIED;
            }
        }
    }
    /* 其他进程正常终止 */
    return ((NtTerminateProcess_t)g_OriginalNtTerminateProcess)(ProcessHandle, ExitStatus);
}

static NTSTATUS NTAPI FakeNtShutdownSystem(ULONG ShutdownAction)
{
    UNREFERENCED_PARAMETER(ShutdownAction);
    InterlockedIncrement(&g_BlockedCount);
    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtShutdownSystem\n");
    return STATUS_ACCESS_DENIED;
}

static NTSTATUS NTAPI FakeNtInitiatePowerAction(
    POWER_ACTION Action,
    SYSTEM_POWER_STATE MinSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous)
{
    UNREFERENCED_PARAMETER(Action);
    UNREFERENCED_PARAMETER(MinSystemState);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Asynchronous);
    InterlockedIncrement(&g_BlockedCount);
    DbgPrintEx(0, 0, "[Auxiliary] Blocked NtInitiatePowerAction\n");
    return STATUS_ACCESS_DENIED;
}

/* ============================================================
 *  InfinityHook 回调函数
 *  在 syscall 入口被调用，可以替换 syscall 函数指针
 * ============================================================ */

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress)
{
    UNREFERENCED_PARAMETER(nCallIndex);
    if (!pSsdtAddress) return;

    /* 替换我们需要拦截的 syscall */
    if (*pSsdtAddress == g_pNtUnloadDriver)
    {
        g_OriginalNtUnloadDriver = *pSsdtAddress;
        *pSsdtAddress = FakeNtUnloadDriver;
    }
    else if (*pSsdtAddress == g_pNtTerminateProcess)
    {
        g_OriginalNtTerminateProcess = *pSsdtAddress;
        *pSsdtAddress = FakeNtTerminateProcess;
    }
    else if (*pSsdtAddress == g_pNtShutdownSystem)
    {
        g_OriginalNtShutdownSystem = *pSsdtAddress;
        *pSsdtAddress = FakeNtShutdownSystem;
    }
    else if (*pSsdtAddress == g_pNtInitiatePowerAction)
    {
        g_OriginalNtInitiatePowerAction = *pSsdtAddress;
        *pSsdtAddress = FakeNtInitiatePowerAction;
    }
}

/* ============================================================
 *  获取 syscall 函数地址
 * ============================================================ */

static BOOL GetSyscallAddresses()
{
    UNICODE_STRING str;

    WCHAR nameUnload[] = L"NtUnloadDriver";
    RtlInitUnicodeString(&str, nameUnload);
    g_pNtUnloadDriver = MmGetSystemRoutineAddress(&str);
    DbgPrintEx(0, 0, "[Auxiliary] NtUnloadDriver: %p\n", g_pNtUnloadDriver);

    WCHAR nameTerminate[] = L"NtTerminateProcess";
    RtlInitUnicodeString(&str, nameTerminate);
    g_pNtTerminateProcess = MmGetSystemRoutineAddress(&str);
    DbgPrintEx(0, 0, "[Auxiliary] NtTerminateProcess: %p\n", g_pNtTerminateProcess);

    WCHAR nameShutdown[] = L"NtShutdownSystem";
    RtlInitUnicodeString(&str, nameShutdown);
    g_pNtShutdownSystem = MmGetSystemRoutineAddress(&str);
    DbgPrintEx(0, 0, "[Auxiliary] NtShutdownSystem: %p\n", g_pNtShutdownSystem);

    WCHAR namePower[] = L"NtInitiatePowerAction";
    RtlInitUnicodeString(&str, namePower);
    g_pNtInitiatePowerAction = MmGetSystemRoutineAddress(&str);
    DbgPrintEx(0, 0, "[Auxiliary] NtInitiatePowerAction: %p\n", g_pNtInitiatePowerAction);

    return (g_pNtUnloadDriver && g_pNtTerminateProcess &&
            g_pNtShutdownSystem && g_pNtInitiatePowerAction);
}

/* ============================================================
 *  IOCTL 分发
 * ============================================================ */

static NTSTATUS AuxIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_AUX_INITIALIZE:
        DbgPrintEx(0, 0, "[Auxiliary] IOCTL_AUX_INITIALIZE\n");
        if (!GetSyscallAddresses())
        {
            status = STATUS_NOT_FOUND;
            break;
        }
        if (!KHook::Initialize(InfinityCallback) || !KHook::Start())
        {
            status = STATUS_UNSUCCESSFUL;
        }
        break;

    case IOCTL_AUX_SHUTDOWN:
        DbgPrintEx(0, 0, "[Auxiliary] IOCTL_AUX_SHUTDOWN\n");
        KHook::Stop();
        break;

    case IOCTL_AUX_GET_BLOCKED_COUNT:
    {
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG))
        {
            *(PULONG)Irp->AssociatedIrp.SystemBuffer = (ULONG)InterlockedCompareExchange(&g_BlockedCount, 0, 0);
            info = sizeof(ULONG);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_AUX_SET_BGSRV_PID:
    {
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE))
        {
            g_BgSrvPid = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            DbgPrintEx(0, 0, "[Auxiliary] BgSrv PID set to %p\n", g_BgSrvPid);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ============================================================
 *  创建/关闭处理
 * ============================================================ */

static NTSTATUS AuxCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ============================================================
 *  驱动卸载
 * ============================================================ */

VOID DriverUnload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    DbgPrintEx(0, 0, "[Auxiliary] Unloading Auxiliary.sys\n");

    /* 停止 InfinityHook */
    KHook::Stop();

    /* 删除符号链接和设备对象 */
    if (g_DosDeviceName.Buffer)
    {
        IoDeleteSymbolicLink(&g_DosDeviceName);
        RtlFreeUnicodeString(&g_DosDeviceName);
    }
    if (driver->DeviceObject)
    {
        IoDeleteDevice(driver->DeviceObject);
    }

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys unloaded\n");
}

/* ============================================================
 *  DriverEntry
 * ============================================================ */

EXTERN_C
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driver,
    PUNICODE_STRING registe)
{
    UNREFERENCED_PARAMETER(registe);
    NTSTATUS status;
    UNICODE_STRING deviceName;

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys loading (InfinityHook syscall interceptor)\n");

    /* 设置卸载例程 */
    driver->DriverUnload = DriverUnload;

    /* 设置分发例程 */
    driver->MajorFunction[IRP_MJ_CREATE] = AuxCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE] = AuxCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AuxIoctlDispatch;

    /* 创建设备对象 */
    RtlInitUnicodeString(&deviceName, AUX_DEVICE_NAME);
    status = IoCreateDevice(driver, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[Auxiliary] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    /* 创建符号链接 */
    RtlInitUnicodeString(&g_DosDeviceName, AUX_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&g_DosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[Auxiliary] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrintEx(0, 0, "[Auxiliary] Auxiliary.sys loaded successfully\n");
    return STATUS_SUCCESS;
}

/*
 * gsh_driver.c - 驱动入口、设备对象、IOCTL 分发
 */
#include "gsh_common.h"
#include "gsh_state.h"
#include "gsh_worker.h"
#include "gsh_faillog.h"
#include "gsh_notify.h"
#include "gsh_hook.h"

#define GSH_POOL_TAG 'HShG'

/* ---- 前置声明 ---- */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     GshUnload;
DRIVER_DISPATCH   GshCreateClose;
DRIVER_DISPATCH   GshDeviceControl;

static NTSTATUS GshIoctlGetStatus(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static NTSTATUS GshIoctlGetFailLog(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static NTSTATUS GshIoctlClearFailLog(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static NTSTATUS GshIoctlUnhookAll(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static NTSTATUS GshIoctlGetHookedList(PIRP Irp, PIO_STACK_LOCATION IrpSp);

/* ---- 驱动入口 ---- */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING symName;
    PDEVICE_OBJECT deviceObj = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("GSH: DriverEntry loading\n");

    /* 1. 初始化子系统 */
    StateInitialize();
    FailLogInitialize();

    status = WorkerInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: WorkerInitialize failed: 0x%X\n", status);
        StateDestroy();
        FailLogDestroy();
        return status;
    }

    /* 2. 创建设备对象 */
    RtlInitUnicodeString(&devName, GSH_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObj);

    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: IoCreateDevice failed: 0x%X\n", status);
        WorkerShutdown();
        StateDestroy();
        FailLogDestroy();
        return status;
    }

    /* 3. 创建符号链接 */
    RtlInitUnicodeString(&symName, GSH_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(deviceObj);
        WorkerShutdown();
        StateDestroy();
        FailLogDestroy();
        return status;
    }

    /* 4. 设置分发例程 */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = GshCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = GshCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = GshDeviceControl;
    DriverObject->DriverUnload                           = GshUnload;

    deviceObj->Flags |= DO_BUFFERED_IO;

    /* 5. 注册映像加载回调（先注册，再枚举，避免竞态） */
    status = NotifyRegister();
    if (!NT_SUCCESS(status)) {
        DbgPrint("GSH: NotifyRegister failed: 0x%X\n", status);
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(deviceObj);
        WorkerShutdown();
        StateDestroy();
        FailLogDestroy();
        return status;
    }

    /* 6. 枚举现存进程并入队 */
    NotifyEnumerateProcesses();

    DbgPrint("GSH: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

/* ---- 驱动卸载 ---- */
VOID GshUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symName;

    DbgPrint("GSH: Unloading driver\n");

    /* 1. 停止接收新镜像通知 */
    NotifyUnregister();

    /* 2. 停止工作线程（等待队列排空） */
    WorkerShutdown();

    /* 3. 恢复所有已 hook 的函数 */
    HookRestoreAll();

    /* 4. 清理资源 */
    StateDestroy();
    FailLogDestroy();

    /* 5. 删除符号链接和设备 */
    RtlInitUnicodeString(&symName, GSH_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("GSH: Driver unloaded\n");
}

/* ---- IRP_MJ_CREATE / IRP_MJ_CLOSE ---- */
NTSTATUS GshCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ---- IRP_MJ_DEVICE_CONTROL 分发 ---- */
NTSTATUS GshDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_GSH_GET_STATUS:
            status = GshIoctlGetStatus(Irp, irpSp);
            break;
        case IOCTL_GSH_GET_FAIL_LOG:
            status = GshIoctlGetFailLog(Irp, irpSp);
            break;
        case IOCTL_GSH_CLEAR_FAIL_LOG:
            status = GshIoctlClearFailLog(Irp, irpSp);
            break;
        case IOCTL_GSH_UNHOOK_ALL:
            status = GshIoctlUnhookAll(Irp, irpSp);
            break;
        case IOCTL_GSH_GET_HOOKED_LIST:
            status = GshIoctlGetHookedList(Irp, irpSp);
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---- IOCTL: 获取驱动状态 ---- */
static NTSTATUS GshIoctlGetStatus(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen < sizeof(GSH_DRIVER_STATUS)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    GSH_DRIVER_STATUS *status = (GSH_DRIVER_STATUS *)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(status, sizeof(*status));

    ULONG hooked = 0, failed = 0, pending = 0, total = 0;
    StateGetCounts(&hooked, &failed, &pending, &total);

    status->TotalProcessesSeen = total;
    status->HookedCount = hooked;
    status->FailedCount = failed;
    status->PendingCount = pending;
    status->FailLogCount = FailLogCount();

    Irp->IoStatus.Information = sizeof(GSH_DRIVER_STATUS);
    return STATUS_SUCCESS;
}

/* ---- IOCTL: 获取失败日志 ---- */
static NTSTATUS GshIoctlGetFailLog(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen < sizeof(ULONG)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG maxRecords = (outLen - sizeof(ULONG)) / sizeof(GSH_FAIL_RECORD);
    if (maxRecords == 0) {
        *(PULONG)buffer = 0;
        Irp->IoStatus.Information = sizeof(ULONG);
        return STATUS_SUCCESS;
    }

    ULONG count = FailLogGet((PGSH_FAIL_RECORD)(buffer + sizeof(ULONG)), maxRecords);
    *(PULONG)buffer = count;
    Irp->IoStatus.Information = sizeof(ULONG) + count * sizeof(GSH_FAIL_RECORD);
    return STATUS_SUCCESS;
}

/* ---- IOCTL: 清空失败日志 ---- */
static NTSTATUS GshIoctlClearFailLog(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    UNREFERENCED_PARAMETER(IrpSp);
    FailLogClear();
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* ---- IOCTL: 恢复所有 hook ---- */
static NTSTATUS GshIoctlUnhookAll(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    UNREFERENCED_PARAMETER(IrpSp);
    HookRestoreAll();
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* ---- IOCTL: 获取已 hook 列表 ---- */
typedef struct _HOOKED_LIST_CTX {
    PGSH_HOOKED_ENTRY Buffer;
    ULONG MaxCount;
    ULONG Count;
} HOOKED_LIST_CTX;

static BOOLEAN HookedListCallback(PGSH_HOOK_ENTRY Entry, PVOID Context)
{
    HOOKED_LIST_CTX *ctx = (HOOKED_LIST_CTX *)Context;
    if (ctx->Count >= ctx->MaxCount) return FALSE;

    PGSH_HOOKED_ENTRY out = &ctx->Buffer[ctx->Count];
    out->Pid = PtrToUint(Entry->Pid);
    out->FunctionId = Entry->FunctionId;
    out->State = Entry->State;
    out->Reserved = 0;
    RtlCopyMemory(out->ProcessName, Entry->ProcessName, sizeof(out->ProcessName));
    RtlCopyMemory(out->ModuleName, Entry->ModuleName, sizeof(out->ModuleName));
    ctx->Count++;
    return TRUE;
}

static NTSTATUS GshIoctlGetHookedList(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen < sizeof(ULONG)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG maxEntries = (outLen - sizeof(ULONG)) / sizeof(GSH_HOOKED_ENTRY);
    if (maxEntries == 0) {
        *(PULONG)buffer = 0;
        Irp->IoStatus.Information = sizeof(ULONG);
        return STATUS_SUCCESS;
    }

    HOOKED_LIST_CTX ctx;
    ctx.Buffer = (PGSH_HOOKED_ENTRY)(buffer + sizeof(ULONG));
    ctx.MaxCount = maxEntries;
    ctx.Count = 0;

    StateEnumerate(HookedListCallback, &ctx);

    *(PULONG)buffer = ctx.Count;
    Irp->IoStatus.Information = sizeof(ULONG) + ctx.Count * sizeof(GSH_HOOKED_ENTRY);
    return STATUS_SUCCESS;
}

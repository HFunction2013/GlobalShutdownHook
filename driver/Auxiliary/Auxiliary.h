/*
 * Auxiliary.sys - InfinityHook 系统调用拦截 + PPL/DKOM 保护驱动
 * 基于 zhutingxf/InfinityHookPro 最小改动嵌入
 *
 * 公共头文件：定义设备名称、IOCTL 码和数据结构
 */

#ifndef _AUXILIARY_PUBLIC_H_
#define _AUXILIARY_PUBLIC_H_

/* 用户态/内核态通用头文件，不包含内核专用头 */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _NTDEF_
typedef long NTSTATUS;
typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef void* PVOID;
#endif

/* ---- 设备名称 ---- */
#define AUX_DEVICE_NAME     L"\\Device\\Auxiliary"
#define AUX_DOS_DEVICE_NAME L"\\DosDevices\\Auxiliary"
#define AUX_WIN32_NAME      L"\\\\.\\Auxiliary"

/* ---- IOCTL 码 ---- */
#define AUX_IOCTL_BASE      0x800

#define IOCTL_AUX_GET_BLOCKED_COUNT CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUX_SET_BGSRV_PID     CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUX_SET_PROTECTION    CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUX_HIDE_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUX_UNHIDE_PROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AUX_SET_QUITTING      CTL_CODE(FILE_DEVICE_UNKNOWN, AUX_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- 保护级别定义 (PPL) ---- */
#ifndef PROTECTION_LEVEL_WINTCB
#define PROTECTION_LEVEL_WINTCB     0x60
#endif

/* ---- 输入结构 ---- */
typedef struct _AUX_PROTECTION_INPUT {
    HANDLE Pid;
    UCHAR  ProtectionLevel;
} AUX_PROTECTION_INPUT, *PAUX_PROTECTION_INPUT;

typedef struct _AUX_HIDE_INPUT {
    HANDLE Pid;
} AUX_HIDE_INPUT, *PAUX_HIDE_INPUT;

#ifdef __cplusplus
}
#endif

#endif /* _AUXILIARY_PUBLIC_H_ */

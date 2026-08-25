/*
 * gsh_notify.h - 映像加载回调与进程枚举
 */
#ifndef GSH_NOTIFY_H
#define GSH_NOTIFY_H

#include "gsh_common.h"

NTSTATUS NotifyRegister(VOID);
VOID     NotifyUnregister(VOID);

/* PsSetLoadImageNotifyRoutine 回调 */
VOID     NotifyImageLoad(PUNICODE_STRING FullImageName,
                         HANDLE ProcessId, PIMAGE_INFO ImageInfo);

/* 枚举所有现存进程，对已加载目标模块的入队 */
VOID     NotifyEnumerateProcesses(VOID);

#endif /* GSH_NOTIFY_H */

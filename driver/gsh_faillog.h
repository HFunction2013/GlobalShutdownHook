/*
 * gsh_faillog.h - 失败记录环形缓冲区
 *
 * hook 失败的进程信息记录在这里，用户态通过 IOCTL 读取。
 */
#ifndef GSH_FAILLOG_H
#define GSH_FAILLOG_H

#include "gsh_common.h"

VOID    FailLogInitialize(VOID);
VOID    FailLogDestroy(VOID);

VOID    FailLogAdd(HANDLE Pid, PCWSTR ProcessName, PCWSTR ModuleName,
                   ULONG FunctionId, ULONG FailReason);

/* 复制记录到缓冲区，返回实际条数 */
ULONG   FailLogGet(PGSH_FAIL_RECORD Buffer, ULONG MaxCount);

ULONG   FailLogCount(VOID);
VOID    FailLogClear(VOID);

#endif /* GSH_FAILLOG_H */

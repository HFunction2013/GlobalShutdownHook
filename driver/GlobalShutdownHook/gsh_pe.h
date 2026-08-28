/*
 * gsh_pe.h - 用户态进程内存中的 PE 解析
 *
 * 在 KeStackAttachProcess 之后调用，从目标进程地址空间读取
 * PEB → LDR → 模块基址，再解析导出表找到目标函数 RVA。
 */
#ifndef GSH_PE_H
#define GSH_PE_H

#include "gsh_common.h"

/*
 * 获取目标进程中指定模块的加载基址。
 * 调用前必须已 attach 到目标进程。
 * 返回模块基址（用户态指针）和是否 Wow64。
 */
NTSTATUS PeGetModuleBase(PEPROCESS Process, PCWSTR ModuleName,
                         PVOID *ModuleBase, BOOLEAN *IsWow64);

/*
 * 解析模块导出表，按函数名查找地址。
 * 调用前必须已 attach，ModuleBase 是用户态地址。
 */
NTSTATUS PeFindExport(PVOID ModuleBase, PCSTR FunctionName, PVOID *FunctionAddress);

/*
 * 从 EPROCESS 获取进程名（最多 GSH_PROCESS_NAME_LEN-1 个字符）
 */
VOID     PeGetProcessName(PEPROCESS Process, PWCHAR Buffer, ULONG BufferLen);

#endif /* GSH_PE_H */

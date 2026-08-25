/*
 * gsh_hook.h - inline hook 核心逻辑
 */
#ifndef GSH_HOOK_H
#define GSH_HOOK_H

#include "gsh_common.h"
#include "gsh_state.h"

/*
 * 对指定进程的指定模块中的目标函数执行 inline hook。
 * 在 PASSIVE_LEVEL 调用，内部会 attach 进程。
 * 成功后将条目状态设为 HOOKED 并保存原始字节。
 */
NTSTATUS HookPerform(HANDLE Pid, PCWSTR ModuleName, ULONG FunctionId);

/*
 * 恢复单个 hook 条目（卸载或主动取消时调用）。
 */
NTSTATUS HookRestore(PGSH_HOOK_ENTRY Entry);

/*
 * 恢复所有已 hook 的条目。
 */
VOID     HookRestoreAll(VOID);

/*
 * 获取目标函数名和模块名
 */
PCWSTR  HookGetFunctionName(ULONG FunctionId);
PCWSTR  HookGetModuleName(ULONG FunctionId);
PCSTR   HookGetExportName(ULONG FunctionId);

#endif /* GSH_HOOK_H */

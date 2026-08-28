/*
 * gsh_lock.h - 锁状态与密码管理
 *
 * LOCKED  : hook 生效，阻止关机；拒绝卸载/移除钩子等破坏操作
 * UNLOCKED: hook 恢复，允许关机；允许卸载/移除钩子
 *
 * 密码：仅存储 FNV-1a 64-bit 哈希，不明文驻留内存。
 *   hash == 0 表示无密码。
 *   Release 默认密码 "FuckingShit"，Debug 默认无密码。
 */
#ifndef GSH_LOCK_H
#define GSH_LOCK_H

#include "gsh_common.h"

VOID    LockInitialize(VOID);
VOID    LockDestroy(VOID);

/* 查询当前锁状态 */
ULONG   LockGetState(VOID);          /* GSH_LOCKED / GSH_UNLOCKED */
BOOLEAN LockIsLocked(VOID);
BOOLEAN LockHasPassword(VOID);

/* 锁定（无需密码）：重新施加所有 hook，阻止关机 */
NTSTATUS LockDoLock(VOID);

/* 解锁（需密码）：恢复所有 hook 原始字节，允许关机 */
NTSTATUS LockDoUnlock(PCWSTR Password);

/* 设置/修改密码：无密码时 OldPassword 可空；有密码时需验证旧密码 */
NTSTATUS LockSetPassword(PCWSTR OldPassword, PCWSTR NewPassword);

/* 移除密码（需当前密码）：移除后无保护 */
NTSTATUS LockRemovePassword(PCWSTR Password);

/* 验证密码（用于 shutdown_now 等需要额外认证的操作） */
BOOLEAN LockCheckPassword(PCWSTR Password);

#endif /* GSH_LOCK_H */

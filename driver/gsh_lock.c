/*
 * gsh_lock.c - 锁状态与密码管理实现
 *
 * 密码哈希：FNV-1a 64-bit，仅存储哈希值，明文密码不驻留内存。
 *   hash == 0 表示无密码（0 是保留值，FNV-1a 不会产生 0）。
 *
 * Release 默认密码 "FuckingShit"，Debug 默认无密码。
 */
#include "gsh_lock.h"
#include "gsh_hook.h"
#include "gsh_state.h"

/* ---- FNV-1a 64-bit 哈希常量 ---- */
#define FNV1A_64_OFFSET  0xcbf29ce484222325ULL
#define FNV1A_64_PRIME   0x100000001b3ULL

/* ---- 全局状态 ---- */
static volatile ULONG  g_Locked = GSH_LOCKED;   /* 默认锁定 */
static volatile ULONG64 g_PasswordHash = 0;       /* 0 = 无密码 */

/* ---- FNV-1a 64-bit 哈希（对 WCHAR 字符串的字节） ---- */
static ULONG64 HashPassword(PCWSTR Password)
{
    if (!Password) return 0;
    ULONG64 hash = FNV1A_64_OFFSET;
    PUCHAR bytes = (PUCHAR)Password;
    /* 哈希到 null terminator 为止（不含 null） */
    while (Password[0] != 0) {
        for (int i = 0; i < sizeof(WCHAR); i++) {
            hash ^= bytes[i];
            hash *= FNV1A_64_PRIME;
        }
        bytes += sizeof(WCHAR);
        Password++;
    }
    /* 确保不会返回 0（0 保留为"无密码"标记） */
    if (hash == 0) hash = 1;
    return hash;
}

/* ---- 初始化 ---- */
VOID LockInitialize(VOID)
{
    g_Locked = GSH_LOCKED;
    g_PasswordHash = 0;
#ifdef NDEBUG
    /* Release 版本：设置默认密码 "FuckingShit" */
    g_PasswordHash = HashPassword(L"FuckingShit");
#endif
}

VOID LockDestroy(VOID)
{
    g_PasswordHash = 0;
}

/* ---- 查询 ---- */
ULONG LockGetState(VOID)
{
    return g_Locked;
}

BOOLEAN LockIsLocked(VOID)
{
    return (g_Locked == GSH_LOCKED);
}

BOOLEAN LockHasPassword(VOID)
{
    return (g_PasswordHash != 0);
}

/* ---- 密码验证 ---- */
BOOLEAN LockCheckPassword(PCWSTR Password)
{
    if (g_PasswordHash == 0) {
        /* 无密码时，任何密码（包括空）都通过 */
        return TRUE;
    }
    if (!Password) return FALSE;
    return (HashPassword(Password) == g_PasswordHash);
}

/* ---- 锁定（无需密码）：重新施加所有 hook ---- */
typedef struct _REAPPLY_CTX {
    ULONG Reapplied;
    ULONG Skipped;
} REAPPLY_CTX;

static BOOLEAN ReapplyHookCallback(PGSH_HOOK_ENTRY Entry, PVOID Context)
{
    REAPPLY_CTX *ctx = (REAPPLY_CTX *)Context;
    /* 只对已恢复（NONE）且有目标地址的条目重新施加 hook */
    if (Entry->State == HOOK_STATE_NONE && Entry->TargetAddress != NULL) {
        NTSTATUS status = HookPerform(Entry->Pid, Entry->ModuleName, Entry->FunctionId);
        if (NT_SUCCESS(status)) {
            ctx->Reapplied++;
        } else {
            ctx->Skipped++;
        }
    } else {
        ctx->Skipped++;
    }
    return TRUE;
}

NTSTATUS LockDoLock(VOID)
{
    REAPPLY_CTX ctx = {0, 0};
    StateEnumerate(ReapplyHookCallback, &ctx);
    g_Locked = GSH_LOCKED;
    DbgPrint("GSH: Locked. Reapplied %u hooks, skipped %u\n", ctx.Reapplied, ctx.Skipped);
    return STATUS_SUCCESS;
}

/* ---- 解锁（需密码）：恢复所有 hook 原始字节 ---- */
NTSTATUS LockDoUnlock(PCWSTR Password)
{
    if (!LockCheckPassword(Password)) {
        return STATUS_ACCESS_DENIED;
    }
    HookRestoreAll();
    g_Locked = GSH_UNLOCKED;
    DbgPrint("GSH: Unlocked. All hooks restored.\n");
    return STATUS_SUCCESS;
}

/* ---- 设置/修改密码 ---- */
NTSTATUS LockSetPassword(PCWSTR OldPassword, PCWSTR NewPassword)
{
    /* 验证新密码非空 */
    if (!NewPassword || NewPassword[0] == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    /* 如果已有密码，必须验证旧密码 */
    if (g_PasswordHash != 0) {
        if (!LockCheckPassword(OldPassword)) {
            return STATUS_ACCESS_DENIED;
        }
    }
    /* 设置新密码哈希 */
    g_PasswordHash = HashPassword(NewPassword);
    DbgPrint("GSH: Password changed.\n");
    return STATUS_SUCCESS;
}

/* ---- 移除密码（需当前密码） ---- */
NTSTATUS LockRemovePassword(PCWSTR Password)
{
    if (g_PasswordHash == 0) {
        /* 已经没有密码了 */
        return STATUS_SUCCESS;
    }
    if (!LockCheckPassword(Password)) {
        return STATUS_ACCESS_DENIED;
    }
    g_PasswordHash = 0;
    DbgPrint("GSH: Password removed. No protection now.\n");
    return STATUS_SUCCESS;
}

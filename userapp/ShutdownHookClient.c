/*
 * ShutdownHookClient.c - 用户态控制/监控程序
 *
 * 功能：
 *   status              查看驱动状态统计
 *   list                列出所有 hook 条目（成功/失败/待处理）
 *   failures            列出 hook 失败记录
 *   clear               清空失败记录
 *   unhook              恢复所有 hook（驱动仍在运行）
 *   test                调用 ExitWindowsEx 测试拦截效果
 *   test-advapi         调用 InitiateSystemShutdownEx 测试拦截效果
 *   monitor [interval]  持续监控状态（默认2秒刷新）
 *   help                显示帮助
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <conio.h>

#include "../driver/GlobalShutdownHook/gsh_common.h"
#include "../driver/Auxiliary/Auxiliary.h"
#include "RTCore64_embedded.h"  /* 内嵌的 RTCore64.sys (BYOVD) */

/* ---- 调试宏 ---- */
#define DBG_PRINT(fmt, ...) \
    printf("[DEBUG][%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

/* ---- advapi32 函数声明（用于测试） ---- */
typedef BOOL (WINAPI *PFN_InitiateSystemShutdownExW)(
    LPWSTR lpMachineName, LPWSTR lpMessage, DWORD dwTimeout,
    BOOL bForceAppsClosed, BOOL bRebootAfterShutdown, DWORD dwReason);

/* ---- 工具函数 ---- */
static const char *FunctionIdToString(ULONG id)
{
    switch (id)
    {
    case FUNC_EXIT_WINDOWS_EX:
        return "ExitWindowsEx";
    case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A:
        return "InitiateSystemShutdownExA";
    case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W:
        return "InitiateSystemShutdownExW";
    default:
        return "Unknown";
    }
}

static const char *StateToString(ULONG state)
{
    switch (state)
    {
    case HOOK_STATE_NONE:
        return "NONE";
    case HOOK_STATE_NEED_HOOK:
        return "PENDING";
    case HOOK_STATE_HOOKED:
        return "HOOKED";
    case HOOK_STATE_FAILED:
        return "FAILED";
    default:
        return "???";
    }
}

static const char *FailReasonToString(ULONG reason)
{
    switch (reason)
    {
    case FAIL_PROCESS_TERMINATED:
        return "Process terminated";
    case FAIL_MODULE_NOT_FOUND:
        return "Module not found";
    case FAIL_EXPORT_NOT_FOUND:
        return "Export not found";
    case FAIL_ATTACH_FAILED:
        return "Attach failed";
    case FAIL_PROTECT_CHANGE:
        return "Protect change failed (ACG?)";
    case FAIL_WRITE_MEMORY:
        return "Write memory failed (PPL?)";
    case FAIL_ALLOC_MEMORY:
        return "Alloc memory failed";
    case FAIL_THREAD_SUSPEND:
        return "Thread suspend failed";
    case FAIL_PROTECTED_PROCESS:
        return "Protected process";
    case FAIL_WOW64_UNSUPPORTED:
        return "Wow64 unsupported";
    case FAIL_PEEK_MEMORY:
        return "Peek memory failed";
    case FAIL_UNKNOWN:
        return "Unknown";
    default:
        return "Other";
    }
}

static void PrintTime(LARGE_INTEGER *li)
{
    /* li 是系统时间（100ns 间隔，从 1601-01-01 起） */
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)li->LowPart;
    ft.dwHighDateTime = (DWORD)li->HighPart;
    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);
    SYSTEMTIME st;
    FileTimeToSystemTime(&localFt, &st);
    printf("%04u-%02u-%02u %02u:%02u:%02u",
           st.wYear, st.wMonth, st.wDay,
           st.wHour, st.wMinute, st.wSecond);
}

/* ---- 打开驱动 ---- */
static HANDLE OpenGshDriver(VOID)
{
    DBG_PRINT("Opening driver: %ls", GSH_WIN32_NAME);
    HANDLE h = CreateFileW(
        GSH_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        fprintf(stderr, "Error: Cannot open driver %ls (error %lu)\n",
                GSH_WIN32_NAME, err);
        if (err == ERROR_FILE_NOT_FOUND)
        {
            fprintf(stderr, "  Driver not loaded. Use: sc create GSH type= kernel binPath= <path>\n");
            fprintf(stderr, "  Then: sc start GSH\n");
        }
    }
    else
    {
        DBG_PRINT("Driver opened successfully (handle=0x%p)", h);
    }
    return h;
}

/* ---- 命令实现 ---- */
static int CmdStatus(HANDLE hDriver)
{
    DBG_PRINT("CmdStatus called");
    GSH_DRIVER_STATUS status;
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_STATUS,
                         NULL, 0, &status, sizeof(status),
                         &bytesReturned, NULL))
    {
        fprintf(stderr, "IOCTL_GET_STATUS failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_GET_STATUS failed with error %lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_GET_STATUS succeeded, bytesReturned=%lu", bytesReturned);

    printf("=== GlobalShutdownHook Status ===\n");
    printf("  Processes seen : %lu\n", status.TotalProcessesSeen);
    printf("  Hooked (OK)    : %lu\n", status.HookedCount);
    printf("  Failed          : %lu\n", status.FailedCount);
    printf("  Pending         : %lu\n", status.PendingCount);
    printf("  Fail log entries: %lu\n", status.FailLogCount);
    printf("==================================\n");
    return 0;
}

static int CmdList(HANDLE hDriver)
{
    DBG_PRINT("CmdList called");
    BYTE buffer[65536];
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_HOOKED_LIST,
                         NULL, 0, buffer, sizeof(buffer),
                         &bytesReturned, NULL))
    {
        fprintf(stderr, "IOCTL_GET_HOOKED_LIST failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_GET_HOOKED_LIST failed with error %lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_GET_HOOKED_LIST succeeded, bytesReturned=%lu", bytesReturned);

    ULONG count = *(PULONG)buffer;
    DBG_PRINT("Hook entry count = %lu", count);
    PGSH_HOOKED_ENTRY entries = (PGSH_HOOKED_ENTRY)(buffer + sizeof(ULONG));

    printf("=== Hook Entries (%lu) ===\n", count);
    printf("%-8s %-8s %-30s %-10s %s\n",
           "PID", "State", "Function", "Module", "Process");
    printf("------------------------------------------------------------------------\n");

    for (ULONG i = 0; i < count; i++)
    {
        DBG_PRINT("Entry[%lu]: PID=%lu State=%lu Func=%lu",
                  i, entries[i].Pid, entries[i].State, entries[i].FunctionId);
        printf("%-8lu %-8s %-30s %-10ls %ls\n",
               entries[i].Pid,
               StateToString(entries[i].State),
               FunctionIdToString(entries[i].FunctionId),
               entries[i].ModuleName[0] ? entries[i].ModuleName : L"-",
               entries[i].ProcessName[0] ? entries[i].ProcessName : L"-");
    }
    return 0;
}

static int CmdFailures(HANDLE hDriver)
{
    DBG_PRINT("CmdFailures called");
    BYTE buffer[65536];
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_FAIL_LOG,
                         NULL, 0, buffer, sizeof(buffer),
                         &bytesReturned, NULL))
    {
        fprintf(stderr, "IOCTL_GET_FAIL_LOG failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_GET_FAIL_LOG failed with error %lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_GET_FAIL_LOG succeeded, bytesReturned=%lu", bytesReturned);

    ULONG count = *(PULONG)buffer;
    DBG_PRINT("Fail record count = %lu", count);
    PGSH_FAIL_RECORD records = (PGSH_FAIL_RECORD)(buffer + sizeof(ULONG));

    printf("=== Failure Log (%lu records) ===\n", count);
    if (count == 0)
    {
        printf("  (no failures)\n");
        return 0;
    }

    printf("%-8s %-30s %-10s %-25s %s\n",
           "PID", "Function", "Module", "Reason", "Time");
    printf("--------------------------------------------------------------------------------\n");

    for (ULONG i = 0; i < count; i++)
    {
        DBG_PRINT("Fail[%lu]: PID=%lu Func=%lu Reason=%lu",
                  i, records[i].Pid, records[i].FunctionId, records[i].FailReason);
        printf("%-8lu %-30s %-10ls %-25s ",
               records[i].Pid,
               FunctionIdToString(records[i].FunctionId),
               records[i].ModuleName[0] ? records[i].ModuleName : L"-",
               FailReasonToString(records[i].FailReason));
        PrintTime(&records[i].Timestamp);
        printf("  %ls\n",
               records[i].ProcessName[0] ? records[i].ProcessName : L"-");
    }
    return 0;
}

static int CmdClear(HANDLE hDriver)
{
    DBG_PRINT("CmdClear called");
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_CLEAR_FAIL_LOG,
                         NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        fprintf(stderr, "IOCTL_CLEAR_FAIL_LOG failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_CLEAR_FAIL_LOG failed with error %lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_CLEAR_FAIL_LOG succeeded");
    printf("Failure log cleared.\n");
    return 0;
}

static int CmdUnhook(HANDLE hDriver)
{
    DBG_PRINT("CmdUnhook called");
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_UNHOOK_ALL,
                         NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        fprintf(stderr, "IOCTL_UNHOOK_ALL failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_UNHOOK_ALL failed with error %lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_UNHOOK_ALL succeeded");
    printf("All hooks restored. (Driver still running, new processes will be re-hooked.)\n");
    return 0;
}

static int CmdTestExitWindows(VOID)
{
    DBG_PRINT("CmdTestExitWindows called");
    printf("Testing ExitWindowsEx(EWX_LOGOFF, 0)...\n");
    printf("If hook is active, this call will return TRUE but NOT log off.\n");
    printf("Press Ctrl+C to cancel, or Enter to continue...\n");
    getchar();

    DBG_PRINT("Calling ExitWindowsEx(EWX_LOGOFF, 0)");
    BOOL result = ExitWindowsEx(EWX_LOGOFF, 0);
    DWORD err = GetLastError();
    DBG_PRINT("ExitWindowsEx returned %d, error=%lu", result, err);

    printf("ExitWindowsEx returned: %s (error=%lu)\n",
           result ? "TRUE" : "FALSE", err);

    if (result)
    {
        printf("  -> Hook is ACTIVE (function returned success without logging off).\n");
        printf("  -> If you are still here, the shutdown was blocked.\n");
    }
    else
    {
        printf("  -> Hook may NOT be active, or call was refused by system.\n");
    }
    return 0;
}

static int CmdTestAdvapi(VOID)
{
    DBG_PRINT("CmdTestAdvapi called");
    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
    if (!hAdvapi)
    {
        fprintf(stderr, "Cannot load advapi32.dll: %lu\n", GetLastError());
        DBG_PRINT("LoadLibraryW(advapi32.dll) failed, error=%lu", GetLastError());
        return 1;
    }
    DBG_PRINT("advapi32.dll loaded successfully");

    PFN_InitiateSystemShutdownExW pfn = (PFN_InitiateSystemShutdownExW)
        GetProcAddress(hAdvapi, "InitiateSystemShutdownExW");
    if (!pfn)
    {
        fprintf(stderr, "Cannot find InitiateSystemShutdownExW: %lu\n", GetLastError());
        DBG_PRINT("GetProcAddress(InitiateSystemShutdownExW) failed, error=%lu", GetLastError());
        FreeLibrary(hAdvapi);
        return 1;
    }
    DBG_PRINT("InitiateSystemShutdownExW found at 0x%p", pfn);

    printf("Testing InitiateSystemShutdownExW(NULL, L\"test\", 0, FALSE, FALSE, 0)...\n");
    printf("If hook is active, this will return TRUE but NOT initiate shutdown.\n");
    printf("Press Enter to continue...\n");
    getchar();

    DBG_PRINT("Calling InitiateSystemShutdownExW");
    BOOL result = pfn(NULL, L"GSH test", 0, FALSE, FALSE, 0);
    DWORD err = GetLastError();
    DBG_PRINT("InitiateSystemShutdownExW returned %d, error=%lu", result, err);

    printf("InitiateSystemShutdownExW returned: %s (error=%lu)\n",
           result ? "TRUE" : "FALSE", err);

    if (result)
    {
        printf("  -> Hook is ACTIVE.\n");
    }
    else
    {
        printf("  -> Hook may NOT be active (error %lu).\n", err);
        if (err == ERROR_ACCESS_DENIED)
        {
            printf("  -> Note: ACCESS_DENIED is normal if not running as admin.\n");
        }
    }

    FreeLibrary(hAdvapi);
    return 0;
}

static int CmdMonitor(HANDLE hDriver, int intervalSec)
{
    DBG_PRINT("CmdMonitor called, interval=%d", intervalSec);
    if (intervalSec <= 0)
        intervalSec = 2;

    printf("Monitoring (refresh every %ds). Press Ctrl+C to stop.\n\n", intervalSec);

    while (1)
    {
        GSH_DRIVER_STATUS status;
        DWORD bytesReturned = 0;

        if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_STATUS,
                             NULL, 0, &status, sizeof(status),
                             &bytesReturned, NULL))
        {
            fprintf(stderr, "\rIOCTL failed: %lu          ", GetLastError());
            DBG_PRINT("IOCTL_GET_STATUS failed, error=%lu", GetLastError());
            Sleep(intervalSec * 1000);
            continue;
        }

        printf("\r  Hooked=%lu  Failed=%lu  Pending=%lu  FailLog=%lu  (seen=%lu)          ",
               status.HookedCount, status.FailedCount, status.PendingCount,
               status.FailLogCount, status.TotalProcessesSeen);
        fflush(stdout);
        Sleep(intervalSec * 1000);
    }
    return 0;
}

static int CmdQueue(HANDLE hDriver, int intervalSec)
{
    DBG_PRINT("CmdQueue called, interval=%d", intervalSec);
    if (intervalSec <= 0)
        intervalSec = 1;
    printf("GSH Work Queue (refresh every %ds). Press Ctrl+C to stop.\n\n", intervalSec);
    while (1)
    {
        BYTE buffer[65536];
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_QUEUE,
                             NULL, 0, buffer, sizeof(buffer),
                             &bytesReturned, NULL))
        {
            printf("\rIOCTL_GET_QUEUE failed: %lu          ", GetLastError());
            DBG_PRINT("IOCTL_GET_QUEUE failed, error=%lu", GetLastError());
            fflush(stdout);
            Sleep(intervalSec * 1000);
            continue;
        }
        ULONG count = *(PULONG)buffer;
        DBG_PRINT("Queue count = %lu", count);
        PGSH_QUEUE_ENTRY entries = (PGSH_QUEUE_ENTRY)(buffer + sizeof(ULONG));
        system("cls");
        printf("=== GSH Work Queue: %lu pending task(s) ===\n", count);
        if (count == 0)
        {
            printf("  (queue empty)\n");
        }
        else
        {
            printf("%-8s %-32s %s\n", "PID", "Function", "Module");
            printf("----------------------------------------------------------------\n");
            for (ULONG i = 0; i < count; i++)
            {
                DBG_PRINT("Queue[%lu]: PID=%lu Func=%lu", i, entries[i].Pid, entries[i].FunctionId);
                printf("%-8lu %-32s %ls\n",
                       entries[i].Pid,
                       FunctionIdToString(entries[i].FunctionId),
                       entries[i].ModuleName[0] ? entries[i].ModuleName : L"-");
            }
        }
        printf("\n(refresh every %ds, Ctrl+C to stop)\n", intervalSec);
        fflush(stdout);
        Sleep(intervalSec * 1000);
    }
    return 0;
}

static void PrintHelp(const char *progName)
{
    printf("GlobalShutdownHook Client\n\n");
    printf("Usage: %s <command> [args]\n\n", progName);
    printf("Commands:\n");
    printf("  status              Show driver statistics\n");
    printf("  list                List all hook entries\n");
    printf("  failures            List hook failure records\n");
    printf("  clear               Clear failure log\n");
    printf("  unhook              Restore all hooks (driver stays loaded)\n");
    printf("  test                Call ExitWindowsEx to test interception\n");
    printf("  test-advapi         Call InitiateSystemShutdownEx to test\n");
    printf("  monitor [sec]       Continuously monitor status (default 2s)\n");
    printf("  queue [sec]         Show work queue, dynamic refresh (default 1s)\n");
    printf("  lock                Lock driver (block shutdown, no password)\n");
    printf("  unlock              Unlock driver (allow shutdown, needs password)\n");
    printf("  set_pass            Set or change password\n");
    printf("  rm_pass             Remove password (no protection after)\n");
    printf("  shutdown_now        Force immediate shutdown (needs unlock + password)\n");
    printf("  query_status        Show lock state and stats (no password)\n");
    printf("  init                Load driver via GDRVLoader + start background service\n");
    printf("  quit                Unhook + unload driver + exit BgSrv (needs password)\n");
    printf("  help                Show this help\n");
    printf("\nNote: Run as Administrator for full functionality.\n");
}

/* ---- main ---- */
/* 新命令前向声明（定义在文件末尾） */
static int CmdLock(HANDLE hDriver);
static int CmdUnlock(HANDLE hDriver);
static int CmdSetPass(HANDLE hDriver);
static int CmdRmPass(HANDLE hDriver);
static int CmdShutdownNow(HANDLE hDriver);
static int CmdQueryStatus(HANDLE hDriver);
static int CmdInit(VOID);
static int CmdQuit(HANDLE hDriver);

int main(int argc, char *argv[])
{
    DBG_PRINT("main called, argc=%d", argc);
    for (int i = 0; i < argc; i++)
    {
        DBG_PRINT("argv[%d] = %s", i, argv[i]);
    }

    if (argc < 2)
    {
        PrintHelp(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    DBG_PRINT("Command = %s", cmd);

    /* test 命令不需要驱动句柄 */
    if (strcmp(cmd, "test") == 0)
    {
        return CmdTestExitWindows();
    }
    if (strcmp(cmd, "test-advapi") == 0)
    {
        return CmdTestAdvapi();
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0)
    {
        PrintHelp(argv[0]);
        return 0;
    }
    if (strcmp(cmd, "init") == 0)
    {
        return CmdInit();
    }

    /* 其他命令需要打开驱动 */
    HANDLE hDriver = OpenGshDriver();
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        DBG_PRINT("Failed to open driver handle");
        return 1;
    }

    int ret = 0;

    if (strcmp(cmd, "status") == 0)
    {
        ret = CmdStatus(hDriver);
    }
    else if (strcmp(cmd, "list") == 0)
    {
        ret = CmdList(hDriver);
    }
    else if (strcmp(cmd, "failures") == 0)
    {
        ret = CmdFailures(hDriver);
    }
    else if (strcmp(cmd, "clear") == 0)
    {
        ret = CmdClear(hDriver);
    }
    else if (strcmp(cmd, "unhook") == 0)
    {
        ret = CmdUnhook(hDriver);
    }
    else if (strcmp(cmd, "monitor") == 0)
    {
        int interval = (argc >= 3) ? atoi(argv[2]) : 2;
        ret = CmdMonitor(hDriver, interval);
    }
    else if (strcmp(cmd, "queue") == 0)
    {
        int interval = (argc >= 3) ? atoi(argv[2]) : 1;
        ret = CmdQueue(hDriver, interval);
    }
    else if (strcmp(cmd, "lock") == 0)
    {
        ret = CmdLock(hDriver);
    }
    else if (strcmp(cmd, "unlock") == 0)
    {
        ret = CmdUnlock(hDriver);
    }
    else if (strcmp(cmd, "set_pass") == 0)
    {
        ret = CmdSetPass(hDriver);
    }
    else if (strcmp(cmd, "rm_pass") == 0)
    {
        ret = CmdRmPass(hDriver);
    }
    else if (strcmp(cmd, "shutdown_now") == 0)
    {
        ret = CmdShutdownNow(hDriver);
    }
    else if (strcmp(cmd, "query_status") == 0)
    {
        ret = CmdQueryStatus(hDriver);
    }
    else if (strcmp(cmd, "quit") == 0)
    {
        ret = CmdQuit(hDriver);
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        PrintHelp(argv[0]);
        ret = 1;
    }

    DBG_PRINT("Command %s returned %d", cmd, ret);
    CloseHandle(hDriver);
    DBG_PRINT("Driver handle closed");
    return ret;
}

/* ============================================================
 *  新命令：lock / unlock / set_pass / rm_pass / shutdown_now / query_status
 * ============================================================ */

/* ---- 读取密码（不回显） ---- */
static void ReadPassword(const char *prompt, WCHAR *buf, int bufLen)
{
    printf("%s", prompt);
    fflush(stdout);
    int i = 0;
    while (i < bufLen - 1)
    {
        int c = _getch();
        if (c == '\r' || c == '\n')
            break;
        if (c == '\b')
        {
            if (i > 0)
            {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (c == 0 || c == 0xE0)
        {
            _getch();
            continue;
        } /* 跳过功能键 */
        buf[i++] = (WCHAR)c;
        printf("*");
        fflush(stdout);
    }
    buf[i] = 0;
    printf("\n");
    DBG_PRINT("Password read complete (length=%d)", i);
}

/* ---- lock（无需密码） ---- */
static int CmdLock(HANDLE hDriver)
{
    DBG_PRINT("CmdLock called");
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_LOCK,
                         NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        fprintf(stderr, "LOCK failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_GSH_LOCK failed, error=%lu", GetLastError());
        return 1;
    }
    DBG_PRINT("IOCTL_GSH_LOCK succeeded");
    printf("Driver LOCKED. Shutdown is now blocked.\n");
    return 0;
}

/* ---- 密码验证：如果驱动未设置密码则跳过，否则提示输入并验证 ---- */
static BOOL VerifyPasswordOrSkip(HANDLE hDriver)
{
    DBG_PRINT("VerifyPasswordOrSkip called");
    /* 先查询驱动状态，检查是否设置了密码 */
    GSH_LOCK_STATUS status;
    DWORD bytesRet = 0;
    if (DeviceIoControl(hDriver, IOCTL_GSH_QUERY_LOCK_STATUS,
                        NULL, 0, &status, sizeof(status), &bytesRet, NULL))
    {
        DBG_PRINT("Query status: PasswordSet=%d, LockState=%d", status.PasswordSet, status.LockState);
        if (!status.PasswordSet)
        {
            printf("[INFO] No password set, skipping password prompt.\n");
            return TRUE;
        }
    }
    else
    {
        DBG_PRINT("IOCTL_GSH_QUERY_LOCK_STATUS failed, error=%lu", GetLastError());
    }

    /* 有密码，提示输入 */
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter password: ", password, GSH_MAX_PASS_LEN);
    DBG_PRINT("Attempting unlock with password length=%d", wcslen(password));

    if (!DeviceIoControl(hDriver, IOCTL_GSH_UNLOCK,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesRet, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
        {
            fprintf(stderr, "Wrong password.\n");
            DBG_PRINT("Unlock failed: wrong password");
        }
        else
        {
            fprintf(stderr, "Password verify failed: %lu\n", err);
            DBG_PRINT("Unlock failed with error %lu", err);
        }
        return FALSE;
    }
    DBG_PRINT("Unlock succeeded");
    return TRUE;
}

/* ---- unlock（需密码，无密码则跳过） ---- */
static int CmdUnlock(HANDLE hDriver)
{
    DBG_PRINT("CmdUnlock called");
    if (!VerifyPasswordOrSkip(hDriver))
    {
        return 1;
    }
    printf("Driver UNLOCKED. Shutdown is now allowed.\n");
    return 0;
}

/* ---- set_pass ---- */
static int CmdSetPass(HANDLE hDriver)
{
    DBG_PRINT("CmdSetPass called");
    GSH_PASSWORD_INPUT input;
    RtlZeroMemory(&input, sizeof(input));
    ReadPassword("Enter old password (empty if none): ", input.OldPassword, GSH_MAX_PASS_LEN);
    ReadPassword("Enter new password: ", input.NewPassword, GSH_MAX_PASS_LEN);
    WCHAR confirm[GSH_MAX_PASS_LEN];
    ReadPassword("Confirm new password: ", confirm, GSH_MAX_PASS_LEN);
    if (wcscmp(input.NewPassword, confirm) != 0)
    {
        fprintf(stderr, "Passwords do not match.\n");
        DBG_PRINT("Password confirmation mismatch");
        return 1;
    }
    DBG_PRINT("Passwords match, sending IOCTL_GSH_SET_PASS");
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_SET_PASS,
                         &input, sizeof(input), NULL, 0, &bytesReturned, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
        {
            fprintf(stderr, "SET_PASS failed: wrong old password.\n");
            DBG_PRINT("SET_PASS failed: wrong old password");
        }
        else
        {
            fprintf(stderr, "SET_PASS failed: %lu\n", err);
            DBG_PRINT("SET_PASS failed with error %lu", err);
        }
        return 1;
    }
    DBG_PRINT("SET_PASS succeeded");
    printf("Password changed successfully.\n");
    return 0;
}

/* ---- rm_pass ---- */
static int CmdRmPass(HANDLE hDriver)
{
    DBG_PRINT("CmdRmPass called");
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter current password: ", password, GSH_MAX_PASS_LEN);
    DBG_PRINT("Sending IOCTL_GSH_RM_PASS with password length=%d", wcslen(password));
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_RM_PASS,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesReturned, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
        {
            fprintf(stderr, "RM_PASS failed: wrong password.\n");
            DBG_PRINT("RM_PASS failed: wrong password");
        }
        else
        {
            fprintf(stderr, "RM_PASS failed: %lu\n", err);
            DBG_PRINT("RM_PASS failed with error %lu", err);
        }
        return 1;
    }
    DBG_PRINT("RM_PASS succeeded");
    printf("Password removed. No protection now.\n");
    return 0;
}

/* ---- shutdown_now（需解锁 + 密码） ---- */
static int CmdShutdownNow(HANDLE hDriver)
{
    DBG_PRINT("CmdShutdownNow called");
    printf("WARNING: This will force a system shutdown immediately.\n");
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter password to confirm: ", password, GSH_MAX_PASS_LEN);
    DBG_PRINT("Sending IOCTL_GSH_SHUTDOWN_NOW with password length=%d", wcslen(password));
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_SHUTDOWN_NOW,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesReturned, NULL))
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
        {
            fprintf(stderr, "SHUTDOWN_NOW failed: driver locked or wrong password.\n");
            DBG_PRINT("SHUTDOWN_NOW failed: driver locked or wrong password");
        }
        else
        {
            fprintf(stderr, "SHUTDOWN_NOW failed: %lu\n", err);
            DBG_PRINT("SHUTDOWN_NOW failed with error %lu", err);
        }
        return 1;
    }
    DBG_PRINT("SHUTDOWN_NOW succeeded");
    printf("Shutdown initiated...\n");
    return 0;
}

/* ---- query_status（无需密码） ---- */
static int CmdQueryStatus(HANDLE hDriver)
{
    DBG_PRINT("CmdQueryStatus called");
    GSH_LOCK_STATUS status;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_QUERY_LOCK_STATUS,
                         NULL, 0, &status, sizeof(status),
                         &bytesReturned, NULL))
    {
        fprintf(stderr, "QUERY_LOCK_STATUS failed: %lu\n", GetLastError());
        DBG_PRINT("IOCTL_GSH_QUERY_LOCK_STATUS failed, error=%lu", GetLastError());
        return 1;
    }
    DBG_PRINT("Query status: LockState=%d, PasswordSet=%d, Hooked=%lu, Failed=%lu, Pending=%lu",
              status.LockState, status.PasswordSet, status.HookedCount,
              status.FailedCount, status.PendingCount);
    printf("=== GlobalShutdownHook Status ===\n");
    printf("  Lock state  : %s\n", status.LockState == GSH_LOCKED ? "LOCKED" : "UNLOCKED");
    printf("  Password    : %s\n", status.PasswordSet ? "SET" : "NONE");
    printf("  Hooked (OK) : %lu\n", status.HookedCount);
    printf("  Failed      : %lu\n", status.FailedCount);
    printf("  Pending     : %lu\n", status.PendingCount);
    printf("==================================\n");
    return 0;
}

/* GDRVLoader 桥接函数（在 gdrv_bridge.cpp 中实现） */
extern int GdrvLoadDriver(const wchar_t *targetDriverPath);
extern int GdrvUnloadDriver(const wchar_t *driverName);
extern unsigned long GdrvGetLastStatus(void);

/* ---- init（GDRVLoader 加载驱动 + 启动后台服务） ---- */
static int CmdInit(VOID)
{
    DBG_PRINT("CmdInit called");
    printf("[*] GlobalShutdownHook init\n");
    printf("    Loading unsigned driver via GDRVLoader...\n");

    /* 构造驱动路径：相对于可执行文件所在目录 */
    WCHAR driverPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
    {
        fprintf(stderr, "[ERROR] Cannot get module path.\n");
        DBG_PRINT("GetModuleFileNameW failed, error=%lu", GetLastError());
        return 1;
    }
    DBG_PRINT("Module path = %ls", driverPath);
    WCHAR *lastSlash = wcsrchr(driverPath, L'\\');
    if (lastSlash)
        *(lastSlash + 1) = L'\0';
    wcscat_s(driverPath, MAX_PATH, L"GlobalShutdownHook.sys");
    DBG_PRINT("Driver path = %ls", driverPath);

    wprintf(L"    Driver path: %s\n", driverPath);

    /* 1. 通过 GDRVLoader 加载未签名驱动 */
    DBG_PRINT("Calling GdrvLoadDriver(%ls)", driverPath);
    int rc = GdrvLoadDriver(driverPath);
    DBG_PRINT("GdrvLoadDriver returned %d", rc);
    if (rc != 0)
    {
        fprintf(stderr, "[ERROR] GdrvLoadDriver failed (code=%d).\n", rc);
        fprintf(stderr, "        Make sure you are running as Administrator.\n");
        DBG_PRINT("GdrvLoadDriver failed, last status=%lu", GdrvGetLastStatus());
        return 1;
    }
    printf("[OK] Driver loaded successfully.\n");

    /* 2. 等待驱动设备就绪 */
    DBG_PRINT("Waiting 1500ms for driver device...");
    Sleep(1500);
    DBG_PRINT("Wait complete");

    /* 3. 启动后台服务 ShutdownHookBgSrv.exe */
    WCHAR bgSrvPath[MAX_PATH];
    wcscpy_s(bgSrvPath, MAX_PATH, driverPath);
    WCHAR *bsSlash = wcsrchr(bgSrvPath, L'\\');
    if (bsSlash)
        *(bsSlash + 1) = L'\0';
    wcscat_s(bgSrvPath, MAX_PATH, L"ShutdownHookBgSrv.exe");
    DBG_PRINT("BgSrv path = %ls", bgSrvPath);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    DWORD bgSrvPidVal = 0;
    DBG_PRINT("Creating process: %ls", bgSrvPath);
    if (CreateProcessW(bgSrvPath, NULL, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        bgSrvPidVal = pi.dwProcessId;
        printf("[OK] Background service started (PID=%lu).\n", pi.dwProcessId);
        DBG_PRINT("BgSrv started with PID=%lu", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        DBG_PRINT("BgSrv handles closed");
    }
    else
    {
        fprintf(stderr, "[WARN] Could not start background service: %lu\n", GetLastError());
        DBG_PRINT("CreateProcessW failed, error=%lu", GetLastError());
    }

    /* 4. 加载 Auxiliary.sys (InfinityHook 系统调用拦截驱动) */
    WCHAR auxPath[MAX_PATH];
    wcscpy_s(auxPath, MAX_PATH, driverPath);
    WCHAR *auxSlash = wcsrchr(auxPath, L'\\');
    if (auxSlash)
        *(auxSlash + 1) = L'\0';
    wcscat_s(auxPath, MAX_PATH, L"Auxiliary.sys");
    DBG_PRINT("Auxiliary driver path = %ls", auxPath);

    DBG_PRINT("Calling GdrvLoadDriver(%ls)", auxPath);
    int auxRc = GdrvLoadDriver(auxPath);
    DBG_PRINT("GdrvLoadDriver(Auxiliary) returned %d", auxRc);
    if (auxRc != 0)
    {
        fprintf(stderr, "[WARN] GdrvLoadDriver(Auxiliary) failed (code=%d). Syscall interception disabled.\n", auxRc);
        DBG_PRINT("Auxiliary load failed, last status=%lu", GdrvGetLastStatus());
    }
    else
    {
        printf("[OK] Auxiliary.sys loaded (InfinityHook syscall interceptor).\n");
        Sleep(1000);

        /* 5. 注册 BgSrv PID 到 Auxiliary (供系统调用拦截用) */
        DBG_PRINT("Opening Auxiliary device: %ls", AUX_WIN32_NAME);
        HANDLE hAux = CreateFileW(AUX_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hAux != INVALID_HANDLE_VALUE)
        {
            DBG_PRINT("Auxiliary device opened, handle=0x%p", hAux);
            DWORD auxBytes = 0;
            HANDLE pidHandle = (HANDLE)(ULONG_PTR)bgSrvPidVal;
            DBG_PRINT("Registering BgSrv PID=%lu with Auxiliary", bgSrvPidVal);

            BOOL ioctlResult = DeviceIoControl(hAux, IOCTL_AUX_SET_BGSRV_PID, &pidHandle, sizeof(pidHandle),
                                               NULL, 0, &auxBytes, NULL);
            DBG_PRINT("IOCTL_AUX_SET_BGSRV_PID returned %d, error=%lu", ioctlResult, GetLastError());
            if (ioctlResult)
            {
                printf("[OK] BgSrv PID registered with Auxiliary.\n");
            }
            else
            {
                fprintf(stderr, "[WARN] Failed to register BgSrv PID with Auxiliary: %lu\n", GetLastError());
            }
            CloseHandle(hAux);
            DBG_PRINT("Auxiliary handle closed");
        }
        else
        {
            fprintf(stderr, "[WARN] Cannot open Auxiliary device: %lu\n", GetLastError());
            DBG_PRINT("CreateFileW(AUX) failed, error=%lu", GetLastError());
        }
    }

    /* 6. PPL 保护 — 通过独立 PPLControl.exe 实现 (依赖 RTCore64.sys) */
    {
        DBG_PRINT("Starting PPL protection setup...");

        /* 从内嵌数据释放 RTCore64.sys 到临时文件 */
        WCHAR rtCorePath[MAX_PATH];
        wcscpy_s(rtCorePath, MAX_PATH, driverPath);
        WCHAR *rcSlash = wcsrchr(rtCorePath, L'\\');
        if (rcSlash)
            *(rcSlash + 1) = L'\0';
        wcscat_s(rtCorePath, MAX_PATH, L"RTCore64.sys");
        DBG_PRINT("RTCore64.sys path = %ls", rtCorePath);

        /* 如果文件不存在，从内嵌数据释放 */
        if (GetFileAttributesW(rtCorePath) == INVALID_FILE_ATTRIBUTES)
        {
            DBG_PRINT("RTCore64.sys not found on disk, extracting from embedded data...");
            HANDLE hFile = CreateFileW(rtCorePath, GENERIC_WRITE, 0, NULL,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD bytesWritten = 0;
                WriteFile(hFile, RTCore64_sys_data, (DWORD)RTCore64_sys_size,
                          &bytesWritten, NULL);
                CloseHandle(hFile);
                printf("[OK] RTCore64.sys extracted from embedded data (%zu bytes).\n", RTCore64_sys_size);
                DBG_PRINT("Extracted %lu bytes to %ls", bytesWritten, rtCorePath);
            }
            else
            {
                fprintf(stderr, "[WARN] Failed to extract RTCore64.sys: %lu\n", GetLastError());
            }
        }

        DBG_PRINT("Calling GdrvLoadDriver(%ls)", rtCorePath);
        int rcRtc = GdrvLoadDriver(rtCorePath);
        DBG_PRINT("GdrvLoadDriver(RTCore64) returned %d", rcRtc);
        if (rcRtc == 0)
        {
            printf("[OK] RTCore64.sys loaded (PPLControl dependency).\n");
            Sleep(500);

            /* 运行 PPLControl.exe protect <pid> PPL WinTcb */
            WCHAR pplExePath[MAX_PATH];
            wcscpy_s(pplExePath, MAX_PATH, driverPath);
            WCHAR *pplSlash = wcsrchr(pplExePath, L'\\');
            if (pplSlash)
                *(pplSlash + 1) = L'\0';
            wcscat_s(pplExePath, MAX_PATH, L"PPLcontrol.exe");
            DBG_PRINT("PPLControl.exe path = %ls", pplExePath);

            WCHAR cmdLine[MAX_PATH * 2];
            swprintf_s(cmdLine, _countof(cmdLine),
                       L"\"%s\" protect %lu PPL WinTcb", pplExePath, bgSrvPidVal);
            DBG_PRINT("Command line = %ls", cmdLine);

            STARTUPINFOW siPpl;
            PROCESS_INFORMATION piPpl;
            ZeroMemory(&siPpl, sizeof(siPpl));
            siPpl.cb = sizeof(siPpl);
            ZeroMemory(&piPpl, sizeof(piPpl));

            DBG_PRINT("Creating PPLControl process...");
            if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                               CREATE_NO_WINDOW, NULL, NULL, &siPpl, &piPpl))
            {
                DBG_PRINT("PPLControl process created, PID=%lu", piPpl.dwProcessId);
                WaitForSingleObject(piPpl.hProcess, 10000);
                DWORD exitCode = 1;
                GetExitCodeProcess(piPpl.hProcess, &exitCode);
                DBG_PRINT("PPLControl exit code = %lu", exitCode);
                if (exitCode == 0)
                {
                    printf("[OK] BgSrv set to WinTcb protected (PPL via PPLControl.exe).\n");
                }
                else
                {
                    fprintf(stderr, "[WARN] PPLControl.exe protect failed (exit code=%lu).\n", exitCode);
                }
                CloseHandle(piPpl.hThread);
                CloseHandle(piPpl.hProcess);
                DBG_PRINT("PPLControl handles closed");
            }
            else
            {
                fprintf(stderr, "[WARN] Could not run PPLControl.exe: %lu\n", GetLastError());
                DBG_PRINT("CreateProcessW(PPLControl) failed, error=%lu", GetLastError());
            }
        }
        else
        {
            fprintf(stderr, "[WARN] GdrvLoadDriver(RTCore64) failed (code=%d). PPL protection skipped.\n", rcRtc);
            DBG_PRINT("RTCore64 load failed, last status=%lu", GdrvGetLastStatus());
        }
    }

    /* 7. DKOM 进程隐藏 — 通过独立 HideProcessesDKOM.sys 实现 */
    {
        DBG_PRINT("Starting DKOM hide setup...");
        WCHAR dkomPath[MAX_PATH];
        wcscpy_s(dkomPath, MAX_PATH, driverPath);
        WCHAR *dkSlash = wcsrchr(dkomPath, L'\\');
        if (dkSlash)
            *(dkSlash + 1) = L'\0';
        wcscat_s(dkomPath, MAX_PATH, L"HideProcess.sys");
        DBG_PRINT("HideProcess.sys path = %ls", dkomPath);

        DBG_PRINT("Calling GdrvLoadDriver(%ls)", dkomPath);
        int rcDkom = GdrvLoadDriver(dkomPath);
        DBG_PRINT("GdrvLoadDriver(HideProcess) returned %d", rcDkom);
        if (rcDkom == 0)
        {
            printf("[OK] HideProcess.sys loaded (DKOM process hider).\n");
            Sleep(500);

            /* 打开 \\.\HideProcess 设备，传入 BgSrv 进程名 */
            DBG_PRINT("Opening HideProcess device: \\\\.\\HideProcess");
            HANDLE hDkom = CreateFileW(L"\\\\.\\HideProcess",
                                       GENERIC_READ | GENERIC_WRITE,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDkom != INVALID_HANDLE_VALUE)
            {
                DBG_PRINT("HideProcess device opened, handle=0x%p", hDkom);
                char procName[] = "ShutdownHookBgSrv.exe";
                DWORD bytesRet = 0;
                /* IOCTL 定义照抄 HideProcessesDKOM/UserApp/UserApp.cpp:
                   #define IOCTL_GET_PROCESSNAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) */
                #define IOCTL_GET_PROCESSNAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
                DBG_PRINT("Sending IOCTL IOCTL_GET_PROCESSNAME with process name: %s", procName);
                BOOL ioctlResult = DeviceIoControl(hDkom, IOCTL_GET_PROCESSNAME,
                                                   procName, (DWORD)strlen(procName) + 1,
                                                   NULL, 0, &bytesRet, NULL);
                DBG_PRINT("DKOM hide IOCTL returned %d, error=%lu", ioctlResult, GetLastError());
                if (ioctlResult)
                {
                    printf("[OK] BgSrv hidden via DKOM (HideProcess.sys).\n");
                }
                else
                {
                    fprintf(stderr, "[WARN] DKOM hide IOCTL failed: %lu\n", GetLastError());
                }
                CloseHandle(hDkom);
                DBG_PRINT("HideProcess handle closed");
            }
            else
            {
                fprintf(stderr, "[WARN] Cannot open HideProcess device: %lu\n", GetLastError());
                DBG_PRINT("CreateFileW(HideProcess) failed, error=%lu", GetLastError());
            }
        }
        else
        {
            fprintf(stderr, "[WARN] GdrvLoadDriver(HideProcess) failed (code=%d). DKOM hide skipped.\n", rcDkom);
            DBG_PRINT("HideProcess load failed, last status=%lu", GdrvGetLastStatus());
        }
    }

    printf("\n[OK] GlobalShutdownHook initialized.\n");
    printf("     Use 'query_status' to check driver state.\n");
    DBG_PRINT("CmdInit completed successfully");
    return 0;
}

/* ---- quit（需密码：unhook + 卸载驱动 + 退出 BgSrv） ---- */
static int CmdQuit(HANDLE hDriver)
{
    DBG_PRINT("CmdQuit called");
    DWORD bytesReturned = 0;

    /* 1. 密码验证（无密码则跳过，有密码则提示输入） */
    DBG_PRINT("Step 1/6: Password verification");
    if (!VerifyPasswordOrSkip(hDriver))
    {
        fprintf(stderr, "QUIT failed: password verification failed.\n");
        DBG_PRINT("Password verification failed");
        return 1;
    }
    printf("[1/6] Password verified. Driver UNLOCKED.\n");
    DBG_PRINT("Password verified, driver unlocked");

    /* 2. 删除所有 Hook */
    DBG_PRINT("Step 2/6: Removing all hooks");
    if (!DeviceIoControl(hDriver, IOCTL_GSH_UNHOOK_ALL,
                         NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        fprintf(stderr, "[WARN] UNHOOK_ALL failed: %lu (continuing to unload driver)\n", GetLastError());
        DBG_PRINT("IOCTL_GSH_UNHOOK_ALL failed, error=%lu", GetLastError());
    }
    else
    {
        printf("[2/6] All hooks removed.\n");
        DBG_PRINT("All hooks removed successfully");
    }

    /* 3. 通知 BgSrv 主动退出（释放驱动句柄，否则驱动无法卸载） */
    DBG_PRINT("Step 3/6: Requesting BgSrv exit");
    {
        HANDLE hGsh = CreateFileW(GSH_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hGsh != INVALID_HANDLE_VALUE)
        {
            DBG_PRINT("GSH device opened for exit request, handle=0x%p", hGsh);
            DWORD bytes = 0;
            BOOL ioctlResult = DeviceIoControl(hGsh, IOCTL_GSH_REQUEST_EXIT, NULL, 0, NULL, 0, &bytes, NULL);
            DBG_PRINT("IOCTL_GSH_REQUEST_EXIT returned %d, error=%lu", ioctlResult, GetLastError());
            CloseHandle(hGsh);
            printf("[3/6] Exit request sent to BgSrv.\n");
        }
        else
        {
            DBG_PRINT("CreateFileW(GSH) failed for exit request, error=%lu", GetLastError());
        }
        /* 等待 BgSrv 退出（最多 5 秒，每 200ms 检查一次） */
        DBG_PRINT("Waiting for BgSrv to exit (max 5s)...");
        for (int i = 0; i < 25; i++)
        {
            Sleep(200);
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == INVALID_HANDLE_VALUE)
            {
                DBG_PRINT("CreateToolhelp32Snapshot failed, error=%lu", GetLastError());
                break;
            }
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            BOOL found = FALSE;
            if (Process32FirstW(hSnap, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, L"ShutdownHookBgSrv.exe") == 0)
                    {
                        found = TRUE;
                        DBG_PRINT("BgSrv still running (PID=%lu), iteration=%d", pe.th32ProcessID, i);
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
            if (!found)
            {
                printf("[OK] BgSrv exited.\n");
                DBG_PRINT("BgSrv exited after %d iterations", i);
                break;
            }
        }
    }

    /* 4. 设置 Auxiliary quitting 状态 */
    DBG_PRINT("Step 4/6: Setting Auxiliary QUITTING state");
    HANDLE hAux = CreateFileW(AUX_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hAux != INVALID_HANDLE_VALUE)
    {
        DBG_PRINT("Auxiliary device opened, handle=0x%p", hAux);
        DWORD auxBytes = 0;
        BOOL ioctlResult = DeviceIoControl(hAux, IOCTL_AUX_SET_QUITTING, NULL, 0, NULL, 0, &auxBytes, NULL);
        DBG_PRINT("IOCTL_AUX_SET_QUITTING returned %d, error=%lu", ioctlResult, GetLastError());
        printf("[4/6] Auxiliary QUITTING state set.\n");
        CloseHandle(hAux);
        DBG_PRINT("Auxiliary handle closed");
    }
    else
    {
        DBG_PRINT("CreateFileW(AUX) failed for quitting, error=%lu", GetLastError());
    }

    /* 5. 卸载 GSH 驱动 */
    DBG_PRINT("Step 5/6: Unloading GSH driver");
    WCHAR driverPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
    {
        fprintf(stderr, "[ERROR] GetModuleFileName failed.\n");
        DBG_PRINT("GetModuleFileNameW failed, error=%lu", GetLastError());
        return 1;
    }
    WCHAR *lastSlash = wcsrchr(driverPath, L'\\');
    if (lastSlash)
    {
        *(lastSlash + 1) = L'\0';
        wcscat_s(driverPath, MAX_PATH, L"GlobalShutdownHook.sys");
    }
    DBG_PRINT("GSH driver path = %ls", driverPath);

    printf("[5/6] Unloading GSH driver...\n");
    DBG_PRINT("Calling GdrvUnloadDriver(%ls)", driverPath);
    int rc = GdrvUnloadDriver(driverPath);
    DBG_PRINT("GdrvUnloadDriver(GSH) returned %d", rc);
    if (rc != 0)
    {
        fprintf(stderr, "[WARN] GdrvUnloadDriver(GSH) returned %d\n", rc);
        DBG_PRINT("GSH driver unload failed, last status=%lu", GdrvGetLastStatus());
    }
    else
    {
        printf("[OK] GSH driver unloaded.\n");
    }

    /* 等待 GSH hook 回调全部退出 + BgSrv 完全清理 */
    DBG_PRINT("Waiting 1500ms for GSH cleanup...");
    Sleep(1500);
    DBG_PRINT("Wait complete");

    /* 6. 卸载 Auxiliary 驱动 */
    DBG_PRINT("Step 6/6: Unloading Auxiliary driver");
    printf("[6/6] Unloading Auxiliary driver...\n");
    WCHAR auxPath[MAX_PATH];
    wcscpy_s(auxPath, MAX_PATH, driverPath);
    WCHAR *auxSlash = wcsrchr(auxPath, L'\\');
    if (auxSlash)
    {
        *(auxSlash + 1) = L'\0';
        wcscat_s(auxPath, MAX_PATH, L"Auxiliary.sys");
    }
    DBG_PRINT("Auxiliary driver path = %ls", auxPath);
    DBG_PRINT("Calling GdrvUnloadDriver(%ls)", auxPath);
    int auxRc = GdrvUnloadDriver(auxPath);
    DBG_PRINT("GdrvUnloadDriver(Aux) returned %d", auxRc);
    if (auxRc != 0)
    {
        fprintf(stderr, "[WARN] GdrvUnloadDriver(Aux) returned %d\n", auxRc);
        DBG_PRINT("Auxiliary driver unload failed, last status=%lu", GdrvGetLastStatus());
    }
    else
    {
        printf("[OK] Auxiliary driver unloaded.\n");
    }

    printf("\n[DONE] GlobalShutdownHook shutdown complete.\n");
    printf("       Background service will exit automatically (detected driver unload).\n");
    DBG_PRINT("CmdQuit completed successfully");
    return 0;
}

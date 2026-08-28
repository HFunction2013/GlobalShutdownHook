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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <conio.h>

#include "../driver/gsh_common.h"

/* ---- advapi32 函数声明（用于测试） ---- */
typedef BOOL (WINAPI *PFN_InitiateSystemShutdownExW)(
    LPWSTR lpMachineName, LPWSTR lpMessage, DWORD dwTimeout,
    BOOL bForceAppsClosed, BOOL bRebootAfterShutdown, DWORD dwReason);

/* ---- 工具函数 ---- */
static const char *FunctionIdToString(ULONG id)
{
    switch (id) {
        case FUNC_EXIT_WINDOWS_EX:               return "ExitWindowsEx";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A: return "InitiateSystemShutdownExA";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W: return "InitiateSystemShutdownExW";
        default:                                 return "Unknown";
    }
}

static const char *StateToString(ULONG state)
{
    switch (state) {
        case HOOK_STATE_NONE:      return "NONE";
        case HOOK_STATE_NEED_HOOK: return "PENDING";
        case HOOK_STATE_HOOKED:    return "HOOKED";
        case HOOK_STATE_FAILED:    return "FAILED";
        default:                   return "???";
    }
}

static const char *FailReasonToString(ULONG reason)
{
    switch (reason) {
        case FAIL_PROCESS_TERMINATED:    return "Process terminated";
        case FAIL_MODULE_NOT_FOUND:       return "Module not found";
        case FAIL_EXPORT_NOT_FOUND:       return "Export not found";
        case FAIL_ATTACH_FAILED:          return "Attach failed";
        case FAIL_PROTECT_CHANGE:         return "Protect change failed (ACG?)";
        case FAIL_WRITE_MEMORY:           return "Write memory failed (PPL?)";
        case FAIL_ALLOC_MEMORY:           return "Alloc memory failed";
        case FAIL_THREAD_SUSPEND:         return "Thread suspend failed";
        case FAIL_PROTECTED_PROCESS:      return "Protected process";
        case FAIL_WOW64_UNSUPPORTED:      return "Wow64 unsupported";
        case FAIL_PEEK_MEMORY:            return "Peek memory failed";
        case FAIL_UNKNOWN:                return "Unknown";
        default:                          return "Other";
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
    HANDLE h = CreateFileW(
        GSH_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "Error: Cannot open driver %ls (error %lu)\n",
                GSH_WIN32_NAME, err);
        if (err == ERROR_FILE_NOT_FOUND) {
            fprintf(stderr, "  Driver not loaded. Use: sc create GSH type= kernel binPath= <path>\n");
            fprintf(stderr, "  Then: sc start GSH\n");
        }
    }
    return h;
}

/* ---- 命令实现 ---- */
static int CmdStatus(HANDLE hDriver)
{
    GSH_DRIVER_STATUS status;
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_STATUS,
                         NULL, 0, &status, sizeof(status),
                         &bytesReturned, NULL)) {
        fprintf(stderr, "IOCTL_GET_STATUS failed: %lu\n", GetLastError());
        return 1;
    }

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
    BYTE buffer[65536];
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_HOOKED_LIST,
                         NULL, 0, buffer, sizeof(buffer),
                         &bytesReturned, NULL)) {
        fprintf(stderr, "IOCTL_GET_HOOKED_LIST failed: %lu\n", GetLastError());
        return 1;
    }

    ULONG count = *(PULONG)buffer;
    PGSH_HOOKED_ENTRY entries = (PGSH_HOOKED_ENTRY)(buffer + sizeof(ULONG));

    printf("=== Hook Entries (%lu) ===\n", count);
    printf("%-8s %-8s %-30s %-10s %s\n",
           "PID", "State", "Function", "Module", "Process");
    printf("------------------------------------------------------------------------\n");

    for (ULONG i = 0; i < count; i++) {
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
    BYTE buffer[65536];
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_FAIL_LOG,
                         NULL, 0, buffer, sizeof(buffer),
                         &bytesReturned, NULL)) {
        fprintf(stderr, "IOCTL_GET_FAIL_LOG failed: %lu\n", GetLastError());
        return 1;
    }

    ULONG count = *(PULONG)buffer;
    PGSH_FAIL_RECORD records = (PGSH_FAIL_RECORD)(buffer + sizeof(ULONG));

    printf("=== Failure Log (%lu records) ===\n", count);
    if (count == 0) {
        printf("  (no failures)\n");
        return 0;
    }

    printf("%-8s %-30s %-10s %-25s %s\n",
           "PID", "Function", "Module", "Reason", "Time");
    printf("--------------------------------------------------------------------------------\n");

    for (ULONG i = 0; i < count; i++) {
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
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_CLEAR_FAIL_LOG,
                         NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fprintf(stderr, "IOCTL_CLEAR_FAIL_LOG failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Failure log cleared.\n");
    return 0;
}

static int CmdUnhook(HANDLE hDriver)
{
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_UNHOOK_ALL,
                         NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fprintf(stderr, "IOCTL_UNHOOK_ALL failed: %lu\n", GetLastError());
        return 1;
    }
    printf("All hooks restored. (Driver still running, new processes will be re-hooked.)\n");
    return 0;
}

static int CmdTestExitWindows(VOID)
{
    printf("Testing ExitWindowsEx(EWX_LOGOFF, 0)...\n");
    printf("If hook is active, this call will return TRUE but NOT log off.\n");
    printf("Press Ctrl+C to cancel, or Enter to continue...\n");
    getchar();

    BOOL result = ExitWindowsEx(EWX_LOGOFF, 0);
    DWORD err = GetLastError();

    printf("ExitWindowsEx returned: %s (error=%lu)\n",
           result ? "TRUE" : "FALSE", err);

    if (result) {
        printf("  -> Hook is ACTIVE (function returned success without logging off).\n");
        printf("  -> If you are still here, the shutdown was blocked.\n");
    } else {
        printf("  -> Hook may NOT be active, or call was refused by system.\n");
    }
    return 0;
}

static int CmdTestAdvapi(VOID)
{
    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
    if (!hAdvapi) {
        fprintf(stderr, "Cannot load advapi32.dll: %lu\n", GetLastError());
        return 1;
    }

    PFN_InitiateSystemShutdownExW pfn = (PFN_InitiateSystemShutdownExW)
        GetProcAddress(hAdvapi, "InitiateSystemShutdownExW");
    if (!pfn) {
        fprintf(stderr, "Cannot find InitiateSystemShutdownExW: %lu\n", GetLastError());
        FreeLibrary(hAdvapi);
        return 1;
    }

    printf("Testing InitiateSystemShutdownExW(NULL, L\"test\", 0, FALSE, FALSE, 0)...\n");
    printf("If hook is active, this will return TRUE but NOT initiate shutdown.\n");
    printf("Press Enter to continue...\n");
    getchar();

    BOOL result = pfn(NULL, L"GSH test", 0, FALSE, FALSE, 0);
    DWORD err = GetLastError();

    printf("InitiateSystemShutdownExW returned: %s (error=%lu)\n",
           result ? "TRUE" : "FALSE", err);

    if (result) {
        printf("  -> Hook is ACTIVE.\n");
    } else {
        printf("  -> Hook may NOT be active (error %lu).\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            printf("  -> Note: ACCESS_DENIED is normal if not running as admin.\n");
        }
    }

    FreeLibrary(hAdvapi);
    return 0;
}

static int CmdMonitor(HANDLE hDriver, int intervalSec)
{
    if (intervalSec <= 0) intervalSec = 2;

    printf("Monitoring (refresh every %ds). Press Ctrl+C to stop.\n\n", intervalSec);

    while (1) {
        GSH_DRIVER_STATUS status;
        DWORD bytesReturned = 0;

        if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_STATUS,
                             NULL, 0, &status, sizeof(status),
                             &bytesReturned, NULL)) {
            fprintf(stderr, "\rIOCTL failed: %lu          ", GetLastError());
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
    if (intervalSec <= 0) intervalSec = 1;
    printf("GSH Work Queue (refresh every %ds). Press Ctrl+C to stop.\n\n", intervalSec);
    while (1) {
        BYTE buffer[65536];
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(hDriver, IOCTL_GSH_GET_QUEUE,
                             NULL, 0, buffer, sizeof(buffer),
                             &bytesReturned, NULL)) {
            printf("\rIOCTL_GET_QUEUE failed: %lu          ", GetLastError());
            fflush(stdout);
            Sleep(intervalSec * 1000);
            continue;
        }
        ULONG count = *(PULONG)buffer;
        PGSH_QUEUE_ENTRY entries = (PGSH_QUEUE_ENTRY)(buffer + sizeof(ULONG));
        system("cls");
        printf("=== GSH Work Queue: %lu pending task(s) ===\n", count);
        if (count == 0) {
            printf("  (queue empty)\n");
        } else {
            printf("%-8s %-32s %s\n", "PID", "Function", "Module");
            printf("----------------------------------------------------------------\n");
            for (ULONG i = 0; i < count; i++) {
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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        PrintHelp(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    /* test 命令不需要驱动句柄 */
    if (strcmp(cmd, "test") == 0) {
        return CmdTestExitWindows();
    }
    if (strcmp(cmd, "test-advapi") == 0) {
        return CmdTestAdvapi();
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        PrintHelp(argv[0]);
        return 0;
    }
    if (strcmp(cmd, "init") == 0) {
        return CmdInit();
    }

    /* 其他命令需要打开驱动 */
    HANDLE hDriver = OpenGshDriver();
    if (hDriver == INVALID_HANDLE_VALUE) {
        return 1;
    }

    int ret = 0;

    if (strcmp(cmd, "status") == 0) {
        ret = CmdStatus(hDriver);
    } else if (strcmp(cmd, "list") == 0) {
        ret = CmdList(hDriver);
    } else if (strcmp(cmd, "failures") == 0) {
        ret = CmdFailures(hDriver);
    } else if (strcmp(cmd, "clear") == 0) {
        ret = CmdClear(hDriver);
    } else if (strcmp(cmd, "unhook") == 0) {
        ret = CmdUnhook(hDriver);
    } else if (strcmp(cmd, "monitor") == 0) {
        int interval = (argc >= 3) ? atoi(argv[2]) : 2;
        ret = CmdMonitor(hDriver, interval);
    } else if (strcmp(cmd, "queue") == 0) {
        int interval = (argc >= 3) ? atoi(argv[2]) : 1;
        ret = CmdQueue(hDriver, interval);
    } else if (strcmp(cmd, "lock") == 0) {
        ret = CmdLock(hDriver);
    } else if (strcmp(cmd, "unlock") == 0) {
        ret = CmdUnlock(hDriver);
    } else if (strcmp(cmd, "set_pass") == 0) {
        ret = CmdSetPass(hDriver);
    } else if (strcmp(cmd, "rm_pass") == 0) {
        ret = CmdRmPass(hDriver);
    } else if (strcmp(cmd, "shutdown_now") == 0) {
        ret = CmdShutdownNow(hDriver);
    } else if (strcmp(cmd, "query_status") == 0) {
        ret = CmdQueryStatus(hDriver);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        PrintHelp(argv[0]);
        ret = 1;
    }

    CloseHandle(hDriver);
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
    while (i < bufLen - 1) {
        int c = _getch();
        if (c == '\r' || c == '\n') break;
        if (c == '\b') {
            if (i > 0) { i--; printf("\b \b"); fflush(stdout); }
            continue;
        }
        if (c == 0 || c == 0xE0) { _getch(); continue; }  /* 跳过功能键 */
        buf[i++] = (WCHAR)c;
        printf("*");
        fflush(stdout);
    }
    buf[i] = 0;
    printf("\n");
}

/* ---- lock（无需密码） ---- */
static int CmdLock(HANDLE hDriver)
{
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_LOCK,
                         NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        fprintf(stderr, "LOCK failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Driver LOCKED. Shutdown is now blocked.\n");
    return 0;
}

/* ---- unlock（需密码） ---- */
static int CmdUnlock(HANDLE hDriver)
{
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter password: ", password, GSH_MAX_PASS_LEN);
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_UNLOCK,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesReturned, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "UNLOCK failed: wrong password.\n");
        } else {
            fprintf(stderr, "UNLOCK failed: %lu\n", err);
        }
        return 1;
    }
    printf("Driver UNLOCKED. Shutdown is now allowed.\n");
    return 0;
}

/* ---- set_pass ---- */
static int CmdSetPass(HANDLE hDriver)
{
    GSH_PASSWORD_INPUT input;
    RtlZeroMemory(&input, sizeof(input));
    ReadPassword("Enter old password (empty if none): ", input.OldPassword, GSH_MAX_PASS_LEN);
    ReadPassword("Enter new password: ", input.NewPassword, GSH_MAX_PASS_LEN);
    WCHAR confirm[GSH_MAX_PASS_LEN];
    ReadPassword("Confirm new password: ", confirm, GSH_MAX_PASS_LEN);
    if (wcscmp(input.NewPassword, confirm) != 0) {
        fprintf(stderr, "Passwords do not match.\n");
        return 1;
    }
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_SET_PASS,
                         &input, sizeof(input), NULL, 0, &bytesReturned, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "SET_PASS failed: wrong old password.\n");
        } else {
            fprintf(stderr, "SET_PASS failed: %lu\n", err);
        }
        return 1;
    }
    printf("Password changed successfully.\n");
    return 0;
}

/* ---- rm_pass ---- */
static int CmdRmPass(HANDLE hDriver)
{
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter current password: ", password, GSH_MAX_PASS_LEN);
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_RM_PASS,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesReturned, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "RM_PASS failed: wrong password.\n");
        } else {
            fprintf(stderr, "RM_PASS failed: %lu\n", err);
        }
        return 1;
    }
    printf("Password removed. No protection now.\n");
    return 0;
}

/* ---- shutdown_now（需解锁 + 密码） ---- */
static int CmdShutdownNow(HANDLE hDriver)
{
    printf("WARNING: This will force a system shutdown immediately.\n");
    WCHAR password[GSH_MAX_PASS_LEN];
    ReadPassword("Enter password to confirm: ", password, GSH_MAX_PASS_LEN);
    DWORD bytesReturned;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_SHUTDOWN_NOW,
                         password, (DWORD)(wcslen(password) + 1) * sizeof(WCHAR),
                         NULL, 0, &bytesReturned, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "SHUTDOWN_NOW failed: driver locked or wrong password.\n");
        } else {
            fprintf(stderr, "SHUTDOWN_NOW failed: %lu\n", err);
        }
        return 1;
    }
    printf("Shutdown initiated...\n");
    return 0;
}

/* ---- query_status（无需密码） ---- */
static int CmdQueryStatus(HANDLE hDriver)
{
    GSH_LOCK_STATUS status;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDriver, IOCTL_GSH_QUERY_LOCK_STATUS,
                         NULL, 0, &status, sizeof(status),
                         &bytesReturned, NULL)) {
        fprintf(stderr, "QUERY_LOCK_STATUS failed: %lu\n", GetLastError());
        return 1;
    }
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
extern int GdrvLoadDriver(const wchar_t* targetDriverPath);
extern int GdrvUnloadDriver(const wchar_t* driverName);
extern unsigned long GdrvGetLastStatus(void);

/* ---- init（GDRVLoader 加载驱动 + 启动后台服务） ---- */
static int CmdInit(VOID)
{
    printf("[*] GlobalShutdownHook init\n");
    printf("    Loading unsigned driver via GDRVLoader...\n");

    /* 构造驱动路径：相对于可执行文件所在目录 */
    WCHAR driverPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        fprintf(stderr, "[ERROR] Cannot get module path.\n");
        return 1;
    }
    WCHAR* lastSlash = wcsrchr(driverPath, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    wcscat_s(driverPath, MAX_PATH, L"GlobalShutdownHook.sys");

    wprintf(L"    Driver path: %s\n", driverPath);

    /* 1. 通过 GDRVLoader 加载未签名驱动 */
    int rc = GdrvLoadDriver(driverPath);
    if (rc != 0) {
        fprintf(stderr, "[ERROR] GdrvLoadDriver failed (code=%d).\n", rc);
        fprintf(stderr, "        Make sure you are running as Administrator.\n");
        return 1;
    }
    printf("[OK] Driver loaded successfully.\n");

    /* 2. 等待驱动设备就绪 */
    Sleep(1500);

    /* 3. 启动后台服务 ShutdownHookBgSrv.exe */
    WCHAR bgSrvPath[MAX_PATH];
    wcscpy_s(bgSrvPath, MAX_PATH, driverPath);
    WCHAR* bsSlash = wcsrchr(bgSrvPath, L'\\');
    if (bsSlash) *(bsSlash + 1) = L'\0';
    wcscat_s(bgSrvPath, MAX_PATH, L"ShutdownHookBgSrv.exe");

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessW(bgSrvPath, NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[OK] Background service started (PID=%lu).\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        fprintf(stderr, "[WARN] Could not start background service: %lu\n", GetLastError());
    }

    printf("\n[OK] GlobalShutdownHook initialized.\n");
    printf("     Use 'query_status' to check driver state.\n");
    return 0;
}

/*
 * main.c - CMD 版本入口
 * 调用 Client.dll 完成所有操作
 */
#include <stdio.h>
#include <windows.h>
#include "../ClientLib/GshClient.h"

#pragma comment(lib, "ClientLib.lib")

static void PrintUsage(void) {
    printf("GlobalShutdownHook CMD Client\n");
    printf("Usage:\n");
    printf("  ShutdownHookCMD init              - Initialize (load drivers, start BgSrv)\n");
    printf("  ShutdownHookCMD quit [password]  - Shutdown (unload drivers, stop BgSrv)\n");
    printf("  ShutdownHookCMD lock              - Lock\n");
    printf("  ShutdownHookCMD unlock [password] - Unlock\n");
    printf("  ShutdownHookCMD status            - Query status\n");
    printf("  ShutdownHookCMD setpass <old> <new> - Set password\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) { PrintUsage(); return 1; }

    if (wcscmp(argv[1], L"init") == 0) {
        printf("[*] Initializing...\n");
        int rc = Gsh_Init();
        printf(rc == 0 ? "[OK] Init complete\n" : "[ERROR] %s\n", Gsh_GetLastError());
        return rc;
    }
    else if (wcscmp(argv[1], L"quit") == 0) {
        const wchar_t* pwd = (argc > 2) ? argv[2] : NULL;
        printf("[*] Shutting down...\n");
        int rc = Gsh_Quit(pwd);
        printf(rc == 0 ? "[OK] Shutdown complete\n" : "[ERROR] %s\n", Gsh_GetLastError());
        return rc;
    }
    else if (wcscmp(argv[1], L"lock") == 0) {
        int rc = Gsh_Lock();
        printf(rc == 0 ? "[OK] Locked\n" : "[ERROR] %s\n", Gsh_GetLastError());
        return rc;
    }
    else if (wcscmp(argv[1], L"unlock") == 0) {
        const wchar_t* pwd = (argc > 2) ? argv[2] : NULL;
        int rc = Gsh_Unlock(pwd);
        printf(rc == 0 ? "[OK] Unlocked\n" : "[ERROR] %s\n", Gsh_GetLastError());
        return rc;
    }
    else if (wcscmp(argv[1], L"status") == 0) {
        int locked, blocked, hooked, failed, inqueue;
        int rc = Gsh_QueryStatus(&locked, &blocked, &hooked, &failed, &inqueue);
        if (rc == 0) {
            printf("Locked: %s\n", locked ? "true" : "false");
            printf("Blocked: %d\n", blocked);
            printf("Hooked: %d\n", hooked);
            printf("Failed: %d\n", failed);
            printf("Inqueue: %d\n", inqueue);
        } else {
            printf("[ERROR] %s\n", Gsh_GetLastError());
        }
        return rc;
    }
    else if (wcscmp(argv[1], L"setpass") == 0) {
        if (argc < 4) { printf("Usage: setpass <old> <new>\n"); return 1; }
        int rc = Gsh_SetPassword(argv[2], argv[3]);
        printf(rc == 0 ? "[OK] Password changed\n" : "[ERROR] %s\n", Gsh_GetLastError());
        return rc;
    }

    PrintUsage();
    return 1;
}

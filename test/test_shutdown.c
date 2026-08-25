/*
 * test_shutdown.c - 独立测试程序
 *
 * 编译后在 VM 中运行（管理员权限）。
 * 调用 ExitWindowsEx，如果驱动已加载且 hook 生效，
 * 函数会返回 TRUE 但不会实际注销/关机。
 *
 * 编译（VS Developer Prompt）：
 *   cl /nologo /W3 test_shutdown.c user32.lib advapi32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

typedef BOOL (WINAPI *PFN_InitiateSystemShutdownExW)(
    LPWSTR, LPWSTR, DWORD, BOOL, BOOL, DWORD);

int main(void)
{
    printf("=== GlobalShutdownHook Test Program ===\n\n");
    printf("This program calls shutdown APIs. If the driver is active,\n");
    printf("the calls will return TRUE but NOT actually shut down.\n\n");

    int choice;
    do {
        printf("\n--- Menu ---\n");
        printf("  1. Test ExitWindowsEx(EWX_LOGOFF)\n");
        printf("  2. Test ExitWindowsEx(EWX_SHUTDOWN)\n");
        printf("  3. Test ExitWindowsEx(EWX_REBOOT)\n");
        printf("  4. Test InitiateSystemShutdownExW\n");
        printf("  5. Test AbortSystemShutdown\n");
        printf("  0. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);
        getchar(); /* consume newline */

        BOOL result = FALSE;
        DWORD err = 0;

        switch (choice) {
            case 1:
                printf("\nCalling ExitWindowsEx(EWX_LOGOFF, 0)...\n");
                result = ExitWindowsEx(EWX_LOGOFF, 0);
                err = GetLastError();
                break;
            case 2:
                printf("\nCalling ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0)...\n");
                result = ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0);
                err = GetLastError();
                break;
            case 3:
                printf("\nCalling ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0)...\n");
                result = ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
                err = GetLastError();
                break;
            case 4: {
                printf("\nCalling InitiateSystemShutdownExW(NULL, L\"test\", 0, FALSE, FALSE, 0)...\n");
                HMODULE hAdv = GetModuleHandleW(L"advapi32.dll");
                if (!hAdv) hAdv = LoadLibraryW(L"advapi32.dll");
                if (hAdv) {
                    PFN_InitiateSystemShutdownExW pfn =
                        (PFN_InitiateSystemShutdownExW)GetProcAddress(hAdv, "InitiateSystemShutdownExW");
                    if (pfn) {
                        result = pfn(NULL, L"GSH Test", 0, FALSE, FALSE, 0);
                        err = GetLastError();
                    } else {
                        printf("  GetProcAddress failed: %lu\n", GetLastError());
                    }
                }
                break;
            }
            case 5:
                printf("\nCalling AbortSystemShutdown(NULL)...\n");
                result = AbortSystemShutdownW(NULL);
                err = GetLastError();
                break;
            case 0:
                printf("Exiting.\n");
                return 0;
            default:
                printf("Invalid choice.\n");
                continue;
        }

        printf("  Result: %s (GetLastError=%lu)\n",
               result ? "TRUE" : "FALSE", err);

        if (result && choice >= 1 && choice <= 4) {
            printf("  -> If the system is still running, the hook is ACTIVE.\n");
            printf("  -> (Call returned success but shutdown was blocked)\n");
        } else if (!result && err == ERROR_ACCESS_DENIED) {
            printf("  -> Access denied. Run as Administrator, or hook not active.\n");
        } else if (!result) {
            printf("  -> Call failed. Hook may not be active for this process/function.\n");
        }

        if (choice == 5 && result) {
            printf("  -> AbortSystemShutdown succeeded (this API is not hooked).\n");
        }

    } while (1);

    return 0;
}

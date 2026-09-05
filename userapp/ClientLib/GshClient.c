/*
 * GshClient.c - GlobalShutdownHook 客户端库核心实现
 * 基于 ShutdownHookClient.c 重构为 DLL
 */
#define GSHCLIENT_EXPORTS
#include "GshClient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 引用原有驱动头文件 */
#include "../../driver/GlobalShutdownHook/gsh_common.h"
#include "../../driver/Auxiliary/Auxiliary.h"

/* GDRVLoader 函数声明（从 gdrv_bridge.cpp 导出） */
extern int GdrvLoadDriver(const wchar_t* path);
extern int GdrvUnloadDriver(const wchar_t* path);
extern unsigned long GdrvGetLastStatus(void);

static char g_lastError[256] = {0};

static void SetLastError(const char* msg) {
    strncpy_s(g_lastError, sizeof(g_lastError), msg, _TRUNCATE);
}

GSH_API const char* Gsh_GetLastError(void) {
    return g_lastError;
}

static HANDLE OpenGshDevice(void) {
    return CreateFileW(GSH_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static HANDLE OpenAuxDevice(void) {
    return CreateFileW(AUX_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void GetDriverPath(wchar_t* path, const wchar_t* fileName) {
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash) *(slash + 1) = L'\0';
        wcscat_s(path, MAX_PATH, fileName);
    }
}

GSH_API int Gsh_Init(void) {
    wchar_t driverPath[MAX_PATH];
    wchar_t auxPath[MAX_PATH];
    wchar_t bgSrvPath[MAX_PATH];

    /* 1. 加载 GSH 驱动 */
    GetDriverPath(driverPath, L"GlobalShutdownHook.sys");
    int rc = GdrvLoadDriver(driverPath);
    if (rc != 0) { SetLastError("Failed to load GSH driver"); return 1; }
    Sleep(1500);

    /* 2. 启动 BgSrv */
    GetDriverPath(bgSrvPath, L"ShutdownHookBgSrv.exe");
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si); ZeroMemory(&pi, sizeof(pi));
    DWORD bgSrvPid = 0;
    if (CreateProcessW(bgSrvPath, NULL, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        bgSrvPid = pi.dwProcessId;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }

    /* 3. 加载 Auxiliary 驱动 */
    GetDriverPath(auxPath, L"Auxiliary.sys");
    int auxRc = GdrvLoadDriver(auxPath);
    if (auxRc == 0) {
        Sleep(1000);
        HANDLE hAux = OpenAuxDevice();
        if (hAux != INVALID_HANDLE_VALUE) {
            DWORD bytes = 0;
            HANDLE pidHandle = (HANDLE)(ULONG_PTR)bgSrvPid;

            /* 设置 BgSrv PID */
            DeviceIoControl(hAux, IOCTL_AUX_SET_BGSRV_PID, &pidHandle, sizeof(pidHandle),
                             NULL, 0, &bytes, NULL);

            /* 设置 WinTCB 保护 */
            AUX_PROTECTION_INPUT protIn;
            protIn.Pid = pidHandle;
            protIn.ProtectionLevel = PROTECTION_LEVEL_WINTCB;
            DeviceIoControl(hAux, IOCTL_AUX_SET_PROTECTION, &protIn, sizeof(protIn),
                             NULL, 0, &bytes, NULL);

            /* DKOM 隐藏 */
            AUX_HIDE_INPUT hideIn;
            hideIn.Pid = pidHandle;
            DeviceIoControl(hAux, IOCTL_AUX_HIDE_PROCESS, &hideIn, sizeof(hideIn),
                             NULL, 0, &bytes, NULL);

            CloseHandle(hAux);
        }
    }

    SetLastError("OK");
    return 0;
}

GSH_API int Gsh_Quit(const wchar_t* password) {
    HANDLE hDriver = OpenGshDevice();
    if (hDriver == INVALID_HANDLE_VALUE) { SetLastError("Cannot open GSH device"); return 1; }

    DWORD bytes = 0;

    /* 1. 密码校验 (UNLOCK) */
    if (password && password[0]) {
        wchar_t pwdBuf[64];
        wcscpy_s(pwdBuf, 64, password);
        if (!DeviceIoControl(hDriver, IOCTL_GSH_UNLOCK, pwdBuf, sizeof(pwdBuf),
                             NULL, 0, &bytes, NULL)) {
            CloseHandle(hDriver);
            SetLastError("Password verification failed");
            return 1;
        }
    }

    /* 2. 设置 Auxiliary quitting 状态 */
    HANDLE hAux = OpenAuxDevice();
    if (hAux != INVALID_HANDLE_VALUE) {
        DeviceIoControl(hAux, IOCTL_AUX_SET_QUITTING, NULL, 0, NULL, 0, &bytes, NULL);
        CloseHandle(hAux);
    }

    /* 3. Unhook all */
    DeviceIoControl(hDriver, IOCTL_GSH_UNHOOK_ALL, NULL, 0, NULL, 0, &bytes, NULL);

    /* 4. 卸载 GSH 驱动 */
    wchar_t driverPath[MAX_PATH];
    GetDriverPath(driverPath, L"GlobalShutdownHook.sys");
    GdrvUnloadDriver(driverPath);

    /* 5. 卸载 Auxiliary 驱动 */
    wchar_t auxPath[MAX_PATH];
    GetDriverPath(auxPath, L"Auxiliary.sys");
    GdrvUnloadDriver(auxPath);

    CloseHandle(hDriver);
    SetLastError("OK");
    return 0;
}

GSH_API int Gsh_Lock(void) {
    HANDLE hDriver = OpenGshDevice();
    if (hDriver == INVALID_HANDLE_VALUE) { SetLastError("Cannot open GSH device"); return 1; }
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(hDriver, IOCTL_GSH_LOCK, NULL, 0, NULL, 0, &bytes, NULL);
    CloseHandle(hDriver);
    if (!ok) { SetLastError("Lock failed"); return 1; }
    SetLastError("OK");
    return 0;
}

GSH_API int Gsh_Unlock(const wchar_t* password) {
    HANDLE hDriver = OpenGshDevice();
    if (hDriver == INVALID_HANDLE_VALUE) { SetLastError("Cannot open GSH device"); return 1; }
    DWORD bytes = 0;
    wchar_t pwdBuf[64];
    if (password && password[0]) wcscpy_s(pwdBuf, 64, password);
    else pwdBuf[0] = L'\0';
    BOOL ok = DeviceIoControl(hDriver, IOCTL_GSH_UNLOCK, pwdBuf, sizeof(pwdBuf),
                               NULL, 0, &bytes, NULL);
    CloseHandle(hDriver);
    if (!ok) { SetLastError("Unlock failed (wrong password?)"); return 1; }
    SetLastError("OK");
    return 0;
}

GSH_API int Gsh_QueryStatus(int* locked, int* blocked, int* hooked, int* failed, int* inqueue) {
    HANDLE hDriver = OpenGshDevice();
    if (hDriver == INVALID_HANDLE_VALUE) { SetLastError("Cannot open GSH device"); return 1; }
    DWORD bytes = 0;
    GSH_STATUS status;
    BOOL ok = DeviceIoControl(hDriver, IOCTL_GSH_QUERY_STATUS, NULL, 0,
                               &status, sizeof(status), &bytes, NULL);
    CloseHandle(hDriver);
    if (!ok) { SetLastError("Query status failed"); return 1; }
    if (locked) *locked = status.LockState;
    if (blocked) *blocked = status.BlockedCount;
    if (hooked) *hooked = status.HookedCount;
    if (failed) *failed = status.FailedCount;
    if (inqueue) *inqueue = status.InQueueCount;
    SetLastError("OK");
    return 0;
}

GSH_API int Gsh_SetPassword(const wchar_t* oldPassword, const wchar_t* newPassword) {
    HANDLE hDriver = OpenGshDevice();
    if (hDriver == INVALID_HANDLE_VALUE) { SetLastError("Cannot open GSH device"); return 1; }
    DWORD bytes = 0;
    GSH_PASSWORD_CHANGE pwdChange;
    if (oldPassword) wcscpy_s(pwdChange.OldPassword, 64, oldPassword);
    else pwdChange.OldPassword[0] = L'\0';
    if (newPassword) wcscpy_s(pwdChange.NewPassword, 64, newPassword);
    else pwdChange.NewPassword[0] = L'\0';
    BOOL ok = DeviceIoControl(hDriver, IOCTL_GSH_SET_PASSWORD, &pwdChange, sizeof(pwdChange),
                               NULL, 0, &bytes, NULL);
    CloseHandle(hDriver);
    if (!ok) { SetLastError("Set password failed"); return 1; }
    SetLastError("OK");
    return 0;
}

/*
 * ShutdownHookBgSrv.c - 后台常驻服务
 *
 * 功能：
 *   - 隐藏窗口后台运行
 *   - 每 2 秒轮询驱动锁状态
 *   - 系统托盘图标显示当前状态（绿=解锁, 红=锁定）
 *   - 状态从 UNLOCKED -> LOCKED 时弹窗 "Shutdown blocked!"
 *   - LOCKED 状态下有关机尝试时弹窗提示
 *
 * 注意：inline hook (mov rax,1;ret) 不回调驱动，因此无法实时检测
 *       每一次被拦截的关机调用。本服务通过轮询锁状态 + 关机消息
 *       检测来实现近似实时的弹窗提示。
 */
#include <windows.h>
#include <stdio.h>
#include "../driver/gsh_common.h"

#define TRAY_ICON_ID    1
#define WM_TRAYICON     (WM_USER + 1)
#define POLL_TIMER_ID   1
#define POLL_INTERVAL   2000   /* 2 秒 */

static HINSTANCE g_hInst = NULL;
static HWND      g_hWnd = NULL;
static NOTIFYICONDATAW g_nid = {0};
static ULONG     g_lastLockState = 0xFFFFFFFF;  /* 初始为无效值，确保首次弹窗 */
static HANDLE    g_hDriver = INVALID_HANDLE_VALUE;

/* ---- 打开驱动 ---- */
static BOOL OpenGshDriver(VOID)
{
    if (g_hDriver != INVALID_HANDLE_VALUE) return TRUE;
    g_hDriver = CreateFileW(
        GSH_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return (g_hDriver != INVALID_HANDLE_VALUE);
}

/* ---- 查询锁状态 ---- */
static BOOL QueryLockState(PULONG state, PULONG passwordSet)
{
    if (!OpenGshDriver()) return FALSE;
    GSH_LOCK_STATUS status;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(g_hDriver, IOCTL_GSH_QUERY_LOCK_STATUS,
                         NULL, 0, &status, sizeof(status),
                         &bytesReturned, NULL)) {
        return FALSE;
    }
    if (state) *state = status.LockState;
    if (passwordSet) *passwordSet = status.PasswordSet;
    return TRUE;
}

/* ---- 更新托盘图标 ---- */
static void UpdateTrayIcon(ULONG lockState)
{
    g_nid.uFlags = NIF_ICON | NIF_TIP;
    if (lockState == GSH_LOCKED) {
        g_nid.hIcon = LoadIcon(NULL, IDI_ERROR);  /* 红色 = 锁定 */
        wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"GlobalShutdownHook - LOCKED (shutdown blocked)");
    } else {
        g_nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);  /* 绿色/蓝色 = 解锁 */
        wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"GlobalShutdownHook - UNLOCKED (shutdown allowed)");
    }
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

/* ---- 弹窗提示 ---- */
static void ShowBlockedPopup(VOID)
{
    MessageBoxW(NULL,
        L"A shutdown attempt was blocked by GlobalShutdownHook.\n\n"
        L"The driver is currently LOCKED. Use 'ShutdownHookClient.exe unlock' "
        L"to allow shutdown.",
        L"Shutdown blocked!",
        MB_ICONWARNING | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
}

/* ---- 窗口过程 ---- */
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        /* 创建托盘图标 */
        ZeroMemory(&g_nid, sizeof(g_nid));
        g_nid.cbSize = sizeof(NOTIFYICONDATAW);
        g_nid.hWnd = hWnd;
        g_nid.uID = TRAY_ICON_ID;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WM_TRAYICON;
        g_nid.hIcon = LoadIcon(NULL, IDI_INFORMATION);
        wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"GlobalShutdownHook");
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        /* 启动轮询定时器 */
        SetTimer(hWnd, POLL_TIMER_ID, POLL_INTERVAL, NULL);
        break;

    case WM_TIMER:
        if (wParam == POLL_TIMER_ID) {
            ULONG state = 0, pwdSet = 0;
            if (QueryLockState(&state, &pwdSet)) {
                UpdateTrayIcon(state);
                /* 状态从 UNLOCKED -> LOCKED，或首次检测到 LOCKED，弹窗 */
                if (state == GSH_LOCKED && g_lastLockState != GSH_LOCKED) {
                    ShowBlockedPopup();
                }
                g_lastLockState = state;
            }
        }
        break;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) {
            /* 双击显示状态 */
            ULONG state = 0, pwdSet = 0;
            if (QueryLockState(&state, &pwdSet)) {
                WCHAR msg[256];
                swprintf_s(msg, ARRAYSIZE(msg),
                    L"GlobalShutdownHook\n\nState: %s\nPassword: %s",
                    state == GSH_LOCKED ? L"LOCKED" : L"UNLOCKED",
                    pwdSet ? L"SET" : L"NONE");
                MessageBoxW(hWnd, msg, L"GlobalShutdownHook Status", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(hWnd, L"Driver not loaded or not accessible.",
                    L"GlobalShutdownHook", MB_OK | MB_ICONERROR);
            }
        } else if (lParam == WM_RBUTTONUP) {
            /* 右键菜单：退出 */
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, 1, L"E&xit");
            SetForegroundWindow(hWnd);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            /* 退出 */
            DestroyWindow(hWnd);
        }
        break;

    case WM_QUERYENDSESSION:
        /* 系统请求关机——如果驱动 LOCKED，说明有其他进程的关机被拦截，
           但本服务收到此消息说明关机真的开始了（驱动 UNLOCKED）。
           允许关机。 */
        return TRUE;

    case WM_DESTROY:
        KillTimer(hWnd, POLL_TIMER_ID);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hDriver);
            g_hDriver = INVALID_HANDLE_VALUE;
        }
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

/* ---- WinMain ---- */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     PWSTR pCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(pCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_hInst = hInstance;

    /* 注册窗口类 */
    WNDCLASSW wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = L"GSHBgSrvWindow";
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    if (!RegisterClassW(&wc)) {
        return 1;
    }

    /* 创建隐藏窗口 */
    g_hWnd = CreateWindowW(L"GSHBgSrvWindow", L"GlobalShutdownHook Background Service",
                            0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    if (!g_hWnd) {
        return 1;
    }

    /* 不显示窗口（后台运行） */
    ShowWindow(g_hWnd, SW_HIDE);

    /* 消息循环 */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

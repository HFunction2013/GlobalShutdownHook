/*
 * ShutdownHookBgSrv.c - 后台常驻服务 + 右上角状态 Overlay
 *
 * 功能：
 *   - 无边框半透明 overlay 窗口，始终置顶，显示在屏幕右上角
 *   - 每秒轮询驱动状态，实时刷新显示
 *   - 显示：Locked / Blocked / Hooked / Failed / Inqueue
 *   - 标题行："Just give up! you can't kill me!"
 *   - 系统托盘图标（右键退出，双击显示/隐藏 overlay）
 *   - LOCKED 状态变化时弹窗 "Shutdown blocked!"
 *
 * Overlay 窗口属性：
 *   - WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
 *   - 半透明 (alpha 210)，深色背景，等宽字体
 *   - 参考 UIAccess overlay 模式（TOPMOST 即可满足多数场景）
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "../driver/gsh_common.h"

/* ============================================================
 *  UIAccess 提权模块（参考 killtimer0/uiaccess + arcanine300/CreateWindowInBand）
 *
 *  原理：
 *    正常启用 UIAccess 需要：数字签名 + 安装在 Program Files 等受保护目录。
 *    绕过方法：从同会话的 winlogon.exe "偷"令牌（具有 SeTcbPrivilege），
 *    用 SetTokenInformation 设置 TokenUIAccess=TRUE，然后用新令牌重启自身进程。
 *    新进程获得 UIAccess 后，窗口 Z 序达到 ZBID_UIACCESS band（高于任务管理器）。
 *
 *  用法：在 wWinMain 最开始调用 PrepareForUIAccess()。
 *        成功返回 ERROR_SUCCESS（此时进程已有 UIAccess），失败返回错误码。
 * ============================================================ */

/* 从同会话的 winlogon.exe 复制令牌（具有 SeTcbPrivilege） */
static DWORD DuplicateWinlogonToken(DWORD dwSessionId, DWORD dwDesiredAccess, PHANDLE phToken)
{
    DWORD dwErr;
    PRIVILEGE_SET ps;
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    if (!LookupPrivilegeValueW(NULL, SE_TCB_NAME, &ps.Privilege[0].Luid))
        return GetLastError();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return GetLastError();

    BOOL bCont, bFound = FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    dwErr = ERROR_NOT_FOUND;

    for (bCont = Process32FirstW(hSnapshot, &pe); bCont; bCont = Process32NextW(hSnapshot, &pe)) {
        HANDLE hProcess;
        if (_wcsicmp(pe.szExeFile, L"winlogon.exe") != 0)
            continue;

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProcess)
            continue;

        HANDLE hToken;
        DWORD dwRetLen, sid;
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
            BOOL fTcb;
            if (PrivilegeCheck(hToken, &ps, &fTcb) && fTcb) {
                if (GetTokenInformation(hToken, TokenSessionId, &sid, sizeof(sid), &dwRetLen) && sid == dwSessionId) {
                    bFound = TRUE;
                    if (DuplicateTokenEx(hToken, dwDesiredAccess, NULL, SecurityImpersonation, TokenImpersonation, phToken)) {
                        dwErr = ERROR_SUCCESS;
                    } else {
                        dwErr = GetLastError();
                    }
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
        if (bFound) break;
    }
    CloseHandle(hSnapshot);
    return dwErr;
}

/* 创建带有 TokenUIAccess 的新令牌 */
static DWORD CreateUIAccessToken(PHANDLE phToken)
{
    DWORD dwSessionId, dwRetLen, dwErr;
    HANDLE hTokenSelf, hTokenSystem;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTokenSelf))
        return GetLastError();

    if (!GetTokenInformation(hTokenSelf, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwRetLen)) {
        CloseHandle(hTokenSelf);
        return GetLastError();
    }

    dwErr = DuplicateWinlogonToken(dwSessionId, TOKEN_IMPERSONATE, &hTokenSystem);
    if (ERROR_SUCCESS != dwErr) {
        CloseHandle(hTokenSelf);
        return ERROR_NOT_FOUND;
    }

    if (SetThreadToken(NULL, hTokenSystem)) {
        if (DuplicateTokenEx(hTokenSelf,
                              TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                              NULL, SecurityAnonymous, TokenPrimary, phToken)) {
            BOOL bUIAccess = TRUE;
            if (!SetTokenInformation(*phToken, TokenUIAccess, &bUIAccess, sizeof(bUIAccess))) {
                dwErr = GetLastError();
                CloseHandle(*phToken);
            }
        } else {
            dwErr = GetLastError();
        }
        RevertToSelf();
    } else {
        dwErr = GetLastError();
    }

    CloseHandle(hTokenSystem);
    CloseHandle(hTokenSelf);
    return dwErr;
}

/* 主入口：检查 UIAccess，没有则用 UIAccess 令牌重启自身 */
static DWORD PrepareForUIAccess(VOID)
{
    DWORD dwErr, dwUIAccess;
    HANDLE hTokenUIAccess, hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD dwRetLen;
        if (GetTokenInformation(hToken, TokenUIAccess, &dwUIAccess, sizeof(dwUIAccess), &dwRetLen)) {
            if (dwUIAccess) {
                /* 已经是 UIAccess 进程（重启后的新实例），直接返回成功 */
                CloseHandle(hToken);
                return ERROR_SUCCESS;
            }
        } else {
            CloseHandle(hToken);
            return GetLastError();
        }
        CloseHandle(hToken);
    } else {
        return GetLastError();
    }

    /* 当前没有 UIAccess，创建 UIAccess 令牌并重启自身 */
    dwErr = CreateUIAccessToken(&hTokenUIAccess);
    if (dwErr != ERROR_SUCCESS)
        return dwErr;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    GetStartupInfoW(&si);

    if (CreateProcessAsUserW(hTokenUIAccess, NULL, GetCommandLineW(),
                              NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hTokenUIAccess);
        /* 旧进程退出，让新的 UIAccess 进程继续运行 */
        ExitProcess(0);
    } else {
        dwErr = GetLastError();
    }

    CloseHandle(hTokenUIAccess);
    return dwErr;
}

/* ============================================================
 *  Critical 进程模块
 *
 *  原理：调用 ntdll!RtlSetProcessIsCritical(TRUE) 将自身标记为
 *  关键系统进程。关键进程被终止（包括任务管理器结束进程）会触发
 *  BSOD (CRITICAL_PROCESS_DIED)，从而实现"不允许退出"。
 *
 *  退出条件：仅当驱动被卸载（CreateFile 失败）时，BgSrv 自动调用
 *  RtlSetProcessIsCritical(FALSE) 取消关键标记，然后安全退出。
 *
 *  需要 SE_DEBUG_PRIVILEGE 权限。
 * ============================================================ */

typedef NTSTATUS (NTAPI *PFN_RtlSetProcessIsCritical)(
    IN BOOLEAN NewValue,
    OUT PBOOLEAN OldValue OPTIONAL,
    IN BOOLEAN NeedBreaks
);

static volatile BOOL g_bIsCritical = FALSE;

/* 启用调试权限（RtlSetProcessIsCritical 需要） */
static BOOL EnableDebugPrivilege(VOID)
{
    HANDLE hToken = NULL;
    LUID debugLuid = {0};
    TOKEN_PRIVILEGES tp = {0};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &debugLuid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = debugLuid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok;
}

/* 设置/取消关键进程标记 */
static BOOL SetProcessCritical(BOOL bCritical)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    PFN_RtlSetProcessIsCritical pfn = (PFN_RtlSetProcessIsCritical)
        GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    if (!pfn) return FALSE;

    NTSTATUS status = pfn(bCritical, NULL, FALSE);
    if (NT_SUCCESS(status)) {
        g_bIsCritical = bCritical;
        return TRUE;
    }
    return FALSE;
}

/* 安全退出：先取消 Critical，再退出进程 */
static void SafeExitProcess(UINT uExitCode)
{
    if (g_bIsCritical) {
        SetProcessCritical(FALSE);
    }
    ExitProcess(uExitCode);
}

/* ---- Overlay 窗口常量 ---- */
#define OVERLAY_WIDTH       310
#define OVERLAY_HEIGHT      190
#define OVERLAY_MARGIN      20
#define OVERLAY_ALPHA       210
#define TIMER_OVERLAY_ID    1
#define TIMER_INTERVAL      1000   /* 1 秒刷新 */

#define TRAY_ICON_ID        1
#define WM_TRAYICON         (WM_USER + 1)

/* ---- 全局状态 ---- */
static HINSTANCE g_hInst = NULL;
static HWND      g_hOverlayWnd = NULL;
static HWND      g_hTrayWnd = NULL;
static HFONT     g_hFont = NULL;
static HFONT     g_hTitleFont = NULL;
static HANDLE    g_hDriver = INVALID_HANDLE_VALUE;
static ULONG     g_lastLockState = 0xFFFFFFFF;
static ULONG     g_localBlockedCount = 0;  /* BgSrv 本地辅助统计 */
static BOOL      g_bDriverWasAvailable = FALSE;  /* 跟踪驱动是否之前可用 */

/* 最新驱动状态缓存 */
static GSH_LOCK_STATUS g_currentStatus = {0};

/* ============================================================
 *  驱动通信
 * ============================================================ */

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

static BOOL QueryDriverStatus(VOID)
{
    if (!OpenGshDriver()) return FALSE;
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(g_hDriver, IOCTL_GSH_QUERY_LOCK_STATUS,
                              NULL, 0, &g_currentStatus, sizeof(g_currentStatus),
                              &bytesReturned, NULL);
    if (ok) {
        /* 合并本地统计的 blocked count */
        if (g_currentStatus.BlockedCount < g_localBlockedCount) {
            g_currentStatus.BlockedCount = g_localBlockedCount;
        }
    }
    return ok;
}

/* ============================================================
 *  Overlay 窗口绘制
 * ============================================================ */

static void DrawOverlayText(HDC hdc, RECT *rcClient)
{
    /* 背景 */
    HBRUSH hBgBrush = CreateSolidBrush(RGB(15, 15, 20));
    FillRect(hdc, rcClient, hBgBrush);
    DeleteObject(hBgBrush);

    /* 边框 */
    HPEN hBorderPen = CreatePen(PS_SOLID, 1, RGB(80, 80, 100));
    HGDIOBJ oldPen = SelectObject(hdc, hBorderPen);
    HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, 0, 0, rcClient->right, rcClient->bottom);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBrush);
    DeleteObject(hBorderPen);

    int y = 8;
    int x = 14;
    WCHAR line[256];

    /* ---- 标题行：Just give up! you can't kill me! ---- */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 80, 80));  /* 红色 */
    SelectObject(hdc, g_hTitleFont);
    TextOutW(hdc, x, y, L"Just give up! you can't kill me!",
             (int)wcslen(L"Just give up! you can't kill me!"));
    y += 26;

    /* 分隔线 */
    HPEN hLinePen = CreatePen(PS_SOLID, 1, RGB(60, 60, 80));
    oldPen = SelectObject(hdc, hLinePen);
    MoveToEx(hdc, x, y, NULL);
    LineTo(hdc, rcClient->right - x, y);
    SelectObject(hdc, oldPen);
    DeleteObject(hLinePen);
    y += 10;

    /* ---- 状态行 ---- */
    SelectObject(hdc, g_hFont);

    /* Locked */
    if (g_currentStatus.LockState == GSH_LOCKED) {
        SetTextColor(hdc, RGB(255, 100, 100));  /* 红 = 锁定 */
    } else {
        SetTextColor(hdc, RGB(100, 255, 100));  /* 绿 = 解锁 */
    }
    swprintf_s(line, 256, L"Locked:  %s",
               g_currentStatus.LockState == GSH_LOCKED ? L"true" : L"false");
    TextOutW(hdc, x, y, line, (int)wcslen(line));
    y += 20;

    /* Blocked */
    SetTextColor(hdc, RGB(255, 200, 80));  /* 橙黄 */
    swprintf_s(line, 256, L"Blocked: %lu", g_currentStatus.BlockedCount);
    TextOutW(hdc, x, y, line, (int)wcslen(line));
    y += 20;

    /* Hooked */
    SetTextColor(hdc, RGB(100, 200, 255));  /* 蓝 */
    swprintf_s(line, 256, L"Hooked:  %lu", g_currentStatus.HookedCount);
    TextOutW(hdc, x, y, line, (int)wcslen(line));
    y += 20;

    /* Failed */
    SetTextColor(hdc, RGB(255, 100, 100));  /* 红 */
    swprintf_s(line, 256, L"Failed:  %lu", g_currentStatus.FailedCount);
    TextOutW(hdc, x, y, line, (int)wcslen(line));
    y += 20;

    /* Inqueue */
    SetTextColor(hdc, RGB(180, 180, 200));  /* 灰 */
    swprintf_s(line, 256, L"Inqueue: %lu", g_currentStatus.PendingCount);
    TextOutW(hdc, x, y, line, (int)wcslen(line));
}

/* ============================================================
 *  Overlay 窗口过程
 * ============================================================ */

static LRESULT CALLBACK OverlayWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        /* 创建字体 */
        g_hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        g_hTitleFont = CreateFontW(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

        /* 设置半透明 */
        SetLayeredWindowAttributes(hWnd, 0, OVERLAY_ALPHA, LWA_ALPHA);

        /* 始终置顶 */
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0,
                      SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

        /* 启动刷新定时器 */
        SetTimer(hWnd, TIMER_OVERLAY_ID, TIMER_INTERVAL, NULL);

        /* 首次查询 */
        QueryDriverStatus();
        break;
    }

    case WM_TIMER:
        if (wParam == TIMER_OVERLAY_ID) {
            ULONG oldState = g_currentStatus.LockState;
            BOOL driverOk = QueryDriverStatus();

            /* ===== 驱动被卸载检测 =====
             * 如果之前驱动可用但现在不可用，说明驱动刚被卸载（通过 quit 命令）。
             * 此时取消 Critical 标记并安全退出（这是唯一允许的退出途径）。
             */
            if (!driverOk && g_bDriverWasAvailable) {
                OutputDebugStringW(L"[GSH BgSrv] Driver unloaded, exiting safely (removing CRITICAL flag).\n");
                SafeExitProcess(0);
                return 0;  /* 不会到达 */
            }
            if (driverOk) {
                g_bDriverWasAvailable = TRUE;
            }

            /* 检测 LOCKED 状态变化：UNLOCKED -> LOCKED 时弹窗+计数 */
            if (driverOk && g_currentStatus.LockState == GSH_LOCKED && oldState != GSH_LOCKED
                && g_lastLockState != GSH_LOCKED) {
                g_localBlockedCount++;
                MessageBoxW(NULL,
                    L"A shutdown attempt was blocked by GlobalShutdownHook.\n\n"
                    L"Driver is LOCKED. Use 'ShutdownHookClient.exe unlock' to allow shutdown.",
                    L"Shutdown blocked!",
                    MB_ICONWARNING | MB_OK | MB_TOPMOST | MB_SETFOREGROUND);
            }
            g_lastLockState = g_currentStatus.LockState;

            InvalidateRect(hWnd, NULL, FALSE);
        }
        break;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);
        DrawOverlayText(hdc, &rcClient);
        EndPaint(hWnd, &ps);
        break;
    }

    /* 允许拖动窗口（左键拖动） */
    case WM_LBUTTONDOWN: {
        ReleaseCapture();
        SendMessageW(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        break;
    }

    /* 右键菜单（仅 Hide，无 Exit —— Critical 进程不允许手动退出） */
    case WM_RBUTTONUP: {
        POINT pt;
        GetCursorPos(&pt);
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, 1, L"&Hide overlay");
        AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 2, L"Exit (disabled - driver must be unloaded first)");
        SetForegroundWindow(hWnd);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            ShowWindow(hWnd, SW_HIDE);
        }
        /* wParam == 2 (Exit) 已禁用，不做任何处理 */
        break;

    case WM_DESTROY:
        KillTimer(hWnd, TIMER_OVERLAY_ID);
        if (g_hFont) DeleteObject(g_hFont);
        if (g_hTitleFont) DeleteObject(g_hTitleFont);
        if (g_hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hDriver);
            g_hDriver = INVALID_HANDLE_VALUE;
        }
        /* 窗口被销毁时也必须取消 Critical，否则进程退出会蓝屏 */
        SafeExitProcess(0);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

/* ============================================================
 *  托盘窗口过程
 * ============================================================ */

static NOTIFYICONDATAW g_nid = {0};

static LRESULT CALLBACK TrayWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        ZeroMemory(&g_nid, sizeof(g_nid));
        g_nid.cbSize = sizeof(NOTIFYICONDATAW);
        g_nid.hWnd = hWnd;
        g_nid.uID = TRAY_ICON_ID;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WM_TRAYICON;
        g_nid.hIcon = LoadIcon(NULL, IDI_SHIELD);
        wcscpy_s(g_nid.szTip, ARRAYSIZE(g_nid.szTip), L"GlobalShutdownHook");
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        break;
    }

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) {
            if (IsWindowVisible(g_hOverlayWnd)) {
                ShowWindow(g_hOverlayWnd, SW_HIDE);
            } else {
                ShowWindow(g_hOverlayWnd, SW_SHOW);
                SetWindowPos(g_hOverlayWnd, HWND_TOPMOST, 0, 0, 0, 0,
                              SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            }
        } else if (lParam == WM_RBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, 1, L"Show/&Hide overlay");
            AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 2, L"Exit (disabled - driver must be unloaded first)");
            SetForegroundWindow(hWnd);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            if (IsWindowVisible(g_hOverlayWnd)) {
                ShowWindow(g_hOverlayWnd, SW_HIDE);
            } else {
                ShowWindow(g_hOverlayWnd, SW_SHOW);
            }
        }
        /* wParam == 2 (Exit) 已禁用，不做任何处理 */
        break;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        break;

    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

/* ============================================================
 *  WinMain
 * ============================================================ */

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     PWSTR pCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(pCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    g_hInst = hInstance;

    /* ===== UIAccess 提权（必须在最开始调用） =====
     * 成功：进程获得 UIAccess，overlay 窗口 Z 序达到 ZBID_UIACCESS band
     *       （高于任务管理器、与屏幕键盘同层），无需数字签名和 Program Files。
     * 失败：回退到普通 WS_EX_TOPMOST 模式（仍可置顶，但 Z 序低于任务管理器）。
     */
    DWORD uiAccessResult = PrepareForUIAccess();
    if (uiAccessResult == ERROR_SUCCESS) {
        OutputDebugStringW(L"[GSH BgSrv] UIAccess acquired successfully.\n");
    } else {
        WCHAR dbgMsg[256];
        swprintf_s(dbgMsg, 256, L"[GSH BgSrv] UIAccess failed (0x%lX), falling back to TOPMOST.\n", uiAccessResult);
        OutputDebugStringW(dbgMsg);
    }

    /* ===== 设置自身为 Critical 进程（退出即 BSOD，实现"不允许退出"） ===== */
    if (EnableDebugPrivilege()) {
        if (SetProcessCritical(TRUE)) {
            OutputDebugStringW(L"[GSH BgSrv] Process set to CRITICAL. Termination will cause BSOD.\n");
        } else {
            OutputDebugStringW(L"[GSH BgSrv] WARNING: Failed to set process CRITICAL.\n");
        }
    } else {
        OutputDebugStringW(L"[GSH BgSrv] WARNING: Failed to enable debug privilege, cannot set CRITICAL.\n");
    }

    /* ---- 注册 Overlay 窗口类 ---- */
    WNDCLASSW wcOverlay = {0};
    wcOverlay.lpfnWndProc   = OverlayWndProc;
    wcOverlay.hInstance     = hInstance;
    wcOverlay.lpszClassName = L"GSHOverlayWindow";
    wcOverlay.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wcOverlay.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    if (!RegisterClassW(&wcOverlay)) {
        return 1;
    }

    /* ---- 注册托盘窗口类 ---- */
    WNDCLASSW wcTray = {0};
    wcTray.lpfnWndProc   = TrayWndProc;
    wcTray.hInstance     = hInstance;
    wcTray.lpszClassName = L"GSHTrayWindow";
    if (!RegisterClassW(&wcTray)) {
        return 1;
    }

    /* ---- 计算右上角位置 ---- */
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int x = screenW - OVERLAY_WIDTH - OVERLAY_MARGIN;
    int y = OVERLAY_MARGIN;

    /* ---- 创建 Overlay 窗口 ---- */
    g_hOverlayWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        L"GSHOverlayWindow",
        L"GlobalShutdownHook Status",
        WS_POPUP | WS_VISIBLE,
        x, y, OVERLAY_WIDTH, OVERLAY_HEIGHT,
        NULL, NULL, hInstance, NULL);

    if (!g_hOverlayWnd) {
        return 1;
    }

    /* ---- 创建托盘窗口（隐藏，仅用于托盘交互） ---- */
    g_hTrayWnd = CreateWindowW(L"GSHTrayWindow", L"", 0,
                                0, 0, 0, 0, NULL, NULL, hInstance, NULL);

    /* ---- 消息循环 ---- */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

/*
 * main.c - GUI 版本入口
 * 简单对话框界面，调用 Client.dll
 */
#include <windows.h>
#include <commctrl.h>
#include "../ClientLib/GshClient.h"

#pragma comment(lib, "ClientLib.lib")
#pragma comment(lib, "comctl32.lib")

#define IDC_BTN_INIT     1001
#define IDC_BTN_QUIT     1002
#define IDC_BTN_LOCK     1003
#define IDC_BTN_UNLOCK   1004
#define IDC_BTN_STATUS   1005
#define IDC_EDIT_PWD     1006
#define IDC_STATIC_STATUS 1007

static HWND hStatusWnd = NULL;
static HWND hPwdWnd = NULL;

static void UpdateStatus(void) {
    int locked, blocked, hooked, failed, inqueue;
    if (Gsh_QueryStatus(&locked, &blocked, &hooked, &failed, &inqueue) == 0) {
        wchar_t buf[512];
        wsprintfW(buf, L"Locked: %s\r\nBlocked: %d\r\nHooked: %d\r\nFailed: %d\r\nInqueue: %d",
                  locked ? L"true" : L"false", blocked, hooked, failed, inqueue);
        SetWindowTextW(hStatusWnd, buf);
    } else {
        SetWindowTextW(hStatusWnd, L"Status: unavailable");
    }
}

static INT_PTR CALLBACK DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        hStatusWnd = GetDlgItem(hWnd, IDC_STATIC_STATUS);
        hPwdWnd = GetDlgItem(hWnd, IDC_EDIT_PWD);
        UpdateStatus();
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_INIT:
            if (Gsh_Init() == 0) MessageBoxW(hWnd, L"Init OK", L"Info", MB_OK);
            else MessageBoxW(hWnd, L"Init failed", L"Error", MB_ICONERROR);
            UpdateStatus();
            break;
        case IDC_BTN_QUIT: {
            wchar_t pwd[64]; GetWindowTextW(hPwdWnd, pwd, 64);
            if (Gsh_Quit(pwd[0] ? pwd : NULL) == 0) MessageBoxW(hWnd, L"Quit OK", L"Info", MB_OK);
            else MessageBoxW(hWnd, L"Quit failed (wrong password?)", L"Error", MB_ICONERROR);
            UpdateStatus();
            break;
        }
        case IDC_BTN_LOCK:
            Gsh_Lock(); UpdateStatus();
            break;
        case IDC_BTN_UNLOCK: {
            wchar_t pwd[64]; GetWindowTextW(hPwdWnd, pwd, 64);
            if (Gsh_Unlock(pwd[0] ? pwd : NULL) == 0) MessageBoxW(hWnd, L"Unlock OK", L"Info", MB_OK);
            else MessageBoxW(hWnd, L"Unlock failed", L"Error", MB_ICONERROR);
            UpdateStatus();
            break;
        }
        case IDC_BTN_STATUS:
            UpdateStatus();
            break;
        case IDOK:
        case IDCANCEL:
            EndDialog(hWnd, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
    UNREFERENCED_PARAMETER(hPrev); UNREFERENCED_PARAMETER(cmd);
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc); icc.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icc);

    /* 简单对话框模板 */
    DLGTEMPLATE dlg;
    ZeroMemory(&dlg, sizeof(dlg));
    dlg.style = WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    dlg.cx = 280; dlg.cy = 320;

    /* 使用内存对话框模板 */
    struct {
        DLGTEMPLATE dlg;
        WCHAR menu[1];
        WCHAR cls[1];
        WCHAR title[32];
    } tmpl;
    ZeroMemory(&tmpl, sizeof(tmpl));
    tmpl.dlg.style = WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    tmpl.dlg.cx = 280; tmpl.dlg.cy = 320;
    tmpl.dlg.cdit = 0;
    wcscpy_s(tmpl.title, 32, L"GlobalShutdownHook GUI");

    /* 由于动态创建控件较复杂，这里用 CreateWindow 方式 */
    HWND hMainWnd = CreateWindowExW(0, L"STATIC", L"GlobalShutdownHook GUI",
                                      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                      300, 360, NULL, NULL, hInst, NULL);
    if (!hMainWnd) return 1;

    CreateWindowW(L"BUTTON", L"Init", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                   10, 10, 80, 30, hMainWnd, (HMENU)IDC_BTN_INIT, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Quit", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                   100, 10, 80, 30, hMainWnd, (HMENU)IDC_BTN_QUIT, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Lock", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                   10, 50, 80, 30, hMainWnd, (HMENU)IDC_BTN_LOCK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Unlock", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                   100, 50, 80, 30, hMainWnd, (HMENU)IDC_BTN_UNLOCK, hInst, NULL);
    CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                   190, 50, 80, 30, hMainWnd, (HMENU)IDC_BTN_STATUS, hInst, NULL);
    CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                   10, 95, 260, 25, hMainWnd, (HMENU)IDC_EDIT_PWD, hInst, NULL);
    hStatusWnd = CreateWindowW(L"STATIC", L"Status: loading...",
                                WS_CHILD | WS_VISIBLE, 10, 135, 260, 180,
                                hMainWnd, (HMENU)IDC_STATIC_STATUS, hInst, NULL);

    ShowWindow(hMainWnd, show);
    UpdateStatus();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (msg.message == WM_COMMAND && HIWORD(msg.wParam) == BN_CLICKED) {
            switch (LOWORD(msg.wParam)) {
            case IDC_BTN_INIT:
                if (Gsh_Init() == 0) MessageBoxW(hMainWnd, L"Init OK", L"Info", MB_OK);
                else MessageBoxW(hMainWnd, L"Init failed", L"Error", MB_ICONERROR);
                UpdateStatus(); break;
            case IDC_BTN_QUIT: {
                wchar_t pwd[64]; GetWindowTextW(hPwdWnd, pwd, 64);
                if (Gsh_Quit(pwd[0] ? pwd : NULL) == 0) MessageBoxW(hMainWnd, L"Quit OK", L"Info", MB_OK);
                else MessageBoxW(hMainWnd, L"Quit failed", L"Error", MB_ICONERROR);
                UpdateStatus(); break;
            }
            case IDC_BTN_LOCK: Gsh_Lock(); UpdateStatus(); break;
            case IDC_BTN_UNLOCK: {
                wchar_t pwd[64]; GetWindowTextW(hPwdWnd, pwd, 64);
                if (Gsh_Unlock(pwd[0] ? pwd : NULL) == 0) MessageBoxW(hMainWnd, L"Unlock OK", L"Info", MB_OK);
                else MessageBoxW(hMainWnd, L"Unlock failed", L"Error", MB_ICONERROR);
                UpdateStatus(); break;
            }
            case IDC_BTN_STATUS: UpdateStatus(); break;
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

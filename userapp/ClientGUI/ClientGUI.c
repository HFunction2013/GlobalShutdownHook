/*
 * ClientGUI.c - GlobalShutdownHook 现代化 GUI 客户端
 * 原生 Win32 自绘控件，深色主题，无第三方依赖
 * 功能与 CLI 完全对齐
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <commctrl.h>

#include "../../driver/GlobalShutdownHook/gsh_common.h"
#include "../../driver/Auxiliary/Auxiliary.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

#define COLOR_BG        RGB(30, 30, 46)
#define COLOR_SURFACE   RGB(49, 50, 68)
#define COLOR_OVERLAY   RGB(69, 71, 90)
#define COLOR_TEXT      RGB(205, 214, 244)
#define COLOR_SUBTEXT   RGB(147, 153, 178)
#define COLOR_BLUE      RGB(137, 180, 250)
#define COLOR_GREEN     RGB(166, 227, 161)
#define COLOR_RED       RGB(243, 139, 168)
#define COLOR_YELLOW    RGB(249, 226, 175)
#define COLOR_PEACH     RGB(250, 179, 135)
#define COLOR_MAUVE     RGB(203, 166, 247)
#define COLOR_TEAL      RGB(148, 226, 213)
#define COLOR_MAROON    RGB(235, 160, 172)

#define BTN_STATE_NORMAL   0
#define BTN_STATE_HOVER    1
#define BTN_STATE_PRESSED  2

typedef struct {
    WCHAR text[64]; int id; int state; COLORREF bgColor; BOOL isPrimary; int group;
} CustomButton;

#define ID_BTN_INIT          1001
#define ID_BTN_QUIT          1002
#define ID_BTN_LOCK          1003
#define ID_BTN_UNLOCK        1004
#define ID_BTN_STATUS        1005
#define ID_BTN_LIST          1006
#define ID_BTN_FAILURES      1007
#define ID_BTN_QUEUE         1008
#define ID_BTN_SETPASS       1009
#define ID_BTN_RMPASS        1010
#define ID_BTN_CLEAR         1011
#define ID_BTN_UNHOOK        1012
#define ID_BTN_TEST          1013
#define ID_BTN_TESTADVAPI    1014
#define ID_BTN_MONITOR       1015
#define ID_BTN_SHUTDOWNNOW   1016
#define ID_OUTPUT            1020
#define ID_TIMER_MONITOR     2001

static HANDLE g_hDriver=INVALID_HANDLE_VALUE, g_hAux=INVALID_HANDLE_VALUE;
static HWND g_hOutput=NULL, g_hWnd=NULL;
static HFONT g_hFont=NULL, g_hFontBold=NULL, g_hFontSmall=NULL;
static CustomButton g_buttons[16];
static int g_buttonCount=0;
static BOOL g_bMonitoring=FALSE;

static const char* FunctionIdToString(ULONG id) {
    switch(id) {
        case FUNC_EXIT_WINDOWS_EX: return "ExitWindowsEx";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_A: return "InitiateSystemShutdownExA";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_EX_W: return "InitiateSystemShutdownExW";
        case FUNC_INITIATE_SHUTDOWN_A: return "InitiateShutdownA";
        case FUNC_INITIATE_SHUTDOWN_W: return "InitiateShutdownW";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_A: return "InitiateSystemShutdownA";
        case FUNC_INITIATE_SYSTEM_SHUTDOWN_W: return "InitiateSystemShutdownW";
        default: return "Unknown";
    }
}
static const char* StateToString(ULONG state) {
    switch(state) {
        case HOOK_STATE_NONE: return "NONE";
        case HOOK_STATE_NEED_HOOK: return "PENDING";
        case HOOK_STATE_HOOKED: return "HOOKED";
        case HOOK_STATE_FAILED: return "FAILED";
        default: return "???";
    }
}

#define DLG_RESULT_CANCEL 0
#define DLG_RESULT_OK 1
typedef struct {
    HWND hDlg,hEdit1,hEdit2,hEdit3;
    WCHAR result1[256],result2[256],result3[256];
    int dialogResult,numFields; BOOL passwordMode;
} ModalDialog;

static LRESULT CALLBACK ModalDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ModalDialog* dlg=(ModalDialog*)GetWindowLongPtrW(hWnd,GWLP_USERDATA);
    switch(msg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs=(CREATESTRUCTW*)lParam;
        dlg=(ModalDialog*)cs->lpCreateParams;
        SetWindowLongPtrW(hWnd,GWLP_USERDATA,(LONG_PTR)dlg);
        dlg->hDlg=hWnd; HINSTANCE hInst=cs->hInstance;
        int y=15,editW=280,editH=26,labelH=18;
        WCHAR* labelTexts[3]={dlg->result1,dlg->result2,dlg->result3};
        HWND hEdits[3]={0};
        for(int i=0;i<dlg->numFields;i++) {
            HWND hLbl=CreateWindowW(L"STATIC",labelTexts[i],WS_CHILD|WS_VISIBLE|SS_LEFT,20,y,editW,labelH,hWnd,NULL,hInst,NULL);
            SendMessageW(hLbl,WM_SETFONT,(WPARAM)g_hFont,TRUE); y+=labelH+4;
            DWORD style=WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL;
            if(dlg->passwordMode) style|=ES_PASSWORD;
            hEdits[i]=CreateWindowW(L"EDIT",L"",style,20,y,editW,editH,hWnd,NULL,hInst,NULL);
            SendMessageW(hEdits[i],WM_SETFONT,(WPARAM)g_hFont,TRUE); y+=editH+12;
        }
        dlg->hEdit1=hEdits[0]; dlg->hEdit2=hEdits[1]; dlg->hEdit3=hEdits[2];
        int btnY=y+5;
        HWND hOk=CreateWindowW(L"BUTTON",L"OK",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,100,btnY,80,30,hWnd,(HMENU)IDOK,hInst,NULL);
        HWND hCancel=CreateWindowW(L"BUTTON",L"Cancel",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,195,btnY,80,30,hWnd,(HMENU)IDCANCEL,hInst,NULL);
        SendMessageW(hOk,WM_SETFONT,(WPARAM)g_hFontBold,TRUE);
        SendMessageW(hCancel,WM_SETFONT,(WPARAM)g_hFont,TRUE);
        if(hEdits[0]) SetFocus(hEdits[0]);
        return 0;
    }
    case WM_CTLCOLORSTATIC: case WM_CTLCOLOREDIT: {
        HDC hdc=(HDC)wParam; SetBkColor(hdc,COLOR_SURFACE); SetTextColor(hdc,COLOR_TEXT);
        return (LRESULT)CreateSolidBrush(COLOR_SURFACE);
    }
    case WM_CTLCOLORBTN: { HDC hdc=(HDC)wParam; SetBkColor(hdc,COLOR_BG); return (LRESULT)CreateSolidBrush(COLOR_BG); }
    case WM_COMMAND:
        if(LOWORD(wParam)==IDOK) {
            if(dlg->numFields>=1&&dlg->hEdit1) GetWindowTextW(dlg->hEdit1,dlg->result1,256);
            if(dlg->numFields>=2&&dlg->hEdit2) GetWindowTextW(dlg->hEdit2,dlg->result2,256);
            if(dlg->numFields>=3&&dlg->hEdit3) GetWindowTextW(dlg->hEdit3,dlg->result3,256);
            dlg->dialogResult=DLG_RESULT_OK; EnableWindow(g_hWnd,TRUE); DestroyWindow(hWnd); return 0;
        }
        if(LOWORD(wParam)==IDCANCEL) { dlg->dialogResult=DLG_RESULT_CANCEL; EnableWindow(g_hWnd,TRUE); DestroyWindow(hWnd); return 0; }
        break;
    case WM_CLOSE: dlg->dialogResult=DLG_RESULT_CANCEL; EnableWindow(g_hWnd,TRUE); DestroyWindow(hWnd); return 0;
    case WM_PAINT: { PAINTSTRUCT ps; HDC hdc=BeginPaint(hWnd,&ps); RECT rc; GetClientRect(hWnd,&rc);
        HBRUSH hBg=CreateSolidBrush(COLOR_BG); FillRect(hdc,&rc,hBg); DeleteObject(hBg); EndPaint(hWnd,&ps); return 0; }
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

static void RegisterModalDlgClass(HINSTANCE hInst) {
    WNDCLASSW wc={0}; wc.lpfnWndProc=ModalDlgProc; wc.hInstance=hInst; wc.lpszClassName=L"GSHModalDlg";
    wc.hbrBackground=CreateSolidBrush(COLOR_BG); wc.hCursor=LoadCursor(NULL,IDC_ARROW); RegisterClassW(&wc);
}

static int ShowModalDialog(HINSTANCE hInst, const WCHAR* title, const WCHAR* l1, const WCHAR* l2, const WCHAR* l3,
    int numFields, BOOL passwordMode, WCHAR* out1, WCHAR* out2, WCHAR* out3) {
    ModalDialog dlg; ZeroMemory(&dlg,sizeof(dlg));
    dlg.numFields=numFields; dlg.passwordMode=passwordMode; dlg.dialogResult=DLG_RESULT_CANCEL;
    if(l1) wcscpy_s(dlg.result1,256,l1); if(l2) wcscpy_s(dlg.result2,256,l2); if(l3) wcscpy_s(dlg.result3,256,l3);
    int dlgH=60+numFields*58+50;
    EnableWindow(g_hWnd,FALSE);
    HWND hDlg=CreateWindowW(L"GSHModalDlg",title,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,CW_USEDEFAULT,CW_USEDEFAULT,340,dlgH,g_hWnd,NULL,hInst,&dlg);
    MSG msg;
    while(IsWindow(hDlg)&&GetMessageW(&msg,NULL,0,0)) { if(!IsDialogMessageW(hDlg,&msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
    if(dlg.dialogResult==DLG_RESULT_OK) {
        if(out1&&numFields>=1) wcscpy_s(out1,256,dlg.result1);
        if(out2&&numFields>=2) wcscpy_s(out2,256,dlg.result2);
        if(out3&&numFields>=3) wcscpy_s(out3,256,dlg.result3);
    }
    return dlg.dialogResult;
}

static BOOL ShowConfirmDialog(HINSTANCE hInst, const WCHAR* title, const WCHAR* message) {
    return IDYES==MessageBoxW(g_hWnd,message,title,MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2);
}

static void LogOutput(const WCHAR* fmt, ...) {
    if(!g_hOutput) return;
    WCHAR buf[2048]; va_list args; va_start(args,fmt); vswprintf_s(buf,_countof(buf),fmt,args); va_end(args);
    int len=GetWindowTextLengthW(g_hOutput);
    SendMessageW(g_hOutput,EM_SETSEL,len,len);
    SendMessageW(g_hOutput,EM_REPLACESEL,FALSE,(LPARAM)buf);
    SendMessageW(g_hOutput,EM_SCROLLCARET,0,0);
}

static void DrawRoundRect(HDC hdc, int x, int y, int w, int h, int radius, COLORREF bg, COLORREF border) {
    HBRUSH hBrush=CreateSolidBrush(bg); HPEN hPen=CreatePen(PS_SOLID,1,border);
    HBRUSH hOld=(HBRUSH)SelectObject(hdc,hBrush); HPEN hOldPen=(HPEN)SelectObject(hdc,hPen);
    POINT pts[8]={{x+radius,y},{x+w-radius,y},{x+w,y+radius},{x+w,y+h-radius},{x+w-radius,y+h},{x+radius,y+h},{x,y+h-radius},{x,y+radius}};
    Polyline(hdc,pts,8); RECT rc={x+1,y+1,x+w-1,y+h-1}; FillRect(hdc,&rc,hBrush); Polyline(hdc,pts,8);
    SelectObject(hdc,hOld); SelectObject(hdc,hOldPen); DeleteObject(hBrush); DeleteObject(hPen);
}
static void DrawCustomButton(HDC hdc, CustomButton* btn, RECT* rc) {
    COLORREF bg,text,border; int offsetY=0;
    if(btn->state==BTN_STATE_PRESSED) { bg=btn->isPrimary?RGB(100,140,210):RGB(60,62,82); text=COLOR_TEXT; border=btn->bgColor; offsetY=1; }
    else if(btn->state==BTN_STATE_HOVER) { bg=btn->isPrimary?RGB(150,190,255):RGB(70,72,95); text=COLOR_TEXT; border=btn->bgColor; }
    else { bg=btn->bgColor; text=COLOR_TEXT; border=COLOR_OVERLAY; }
    int w=rc->right-rc->left,h=rc->bottom-rc->top;
    DrawRoundRect(hdc,rc->left,rc->top+offsetY,w,h-offsetY,6,bg,border);
    SetBkMode(hdc,TRANSPARENT); SetTextColor(hdc,text);
    HFONT hOld=(HFONT)SelectObject(hdc,btn->isPrimary?g_hFontBold:g_hFont);
    RECT trc=*rc; trc.top+=offsetY;
    DrawTextW(hdc,btn->text,-1,&trc,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    SelectObject(hdc,hOld);
}

static BOOL OpenDrivers(void) {
    if(g_hDriver==INVALID_HANDLE_VALUE) g_hDriver=CreateFileW(GSH_WIN32_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_hAux==INVALID_HANDLE_VALUE) g_hAux=CreateFileW(AUX_WIN32_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    return (g_hDriver!=INVALID_HANDLE_VALUE);
}
static void CloseDrivers(void) {
    if(g_hDriver!=INVALID_HANDLE_VALUE) { CloseHandle(g_hDriver); g_hDriver=INVALID_HANDLE_VALUE; }
    if(g_hAux!=INVALID_HANDLE_VALUE) { CloseHandle(g_hAux); g_hAux=INVALID_HANDLE_VALUE; }
}
static BOOL DoIoctl(HANDLE h, DWORD code, PVOID in, DWORD inLen, PVOID out, DWORD outLen) {
    if(h==INVALID_HANDLE_VALUE) return FALSE; DWORD bytes=0; return DeviceIoControl(h,code,in,inLen,out,outLen,&bytes,NULL);
}
static BOOL IsPasswordSet(void) {
    GSH_LOCK_STATUS st;
    if(OpenDrivers()&&DoIoctl(g_hDriver,IOCTL_GSH_QUERY_LOCK_STATUS,NULL,0,&st,sizeof(st))) return st.PasswordSet?TRUE:FALSE;
    return FALSE;
}
static BOOL UnlockWithPassword(HINSTANCE hInst) {
    if(!IsPasswordSet()) { WCHAR empty[1]={0}; return DoIoctl(g_hDriver,IOCTL_GSH_UNLOCK,empty,sizeof(WCHAR),NULL,0); }
    WCHAR password[256]={0};
    if(DLG_RESULT_OK!=ShowModalDialog(hInst,L"Enter Password",L"Password:",NULL,NULL,1,TRUE,password,NULL,NULL)) return FALSE;
    return DoIoctl(g_hDriver,IOCTL_GSH_UNLOCK,(PVOID)password,(DWORD)((wcslen(password)+1)*sizeof(WCHAR)),NULL,0);
}

static void CmdStatus(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    GSH_LOCK_STATUS s;
    if(DoIoctl(g_hDriver,IOCTL_GSH_QUERY_LOCK_STATUS,NULL,0,&s,sizeof(s))) {
        LogOutput(L"=== GlobalShutdownHook Status ===\n");
        LogOutput(L"  Lock state  : %s\n", s.LockState==GSH_LOCKED?L"LOCKED":L"UNLOCKED");
        LogOutput(L"  Password    : %s\n", s.PasswordSet?L"SET":L"NONE");
        LogOutput(L"  Hooked (OK) : %lu\n", s.HookedCount);
        LogOutput(L"  Failed      : %lu\n", s.FailedCount);
        LogOutput(L"  Pending     : %lu\n", s.PendingCount);
        LogOutput(L"==================================\n");
    } else LogOutput(L"[ERROR] QUERY_LOCK_STATUS failed: %lu\n", GetLastError());
}
static void CmdLock(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(DoIoctl(g_hDriver,IOCTL_GSH_LOCK,NULL,0,NULL,0)) LogOutput(L"[OK] System LOCKED.\n");
    else LogOutput(L"[ERROR] Lock failed: %lu\n", GetLastError());
}
static void CmdUnlock(HINSTANCE hInst) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(UnlockWithPassword(hInst)) LogOutput(L"[OK] System UNLOCKED.\n");
    else LogOutput(L"[ERROR] Unlock failed (wrong password or cancelled).\n");
}
static void CmdUnhook(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(DoIoctl(g_hDriver,IOCTL_GSH_UNHOOK_ALL,NULL,0,NULL,0)) LogOutput(L"[OK] All hooks removed.\n");
    else LogOutput(L"[ERROR] Unhook failed: %lu\n", GetLastError());
}
static void CmdList(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    BYTE buf[8192];
    if(DoIoctl(g_hDriver,IOCTL_GSH_GET_HOOKED_LIST,NULL,0,buf,sizeof(buf))) {
        GSH_HOOKED_LIST_OUTPUT* out=(GSH_HOOKED_LIST_OUTPUT*)buf;
        LogOutput(L"=== Hooked Functions (%lu) ===\n", out->Count);
        for(ULONG i=0;i<out->Count&&i<64;i++)
            LogOutput(L"  [%lu] %-28hs PID=%-6lu %s\n", i, FunctionIdToString(out->Entries[i].FunctionId), out->Entries[i].Pid, StateToString(out->Entries[i].State));
    } else LogOutput(L"[ERROR] Get list failed: %lu\n", GetLastError());
}
static void CmdFailures(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    BYTE buf[8192];
    if(DoIoctl(g_hDriver,IOCTL_GSH_GET_FAIL_LOG,NULL,0,buf,sizeof(buf))) {
        GSH_FAIL_LOG_OUTPUT* out=(GSH_FAIL_LOG_OUTPUT*)buf;
        LogOutput(L"=== Failures (%lu) ===\n", out->Count);
        for(ULONG i=0;i<out->Count&&i<32;i++)
            LogOutput(L"  [%lu] %-28hs PID=%lu %S\n", i, FunctionIdToString(out->Records[i].FunctionId), out->Records[i].Pid, out->Records[i].ModuleName);
    } else LogOutput(L"[ERROR] Get failures failed: %lu\n", GetLastError());
}
static void CmdClearFailures(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(DoIoctl(g_hDriver,IOCTL_GSH_CLEAR_FAIL_LOG,NULL,0,NULL,0)) LogOutput(L"[OK] Failure log cleared.\n");
    else LogOutput(L"[ERROR] Clear failed: %lu\n", GetLastError());
}
static void CmdQueue(void) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    BYTE buf[8192];
    if(DoIoctl(g_hDriver,IOCTL_GSH_GET_QUEUE,NULL,0,buf,sizeof(buf))) {
        GSH_QUEUE_OUTPUT* out=(GSH_QUEUE_OUTPUT*)buf;
        LogOutput(L"=== Pending Queue (%lu) ===\n", out->Count);
        for(ULONG i=0;i<out->Count&&i<32;i++)
            LogOutput(L"  [%lu] %-28hs PID=%lu %S\n", i, FunctionIdToString(out->Entries[i].FunctionId), out->Entries[i].Pid, out->Entries[i].ModuleName);
    } else LogOutput(L"[ERROR] Get queue failed: %lu\n", GetLastError());
}

static void CmdTestExitWindows(void) {
    LogOutput(L"Testing ExitWindowsEx(EWX_LOGOFF, 0)...\n");
    LogOutput(L"If hook is active, this call will return TRUE but NOT log off.\n");
    BOOL result=ExitWindowsEx(EWX_LOGOFF,0); DWORD err=GetLastError();
    LogOutput(L"ExitWindowsEx returned: %s (error=%lu)\n", result?L"TRUE":L"FALSE", err);
    if(result) LogOutput(L"  -> Hook is ACTIVE (shutdown blocked).\n");
    else LogOutput(L"  -> Hook may NOT be active.\n");
}

typedef BOOL (WINAPI *PFN_InitiateSystemShutdownExW)(LPWSTR,LPWSTR,DWORD,BOOL,BOOL,DWORD);
static void CmdTestAdvapi(void) {
    HMODULE hAdvapi=LoadLibraryW(L"advapi32.dll");
    if(!hAdvapi) { LogOutput(L"[ERROR] Cannot load advapi32.dll: %lu\n", GetLastError()); return; }
    PFN_InitiateSystemShutdownExW pfn=(PFN_InitiateSystemShutdownExW)GetProcAddress(hAdvapi,"InitiateSystemShutdownExW");
    if(!pfn) { LogOutput(L"[ERROR] Cannot find InitiateSystemShutdownExW: %lu\n", GetLastError()); FreeLibrary(hAdvapi); return; }
    LogOutput(L"Testing InitiateSystemShutdownExW(NULL, L\"test\", 0, FALSE, FALSE, 0)...\n");
    BOOL result=pfn(NULL,L"GSH test",0,FALSE,FALSE,0); DWORD err=GetLastError();
    LogOutput(L"InitiateSystemShutdownExW returned: %s (error=%lu)\n", result?L"TRUE":L"FALSE", err);
    if(result) LogOutput(L"  -> Hook is ACTIVE.\n");
    else { LogOutput(L"  -> Hook may NOT be active (error %lu).\n", err); if(err==ERROR_ACCESS_DENIED) LogOutput(L"  -> Note: ACCESS_DENIED is normal if not running as admin.\n"); }
    FreeLibrary(hAdvapi);
}

static void MonitorTick(void) {
    if(!OpenDrivers()) return;
    GSH_DRIVER_STATUS status;
    if(DoIoctl(g_hDriver,IOCTL_GSH_GET_STATUS,NULL,0,&status,sizeof(status))) {
        int len=GetWindowTextLengthW(g_hOutput);
        SendMessageW(g_hOutput,EM_SETSEL,len,len);
        WCHAR buf[256];
        swprintf_s(buf,_countof(buf),L"\r  Hooked=%lu  Failed=%lu  Pending=%lu  FailLog=%lu  (seen=%lu)          ",
            status.HookedCount,status.FailedCount,status.PendingCount,status.FailLogCount,status.TotalProcessesSeen);
        SendMessageW(g_hOutput,EM_REPLACESEL,FALSE,(LPARAM)buf);
        SendMessageW(g_hOutput,EM_SCROLLCARET,0,0);
    }
}
static void CmdMonitorToggle(void) {
    if(g_bMonitoring) { KillTimer(g_hWnd,ID_TIMER_MONITOR); g_bMonitoring=FALSE; LogOutput(L"\n[Monitor stopped]\n"); }
    else {
        if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
        g_bMonitoring=TRUE;
        LogOutput(L"Monitoring (refresh every 2s). Click Monitor again to stop.\n\n");
        SetTimer(g_hWnd,ID_TIMER_MONITOR,2000,NULL); MonitorTick();
    }
}

static void CmdShutdownNow(HINSTANCE hInst) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(!ShowConfirmDialog(hInst,L"WARNING",L"This will force a system shutdown IMMEDIATELY.\n\nContinue?")) return;
    WCHAR password[256]={0};
    if(IsPasswordSet()) {
        if(DLG_RESULT_OK!=ShowModalDialog(hInst,L"Shutdown Now",L"Enter password to confirm:",NULL,NULL,1,TRUE,password,NULL,NULL)) return;
    }
    if(DoIoctl(g_hDriver,IOCTL_GSH_SHUTDOWN_NOW,(PVOID)password,(DWORD)((wcslen(password)+1)*sizeof(WCHAR)),NULL,0))
        LogOutput(L"Shutdown initiated...\n");
    else { DWORD err=GetLastError(); if(err==ERROR_ACCESS_DENIED) LogOutput(L"[ERROR] SHUTDOWN_NOW failed: driver locked or wrong password.\n"); else LogOutput(L"[ERROR] SHUTDOWN_NOW failed: %lu\n", err); }
}

extern int GdrvLoadDriver(const WCHAR* driverPath);
extern int GdrvUnloadDriver(const WCHAR* driverPath);

static void CmdInit(HINSTANCE hInst) {
    WCHAR driverPath[MAX_PATH];
    DWORD len=GetModuleFileNameW(NULL,driverPath,MAX_PATH);
    if(len==0||len>=MAX_PATH) { LogOutput(L"[ERROR] Cannot get module path.\n"); return; }
    WCHAR* slash=wcsrchr(driverPath,L'\\');
    if(slash) { *(slash+1)=L'\0'; wcscat_s(driverPath,MAX_PATH,L"GlobalShutdownHook.sys"); }
    LogOutput(L"[*] GlobalShutdownHook init\n");
    LogOutput(L"    Loading unsigned driver via GDRVLoader...\n");
    int rc=GdrvLoadDriver(driverPath);
    if(rc!=0) { LogOutput(L"[ERROR] GdrvLoadDriver failed (code=%d).\n", rc); return; }
    LogOutput(L"[OK] Driver loaded successfully.\n");
    Sleep(1500);
    WCHAR bgPath[MAX_PATH]; wcscpy_s(bgPath,MAX_PATH,driverPath);
    slash=wcsrchr(bgPath,L'\\');
    if(slash) { *(slash+1)=L'\0'; wcscat_s(bgPath,MAX_PATH,L"ShutdownHookBgSrv.exe"); }
    STARTUPINFOW si; ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof(pi));
    DWORD bgSrvPid=0;
    if(CreateProcessW(bgPath,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) {
        bgSrvPid=pi.dwProcessId;
        LogOutput(L"[OK] Background service started (PID=%lu).\n", pi.dwProcessId);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    } else LogOutput(L"[WARN] Could not start background service: %lu\n", GetLastError());
    WCHAR auxPath[MAX_PATH]; wcscpy_s(auxPath,MAX_PATH,driverPath);
    slash=wcsrchr(auxPath,L'\\');
    if(slash) { *(slash+1)=L'\0'; wcscat_s(auxPath,MAX_PATH,L"Auxiliary.sys"); }
    int auxRc=GdrvLoadDriver(auxPath);
    if(auxRc!=0) LogOutput(L"[WARN] GdrvLoadDriver(Auxiliary) failed (code=%d).\n", auxRc);
    else {
        LogOutput(L"[OK] Auxiliary.sys loaded.\n");
        Sleep(1000);
        HANDLE hAux=CreateFileW(AUX_WIN32_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hAux!=INVALID_HANDLE_VALUE) {
            DWORD bytes=0; HANDLE pidHandle=(HANDLE)(ULONG_PTR)bgSrvPid;
            DeviceIoControl(hAux,IOCTL_AUX_SET_BGSRV_PID,&pidHandle,sizeof(pidHandle),NULL,0,&bytes,NULL);
            LogOutput(L"[OK] BgSrv PID registered with Auxiliary.\n");
            AUX_PROTECTION_INPUT prot; ZeroMemory(&prot,sizeof(prot)); prot.Pid=pidHandle; prot.ProtectionLevel=PROTECTION_LEVEL_WINTCB;
            if(DeviceIoControl(hAux,IOCTL_AUX_SET_PROTECTION,&prot,sizeof(prot),NULL,0,&bytes,NULL)) LogOutput(L"[OK] BgSrv set to WinTCB protected (PPL).\n");
            else LogOutput(L"[WARN] Set WinTCB protection failed: %lu\n", GetLastError());
            AUX_HIDE_INPUT hide; ZeroMemory(&hide,sizeof(hide)); hide.Pid=pidHandle;
            if(DeviceIoControl(hAux,IOCTL_AUX_HIDE_PROCESS,&hide,sizeof(hide),NULL,0,&bytes,NULL)) LogOutput(L"[OK] BgSrv hidden via DKOM.\n");
            else LogOutput(L"[WARN] DKOM hide failed: %lu\n", GetLastError());
            CloseHandle(hAux);
        } else LogOutput(L"[WARN] Cannot open Auxiliary device: %lu\n", GetLastError());
    }
    LogOutput(L"\n[OK] GlobalShutdownHook initialized.\n\n");
}

static void CmdQuit(HINSTANCE hInst) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(!ShowConfirmDialog(hInst,L"Confirm Quit",L"This will unlock, unhook, stop BgSrv, and unload ALL drivers.\n\nContinue?")) return;
    if(!UnlockWithPassword(hInst)) { LogOutput(L"[ERROR] Unlock failed. Cannot quit.\n"); return; }
    LogOutput(L"[1/6] Password verified. Driver UNLOCKED.\n");
    DoIoctl(g_hDriver,IOCTL_GSH_UNHOOK_ALL,NULL,0,NULL,0);
    LogOutput(L"[2/6] All hooks removed.\n");
    {
        HANDLE hGsh=CreateFileW(GSH_WIN32_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hGsh!=INVALID_HANDLE_VALUE) { DWORD bytes=0; DeviceIoControl(hGsh,IOCTL_GSH_REQUEST_EXIT,NULL,0,NULL,0,&bytes,NULL); CloseHandle(hGsh); LogOutput(L"[3/6] Exit request sent to BgSrv.\n"); }
        for(int i=0;i<25;i++) {
            Sleep(200); HANDLE hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
            if(hSnap==INVALID_HANDLE_VALUE) break;
            PROCESSENTRY32W pe; pe.dwSize=sizeof(pe); BOOL found=FALSE;
            if(Process32FirstW(hSnap,&pe)) { do { if(_wcsicmp(pe.szExeFile,L"ShutdownHookBgSrv.exe")==0) { found=TRUE; break; } } while(Process32NextW(hSnap,&pe)); }
            CloseHandle(hSnap);
            if(!found) { LogOutput(L"[OK] BgSrv exited.\n"); break; }
        }
    }
    HANDLE hAux=CreateFileW(AUX_WIN32_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hAux!=INVALID_HANDLE_VALUE) { DWORD bytes=0; DeviceIoControl(hAux,IOCTL_AUX_SET_QUITTING,NULL,0,NULL,0,&bytes,NULL); LogOutput(L"[4/6] Auxiliary QUITTING state set.\n"); CloseHandle(hAux); }
    WCHAR driverPath[MAX_PATH]; GetModuleFileNameW(NULL,driverPath,MAX_PATH);
    WCHAR* slash=wcsrchr(driverPath,L'\\');
    if(slash) { *(slash+1)=L'\0'; wcscat_s(driverPath,MAX_PATH,L"GlobalShutdownHook.sys"); }
    CloseDrivers();
    LogOutput(L"[5/6] Unloading GSH driver...\n");
    int rc=GdrvUnloadDriver(driverPath);
    if(rc!=0) LogOutput(L"[WARN] GdrvUnloadDriver(GSH) returned %d\n", rc);
    else LogOutput(L"[OK] GSH driver unloaded.\n");
    Sleep(1500);
    LogOutput(L"[6/6] Unloading Auxiliary driver...\n");
    WCHAR auxPath[MAX_PATH]; wcscpy_s(auxPath,MAX_PATH,driverPath);
    slash=wcsrchr(auxPath,L'\\');
    if(slash) { *(slash+1)=L'\0'; wcscat_s(auxPath,MAX_PATH,L"Auxiliary.sys"); }
    int auxRc=GdrvUnloadDriver(auxPath);
    if(auxRc!=0) LogOutput(L"[WARN] GdrvUnloadDriver(Aux) returned %d\n", auxRc);
    else LogOutput(L"[OK] Auxiliary driver unloaded.\n");
    LogOutput(L"\n[DONE] GlobalShutdownHook shutdown complete.\n\n");
}

static void CmdSetPassword(HINSTANCE hInst) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    WCHAR oldPwd[256]={0},newPwd[256]={0},confirmPwd[256]={0};
    BOOL hasOld=IsPasswordSet();
    if(hasOld) {
        if(DLG_RESULT_OK!=ShowModalDialog(hInst,L"Set Password",L"Old Password:",L"New Password:",L"Confirm New Password:",3,TRUE,oldPwd,newPwd,confirmPwd)) return;
        if(wcscmp(newPwd,confirmPwd)!=0) { LogOutput(L"[ERROR] New password and confirmation do not match.\n"); return; }
    } else {
        if(DLG_RESULT_OK!=ShowModalDialog(hInst,L"Set Password",L"New Password:",L"Confirm New Password:",NULL,2,TRUE,newPwd,confirmPwd,NULL)) return;
        if(wcscmp(newPwd,confirmPwd)!=0) { LogOutput(L"[ERROR] New password and confirmation do not match.\n"); return; }
    }
    GSH_PASSWORD_INPUT pwd; ZeroMemory(&pwd,sizeof(pwd));
    wcscpy_s(pwd.OldPassword,_countof(pwd.OldPassword),oldPwd);
    wcscpy_s(pwd.NewPassword,_countof(pwd.NewPassword),newPwd);
    if(DoIoctl(g_hDriver,IOCTL_GSH_SET_PASS,&pwd,sizeof(pwd),NULL,0)) LogOutput(L"[OK] Password set successfully.\n");
    else LogOutput(L"[ERROR] Set password failed: %lu (wrong old password?)\n", GetLastError());
}

static void CmdRemovePassword(HINSTANCE hInst) {
    if(!OpenDrivers()) { LogOutput(L"[ERROR] Driver not loaded.\n"); return; }
    if(!ShowConfirmDialog(hInst,L"Remove Password",L"Are you sure you want to remove the password?\n\nAnyone will be able to unlock/quit.")) return;
    WCHAR password[256]={0};
    if(IsPasswordSet()) { if(DLG_RESULT_OK!=ShowModalDialog(hInst,L"Remove Password",L"Current Password:",NULL,NULL,1,TRUE,password,NULL,NULL)) return; }
    if(DoIoctl(g_hDriver,IOCTL_GSH_RM_PASS,(PVOID)password,(DWORD)((wcslen(password)+1)*sizeof(WCHAR)),NULL,0)) LogOutput(L"[OK] Password removed.\n");
    else LogOutput(L"[ERROR] Remove password failed: %lu\n", GetLastError());
}

static void AddButton(int id, const WCHAR* text, COLORREF bg, BOOL primary, int group) {
    CustomButton* btn=&g_buttons[g_buttonCount++]; ZeroMemory(btn,sizeof(*btn));
    btn->id=id; wcscpy_s(btn->text,_countof(btn->text),text); btn->bgColor=bg; btn->state=BTN_STATE_NORMAL; btn->isPrimary=primary; btn->group=group;
}
static void InitButtons(void) {
    g_buttonCount=0;
    AddButton(ID_BTN_INIT,L"Init",COLOR_BLUE,TRUE,0);
    AddButton(ID_BTN_QUIT,L"Quit",COLOR_RED,TRUE,0);
    AddButton(ID_BTN_LOCK,L"Lock",COLOR_MAUVE,FALSE,0);
    AddButton(ID_BTN_UNLOCK,L"Unlock",COLOR_TEAL,FALSE,0);
    AddButton(ID_BTN_STATUS,L"Status",COLOR_SURFACE,FALSE,1);
    AddButton(ID_BTN_LIST,L"List",COLOR_SURFACE,FALSE,1);
    AddButton(ID_BTN_FAILURES,L"Failures",COLOR_SURFACE,FALSE,1);
    AddButton(ID_BTN_QUEUE,L"Queue",COLOR_SURFACE,FALSE,1);
    AddButton(ID_BTN_SETPASS,L"Set Password",COLOR_PEACH,FALSE,2);
    AddButton(ID_BTN_RMPASS,L"Remove Password",COLOR_PEACH,FALSE,2);
    AddButton(ID_BTN_CLEAR,L"Clear Log",COLOR_SURFACE,FALSE,2);
    AddButton(ID_BTN_UNHOOK,L"Unhook All",COLOR_YELLOW,FALSE,2);
    AddButton(ID_BTN_TEST,L"Test",COLOR_GREEN,FALSE,3);
    AddButton(ID_BTN_TESTADVAPI,L"Test Advapi",COLOR_GREEN,FALSE,3);
    AddButton(ID_BTN_MONITOR,L"Monitor",COLOR_MAROON,FALSE,3);
    AddButton(ID_BTN_SHUTDOWNNOW,L"Shutdown Now",COLOR_RED,FALSE,3);
}
static void HandleButtonClick(int id, HINSTANCE hInst) {
    switch(id) {
    case ID_BTN_INIT: CmdInit(hInst); break;
    case ID_BTN_QUIT: CmdQuit(hInst); break;
    case ID_BTN_LOCK: CmdLock(); break;
    case ID_BTN_UNLOCK: CmdUnlock(hInst); break;
    case ID_BTN_STATUS: CmdStatus(); break;
    case ID_BTN_LIST: CmdList(); break;
    case ID_BTN_FAILURES: CmdFailures(); break;
    case ID_BTN_QUEUE: CmdQueue(); break;
    case ID_BTN_SETPASS: CmdSetPassword(hInst); break;
    case ID_BTN_RMPASS: CmdRemovePassword(hInst); break;
    case ID_BTN_CLEAR: CmdClearFailures(); break;
    case ID_BTN_UNHOOK: CmdUnhook(); break;
    case ID_BTN_TEST: CmdTestExitWindows(); break;
    case ID_BTN_TESTADVAPI: CmdTestAdvapi(); break;
    case ID_BTN_MONITOR: CmdMonitorToggle(); break;
    case ID_BTN_SHUTDOWNNOW: CmdShutdownNow(hInst); break;
    }
}
static void GetButtonRect(int index, RECT* rc) {
    int btnW=100,btnH=28,gap=6,startX=100,startY=5;
    int groupStartIdx[4]={0,4,8,12};
    int group=g_buttons[index].group;
    int idxInGroup=index-groupStartIdx[group];
    rc->left=startX+idxInGroup*(btnW+gap);
    rc->top=startY+group*(btnH+gap+16);
    rc->right=rc->left+btnW;
    rc->bottom=rc->top+btnH;
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HINSTANCE s_hInst=NULL;
    switch(msg) {
    case WM_CREATE: {
        g_hWnd=hWnd; s_hInst=((LPCREATESTRUCTW)lParam)->hInstance; RegisterModalDlgClass(s_hInst);
        g_hFont=CreateFontW(14,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_hFontBold=CreateFontW(14,0,0,0,FW_BOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_hFontSmall=CreateFontW(12,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        g_hOutput=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY,0,0,0,0,hWnd,(HMENU)ID_OUTPUT,s_hInst,NULL);
        SendMessageW(g_hOutput,WM_SETFONT,(WPARAM)g_hFont,TRUE);
        InitButtons();
        LogOutput(L"GlobalShutdownHook GUI Control Panel\n");
        LogOutput(L"==================================\n");
        LogOutput(L"Click 'Init' to load drivers and start BgSrv.\n\n");
        return 0;
    }
    case WM_TIMER: if(wParam==ID_TIMER_MONITOR) { MonitorTick(); return 0; } break;
    case WM_SIZE: { int w=LOWORD(lParam),h=HIWORD(lParam); int btnAreaH=185; SetWindowPos(g_hOutput,NULL,15,btnAreaH,w-30,h-btnAreaH-10,SWP_NOZORDER); InvalidateRect(hWnd,NULL,TRUE); return 0; }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc=BeginPaint(hWnd,&ps); RECT rc; GetClientRect(hWnd,&rc);
        HBRUSH hBg=CreateSolidBrush(COLOR_BG); FillRect(hdc,&rc,hBg); DeleteObject(hBg);
        SetBkMode(hdc,TRANSPARENT); SetTextColor(hdc,COLOR_SUBTEXT);
        HFONT hOld=(HFONT)SelectObject(hdc,g_hFontSmall);
        const WCHAR* groups[4]={L"CONTROL",L"QUERY",L"MANAGE",L"TEST"};
        for(int g=0;g<4;g++) { RECT br; GetButtonRect(g*4,&br); TextOutW(hdc,15,br.top-14,groups[g],(int)wcslen(groups[g])); }
        RECT outRc; GetWindowRect(g_hOutput,&outRc); ScreenToClient(hWnd,(LPPOINT)&outRc);
        TextOutW(hdc,15,outRc.top-16,L"OUTPUT",6);
        SelectObject(hdc,hOld);
        for(int i=0;i<g_buttonCount;i++) { RECT br; GetButtonRect(i,&br); DrawCustomButton(hdc,&g_buttons[i],&br); }
        EndPaint(hWnd,&ps); return 0;
    }
    case WM_LBUTTONDOWN: { int x=LOWORD(lParam),y=HIWORD(lParam);
        for(int i=0;i<g_buttonCount;i++) { RECT rc; GetButtonRect(i,&rc);
            if(x>=rc.left&&x<=rc.right&&y>=rc.top&&y<=rc.bottom) { g_buttons[i].state=BTN_STATE_PRESSED; InvalidateRect(hWnd,NULL,FALSE); SetCapture(hWnd); return 0; } }
        return 0; }
    case WM_LBUTTONUP: { ReleaseCapture(); int x=LOWORD(lParam),y=HIWORD(lParam);
        for(int i=0;i<g_buttonCount;i++) { g_buttons[i].state=BTN_STATE_NORMAL; RECT rc; GetButtonRect(i,&rc);
            if(x>=rc.left&&x<=rc.right&&y>=rc.top&&y<=rc.bottom) HandleButtonClick(g_buttons[i].id,s_hInst); }
        InvalidateRect(hWnd,NULL,FALSE); return 0; }
    case WM_MOUSEMOVE: { if(wParam&MK_LBUTTON) { int x=LOWORD(lParam),y=HIWORD(lParam);
        for(int i=0;i<g_buttonCount;i++) { RECT rc; GetButtonRect(i,&rc);
            BOOL inside=(x>=rc.left&&x<=rc.right&&y>=rc.top&&y<=rc.bottom);
            if(inside&&g_buttons[i].state!=BTN_STATE_PRESSED) g_buttons[i].state=BTN_STATE_PRESSED;
            else if(!inside&&g_buttons[i].state==BTN_STATE_PRESSED) g_buttons[i].state=BTN_STATE_NORMAL; }
        InvalidateRect(hWnd,NULL,FALSE); } return 0; }
    case WM_CTLCOLOREDIT: case WM_CTLCOLORSTATIC: { HDC hdc=(HDC)wParam; SetBkColor(hdc,COLOR_SURFACE); SetTextColor(hdc,COLOR_TEXT); return (LRESULT)CreateSolidBrush(COLOR_SURFACE); }
    case WM_DESTROY: if(g_bMonitoring) KillTimer(hWnd,ID_TIMER_MONITOR); CloseDrivers();
        if(g_hFont)DeleteObject(g_hFont); if(g_hFontBold)DeleteObject(g_hFontBold); if(g_hFontSmall)DeleteObject(g_hFontSmall);
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show) {
    UNREFERENCED_PARAMETER(hPrev); UNREFERENCED_PARAMETER(cmd);
    INITCOMMONCONTROLSEX icc; icc.dwSize=sizeof(icc); icc.dwICC=ICC_WIN95_CLASSES; InitCommonControlsEx(&icc);
    WNDCLASSW wc={0}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.lpszClassName=L"GSHGUI";
    wc.hbrBackground=CreateSolidBrush(COLOR_BG); wc.hCursor=LoadCursor(NULL,IDC_ARROW); RegisterClassW(&wc);
    HWND hWnd=CreateWindowExW(0,L"GSHGUI",L"GlobalShutdownHook Control Panel",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,CW_USEDEFAULT,CW_USEDEFAULT,660,560,NULL,NULL,hInst,NULL);
    ShowWindow(hWnd,show); UpdateWindow(hWnd);
    MSG msg; while(GetMessageW(&msg,NULL,0,0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return (int)msg.wParam;
}

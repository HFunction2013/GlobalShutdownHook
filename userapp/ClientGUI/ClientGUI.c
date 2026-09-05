/*
 * ClientGUI.c - GlobalShutdownHook GUI 客户端
 * 直接静态编译原始 CMD 代码（client_core.c），不依赖 DLL
 * 按钮点击转化为命令行参数调用 CliMain
 */
#include <windows.h>
#include <stdio.h>

/* client_core.c 中导出的入口（原 main 改名） */
extern int CliMain(int argc, char* argv[]);

#define ID_BTN_INIT    1001
#define ID_BTN_QUIT    1002
#define ID_BTN_LOCK    1003
#define ID_BTN_UNLOCK  1004
#define ID_BTN_STATUS  1005
#define ID_EDIT_PWD    1006
#define ID_EDIT_OUTPUT 1007

static HWND hOutput=NULL, hPwd=NULL;

static void RunCmd(const char* cmd) {
    char* argv[3];
    char arg0[64]="GlobalShutdownHook";
    char arg1[128];
    strcpy_s(arg1, sizeof(arg1), cmd);
    argv[0]=arg0; argv[1]=arg1; argv[2]=NULL;
    /* 重定向 stdout 到 output 窗口 */
    CliMain(2, argv);
}

static void RefreshOutput(void) {
    RunCmd("query_status");
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
    case WM_CREATE: {
        HINSTANCE hInst=((LPCREATESTRUCT)lParam)->hInstance;
        CreateWindowW(L"BUTTON",L"Init",WS_CHILD|WS_VISIBLE,10,10,70,28,hWnd,(HMENU)ID_BTN_INIT,hInst,NULL);
        CreateWindowW(L"BUTTON",L"Quit",WS_CHILD|WS_VISIBLE,90,10,70,28,hWnd,(HMENU)ID_BTN_QUIT,hInst,NULL);
        CreateWindowW(L"BUTTON",L"Lock",WS_CHILD|WS_VISIBLE,10,45,70,28,hWnd,(HMENU)ID_BTN_LOCK,hInst,NULL);
        CreateWindowW(L"BUTTON",L"Unlock",WS_CHILD|WS_VISIBLE,90,45,70,28,hWnd,(HMENU)ID_BTN_UNLOCK,hInst,NULL);
        CreateWindowW(L"BUTTON",L"Status",WS_CHILD|WS_VISIBLE,170,45,70,28,hWnd,(HMENU)ID_BTN_STATUS,hInst,NULL);
        CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD,10,82,230,24,hWnd,(HMENU)ID_EDIT_PWD,hInst,NULL);
        hOutput=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|ES_READONLY,
            10,115,250,140,hWnd,(HMENU)ID_EDIT_OUTPUT,hInst,NULL);
        hPwd=GetDlgItem(hWnd,ID_EDIT_PWD);
        SetWindowTextW(hOutput,L"Click buttons to operate.\nStatus: ready");
        return 0;
    }
    case WM_COMMAND: {
        switch(LOWORD(wParam)) {
        case ID_BTN_INIT:    RunCmd("init"); break;
        case ID_BTN_QUIT:    RunCmd("quit"); break;
        case ID_BTN_LOCK:    RunCmd("lock"); break;
        case ID_BTN_UNLOCK:  RunCmd("unlock"); break;
        case ID_BTN_STATUS:  RunCmd("query_status"); break;
        }
        return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR cmd,int show) {
    UNREFERENCED_PARAMETER(hPrev); UNREFERENCED_PARAMETER(cmd);
    WNDCLASSW wc={0};
    wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.lpszClassName=L"GSHGUI";
    wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1); wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    RegisterClassW(&wc);
    HWND hWnd=CreateWindowExW(0,L"GSHGUI",L"GlobalShutdownHook GUI",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,280,300,NULL,NULL,hInst,NULL);
    ShowWindow(hWnd,show); UpdateWindow(hWnd);
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return (int)msg.wParam;
}

/*
 * GshClient.h - GlobalShutdownHook 客户端库导出接口
 * 供 CMD 和 GUI 版本调用
 */
#ifndef _GSH_CLIENT_H_
#define _GSH_CLIENT_H_

#include <windows.h>

#ifdef GSHCLIENT_EXPORTS
#define GSH_API __declspec(dllexport)
#else
#define GSH_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化：加载驱动 + 启动BgSrv + 加载Auxiliary + PPL+DKOM */
GSH_API int Gsh_Init(void);

/* 退出：密码校验 + unhook + 卸载GSH + 卸载Aux + 终止BgSrv */
GSH_API int Gsh_Quit(const wchar_t* password);

/* 锁定 */
GSH_API int Gsh_Lock(void);

/* 解锁（需密码） */
GSH_API int Gsh_Unlock(const wchar_t* password);

/* 查询状态 */
GSH_API int Gsh_QueryStatus(int* locked, int* blocked, int* hooked, int* failed, int* inqueue);

/* 设置密码 */
GSH_API int Gsh_SetPassword(const wchar_t* oldPassword, const wchar_t* newPassword);

/* 获取最后错误信息 */
GSH_API const char* Gsh_GetLastError(void);

#ifdef __cplusplus
}
#endif

#endif /* _GSH_CLIENT_H_ */

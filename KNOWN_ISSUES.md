# 1. `quit` 指令问题
### 先说重要的事情: 千万千万不能 `quit` 了以后重新加载!!!!
### 如果你想体验BSOD的话也不是不可以(`SYSTEM_THREAD_EXCEPTION_NOT_HANDLED`).

# 2. `InfinityHook` 问题
### 暂时没能拦截到内核关机调用.....
### 初始化时报错 `STATUS_NOT_SUPPORTED`(31).
### (1.) 的问题也来源于这里的 `Auxilary.sys` 的问题.

# 3. 阻止关机计数问题
### 貌似 `Blocked` 统计有问题(乱统计....).可能不会修复

# 4. `quit` 时 `BgSrv` 不会退出
### 不知道为啥检测到驱动退出后不退出

# 5. `queue` 指令的实际情况和 `inqueue` 情况不对应.

# 6. 大部分进程都可以注入
### 唯独一些 `PPL` 和 `Wow64` 无法注入.
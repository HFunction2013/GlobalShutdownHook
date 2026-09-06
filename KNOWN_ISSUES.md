# 2. `InfinityHook` 问题
### 初始化成功无法拦截 `NtTerminateProcess`.

# 3. 阻止关机计数问题
### 貌似 `Blocked` 统计有问题(乱统计....其实没统计).可能不会修复

# 5. `queue` 指令的实际情况和 `inqueue` 情况不对应.

# 6. 大部分进程都可以注入
### 唯独一些 `PPL` 和 `Wow64` 无法注入.

# 7. DKOM/PPL 给 BgSrv 还是无法工作.
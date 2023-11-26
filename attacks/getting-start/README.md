
## 攻击开发  
在本地搭建攻击测试环境，开一个VM，在VM里面创建Docker，在Docker里面执行eBPF攻击程序。
这里详细介绍了如何一步步的开发一个eBPF Container namespace逃逸攻击的Demo。

### 首先部署Go环境  
下载go linux。  
```bash
go mod tidy
```
或者使用vs-code的go插件，能自动更新mod依赖。

### eBPF程序开发  
学习步骤：
1. [0-trace](0-trace) 写一个简单打印进程名的程序。
2. [1-bash](1-bash) 写bash劫持程序。
3. [2-cron](2-cron) 看懂cron程序的流程。

